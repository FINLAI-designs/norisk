"""links_tab — GUI-Tab für Wichtige Links (kuratiert + benutzereigen).

Zeigt zuerst die fixen kuratierten Links (nicht editierbar, nicht löschbar),
dann die benutzereigenen Links mit den gewohnten Bearbeiten-/Löschen-Buttons.

Schichtzugehörigkeit: gui/ — nur PySide6 und core/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.auth.session import Session
from core.curated_links import get_curated_links
from core.icons import Icons, get_icon
from core.links_repository import LinksRepository, UserLink


class LinksTab(QWidget):
    """Tab-Widget für Wichtige Links in den Einstellungen.

    Zeigt kuratierte Links (oben, gesperrt) und benutzereigene Links (unten,
    editierbar) getrennt durch eine Trennlinie.

    Signals:
        links_changed: Wird emittiert nachdem die User-Link-Liste gespeichert wurde.
    """

    links_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._repo = LinksRepository()
        self._links: list[UserLink] = []
        self._app_id = "finlai"
        self._build_ui()
        self._lade_links()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self._apply_theme)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        """Erstellt die Oberfläche: kuratierte Sektion oben, User-Sektion unten."""
        c = theme.get()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # --- Kuratierte Links ---
        curated_header = QLabel("Kuratierte Links")
        curated_header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-bottom: 2px;"
        )
        layout.addWidget(curated_header)

        curated_hint = QLabel(
            "Diese Links werden von FINLAI bereitgestellt und können nicht bearbeitet werden."
        )
        curated_hint.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        curated_hint.setWordWrap(True)
        layout.addWidget(curated_hint)

        self._curated_list = QListWidget()
        self._curated_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._curated_list.setMaximumHeight(180)
        self._curated_list.setStyleSheet(self._list_style(c, locked=True))
        self._curated_list.itemDoubleClicked.connect(self._on_curated_open)
        layout.addWidget(self._curated_list)

        # --- Trennlinie ---
        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {c.BORDER};")
        self._sep = sep
        layout.addWidget(sep)

        # --- User-eigene Links ---
        user_header = QLabel("Deine Links")
        user_header.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-bottom: 2px;"
        )
        layout.addWidget(user_header)

        user_hint = QLabel(
            "Diese Links erscheinen in der Sidebar unter \u201eWichtige Links\u201c."
            " Jeder Benutzer pflegt seine eigene Liste."
        )
        user_hint.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        user_hint.setWordWrap(True)
        layout.addWidget(user_hint)

        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list.setStyleSheet(self._list_style(c, locked=False))
        self._list.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._list, stretch=1)

        # Aktions-Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        _btn_style = self._btn_style(c)

        self._btn_hinzu = QPushButton("Hinzufügen")
        self._btn_hinzu.setIcon(get_icon(Icons.ADD))
        self._btn_hinzu.setStyleSheet(_btn_style)
        self._btn_hinzu.clicked.connect(self._on_hinzu)
        btn_row.addWidget(self._btn_hinzu)

        self._btn_bearbeiten = QPushButton("Bearbeiten")
        self._btn_bearbeiten.setIcon(get_icon(Icons.EDIT))
        self._btn_bearbeiten.setEnabled(False)
        self._btn_bearbeiten.setStyleSheet(_btn_style)
        self._btn_bearbeiten.clicked.connect(self._on_bearbeiten)
        btn_row.addWidget(self._btn_bearbeiten)

        btn_row.addStretch()

        self._btn_hoch = QPushButton()
        self._btn_hoch.setIcon(get_icon(Icons.ARROW_UP))
        self._btn_hoch.setEnabled(False)
        self._btn_hoch.setFixedWidth(34)
        self._btn_hoch.setStyleSheet(_btn_style)
        self._btn_hoch.clicked.connect(self._on_hoch)
        btn_row.addWidget(self._btn_hoch)

        self._btn_runter = QPushButton()
        self._btn_runter.setIcon(get_icon(Icons.ARROW_DOWN))
        self._btn_runter.setEnabled(False)
        self._btn_runter.setFixedWidth(34)
        self._btn_runter.setStyleSheet(_btn_style)
        self._btn_runter.clicked.connect(self._on_runter)
        btn_row.addWidget(self._btn_runter)

        btn_row.addStretch()

        self._btn_loeschen = QPushButton("Löschen")
        self._btn_loeschen.setIcon(get_icon(Icons.DELETE))
        self._btn_loeschen.setEnabled(False)
        self._btn_loeschen.setStyleSheet(self._danger_btn_style(c))
        self._btn_loeschen.clicked.connect(self._on_loeschen)
        btn_row.addWidget(self._btn_loeschen)

        layout.addLayout(btn_row)

    # ------------------------------------------------------------------
    @staticmethod
    def _list_style(c: object, *, locked: bool) -> str:
        bg = c.BG_BUTTON_DISABLED if locked else c.BG_INPUT
        return (
            f"QListWidget {{ background: {bg}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px; }}"
            f"QListWidget::item {{ padding: 4px 6px; }}"
            f"QListWidget::item:selected {{ background: {c.ACCENT};"
            f" color: {c.BG_DARK}; }}"
            f"QListWidget::item:hover:!selected {{ background: {c.BG_SIDEBAR_HOVER}; }}"
        )

    @staticmethod
    def _btn_style(c: object) -> str:
        return (
            f"QPushButton {{ background: {c.BG_BUTTON};"
            f" color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT};"
            f" color: {c.BG_DARK}; border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT};"
            f" color: {c.BG_DARK}; padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED};"
            f" border-color: {c.BORDER}; }}"
        )

    @staticmethod
    def _danger_btn_style(c: object) -> str:
        return (
            f"QPushButton {{ background: {c.DANGER}; color: {theme.DARK_TEXT_ON_ACCENT};"
            f" border: 1px solid {c.DANGER}; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ERROR};"
            f" border-color: {c.ERROR}; }}"
            f"QPushButton:pressed {{ background: {c.DANGER};"
            f" padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED};"
            f" border-color: {c.BORDER_BUTTON_DISABLED}; }}"
        )

    # ------------------------------------------------------------------
    def _apply_theme(self) -> None:
        """Aktualisiert Farben bei Theme-Wechsel ohne UI-Neuaufbau."""
        c = theme.get()
        self._curated_list.setStyleSheet(self._list_style(c, locked=True))
        self._list.setStyleSheet(self._list_style(c, locked=False))
        self._sep.setStyleSheet(f"background: {c.BORDER};")
        _btn_style = self._btn_style(c)
        for btn in (
            self._btn_hinzu,
            self._btn_bearbeiten,
            self._btn_hoch,
            self._btn_runter,
        ):
            btn.setStyleSheet(_btn_style)
        self._btn_loeschen.setStyleSheet(self._danger_btn_style(c))

    # ------------------------------------------------------------------
    def _lade_links(self) -> None:
        """Lädt kuratierte und User-Links für die aktive App."""
        from apps.app_config import get_active_config  # noqa: PLC0415

        user = Session().current_user
        if user is None:
            return
        cfg = get_active_config()
        self._app_id = cfg.app_id if cfg else "finlai"

        # Kuratierte Links befüllen
        self._curated_list.clear()
        for lnk in get_curated_links(self._app_id):
            icon_val = get_icon(lnk.icon) if lnk.icon else get_icon("link")
            item = QListWidgetItem(icon_val, f"{lnk.title}  —  {lnk.category}")
            item.setData(Qt.ItemDataRole.UserRole, lnk.url)
            item.setToolTip(lnk.description or lnk.url)
            self._curated_list.addItem(item)

        # User-Links befüllen
        self._links = self._repo.lade(user.username, app_id=self._app_id)
        self._refresh_list()

    def _refresh_list(self) -> None:
        """Synchronisiert QListWidget mit self._links."""
        self._list.clear()
        for lnk in self._links:
            icon_name = lnk.icon
            if (
                icon_name
                and icon_name.isascii()
                and icon_name.replace("_", "").isalpha()
            ):
                icon_val = get_icon(icon_name)
                item = QListWidgetItem(icon_val, f"{lnk.label}  —  {lnk.url}")
            else:
                item = QListWidgetItem(f"{icon_name}  {lnk.label}  —  {lnk.url}")
            item.setData(Qt.ItemDataRole.UserRole, lnk)
            self._list.addItem(item)

    def _speichere(self) -> None:
        """Speichert self._links in der DB und emittiert links_changed."""
        user = Session().current_user
        if user is None:
            return
        self._repo.speichere(user.username, self._links, app_id=self._app_id)
        self.links_changed.emit()

    # ------------------------------------------------------------------
    def _on_curated_open(self, item: QListWidgetItem) -> None:
        """Öffnet kuratierten Link im Standard-Browser bei Doppelklick."""
        url = item.data(Qt.ItemDataRole.UserRole)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def _on_selection_changed(self) -> None:
        """Aktiviert oder deaktiviert Aktions-Buttons je nach Auswahl."""
        has_sel = bool(self._list.selectedItems())
        idx = self._list.currentRow()
        count = self._list.count()
        self._btn_bearbeiten.setEnabled(has_sel)
        self._btn_loeschen.setEnabled(has_sel)
        self._btn_hoch.setEnabled(has_sel and idx > 0)
        self._btn_runter.setEnabled(has_sel and idx < count - 1)

    def _selected_index(self) -> int:
        """Gibt den aktuellen Listenindex zurück oder -1."""
        return self._list.currentRow()

    # ------------------------------------------------------------------
    def _on_hinzu(self) -> None:
        """Öffnet Dialog zum Anlegen eines neuen Links."""
        dlg = _LinkDialog(parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            lnk = dlg.result_link()
            self._links.append(lnk)
            self._speichere()
            self._refresh_list()
            self._list.setCurrentRow(len(self._links) - 1)

    def _on_bearbeiten(self) -> None:
        """Öffnet Dialog zum Bearbeiten des ausgewählten Links."""
        idx = self._selected_index()
        if idx < 0:
            return
        dlg = _LinkDialog(link=self._links[idx], parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._links[idx] = dlg.result_link()
            self._speichere()
            self._refresh_list()
            self._list.setCurrentRow(idx)

    def _on_loeschen(self) -> None:
        """Löscht den ausgewählten Link."""
        idx = self._selected_index()
        if idx < 0:
            return
        self._links.pop(idx)
        self._speichere()
        self._refresh_list()

    def _on_hoch(self) -> None:
        """Verschiebt den ausgewählten Link eine Position nach oben."""
        idx = self._selected_index()
        if idx <= 0:
            return
        self._links[idx - 1], self._links[idx] = self._links[idx], self._links[idx - 1]
        self._speichere()
        self._refresh_list()
        self._list.setCurrentRow(idx - 1)

    def _on_runter(self) -> None:
        """Verschiebt den ausgewählten Link eine Position nach unten."""
        idx = self._selected_index()
        if idx < 0 or idx >= len(self._links) - 1:
            return
        self._links[idx], self._links[idx + 1] = self._links[idx + 1], self._links[idx]
        self._speichere()
        self._refresh_list()
        self._list.setCurrentRow(idx + 1)


# ---------------------------------------------------------------------------
# Eingabe-Dialog
# ---------------------------------------------------------------------------


class _LinkDialog(QDialog):
    """Modaler Dialog zum Anlegen oder Bearbeiten eines benutzereigenen Links."""

    def __init__(
        self,
        link: UserLink | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._link = link
        self.setWindowTitle("Link bearbeiten" if link else "Link hinzufügen")
        self.setMinimumWidth(420)
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        form = QFormLayout()
        form.setSpacing(8)

        _field_style = (
            f"QLineEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
        )
        _label_style = f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 13px;"

        lbl_icon = QLabel("Icon:")
        lbl_icon.setStyleSheet(_label_style)

        icon_row = QHBoxLayout()
        icon_row.setContentsMargins(0, 0, 0, 0)
        icon_row.setSpacing(6)

        self._icon_edit = QLineEdit(self._link.icon if self._link else "language")
        self._icon_edit.setFixedWidth(120)
        self._icon_edit.setReadOnly(True)
        self._icon_edit.setStyleSheet(_field_style)
        icon_row.addWidget(self._icon_edit)

        btn_palette = QPushButton("…")
        btn_palette.setFixedSize(28, 28)
        btn_palette.setToolTip("Icon aus Palette wählen")
        btn_palette.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK}; color: {c.BG_DARK}; }}"
        )
        btn_palette.clicked.connect(self._on_palette_oeffnen)
        icon_row.addWidget(btn_palette)
        icon_row.addStretch()

        icon_widget = QWidget()
        icon_widget.setLayout(icon_row)
        form.addRow(lbl_icon, icon_widget)

        lbl_label = QLabel("Bezeichnung:")
        lbl_label.setStyleSheet(_label_style)
        self._label_edit = QLineEdit(self._link.label if self._link else "")
        self._label_edit.setStyleSheet(_field_style)
        form.addRow(lbl_label, self._label_edit)

        lbl_url = QLabel("URL:")
        lbl_url.setStyleSheet(_label_style)
        self._url_edit = QLineEdit(self._link.url if self._link else "https://")
        self._url_edit.setStyleSheet(_field_style)
        form.addRow(lbl_url, self._url_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK}; }}"
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_palette_oeffnen(self) -> None:
        """Öffnet eine Material-Icon-Palette als modales Popup."""
        c = theme.get()
        popup = QDialog(self)
        popup.setWindowTitle("Icon wählen")
        popup.setWindowFlags(
            popup.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )
        popup.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; }}"
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" min-width: 80px; min-height: 56px; padding: 4px 6px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DIM}; border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK}; }}"
        )
        grid = QGridLayout(popup)
        grid.setSpacing(6)
        grid.setContentsMargins(12, 12, 12, 12)

        cols = 5
        for idx, (icon_name, label) in enumerate(Icons.LINK_ICON_CHOICES):
            btn = QPushButton(label)
            btn.setIcon(get_icon(icon_name, color=c.ACCENT))
            btn.setToolTip(label)

            def _make_handler(n: str) -> object:
                def _handler() -> None:
                    self._icon_edit.setText(n)
                    popup.accept()

                return _handler

            btn.clicked.connect(_make_handler(icon_name))
            grid.addWidget(btn, idx // cols, idx % cols)

        popup.exec()

    def _on_accept(self) -> None:
        """Validiert Eingaben und schließt den Dialog."""
        if not self._label_edit.text().strip():
            self._label_edit.setFocus()
            return
        if not self._url_edit.text().strip():
            self._url_edit.setFocus()
            return
        self.accept()

    def result_link(self) -> UserLink:
        """Gibt den UserLink mit den eingegebenen Werten zurück.

        Returns:
            UserLink mit label, url und icon aus den Eingabefeldern.
        """
        return UserLink(
            label=self._label_edit.text().strip(),
            url=self._url_edit.text().strip(),
            icon=self._icon_edit.text().strip() or "language",
            id=self._link.id if self._link else 0,
        )
