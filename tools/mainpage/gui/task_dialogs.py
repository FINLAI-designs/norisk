"""
task_dialogs — Dialoge des Task-Boards.

``TaskFormDialog`` ersetzt die früheren Klassen ``NewTaskDialog`` und
``_EditTaskDialog`` aus ``taskboard_widget`` durch EINEN Formular-Dialog
nach dialog-skill Typ D (Header mit Icon, 36px-Felder, Buttons mit
vollständigen Hover-/Pressed-States über die Button-Factory).

``DismissTaskDialog`` erfragt die optionale Begründung beim Ablehnen
einer Aufgabe (Status ``dismissed``).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon
from core.widgets.button_styles import primary_button_qss, secondary_button_qss
from tools.mainpage.domain.models import Task

_FIELD_HEIGHT = 36
_DESC_HEIGHT = 80
# Eingabe-Limits — schützen DB-Zeilen und Karten-Layout vor Riesen-Pastes.
_MAX_TITLE_LEN = 300
_MAX_KLIENT_LEN = 200
_MAX_REASON_LEN = 500


def _combo_css(t) -> str:
    """Gibt CSS für QComboBox-Felder zurück."""
    return (
        f"QComboBox {{ background: {t.BG_INPUT}; color: {t.TEXT_MAIN}; "
        f"border: 1px solid {t.BORDER}; border-radius: 6px; padding: 4px 8px;"
        f" font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; }}"
        f"QComboBox:focus {{ border: 1px solid {t.ACCENT}; }}"
        f"QComboBox::drop-down {{ border: none; width: 20px; }}"
        f"QComboBox QAbstractItemView {{ background: {t.BG_INPUT}; color: {t.TEXT_MAIN}; "
        f"selection-background-color: {t.ACCENT}; selection-color: {theme.TEXT_ON_ACCENT_DEEP}; }}"
    )


def _input_css(t) -> str:
    """Gibt CSS für QLineEdit/QTextEdit-Felder zurück (Raleway, dialog-skill)."""
    return (
        f"QLineEdit, QTextEdit {{ background: {t.BG_INPUT}; color: {t.TEXT_MAIN}; "
        f"border: 1px solid {t.BORDER}; border-radius: 6px; padding: 4px 8px;"
        f" font-family: 'Raleway';"
        f" font-size: {theme.FONT_SIZE_BODY}px; }}"
        f"QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {t.ACCENT}; }}"
    )


def _label(text: str, t) -> QLabel:
    """Feld-Label im Formular-Stil (Raleway, gedimmt, fett)."""
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; "
        f"color: {t.TEXT_DIM}; font-weight: bold; background: transparent; "
        f"border: none;"
    )
    return lbl


class TaskFormDialog(QDialog):
    """Formular-Dialog zum Erstellen und Bearbeiten einer Aufgabe.

    Args:
        task: Bestehende Aufgabe zum Bearbeiten — ``None`` legt eine
            neue Aufgabe an (leerer Formular-Zustand).
        parent: Eltern-Widget.
    """

    def __init__(self, task: Task | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._task = task
        self.setWindowTitle("Aufgabe bearbeiten" if task else "Neue Aufgabe")
        self.setMinimumWidth(460)
        self.setModal(True)
        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def _build_ui(self) -> None:
        """Erstellt die Dialog-Oberfläche."""
        t = theme.get()
        is_edit = self._task is not None

        lyt = QVBoxLayout(self)
        lyt.setSpacing(12)
        lyt.setContentsMargins(24, 20, 24, 20)

        # Header: Icon + Titel (dialog-skill Typ D)
        header = QHBoxLayout()
        header.setSpacing(10)
        self._icon_lbl = QLabel()
        self._icon_lbl.setPixmap(
            get_icon(Icons.EDIT if is_edit else Icons.ADD, color=t.ACCENT).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(self._icon_lbl)
        self._title_lbl = QLabel(self.windowTitle())
        header.addWidget(self._title_lbl)
        header.addStretch()
        lyt.addLayout(header)

        self._lbl_title = _label("Titel *", t)
        lyt.addWidget(self._lbl_title)
        self.title_edit = QLineEdit(self._task.title if is_edit else "")
        self.title_edit.setPlaceholderText("Aufgabentitel …")
        self.title_edit.setFixedHeight(_FIELD_HEIGHT)
        self.title_edit.setMaxLength(_MAX_TITLE_LEN)
        self.title_edit.textChanged.connect(self._on_title_changed)
        lyt.addWidget(self.title_edit)

        self._lbl_desc = _label("Beschreibung", t)
        lyt.addWidget(self._lbl_desc)
        self.desc_edit = QTextEdit()
        self.desc_edit.setFixedHeight(_DESC_HEIGHT)
        self.desc_edit.setPlaceholderText("Optionale Beschreibung …")
        if is_edit:
            self.desc_edit.setPlainText(self._task.description or "")
        lyt.addWidget(self.desc_edit)

        # Bei KI-Tasks gehören Titel + Beschreibung der Maschine —
        # die Reconciliation rendert sie bei jedem Scan frisch aus dem
        # Finding. User-Edits daran würden still überschrieben, deshalb
        # read-only; Kategorie/Klient/Priorität bleiben editierbar.
        if is_edit and self._task.source == "auto":
            hint = (
                "Wird von der KI aus dem Befund erzeugt und bei jedem "
                "Scan aktualisiert — nicht manuell editierbar."
            )
            for field_widget in (self.title_edit, self.desc_edit):
                field_widget.setReadOnly(True)
                field_widget.setToolTip(hint)

        self._lbl_cat = _label("Kategorie", t)
        lyt.addWidget(self._lbl_cat)
        self.cat_box = QComboBox()
        self.cat_box.addItems(["allgemein", "klient", "tool"])
        self.cat_box.setFixedHeight(_FIELD_HEIGHT)
        if is_edit:
            self.cat_box.setCurrentText(self._task.category)
        lyt.addWidget(self.cat_box)

        self._lbl_klient = _label("Klient (optional)", t)
        lyt.addWidget(self._lbl_klient)
        self.klient_edit = QLineEdit(self._task.klient if is_edit else "")
        self.klient_edit.setPlaceholderText("Klientenname …")
        self.klient_edit.setFixedHeight(_FIELD_HEIGHT)
        self.klient_edit.setMaxLength(_MAX_KLIENT_LEN)
        lyt.addWidget(self.klient_edit)

        self._lbl_prio = _label("Priorität", t)
        lyt.addWidget(self._lbl_prio)
        self.prio_box = QComboBox()
        self.prio_box.addItems(["normal", "low", "high"])
        self.prio_box.setFixedHeight(_FIELD_HEIGHT)
        if is_edit:
            self.prio_box.setCurrentText(self._task.priority)
        lyt.addWidget(self.prio_box)

        lyt.addSpacing(8)
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_save = QPushButton("Speichern")
        self.btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save.setDefault(True)
        self.btn_save.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_save)

        lyt.addLayout(btn_row)
        self.apply_theme()
        self._on_title_changed(self.title_edit.text())

    def _on_title_changed(self, text: str) -> None:
        """Speichern nur mit nicht-leerem Titel zulassen."""
        self.btn_save.setEnabled(bool(text.strip()))

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
        self._title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; "
            f"font-weight: 700; color: {c.TEXT_MAIN}; background: transparent; "
            f"border: none;"
        )
        for lbl in (
            self._lbl_title,
            self._lbl_desc,
            self._lbl_cat,
            self._lbl_klient,
            self._lbl_prio,
        ):
            lbl.setStyleSheet(
                f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; "
                f"color: {c.TEXT_DIM}; font-weight: bold; background: transparent; "
                f"border: none;"
            )
        self.title_edit.setStyleSheet(_input_css(c))
        self.desc_edit.setStyleSheet(_input_css(c))
        self.cat_box.setStyleSheet(_combo_css(c))
        self.klient_edit.setStyleSheet(_input_css(c))
        self.prio_box.setStyleSheet(_combo_css(c))
        self.btn_cancel.setStyleSheet(secondary_button_qss())
        self.btn_save.setStyleSheet(primary_button_qss())

    # ------------------------------------------------------------------
    # Formular-Werte
    # ------------------------------------------------------------------

    @property
    def task_title(self) -> str:
        """Der eingegebene Titel (getrimmt)."""
        return self.title_edit.text().strip()

    @property
    def task_desc(self) -> str:
        """Die eingegebene Beschreibung (getrimmt, ggf. leer)."""
        return self.desc_edit.toPlainText().strip()

    @property
    def task_category(self) -> str:
        """Die gewählte Kategorie (``allgemein``/``klient``/``tool``)."""
        return self.cat_box.currentText()

    @property
    def task_klient(self) -> str:
        """Der eingegebene Klientenname (getrimmt, ggf. leer)."""
        return self.klient_edit.text().strip()

    @property
    def task_priority(self) -> str:
        """Die gewählte Priorität (``normal``/``low``/``high``)."""
        return self.prio_box.currentText()


class DismissTaskDialog(QDialog):
    """Dialog zum Ablehnen einer Aufgabe mit optionaler Begründung.

    Die Aufgabe wird NICHT gelöscht — sie wechselt auf ``dismissed``,
    verschwindet vom Board und bleibt im Aufgabenlog nachvollziehbar.

    Args:
        parent: Eltern-Widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aufgabe ablehnen")
        self.setMinimumWidth(420)
        self.setModal(True)
        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def _build_ui(self) -> None:
        """Erstellt die Dialog-Oberfläche."""
        t = theme.get()

        lyt = QVBoxLayout(self)
        lyt.setSpacing(12)
        lyt.setContentsMargins(24, 20, 24, 20)

        header = QHBoxLayout()
        header.setSpacing(10)
        self._icon_lbl = QLabel()
        self._icon_lbl.setPixmap(
            get_icon(Icons.BLOCK, color=t.WARNING).pixmap(
                ICON_SIZE_DIALOG, ICON_SIZE_DIALOG
            )
        )
        header.addWidget(self._icon_lbl)
        self._title_lbl = QLabel("Aufgabe ablehnen")
        header.addWidget(self._title_lbl)
        header.addStretch()
        lyt.addLayout(header)

        self._hint_lbl = QLabel(
            "Die Aufgabe verschwindet vom Board, bleibt aber im "
            "Aufgabenlog nachvollziehbar und wird nicht erneut "
            "vorgeschlagen."
        )
        self._hint_lbl.setWordWrap(True)
        lyt.addWidget(self._hint_lbl)

        self._lbl_reason = _label("Begründung (optional)", t)
        lyt.addWidget(self._lbl_reason)
        self.reason_edit = QLineEdit()
        self.reason_edit.setPlaceholderText("z. B. betrifft uns nicht …")
        self.reason_edit.setFixedHeight(_FIELD_HEIGHT)
        self.reason_edit.setMaxLength(_MAX_REASON_LEN)
        lyt.addWidget(self.reason_edit)

        lyt.addSpacing(8)
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_dismiss = QPushButton("Ablehnen")
        self.btn_dismiss.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_dismiss.setDefault(True)
        self.btn_dismiss.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_dismiss)

        lyt.addLayout(btn_row)
        self.apply_theme()

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
        self._title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; "
            f"font-weight: 700; color: {c.TEXT_MAIN}; background: transparent; "
            f"border: none;"
        )
        self._hint_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; "
            f"color: {c.TEXT_DIM}; background: transparent; border: none;"
        )
        self._lbl_reason.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; "
            f"color: {c.TEXT_DIM}; font-weight: bold; background: transparent; "
            f"border: none;"
        )
        self.reason_edit.setStyleSheet(_input_css(c))
        self.btn_cancel.setStyleSheet(secondary_button_qss())
        self.btn_dismiss.setStyleSheet(primary_button_qss())

    @property
    def reason(self) -> str:
        """Die eingegebene Begründung (getrimmt, ggf. leer)."""
        return self.reason_edit.text().strip()
