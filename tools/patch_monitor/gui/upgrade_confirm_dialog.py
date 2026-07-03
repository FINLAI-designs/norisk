"""upgrade_confirm_dialog — Bestaetigungs-Modal vor dem Batch-Upgrade.

 / PM-2.x Stop-Step C. Zeigt dem User vor dem Start eines
:meth:`BatchUpgradeService.upgrade_batch` an,

* welche Programme aktualisiert werden (App-Name + von → nach),
* dass der Vorgang Admin-Rechte braucht (winget UAC-Reprompt),
* dass der Batch sequentiell laeuft und abgebrochen werden kann.

Pattern-Vorbild::class:`core.dialogs.FinlaiConfirmDialog` (Framless +
Theme-Farben), erweitert um eine scrollbare Update-Liste fuer >5 Items.

Schicht: ``gui/`` — keine ``data/``-Imports, kein direkter Service-Call.
Der eigentliche Batch-Start passiert im aufrufenden Widget nach
``dialog.exec == QDialog.DialogCode.Accepted``.
"""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_DIALOG, Icons, get_icon
from core.patch_upgrade import UpgradeRequest


class UpgradeConfirmDialog(QDialog):
    """Modaler Dialog mit Update-Liste + Admin-Hinweis + Confirm/Cancel.

    Args:
        requests: Die ausgewaehlten:class:`UpgradeRequest`-Objekte.
            Die Liste darf nicht leer sein — Aufrufer pruefen das vorher
            und blenden den Dialog bei leerer Auswahl gar nicht ein.
        parent: Eltern-Widget fuer Memory-Management + Modal-Anchor.

    Verwendung::

        dialog = UpgradeConfirmDialog(requests=selected, parent=self)
        if dialog.exec == QDialog.DialogCode.Accepted:
            # Batch-Worker starten
...
    """

    def __init__(
        self,
        requests: Iterable[UpgradeRequest],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._requests = list(requests)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 8px; }}"
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addLayout(self._build_header(c))
        root.addWidget(self._build_message(c))
        root.addWidget(self._build_list(c))
        root.addWidget(self._build_admin_hint(c))
        root.addLayout(self._build_buttons(c))

        self.setMinimumWidth(520)
        self.setMinimumHeight(380)

    def _build_header(self, c) -> QHBoxLayout:  # noqa: ANN001 - theme tuple
        header = QHBoxLayout()
        header.setSpacing(10)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.WARNING, color=c.WARNING).pixmap(ICON_SIZE_DIALOG, ICON_SIZE_DIALOG))
        header.addWidget(icon_lbl)

        title_lbl = QLabel(self._title_text())
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        header.addWidget(title_lbl)
        header.addStretch()
        return header

    def _title_text(self) -> str:
        n = len(self._requests)
        if n == 1:
            return "1 Update installieren"
        return f"{n} Updates installieren"

    def _build_message(self, c) -> QLabel:  # noqa: ANN001
        lbl = QLabel(
            "Die folgenden Programme werden sequentiell aktualisiert. "
            "Du kannst den Vorgang jederzeit abbrechen — bereits "
            "gestartete Installationen laufen fertig."
        )
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_DIM};"
        )
        return lbl

    def _build_list(self, c) -> QListWidget:  # noqa: ANN001
        lw = QListWidget()
        lw.setObjectName("UpgradeRequestList")
        lw.setStyleSheet(
            f"QListWidget#UpgradeRequestList {{"
            f"  background: {c.BG_MAIN};"
            f"  border: 1px solid {c.BORDER};"
            f"  border-radius: 4px;"
            f"  padding: 4px;"
            f"  font-family: 'Inter';"
            f"  font-size: 12px;"
            f"  color: {c.TEXT_MAIN};"
            f"}}"
            f"QListWidget#UpgradeRequestList::item {{"
            f"  padding: 4px 6px;"
            f"}}"
        )
        for req in self._requests:
            lw.addItem(QListWidgetItem(_format_request(req)))
        # Volle Liste sichtbar bis ~10 Items, danach Scrollbar.
        lw.setMinimumHeight(160)
        return lw

    def _build_admin_hint(self, c) -> QLabel:  # noqa: ANN001
        lbl = QLabel(
            "ℹ Updates erfordern in der Regel Administrator-Rechte. "
            "Bei fehlenden Rechten meldet winget einen Fehler — die "
            "Batch laeuft trotzdem weiter, die Audit-Historie zeigt's."
        )
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
            f" background: {c.BG_MAIN}; border-radius: 4px; padding: 6px 8px;"
        )
        return lbl

    def _build_buttons(self, c) -> QHBoxLayout:  # noqa: ANN001
        row = QHBoxLayout()
        row.addStretch()

        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.setObjectName("UpgradeConfirmCancel")
        btn_cancel.setStyleSheet(_secondary_style(c))
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)

        btn_confirm = QPushButton(self._confirm_text())
        btn_confirm.setObjectName("UpgradeConfirmAccept")
        btn_confirm.setDefault(True)
        btn_confirm.setStyleSheet(_primary_style(c))
        btn_confirm.clicked.connect(self.accept)
        row.addWidget(btn_confirm)

        return row

    def _confirm_text(self) -> str:
        n = len(self._requests)
        if n == 1:
            return "Update starten"
        return f"{n} Updates starten"


# ---------------------------------------------------------------------------
# Modul-Funktionen — testbar ohne QApplication
# ---------------------------------------------------------------------------


def _format_request(req: UpgradeRequest) -> str:
    """Formatiert eine Update-Zeile als ``"App 1.0 → 2.0"``."""
    if req.version_from and req.version_to:
        return f"{req.display_name}    {req.version_from} → {req.version_to}"
    if req.version_to:
        return f"{req.display_name}    → {req.version_to}"
    return req.display_name


def _primary_style(c) -> str:  # noqa: ANN001
    return (
        f"QPushButton {{ background: {c.ACCENT};"
        f" color: {theme.TEXT_ON_ACCENT_DEEP}; border: none;"
        f" border-radius: 6px; padding: 7px 18px;"
        f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
        f"QPushButton:hover {{ background: {theme.ACCENT_HOVER_BRIGHT}; }}"
    )


def _secondary_style(c) -> str:  # noqa: ANN001
    return (
        f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"
        f" border: 1px solid {c.BORDER}; border-radius: 6px;"
        f" padding: 7px 18px; font-family: 'Raleway'; font-weight: 600;"
        f" font-size: 13px; }}"
        f"QPushButton:hover {{ background: {c.CARD_BG};"
        f" color: {c.TEXT_MAIN}; }}"
    )


__all__ = ["UpgradeConfirmDialog"]
