"""
apply_confirm_dialog — Bestaetigungs-Modal vor dem elevated Apply.

Zeigt vor dem Anwenden: welche Empfehlungen geaendert werden (Titel + Ist→Soll),
dass Admin-Rechte (UAC) noetig sind, ein Wiederherstellungspunkt erstellt wird
und jede Aenderung reversibel ist. Muster::class:`UpgradeConfirmDialog`.

Schicht: ``gui/`` — kein data/-Import, kein Service-Call. Der Apply-Start
passiert im aufrufenden Widget nach ``exec == Accepted``.

Author: Patrick Riederich
Version: 1.0
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


class ApplyConfirmDialog(QDialog):
    """Modaler Dialog: Empfehlungs-Liste + UAC/Restore-Hinweis + Confirm/Cancel.

    Args:
        lines: ``(titel, "Ist → Soll")``-Paare der anzuwendenden Tweaks
            (nicht leer — der Aufrufer prueft das vorher).
        parent: Eltern-Widget.
    """

    def __init__(
        self,
        lines: Iterable[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._lines = list(lines)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 8px; }}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = QLabel(self._title_text())
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        root.addWidget(title)

        msg = QLabel(
            "Die folgenden Datenschutz-Empfehlungen werden angewandt. Vorher wird "
            "ein Wiederherstellungspunkt erstellt; jede Aenderung ist umkehrbar "
            "('Meine Aenderungen zuruecknehmen')."
        )
        msg.setWordWrap(True)
        msg.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_DIM};"
        )
        root.addWidget(msg)

        listing = QListWidget()
        listing.setObjectName("TunerApplyList")
        for title_de, transition in self._lines:
            listing.addItem(QListWidgetItem(f"{title_de}    {transition}"))
        listing.setMinimumHeight(160)
        listing.setStyleSheet(
            f"QListWidget#TunerApplyList {{ background: {c.BG_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px;"
            f" font-family: 'Inter'; font-size: 12px; color: {c.TEXT_MAIN}; }}"
            f"QListWidget#TunerApplyList::item {{ padding: 4px 6px; }}"
        )
        root.addWidget(listing)

        hint = QLabel(
            "ℹ Das Anwenden erfordert Administrator-Rechte (eine UAC-Abfrage). "
            "Auf Pro/Home-Editionen bleibt die strengste Telemetrie-Stufe "
            "'Erforderlich'."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
            f" background: {c.BG_MAIN}; border-radius: 4px; padding: 6px 8px;"
        )
        root.addWidget(hint)

        row = QHBoxLayout()
        row.addStretch()
        cancel = QPushButton("Abbrechen")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet(_secondary_style(c))
        row.addWidget(cancel)
        confirm = QPushButton(self._confirm_text())
        confirm.setDefault(True)
        confirm.clicked.connect(self.accept)
        confirm.setStyleSheet(_primary_style(c))
        row.addWidget(confirm)
        root.addLayout(row)

        self.setMinimumWidth(520)

    def _title_text(self) -> str:
        n = len(self._lines)
        return "1 Empfehlung anwenden" if n == 1 else f"{n} Empfehlungen anwenden"

    def _confirm_text(self) -> str:
        n = len(self._lines)
        return "Anwenden" if n == 1 else f"{n} anwenden"


def _primary_style(c) -> str:  # noqa: ANN001 — theme tuple
    return (
        f"QPushButton {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" border: none; border-radius: 6px; padding: 7px 18px;"
        f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
        f"QPushButton:hover {{ background: {theme.ACCENT_HOVER_BRIGHT}; }}"
    )


def _secondary_style(c) -> str:  # noqa: ANN001
    return (
        f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"
        f" border: 1px solid {c.BORDER}; border-radius: 6px; padding: 7px 18px;"
        f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
        f"QPushButton:hover {{ background: {c.CARD_BG}; color: {c.TEXT_MAIN}; }}"
    )


__all__ = ["ApplyConfirmDialog"]
