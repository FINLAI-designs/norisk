"""
consent_dialog — Modale Einwilligung zum Apply-Nutzungshinweis (R7).

Zeigt den vollstaendigen, scrollbaren Hinweistext (:data:`apply_terms.
APPLY_TERMS_TEXT`) mit einer „Ich stimme zu"-Checkbox; „Zustimmen" ist erst nach
gesetztem Haeckchen aktiv. Wird vor der ERSTEN Anwendung (und nach jeder
Versions-Aenderung) gezeigt; die Zustimmung speichert der:class:`ConsentGate`
versioniert + protokolliert.

Schicht: ``gui/`` — keine data/-Imports; Text aus application/apply_terms.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import theme


class ConsentDialog(QDialog):
    """Scrollbarer Hinweistext + Zustimmungs-Checkbox + Abbrechen/Zustimmen.

    Args:
        text: Der vollstaendige Hinweis-/Einwilligungstext.
        parent: Eltern-Widget.
    """

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = text
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

        title = QLabel("Anwenden — Hinweis und Zustimmung")
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 16px; font-weight: 700;"
            f" color: {c.TEXT_MAIN};"
        )
        root.addWidget(title)

        browser = QTextBrowser()
        browser.setPlainText(self._text)
        browser.setOpenExternalLinks(False)
        browser.setMinimumHeight(260)
        browser.setStyleSheet(
            f"QTextBrowser {{ background: {c.BG_MAIN}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; padding: 8px; font-family: 'Inter';"
            f" font-size: 12px; color: {c.TEXT_MAIN}; }}"
        )
        root.addWidget(browser, stretch=1)

        self._agree = QCheckBox("Ich habe den Hinweis gelesen und stimme zu.")
        self._agree.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.TEXT_MAIN};"
        )
        root.addWidget(self._agree)

        row = QHBoxLayout()
        row.addStretch()
        cancel = QPushButton("Abbrechen")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet(_secondary_style(c))
        row.addWidget(cancel)
        self._confirm = QPushButton("Zustimmen")
        self._confirm.setEnabled(False)
        self._confirm.clicked.connect(self.accept)
        self._confirm.setStyleSheet(_primary_style(c))
        row.addWidget(self._confirm)
        root.addLayout(row)

        self._agree.toggled.connect(self._confirm.setEnabled)
        self.setMinimumWidth(560)


def _primary_style(c) -> str:  # noqa: ANN001 — theme tuple
    return (
        f"QPushButton {{ background: {c.ACCENT}; color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" border: none; border-radius: 6px; padding: 7px 18px;"
        f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
        f"QPushButton:disabled {{ background: {c.BORDER}; color: {c.TEXT_DIM}; }}"
        f"QPushButton:hover:enabled {{ background: {theme.ACCENT_HOVER_BRIGHT}; }}"
    )


def _secondary_style(c) -> str:  # noqa: ANN001
    return (
        f"QPushButton {{ background: transparent; color: {c.TEXT_DIM};"
        f" border: 1px solid {c.BORDER}; border-radius: 6px; padding: 7px 18px;"
        f" font-family: 'Raleway'; font-weight: 600; font-size: 13px; }}"
        f"QPushButton:hover {{ background: {c.CARD_BG}; color: {c.TEXT_MAIN}; }}"
    )


__all__ = ["ConsentDialog"]
