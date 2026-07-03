"""Abschluss-Seite des First-Run-Wizards.

Zeigt eine Erfolgs-Meldung und den gerade angelegten Benutzernamen
(via:meth:`set_username`). Der Wizard schließt sich nach Klick auf
„Fertigstellen".
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from core.first_run_wizard.pages.base_page import BasePage
from core.theme import DARK_ACCENT, DARK_SUCCESS, DARK_TEXT_PRIMARY


class CompletionPage(BasePage):
    """Finale Seite — Bestätigung der erfolgreichen Einrichtung."""

    TITLE = "Fertig"

    def __init__(self) -> None:
        super().__init__()
        self._username: str | None = None

        heading = QLabel("Einrichtung abgeschlossen")
        heading.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 22px; font-weight: bold;"
            f" color: {DARK_SUCCESS};"
        )
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._body = QLabel(
            "Dein Administrator-Konto wurde erfolgreich angelegt.\n\n"
            "Nach dem Schließen dieses Assistenten wirst du zur Anmeldung "
            "weitergeleitet."
        )
        self._body.setWordWrap(True)
        self._body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._body.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_PRIMARY};"
        )

        self._username_label = QLabel("")
        self._username_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._username_label.setStyleSheet(
            f"font-family: 'JetBrains Mono'; font-size: 14px; color: {DARK_ACCENT};"
        )

        self._layout.addStretch(1)
        self._layout.addWidget(heading)
        self._layout.addSpacing(8)
        self._layout.addWidget(self._body)
        self._layout.addSpacing(12)
        self._layout.addWidget(self._username_label)
        self._layout.addStretch(2)

    def set_username(self, username: str) -> None:
        """Übernimmt den angelegten Benutzernamen in die Anzeige."""
        self._username = username
        self._username_label.setText(f"Benutzer: {username}")

    @property
    def username(self) -> str | None:
        return self._username
