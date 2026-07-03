"""Skelett — Backup-Pfad.

Platzhalter für die spätere Auswahl des Backup-Ordners für verschlüsselte
Datenbank-Exporte (SQLCipher).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from core.first_run_wizard.pages.base_page import BasePage
from core.theme import DARK_TEXT_SECONDARY


class BackupLocationPage(BasePage):
    """Platzhalter-Seite für Backup-Pfad."""

    TITLE = "Backup-Speicherort"

    def __init__(self) -> None:
        super().__init__()
        title = QLabel(self.TITLE)
        title.setStyleSheet(
            "font-family: 'Raleway'; font-size: 22px; font-weight: bold;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        body = QLabel(
            "Der Speicherort für verschlüsselte Datenbank-Backups wird zum "
            "Pro-Launch 2026 hier konfiguriert.\n\n"
            "Diese Seite ist derzeit ein Platzhalter."
        )
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_SECONDARY};"
        )

        self._layout.addStretch(1)
        self._layout.addWidget(title)
        self._layout.addWidget(body)
        self._layout.addStretch(2)
