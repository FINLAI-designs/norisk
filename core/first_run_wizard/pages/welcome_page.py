"""Welcome-Seite des First-Run-Wizards.

Reine Info-Seite. Keine Eingabe, immer ``is_complete == True``.
Text wird aus ``AppConfig.app_name`` generiert, sodass der Wizard für
alle vier FINLAI-Apps wiederverwendbar ist.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from core.first_run_wizard.pages.base_page import BasePage
from core.theme import DARK_ACCENT, DARK_TEXT_PRIMARY, DARK_TEXT_SECONDARY


class WelcomePage(BasePage):
    """Begrüßung beim ersten Start."""

    TITLE = "Willkommen"

    def __init__(self, app_name: str) -> None:
        super().__init__()
        self._app_name = app_name

        heading = QLabel(f"Willkommen bei {app_name}")
        heading.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 24px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subheading = QLabel("Ersteinrichtung")
        subheading.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 14px; color: {DARK_TEXT_SECONDARY};"
        )
        subheading.setAlignment(Qt.AlignmentFlag.AlignCenter)

        body = QLabel(
            "Dieser Assistent begleitet dich durch die einmalige Einrichtung deines "
            "Administrator-Kontos. Deine Buchhaltungs-, Steuer- und Scan-Daten werden "
            "ausschließlich lokal verarbeitet und gespeichert.\n\n"
            "Eine Ausnahme bildet die Lizenz-Validierung: Hierfür wird einmalig "
            "und periodisch (24h-Heartbeat) eine Verbindung mit dem FINLAI-Lizenz-"
            "Server hergestellt. Welche Daten dabei übertragen werden, erläutert "
            "die nächste Seite (Datenschutz-Hinweis).\n\n"
            "In den nächsten Schritten legst du einen Benutzernamen und ein "
            "Passwort fest. Weitere optionale Einstellungen (2FA, Firmendaten, "
            "Backup-Ort) folgen mit dem offiziellen Produktstart."
        )
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_PRIMARY};"
        )

        self._layout.addStretch(1)
        self._layout.addWidget(heading)
        self._layout.addWidget(subheading)
        self._layout.addSpacing(12)
        self._layout.addWidget(body)
        self._layout.addStretch(2)
