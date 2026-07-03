"""
core/widgets/ki_disclaimer.py — Human-in-the-Loop Hinweis-Widget.

Zeigt einen dezenten aber sichtbaren Hinweis bei KI-generierten Inhalten
gemäß EU KI-VO Art. 4 (in Kraft seit 02.02.2025).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel

from core import theme
from core.icons import ICON_SIZE_SM, Icons, get_accent_icon


class KiDisclaimerWidget(QFrame):
    """Dezenter Privacy-Banner für KI-Features: lokale Verarbeitung (EU KI-VO Art. 4).

    Zeigt an, dass alle Daten lokal auf dem Gerät des Nutzers verarbeitet
    werden und das Netzwerk nicht verlassen. Transparenzpflicht gemäß
    EU KI-VO Art. 4 (in Kraft seit 02.02.2025).

    Args:
        feature_name: Name des KI-Features, z. B. ``"KI-Briefing"``.
        parent: Optionales Eltern-Widget.
    """

    def __init__(self, feature_name: str = "KI-Analyse", parent=None) -> None:
        """Initialisiert den Privacy-Disclaimer-Banner.

        Args:
            feature_name: Anzeigename des KI-Features.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._feature_name = feature_name
        self._build()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build(self) -> None:
        """Erstellt das Widget-Layout."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        icon = QLabel()
        icon.setPixmap(
            get_accent_icon(Icons.LOCK).pixmap(ICON_SIZE_SM, ICON_SIZE_SM)
        )
        icon.setStyleSheet("background: transparent; border: none;")
        icon.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._text = QLabel(
            f"<b>{self._feature_name}</b> — lokaler KI-Sicherheitsberater. "
            "Alle Daten bleiben auf deinem Computer (Backend: Ollama). "
            "Keine Daten verlassen dein Netzwerk."
        )
        self._text.setWordWrap(True)
        self._text.setStyleSheet("background: transparent; border: none;")

        layout.addWidget(icon)
        layout.addWidget(self._text, 1)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        accent = QColor(c.ACCENT)
        self.setStyleSheet(
            f"QFrame {{"
            f" background-color: rgba({accent.red()}, {accent.green()}, {accent.blue()}, 18);"
            f" border: 1px solid rgba({accent.red()}, {accent.green()}, {accent.blue()}, 60);"
            f" border-radius: 4px;"
            f"}}"
        )
        self._text.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
            " background: transparent; border: none;"
        )


class KiDisclaimer(QLabel):
    """Hinweis-Widget für KI-generierte Inhalte gemäß EU KI-VO Art. 4.

    Zeigt einen dezenten aber sichtbaren Hinweis, dass KI-Ergebnisse
    fachlich überprüft werden müssen.

    Text-Override fuer Security-Chat-Kontext
    eingefuehrt. NoRisk verwendet ``DEFAULT_TEXT_SECURITY`` mit
    Sicherheits-Bezug (keine Steuer-Berufstraeger), AUTOMATE behaelt
    ``DEFAULT_TEXT`` mit Berufstraeger-Wording.
    """

    #: Default-Wording fuer Steuer-/Berufstraeger-Kontext (AUTOMATE).
    DEFAULT_TEXT = (
        "Hinweis: KI-generiert — Ergebnis muss fachlich durch den Berufsträger geprüft werden"
    )

    #: Security-orientiertes Wording (NoRisk). Patrick-Vorgabe
    #: 2026-05-14, basierend auf Mplaw-Risikoeinschaetzung fuer
    #: informative/edukative LLM-Chatbots.
    DEFAULT_TEXT_SECURITY = (
        "Info: Dieser Chat dient ausschließlich zur Information. "
        "Keine Gewähr für Vollständigkeit oder Aktualität. "
        "Für sicherheitskritische Entscheidungen bitte Fachexperten beiziehen."
    )

    #: Backwards-Compat-Alias.
    TEXT = DEFAULT_TEXT

    def __init__(self, parent=None, text: str | None = None):
        """Initialisiert das Disclaimer-Widget.

        Args:
            parent: Optionales Eltern-Widget.
            text: Optionaler Override-Text. Wenn ``None``: nutzt
                ``DEFAULT_TEXT`` (Berufstraeger-Wording).
        """
        super().__init__(text or self.DEFAULT_TEXT, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
        self.apply_theme()
        theme.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        w = QColor(c.WARNING)
        self.setStyleSheet(
            f"QLabel {{"
            f" background-color: rgba({w.red()}, {w.green()}, {w.blue()}, 30);"
            f" color: {c.TEXT_DIM};"
            f" font-family: 'Raleway', 'Segoe UI', sans-serif;"
            f" font-size: 11px;"
            f" padding: 4px 8px;"
            f" border-top: 1px solid rgba({w.red()}, {w.green()}, {w.blue()}, 80);"
            f"}}"
        )
