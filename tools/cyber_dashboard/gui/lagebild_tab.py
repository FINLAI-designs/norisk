"""
lagebild_tab — KI-Lagebild: tägliches Ollama-Briefing.

Zeigt das tägliche KI-Briefing (Ollama) als Startseite des Dashboards.
Videos wurden aus dem Dashboard entfernt — der Tab zeigt nur noch das Briefing.
Das Briefing wird NICHT automatisch generiert — nur auf Benutzer-Anforderung
(Button "Neu generieren" im eingebetteten BriefingTab).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.gui.briefing_tab import BriefingTab

log = get_logger(__name__)


class LagebildTab(QWidget):
    """KI-Lagebild Tab — zeigt das tägliche Ollama-Briefing.

    Startseite des Dashboards. Das Briefing wird on-demand über den
    "Neu generieren"-Button im BriefingTab gestartet — nicht automatisch.

    Args:
        service: DashboardService-Instanz.
        parent: Optionales Eltern-Widget.

    Signals:
        phishing_aktualisiert: Durchgereichtes Signal des eingebetteten
            BriefingTab — der Dashboard-Phishing-Tab haengt sich hier an.
    """

    phishing_aktualisiert: Signal = Signal(dict)

    def __init__(
        self,
        service: DashboardService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Lagebild-Tab."""
        super().__init__(parent)
        self._service = service
        self._briefing_tab = BriefingTab(service, self)
        # Phishing-Signal nach aussen durchreichen (Signal-zu-Signal).
        self._briefing_tab.phishing_aktualisiert.connect(self.phishing_aktualisiert)
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt das Tab-Layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._briefing_tab)

    def aktualisiere_briefing(self, briefing: dict) -> None:
        """Delegiert Briefing-Aktualisierung an den eingebetteten BriefingTab.

        Args:
            briefing: Briefing-Dict mit zusammenfassung/empfehlungen/gesamtrisiko.
        """
        self._briefing_tab.aktualisiere(briefing)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
        )
