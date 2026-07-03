"""quickstart_service — Use-Case-Schicht fuer das Schnellstart-Panel.

 (RUN2-GUI): Kapselt den Zugriff auf den Tool-Verlauf, damit das
Schnellstart-Widget nicht direkt gegen das Repository gehen muss.

Schichtzugehoerigkeit: ``application/`` (Hexagonal — orchestriert
Domain-/Data-Operationen, kein UI-Code).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.mainpage.data.mainpage_repository import MainpageRepository

logger = get_logger(__name__)


class QuickstartService:
    """Liest den Tool-Verlauf fuer das Schnellstart-Panel.

    Kapselt:class:`MainpageRepository`, damit das Widget den
    application/-Service als Abhaengigkeit fuehrt und nicht das
    konkrete Repository GUI/data-Trennung).
    """

    def __init__(self, repo: MainpageRepository) -> None:
        """Initialisiert den Service.

        Args:
            repo: Repository-Instanz (Pflicht — kein Default, klare DI).
        """
        self._repo = repo

    def load_recent_tools(self, *, limit: int = 5, app_id: str | None = None) -> list[str]:
        """Liefert die zuletzt genutzten Tools fuer eine App.

        Args:
            limit: Maximalanzahl der Eintraege (Default 5).
            app_id: App-Filter (``finlai``/``norisk``/``automate``).
                ``None`` heisst app-uebergreifend.

        Returns:
            Liste von Tool-Namen, sortiert nach letzter Nutzung
            (jueneste zuerst).
        """
        return self._repo.load_recent_tools(limit=limit, app_id=app_id)
