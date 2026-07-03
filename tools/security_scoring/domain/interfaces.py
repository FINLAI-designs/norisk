"""
interfaces — Abstrakte Ports für das Security-Scoring-Dashboard.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.security_scoring.domain.models import SecurityScore


class IScoreRepository(ABC):
    """Port für die Persistenz von Security-Scores."""

    @abstractmethod
    def speichere_score(self, score: SecurityScore) -> None:
        """Speichert einen berechneten Score.

        Args:
            score: Zu persistierender SecurityScore.
        """

    @abstractmethod
    def lade_letzte_scores(
        self,
        target_name: str,
        limit: int = 10,
    ) -> list[SecurityScore]:
        """Lädt die letzten Scores für ein Ziel.

        Args:
            target_name: Name des Ziels.
            limit: Maximale Anzahl.

        Returns:
            Scores, neueste zuerst.
        """

    @abstractmethod
    def lade_bekannte_targets(self) -> list[str]:
        """Gibt alle bekannten Target-Namen zurück.

        Returns:
            Alphabetisch sortierte Liste der Target-Namen.
        """
