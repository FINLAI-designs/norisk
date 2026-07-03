"""
advisory_repository — Repository-Interface für CSAF Advisories und Provider.

Schichtzugehörigkeit: domain/ — abstrakte Interfaces, keine konkreten Implementierungen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.domain.csaf_provider import CsafProvider


class IAdvisoryRepository(ABC):
    """Abstrakte Schnittstelle für die Advisory-Datenpersistenz."""

    @abstractmethod
    def save_advisory(self, advisory: CsafAdvisory) -> None:
        """Speichert oder aktualisiert ein Advisory.

        Args:
            advisory: Das zu speichernde Advisory.
        """

    @abstractmethod
    def get_advisory(self, advisory_id: str) -> CsafAdvisory | None:
        """Gibt ein Advisory anhand seiner ID zurück.

        Args:
            advisory_id: Eindeutige Advisory-ID.

        Returns:
            CsafAdvisory oder None wenn nicht gefunden.
        """

    @abstractmethod
    def list_advisories(
        self,
        severity: str | None = None,
        publisher: str | None = None,
        days: int | None = None,
    ) -> list[CsafAdvisory]:
        """Gibt eine gefilterte Liste aller gespeicherten Advisories zurück.

        Args:
            severity: Nur Advisories mit diesem Schweregrad (oder None = alle).
            publisher: Nur Advisories von diesem Herausgeber (oder None = alle).
            days: Nur Advisories der letzten N Tage (oder None = alle).

        Returns:
            Sortierte Liste der passenden Advisories.
        """

    @abstractmethod
    def save_provider(self, provider: CsafProvider) -> None:
        """Speichert oder aktualisiert einen CSAF Provider.

        Args:
            provider: Der zu speichernde Provider.
        """

    @abstractmethod
    def list_providers(self) -> list[CsafProvider]:
        """Gibt alle gespeicherten Provider zurück.

        Returns:
            Liste aller Provider.
        """

    @abstractmethod
    def get_provider(self, provider_id: str) -> CsafProvider | None:
        """Gibt einen Provider anhand seiner ID zurück.

        Args:
            provider_id: Eindeutige Provider-ID.

        Returns:
            CsafProvider oder None wenn nicht gefunden.
        """

    @abstractmethod
    def delete_provider(self, provider_id: str) -> None:
        """Löscht einen Provider (nur user-definierte Provider).

        Args:
            provider_id: Eindeutige Provider-ID.
        """

    @abstractmethod
    def save_match(self, match: AdvisoryMatch) -> None:
        """Speichert einen Advisory-Treffer.

        Args:
            match: Der zu speichernde Treffer.
        """

    @abstractmethod
    def list_matches(self) -> list[AdvisoryMatch]:
        """Gibt alle gespeicherten Treffer zurück.

        Returns:
            Liste aller Treffer.
        """

    @abstractmethod
    def clear_matches(self) -> None:
        """Löscht alle gespeicherten Treffer (wird vor jedem neuen Match-Lauf aufgerufen)."""

    @abstractmethod
    def advisory_count(self) -> int:
        """Gibt die Gesamtanzahl gespeicherter Advisories zurück.

        Returns:
            Anzahl der Advisories in der Datenbank.
        """
