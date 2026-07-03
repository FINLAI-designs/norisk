"""manual_entry_service — Use-Case fuer manuelle Scanner-Eintraege.

Kapselt:class:`ManualScannerEntryRepository`, damit das Scanner-Widget
nicht direkt aus ``data/`` importieren muss. Reine Pass-Through-Schicht
ohne weitere Logik — die Domain-Validierung uebernimmt das Repository.

Schichtzugehoerigkeit: ``application/`` (Hexagonal — orchestriert
Domain-/Data-Operationen).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.system_scanner.data.manual_entry_repository import (
    ManualScannerEntryRepository,
)
from tools.system_scanner.domain.entities import ManualScannerEntry
from tools.system_scanner.domain.enums import ComponentType

logger = get_logger(__name__)


class ManualEntryService:
    """Use-Case fuer das Verwalten manueller Scanner-Eintraege.

    Kapselt das Repository, damit die GUI ueber den application/-Service
    arbeiten kann GUI/data-Trennung).
    """

    def __init__(
        self, repository: ManualScannerEntryRepository | None = None
    ) -> None:
        """Initialisiert den Service.

        Args:
            repository: Optionale Repository-Instanz (Default: neue
                Instanz). Fuer Tests injizierbar.
        """
        self._repository = repository or ManualScannerEntryRepository()

    def get_all(self, category: ComponentType) -> list[ManualScannerEntry]:
        """Liefert alle manuellen Eintraege einer Kategorie.

        Args:
            category: Komponententyp (Antivirus, Firewall, Encryption).

        Returns:
            Liste der Eintraege (kann leer sein).
        """
        return self._repository.get_all(category)

    def add(self, entry: ManualScannerEntry) -> ManualScannerEntry:
        """Legt einen neuen manuellen Eintrag an.

        Args:
            entry: Neuer Eintrag (ohne ``entry_id``).

        Returns:
            Eintrag mit gesetzter ``entry_id``.
        """
        return self._repository.add(entry)

    def update(self, entry: ManualScannerEntry) -> ManualScannerEntry:
        """Aktualisiert einen bestehenden Eintrag.

        Args:
            entry: Eintrag mit gesetzter ``entry_id``.

        Returns:
            Aktualisierter Eintrag.
        """
        return self._repository.update(entry)

    def delete(self, entry_id: int) -> bool:
        """Loescht einen Eintrag anhand der ID.

        Args:
            entry_id: Datenbank-ID des Eintrags.

        Returns:
            True wenn geloescht, False wenn nicht gefunden.
        """
        return self._repository.delete(entry_id)
