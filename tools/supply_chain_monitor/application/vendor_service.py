"""
vendor_service — UseCases rund um das Vendor-Inventar.

Orchestriert das:class:`VendorRepository`. Reine Pass-Through-UseCases
fuer Iter 2a; in 2b-2d kommen Detection-Merger, AVV-Checks und
Patch-Monitor-Joins dazu.

Schichtzugehoerigkeit: application/ — darf domain/ + data/ + core/
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.logger import get_logger
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory

_log = get_logger(__name__)


class VendorService:
    """Anwendungs-Service fuer Vendor-Verwaltung."""

    def __init__(self, repository: VendorRepository | None = None) -> None:
        """Initialisiert den Service.

        Args:
            repository: Optionales Repository (z. B. mit Test-DB). Default:
                neue:class:`VendorRepository`-Instanz auf der Produktiv-DB.
        """
        self._repo = repository or VendorRepository()

    def add_vendor(
        self,
        name: str,
        category: VendorCategory,
        criticality_score: int,
        notes: str = "",
    ) -> Vendor:
        """Legt einen neuen Vendor an.

        Args:
            name: Vendor-Name.
            category::class:`VendorCategory`.
            criticality_score: 1-5.
            notes: Optionale Freitext-Notizen.

        Returns:
            Den persistierten Vendor inklusive vergebener ID.

        Raises:
            ValueError: Bei ungueltigen Domain-Werten (:class:`Vendor.__post_init__`).
        """
        vendor = Vendor(
            id=None,
            name=name,
            category=category,
            criticality_score=criticality_score,
            notes=notes,
        )
        new_id = self._repo.add(vendor)
        # Vendor ist frozen — wir geben eine neue Instanz mit der ID zurueck,
        # damit Aufrufer die DB-ID auch fuer Folge-Operationen verwenden koennen.
        persisted = Vendor(
            id=new_id,
            name=vendor.name,
            category=vendor.category,
            criticality_score=vendor.criticality_score,
            notes=vendor.notes,
            created_at=vendor.created_at,
            updated_at=vendor.updated_at,
        )
        return persisted

    def get_vendor(self, vendor_id: int) -> Vendor | None:
        """Liefert einen Vendor anhand seiner ID oder ``None``."""
        return self._repo.get_by_id(vendor_id)

    def list_vendors(self) -> list[Vendor]:
        """Liefert alle Vendoren (Kritikalitaet desc, Name asc)."""
        return self._repo.list_all()

    def update_vendor(self, vendor: Vendor) -> None:
        """Aktualisiert einen bestehenden Vendor.

        Raises:
            ValueError: Bei fehlender ID oder unbekanntem Datensatz.
        """
        self._repo.update(vendor)

    def delete_vendor(self, vendor_id: int) -> bool:
        """Loescht einen Vendor.

        Returns:
            ``True`` wenn geloescht, ``False`` wenn nicht gefunden.
        """
        return self._repo.delete(vendor_id)
