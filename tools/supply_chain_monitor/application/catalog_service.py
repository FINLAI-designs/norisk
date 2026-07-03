"""
catalog_service — UseCases fuer den Vendor-Catalog (Management).

Iter 2b: GUI-faehiger Service ueber dem
:class:`VendorCatalogRepository`. Eigene Schicht (nicht in
:class:`DetectionService`), damit Catalog-Management und Detection-
Pipeline klar getrennt bleiben — und damit die Hexagonal-Contracts
gewahrt sind (gui ↛ data).

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.logger import get_logger
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.domain.models import VendorCatalogEntry

_log = get_logger(__name__)


class CatalogService:
    """Anwendungs-Service fuer Catalog-CRUD."""

    def __init__(self, repository: VendorCatalogRepository | None = None) -> None:
        self._repo = repository or VendorCatalogRepository()

    def list_entries(self) -> list[VendorCatalogEntry]:
        return self._repo.list_all()

    def get_entry(self, entry_id: int) -> VendorCatalogEntry | None:
        return self._repo.get_by_id(entry_id)

    def add_entry(self, entry: VendorCatalogEntry) -> int:
        """Fuegt einen neuen Catalog-Eintrag ein.

        Raises:
            ValueError: Bei UNIQUE-Verstoss auf ``canonical_name``.
        """
        return self._repo.add(entry)

    def update_entry(self, entry: VendorCatalogEntry) -> None:
        self._repo.update(entry)

    def delete_entry(self, entry_id: int) -> bool:
        return self._repo.delete(entry_id)

    def count(self) -> int:
        return self._repo.count()
