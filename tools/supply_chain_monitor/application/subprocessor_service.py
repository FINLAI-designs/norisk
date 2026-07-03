"""
subprocessor_service — UseCases fuer Sub-Auftragsverarbeiter + Konzentrationsrisiko.

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass

from core.logger import get_logger
from tools.supply_chain_monitor.data.subprocessor_repository import (
    SubprocessorRepository,
)
from tools.supply_chain_monitor.domain.models import (
    CustomerSubprocessorLink,
    Subprocessor,
    VendorCategory,
    VendorSubprocessorLink,
)

_log = get_logger(__name__)

CONCENTRATION_WARNING_THRESHOLD: int = 3  # >=3 Vendoren via einem Sub = Risiko


@dataclass(frozen=True)
class ConcentrationFinding:
    """Konzentrationsrisiko-Aggregat.

    Attributes:
        subprocessor: Der gemeinsame Sub-Auftragnehmer.
        vendor_count: Wie viele Vendoren ihn nutzen.
        is_concentrated: ``True`` wenn ``vendor_count >= CONCENTRATION_WARNING_THRESHOLD``.
    """

    subprocessor: Subprocessor
    vendor_count: int
    is_concentrated: bool


class SubprocessorService:
    """Service-Layer fuer Sub-Auftragnehmer-Management."""

    def __init__(self, repository: SubprocessorRepository | None = None) -> None:
        self._repo = repository or SubprocessorRepository()

    # ------------------------------------------------------------------
    # Subprocessor CRUD
    # ------------------------------------------------------------------

    def add_subprocessor(
        self,
        name: str,
        country: str,
        category: VendorCategory,
        notes: str = "",
    ) -> Subprocessor:
        sub = Subprocessor(
            id=None,
            name=name,
            country=country,
            category=category,
            notes=notes,
        )
        new_id = self._repo.add(sub)
        persisted = self._repo.get_by_id(new_id)
        if persisted is None:
            raise RuntimeError(
                f"Subprocessor wurde mit id={new_id} angelegt, ist aber nicht "
                "lesbar — Datenbank-Inkonsistenz."
            )
        return persisted

    def get_subprocessor(self, sub_id: int) -> Subprocessor | None:
        return self._repo.get_by_id(sub_id)

    def list_subprocessors(self) -> list[Subprocessor]:
        return self._repo.list_all()

    def update_subprocessor(self, sub: Subprocessor) -> None:
        self._repo.update(sub)

    def delete_subprocessor(self, sub_id: int) -> bool:
        return self._repo.delete(sub_id)

    # ------------------------------------------------------------------
    # n:m Linking
    # ------------------------------------------------------------------

    def link(self, vendor_id: int, subprocessor_id: int, role: str = "") -> int:
        return self._repo.link(vendor_id, subprocessor_id, role)

    def unlink(self, link_id: int) -> bool:
        return self._repo.unlink(link_id)

    def links_for_vendor(self, vendor_id: int) -> list[VendorSubprocessorLink]:
        return self._repo.list_links_for_vendor(vendor_id)

    def links_for_subprocessor(
        self, subprocessor_id: int
    ) -> list[VendorSubprocessorLink]:
        return self._repo.list_links_for_subprocessor(subprocessor_id)

    # ------------------------------------------------------------------
    # Kunden-Links (H, Live-Test 2026-07-01)
    # ------------------------------------------------------------------

    def link_customer(
        self, subject_id: str, subprocessor_id: int, role: str = ""
    ) -> int:
        """Verknuepft einen Kunden (``subject_id``) mit einem Subprocessor."""
        return self._repo.link_customer(subject_id, subprocessor_id, role)

    def unlink_customer(self, link_id: int) -> bool:
        return self._repo.unlink_customer(link_id)

    def customer_links_for_subprocessor(
        self, subprocessor_id: int
    ) -> list[CustomerSubprocessorLink]:
        return self._repo.list_customer_links_for_subprocessor(subprocessor_id)

    # ------------------------------------------------------------------
    # Konzentrationsrisiko-Aggregation
    # ------------------------------------------------------------------

    def concentration_findings(self) -> list[ConcentrationFinding]:
        """Liefert pro Subprocessor die Anzahl Vendoren, die ihn nutzen.

        Sortierung: vendor_count desc — die kritischsten zuerst.
        """
        concentration_map = self._repo.concentration()
        result: list[ConcentrationFinding] = []
        for sub_id, count in concentration_map.items():
            sub = self._repo.get_by_id(sub_id)
            if sub is None:
                continue
            result.append(
                ConcentrationFinding(
                    subprocessor=sub,
                    vendor_count=count,
                    is_concentrated=count >= CONCENTRATION_WARNING_THRESHOLD,
                )
            )
        result.sort(key=lambda f: (-f.vendor_count, f.subprocessor.name))
        return result
