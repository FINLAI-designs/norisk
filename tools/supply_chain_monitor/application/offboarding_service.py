"""
offboarding_service — UseCases fuer Vendor-Off-Boarding.

Iter 2d-i: Service-Layer fuer
:class:`OffBoardingRepository` mit High-Level-Operationen wie
``start`` (legt Default-Checks an), ``complete`` (validiert dass alle
Default-Checks erledigt sind), ``progress`` (Fortschritts-Tupel fuer UI).

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1-i, 2026-05-15)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from core.logger import get_logger
from tools.supply_chain_monitor.data.offboarding_repository import (
    OffBoardingRepository,
)
from tools.supply_chain_monitor.domain.models import (
    OffBoarding,
    OffBoardingCheck,
    OffBoardingChecklistEntry,
    OffBoardingStatus,
)

_log = get_logger(__name__)


@dataclass(frozen=True)
class OffBoardingProgress:
    """Compact Status-Aggregat fuer die Vendor-Tabelle.

    Attributes:
        status::class:`OffBoardingStatus`.
        done: Anzahl erledigter Checks.
        total: Gesamtzahl Checks (Default + Custom).
        completable: ``True`` wenn alle Default-Checks erledigt sind
                     (Custom-Checks zaehlen optional, blocken
:meth:`OffBoardingService.complete` nicht).
    """

    status: OffBoardingStatus
    done: int
    total: int
    completable: bool


class OffBoardingService:
    """Service-Layer fuer Off-Boarding."""

    def __init__(self, repository: OffBoardingRepository | None = None) -> None:
        self._repo = repository or OffBoardingRepository()

    # ------------------------------------------------------------------
    # Start / Get / Cancel / Complete
    # ------------------------------------------------------------------

    def start(self, vendor_id: int, *, reason: str = "") -> OffBoarding:
        """Legt eine neue Off-Boarding-Instanz fuer einen Vendor an.

        Initialisiert die Checkliste mit 10 Default-Eintraegen
        (``is_done=False``).

        Raises:
            ValueError: Wenn bereits ein Off-Boarding fuer den Vendor
                existiert (UNIQUE-Constraint).
        """
        offb = OffBoarding(
            id=None,
            vendor_id=int(vendor_id),
            status=OffBoardingStatus.IN_PROGRESS,
            reason=reason,
        )
        new_id = self._repo.add(offb)
        defaults = [
            OffBoardingChecklistEntry(
                id=None,
                offboarding_id=new_id,
                is_done=False,
                check_key=check,
            )
            for check in OffBoardingCheck
        ]
        self._repo.replace_checklist(new_id, defaults)
        return OffBoarding(
            id=new_id,
            vendor_id=offb.vendor_id,
            status=offb.status,
            reason=offb.reason,
            started_at=offb.started_at,
            completed_at=offb.completed_at,
        )

    def get_for_vendor(self, vendor_id: int) -> OffBoarding | None:
        return self._repo.get_for_vendor(vendor_id)

    def get_checklist(self, offb_id: int) -> list[OffBoardingChecklistEntry]:
        return self._repo.list_checklist(offb_id)

    def update_checklist(
        self,
        offb_id: int,
        entries: list[OffBoardingChecklistEntry],
    ) -> None:
        self._repo.replace_checklist(offb_id, entries)

    def complete(self, offb_id: int) -> OffBoarding:
        """Markiert das Off-Boarding als COMPLETED.

        Raises:
            ValueError: Wenn nicht alle 10 Default-Checks erledigt sind
                oder das Off-Boarding nicht existiert.
        """
        offb = self._repo.get_by_id(offb_id)
        if offb is None:
            raise ValueError(f"Kein Off-Boarding mit id={offb_id}.")
        checklist = self._repo.list_checklist(offb_id)
        defaults_done = sum(
            1 for e in checklist if not e.is_custom and e.is_done
        )
        if defaults_done < len(OffBoardingCheck):
            raise ValueError(
                f"Off-Boarding kann nicht abgeschlossen werden — "
                f"{defaults_done}/{len(OffBoardingCheck)} Default-Checks "
                "erledigt."
            )
        updated = OffBoarding(
            id=offb.id,
            vendor_id=offb.vendor_id,
            status=OffBoardingStatus.COMPLETED,
            reason=offb.reason,
            started_at=offb.started_at,
            completed_at=datetime.now(UTC),
        )
        self._repo.update(updated)
        return updated

    def cancel(self, offb_id: int, *, reason: str = "") -> OffBoarding:
        """Markiert das Off-Boarding als CANCELLED."""
        offb = self._repo.get_by_id(offb_id)
        if offb is None:
            raise ValueError(f"Kein Off-Boarding mit id={offb_id}.")
        new_reason = reason or offb.reason
        updated = OffBoarding(
            id=offb.id,
            vendor_id=offb.vendor_id,
            status=OffBoardingStatus.CANCELLED,
            reason=new_reason,
            started_at=offb.started_at,
            completed_at=datetime.now(UTC),
        )
        self._repo.update(updated)
        return updated

    def delete(self, offb_id: int) -> bool:
        return self._repo.delete(offb_id)

    # ------------------------------------------------------------------
    # Progress-Aggregat fuer UI
    # ------------------------------------------------------------------

    def progress_for_vendor(self, vendor_id: int) -> OffBoardingProgress | None:
        """Liefert den Off-Boarding-Status pro Vendor oder ``None``."""
        offb = self._repo.get_for_vendor(vendor_id)
        if offb is None or offb.id is None:
            return None
        checklist = self._repo.list_checklist(offb.id)
        if not checklist:
            return OffBoardingProgress(
                status=offb.status,
                done=0,
                total=0,
                completable=False,
            )
        total = len(checklist)
        done = sum(1 for e in checklist if e.is_done)
        defaults_done = sum(
            1 for e in checklist if not e.is_custom and e.is_done
        )
        return OffBoardingProgress(
            status=offb.status,
            done=done,
            total=total,
            completable=(
                defaults_done == len(OffBoardingCheck)
                and offb.status is OffBoardingStatus.IN_PROGRESS
            ),
        )

    def progress_per_vendor(self) -> dict[int, OffBoardingProgress]:
        """Aggregiert:class:`OffBoardingProgress` ueber alle Vendoren.

        Liefert nur Eintraege fuer Vendoren mit aktivem oder abgeschlossenem
        Off-Boarding.
        """
        result: dict[int, OffBoardingProgress] = {}
        for offb in self._repo.list_all():
            if offb.id is None:
                continue
            progress = self.progress_for_vendor(offb.vendor_id)
            if progress is not None:
                result[offb.vendor_id] = progress
        return result
