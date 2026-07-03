"""inventory_worker — Qt-Worker fuer Patch-Persistence-Tier-Trigger.

 Stop-Step E. Wraps:class:`PatchInventoryService` in einem
``QObject`` + ``moveToThread``-Pattern. Vom Scheduler getriggert
(``daily_refresh_due`` / ``monthly_full_due``) oder vom User-Klick
(Vollscan via Patch-Console-Button).

Signal-Kette pro Lauf::

    full_scan_started(scan_type)
      ├── full_scan_finished(summary) — bei Erfolg
      └── full_scan_failed(scan_type, error) — bei Exception

    daily_refresh_started
      ├── daily_refresh_finished(summary) — bei Erfolg
      └── daily_refresh_failed(error) — bei Exception

Pro Trigger laeuft genau ein Scan — Re-Trigger waehrend ein Scan laeuft
wird per `_busy`-Flag ignoriert (kein Doppel-Aufruf, sonst race auf
``scan_history``-Persistenz).

Schicht: ``gui/`` — importiert ``application/`` (PatchInventoryService),
keinen ``data/``-Direkt-Import.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from core.logger import get_logger
from tools.patch_monitor.application.patch_inventory_service import (
    PatchInventoryService,
)

log = get_logger(__name__)


class InventoryWorker(QObject):
    """Async-Wrapper um:class:`PatchInventoryService`.

    Signals:
        full_scan_started(str): Scan-Type ("initial"|"monthly_full"|"manual").
        full_scan_finished(object)::class:`FullScanSummary` bei Erfolg.
        full_scan_failed(str, str): (scan_type, error_text) bei Exception.
        daily_refresh_started: Lifecycle-Marker.
        daily_refresh_finished(object)::class:`DailyRefreshSummary`.
        daily_refresh_failed(str): Error-Text.
    """

    full_scan_started = Signal(str)
    full_scan_finished = Signal(object)
    full_scan_failed = Signal(str, str)
    daily_refresh_started = Signal()
    daily_refresh_finished = Signal(object)
    daily_refresh_failed = Signal(str)

    def __init__(
        self,
        service: PatchInventoryService | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialisiert den Worker.

        Args:
            service: Optional vorbereiteter Service. ``None`` → lazy
                Init beim ersten Lauf (vermeidet DB-Anlage in Tests die
                den Worker nur konstruieren).
            parent: Standard-Qt-Parent.
        """
        super().__init__(parent)
        self._service = service
        self._busy = False

    def is_busy(self) -> bool:
        """``True`` waehrend ein Scan laeuft. Verhindert Doppel-Trigger."""
        return self._busy

    def _get_service(self) -> PatchInventoryService:
        """Lazy-Init des Service."""
        if self._service is None:
            self._service = PatchInventoryService()
        return self._service

    # ------------------------------------------------------------------
    # Slots — vom Scheduler oder UI-Button getriggert
    # ------------------------------------------------------------------

    @Slot(str)
    def run_full_scan(self, scan_type: str = "manual") -> None:
        """Triggert einen Vollscan (Initial / Monthly / Manual).

        Wenn schon ein Scan laeuft, wird das Signal stille ignoriert —
        Re-Trigger schreiben sonst zwei ``scan_history``-Eintraege.
        """
        if self._busy:
            log.info("InventoryWorker.run_full_scan: schon busy — ignoriert.")
            return
        self._busy = True
        self.full_scan_started.emit(scan_type)
        try:
            service = self._get_service()
            summary = service.full_scan(scan_type=scan_type)  # type: ignore[arg-type]
            self.full_scan_finished.emit(summary)
        except Exception as exc:  # noqa: BLE001 — Worker darf nie crashen
            log.exception(
                "InventoryWorker.run_full_scan: %s — Signal full_scan_failed.",
                type(exc).__name__,
            )
            self.full_scan_failed.emit(scan_type, f"{type(exc).__name__}: {exc}")
        finally:
            self._busy = False

    @Slot()
    def run_monthly_full(self) -> None:
        """Convenience-Slot fuer den Scheduler — ruft ``run_full_scan('monthly_full')``.

        Eigener parameterloser Slot statt Lambda damit Qt die
        Signal→Slot-Verbindung als ``AutoConnection`` korrekt cross-thread
        auf ``QueuedConnection`` aufloest. Lambdas haben keinen QObject-
        Receiver und wuerden im Emitter-Thread (Scheduler / Main-Thread)
        ausgefuehrt — der Vollscan wuerde die GUI dann fuer ~20 min
        blockieren.
        """
        self.run_full_scan("monthly_full")

    @Slot()
    def run_daily_refresh(self) -> None:
        """Triggert einen Daily-Refresh (winget + stale CVEs)."""
        if self._busy:
            log.info("InventoryWorker.run_daily_refresh: schon busy — ignoriert.")
            return
        self._busy = True
        self.daily_refresh_started.emit()
        try:
            service = self._get_service()
            summary = service.daily_refresh()
            self.daily_refresh_finished.emit(summary)
        except Exception as exc:  # noqa: BLE001
            log.exception(
                "InventoryWorker.run_daily_refresh: %s — Signal daily_refresh_failed.",
                type(exc).__name__,
            )
            self.daily_refresh_failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self._busy = False


__all__ = ["InventoryWorker"]
