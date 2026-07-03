"""
test_inventory_worker — Tests fuer Stop-Step E InventoryWorker.

Wraps:class:`PatchInventoryService` mit Signals. Same-Thread-Tests via
DirectConnection — kein QApplication noetig.

Deckt:
* run_full_scan: started → finished bei Erfolg
* run_full_scan: started → failed bei Exception
* run_daily_refresh: started → finished bei Erfolg
* run_daily_refresh: started → failed bei Exception
* is_busy: True waehrend Lauf, False danach
* Re-Trigger waehrend busy wird ignoriert
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from tools.patch_monitor.application.patch_inventory_service import (
    DailyRefreshSummary,
    FullScanSummary,
)
from tools.patch_monitor.gui.inventory_worker import InventoryWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _full_summary(scan_type: str = "manual") -> FullScanSummary:
    return FullScanSummary(
        scan_id="abc123",
        scan_type=scan_type,  # type: ignore[arg-type]
        items_total=10,
        items_with_updates=3,
        items_with_cves=2,
    )


def _daily_summary() -> DailyRefreshSummary:
    return DailyRefreshSummary(
        scan_id="def456",
        items_total=10,
        items_with_updates=3,
        cves_refreshed=5,
    )


class _SignalRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, Any, ...]] = []

    def full_started(self, scan_type: str) -> None:
        self.events.append(("full_started", scan_type))

    def full_finished(self, summary: object) -> None:
        self.events.append(("full_finished", summary))

    def full_failed(self, scan_type: str, error: str) -> None:
        self.events.append(("full_failed", scan_type, error))

    def daily_started(self) -> None:
        self.events.append(("daily_started",))

    def daily_finished(self, summary: object) -> None:
        self.events.append(("daily_finished", summary))

    def daily_failed(self, error: str) -> None:
        self.events.append(("daily_failed", error))


def _connect(worker: InventoryWorker, rec: _SignalRecorder) -> None:
    worker.full_scan_started.connect(rec.full_started)
    worker.full_scan_finished.connect(rec.full_finished)
    worker.full_scan_failed.connect(rec.full_failed)
    worker.daily_refresh_started.connect(rec.daily_started)
    worker.daily_refresh_finished.connect(rec.daily_finished)
    worker.daily_refresh_failed.connect(rec.daily_failed)


# ---------------------------------------------------------------------------
# Full-Scan
# ---------------------------------------------------------------------------


class TestRunFullScan:
    def test_success_emittiert_started_dann_finished(self) -> None:
        service = MagicMock()
        summary = _full_summary("initial")
        service.full_scan.return_value = summary
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run_full_scan("initial")

        kinds = [e[0] for e in rec.events]
        assert kinds == ["full_started", "full_finished"]
        assert rec.events[0] == ("full_started", "initial")
        assert rec.events[1] == ("full_finished", summary)

    def test_exception_emittiert_started_dann_failed(self) -> None:
        service = MagicMock()
        service.full_scan.side_effect = RuntimeError("DB tot")
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run_full_scan("manual")

        kinds = [e[0] for e in rec.events]
        assert kinds == ["full_started", "full_failed"]
        assert rec.events[1][1] == "manual"  # scan_type
        assert "RuntimeError" in rec.events[1][2]  # error message

    def test_default_scan_type_ist_manual(self) -> None:
        service = MagicMock()
        service.full_scan.return_value = _full_summary("manual")
        worker = InventoryWorker(service=service)

        worker.run_full_scan()

        # Service muss mit scan_type="manual" gerufen worden sein
        service.full_scan.assert_called_once_with(scan_type="manual")


# ---------------------------------------------------------------------------
# Daily-Refresh
# ---------------------------------------------------------------------------


class TestRunMonthlyFull:
    def test_run_monthly_full_ruft_run_full_scan_mit_scan_type_monthly_full(self) -> None:
        """run_monthly_full ist Convenience-Wrapper damit Scheduler ohne
        Lambda verdrahten kann — er muss intern run_full_scan('monthly_full')
        aufrufen."""
        service = MagicMock()
        summary = _full_summary("monthly_full")
        service.full_scan.return_value = summary
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run_monthly_full()

        # Service wurde mit scan_type='monthly_full' aufgerufen
        service.full_scan.assert_called_once_with(scan_type="monthly_full")
        # Signal-Trace ist identisch zu run_full_scan
        kinds = [e[0] for e in rec.events]
        assert kinds == ["full_started", "full_finished"]
        assert rec.events[0] == ("full_started", "monthly_full")


class TestRunDailyRefresh:
    def test_success_emittiert_started_dann_finished(self) -> None:
        service = MagicMock()
        summary = _daily_summary()
        service.daily_refresh.return_value = summary
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run_daily_refresh()

        kinds = [e[0] for e in rec.events]
        assert kinds == ["daily_started", "daily_finished"]
        assert rec.events[1] == ("daily_finished", summary)

    def test_exception_emittiert_started_dann_failed(self) -> None:
        service = MagicMock()
        service.daily_refresh.side_effect = ConnectionError("NVD weg")
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        worker.run_daily_refresh()

        kinds = [e[0] for e in rec.events]
        assert kinds == ["daily_started", "daily_failed"]
        assert "ConnectionError" in rec.events[1][1]


# ---------------------------------------------------------------------------
# is_busy / Re-Trigger-Schutz
# ---------------------------------------------------------------------------


class TestBusyFlag:
    def test_initial_nicht_busy(self) -> None:
        worker = InventoryWorker(service=MagicMock())
        assert worker.is_busy() is False

    def test_nach_full_scan_nicht_busy(self) -> None:
        service = MagicMock()
        service.full_scan.return_value = _full_summary()
        worker = InventoryWorker(service=service)
        worker.run_full_scan()
        assert worker.is_busy() is False

    def test_nach_failure_nicht_busy(self) -> None:
        """Busy-Flag muss auch nach Exception zurueckgesetzt sein,
        sonst bleibt der Worker fuer immer stuck."""
        service = MagicMock()
        service.full_scan.side_effect = RuntimeError("x")
        worker = InventoryWorker(service=service)
        worker.run_full_scan()
        assert worker.is_busy() is False

    def test_busy_blockiert_re_trigger(self) -> None:
        """Wenn Worker busy ist, wird Re-Trigger ignoriert (kein Doppel-
        Aufruf des Service)."""
        service = MagicMock()
        # full_scan callback testet ob is_busy=True ist
        busy_observations = []

        def slow_scan(scan_type: str) -> FullScanSummary:
            busy_observations.append(worker.is_busy())
            return _full_summary(scan_type)

        service.full_scan.side_effect = lambda scan_type: slow_scan(scan_type)
        worker = InventoryWorker(service=service)
        worker.run_full_scan("manual")

        # Waehrend service.full_scan lief, sah die Closure busy=True
        assert busy_observations == [True]

    def test_re_trigger_emittiert_nichts(self) -> None:
        """Re-Trigger waehrend busy fuehrt zu KEINEM zweiten Signal-Set."""
        service = MagicMock()
        # Re-Trigger waehrend Service noch laeuft
        worker = InventoryWorker(service=service)
        rec = _SignalRecorder()
        _connect(worker, rec)

        def trigger_self_during_scan(scan_type: str) -> FullScanSummary:
            # Re-Trigger waehrend wir noch im Service-Call sind
            worker.run_full_scan("manual")
            return _full_summary(scan_type)

        service.full_scan.side_effect = trigger_self_during_scan
        worker.run_full_scan("manual")

        # Genau EIN started + EIN finished (kein zweiter Durchlauf)
        kinds = [e[0] for e in rec.events]
        assert kinds == ["full_started", "full_finished"]


# ---------------------------------------------------------------------------
# Lazy-Service-Init
# ---------------------------------------------------------------------------


class TestLazyServiceInit:
    def test_worker_ohne_service_konstruierbar(self) -> None:
        """Konstruktion mit service=None darf nicht crashen — Lazy-Init
        passiert erst beim ersten Lauf."""
        worker = InventoryWorker()
        assert worker.is_busy() is False
