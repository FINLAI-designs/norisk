"""
test_patch_scheduler — Tests fuer Stop-Step C PatchScheduler.

Deckt:
* Pure-Funktionen ``is_daily_refresh_due`` und ``is_monthly_full_due``
  (Qt-frei, deterministisch)
* Scheduler-Tick-Reihenfolge: empty → monthly → daily, sonst no-op
* Garantie: pro Tick max ein Signal
* Tick-Exception crasht den Scheduler nicht
* Lifecycle: start/stop, is_running

Signal-Connections laufen via DirectConnection (same-thread) — kein
``QApplication`` noetig.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from core.patch_scheduler import (
    DEFAULT_DAILY_INTERVAL_HOURS,
    DEFAULT_MONTHLY_INTERVAL_DAYS,
    PatchScheduler,
    is_daily_refresh_due,
    is_monthly_full_due,
)

# ---------------------------------------------------------------------------
# Pure Functions
# ---------------------------------------------------------------------------


class TestIsDailyRefreshDue:
    def test_none_ist_faellig(self) -> None:
        assert is_daily_refresh_due(None) is True

    def test_frischer_refresh_nicht_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(hours=1)
        assert is_daily_refresh_due(last, now=now) is False

    def test_genau_24h_alt_ist_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(hours=24)
        assert is_daily_refresh_due(last, now=now) is True

    def test_alter_refresh_ist_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(hours=48)
        assert is_daily_refresh_due(last, now=now) is True

    def test_custom_threshold(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(hours=6)
        # Default 24 h: 6 h ist NICHT faellig
        assert is_daily_refresh_due(last, now=now) is False
        # Mit 4 h: 6 h IST faellig
        assert is_daily_refresh_due(last, interval_hours=4, now=now) is True


class TestIsMonthlyFullDue:
    def test_none_ist_nicht_faellig(self) -> None:
        """Initial-Scan ist Tier 1, Monthly nur fuer existing inventory."""
        assert is_monthly_full_due(None) is False

    def test_frischer_vollscan_nicht_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(days=10)
        assert is_monthly_full_due(last, now=now) is False

    def test_genau_31_tage_alt_ist_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(days=31)
        assert is_monthly_full_due(last, now=now) is True

    def test_alter_vollscan_ist_faellig(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(days=60)
        assert is_monthly_full_due(last, now=now) is True

    def test_custom_threshold(self) -> None:
        now = datetime(2026, 5, 12, 12, 0, tzinfo=UTC)
        last = now - timedelta(days=15)
        # Default 31 Tage: 15 Tage ist NICHT faellig
        assert is_monthly_full_due(last, now=now) is False
        # Mit 14 Tagen: 15 Tage IST faellig
        assert is_monthly_full_due(last, interval_days=14, now=now) is True


# ---------------------------------------------------------------------------
# Scheduler-Tick-Reihenfolge
# ---------------------------------------------------------------------------


def _service_mock(
    *,
    empty: bool = False,
    last_full: datetime | None = None,
    last_daily: datetime | None = None,
) -> MagicMock:
    """Baut einen Service-Mock mit den 3 Methoden die der Scheduler abfragt."""
    mock = MagicMock()
    mock.is_inventory_empty.return_value = empty
    mock.get_last_full_scan_at.return_value = last_full
    mock.get_last_daily_refresh_at.return_value = last_daily
    return mock


def _recorder() -> dict[str, list]:
    return {"initial": [], "monthly": [], "daily": []}


def _connect(scheduler: PatchScheduler, rec: dict[str, list]) -> None:
    scheduler.initial_scan_due.connect(lambda: rec["initial"].append(True))
    scheduler.monthly_full_due.connect(lambda: rec["monthly"].append(True))
    scheduler.daily_refresh_due.connect(lambda: rec["daily"].append(True))


class TestTickReihenfolge:
    def test_empty_inventory_emittiert_initial(self) -> None:
        service = _service_mock(empty=True)
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        scheduler.tick_now()

        assert len(rec["initial"]) == 1
        assert rec["monthly"] == []
        assert rec["daily"] == []
        # Empty-Pfad fragt last_full nicht erst ab
        service.get_last_full_scan_at.assert_not_called()
        service.get_last_daily_refresh_at.assert_not_called()

    def test_monthly_due_emittiert_monthly(self) -> None:
        now = datetime.now(UTC)
        service = _service_mock(
            empty=False,
            last_full=now - timedelta(days=45),  # > 31 → faellig
            last_daily=now - timedelta(hours=48),  # auch faellig, aber Monthly schluckt
        )
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        scheduler.tick_now()

        assert rec["initial"] == []
        assert len(rec["monthly"]) == 1
        # Daily wird NICHT emittiert wenn Monthly faellig (Monthly schliesst Daily inhaltlich ein)
        assert rec["daily"] == []
        # Daily-Lookup wird gar nicht abgefragt
        service.get_last_daily_refresh_at.assert_not_called()

    def test_daily_due_emittiert_daily(self) -> None:
        now = datetime.now(UTC)
        service = _service_mock(
            empty=False,
            last_full=now - timedelta(days=10),  # nicht faellig
            last_daily=now - timedelta(hours=48),  # faellig
        )
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        scheduler.tick_now()

        assert rec["initial"] == []
        assert rec["monthly"] == []
        assert len(rec["daily"]) == 1

    def test_nichts_faellig_kein_signal(self) -> None:
        now = datetime.now(UTC)
        service = _service_mock(
            empty=False,
            last_full=now - timedelta(days=5),
            last_daily=now - timedelta(hours=2),
        )
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        scheduler.tick_now()

        assert rec["initial"] == []
        assert rec["monthly"] == []
        assert rec["daily"] == []

    def test_daily_faellig_aber_monthly_noch_nicht(self) -> None:
        """Reproduzieren: 25 h seit letztem daily, 25 Tage seit letztem Voll.
        Erwartet: nur daily."""
        now = datetime.now(UTC)
        service = _service_mock(
            empty=False,
            last_full=now - timedelta(days=25),
            last_daily=now - timedelta(hours=25),
        )
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        scheduler.tick_now()

        assert rec["monthly"] == []
        assert len(rec["daily"]) == 1


class TestExceptionTolerance:
    def test_tick_crash_emittiert_nichts_aber_kein_raise(self) -> None:
        service = _service_mock(empty=True)
        service.is_inventory_empty.side_effect = RuntimeError("DB tot")
        scheduler = PatchScheduler(service)
        rec = _recorder()
        _connect(scheduler, rec)

        # Soll NICHT crashen
        scheduler.tick_now()

        # Keine Signals emittiert
        assert rec["initial"] == []
        assert rec["monthly"] == []
        assert rec["daily"] == []


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_neuer_scheduler_ist_inactive(self) -> None:
        scheduler = PatchScheduler(_service_mock(empty=True))
        assert scheduler.is_running() is False

    @pytest.mark.gui
    def test_start_aktiviert_timer(self, qapp) -> None:
        """``start`` benoetigt einen Qt-Event-Loop fuer den QTimer —
        markiert als ``@pytest.mark.gui``."""
        scheduler = PatchScheduler(_service_mock(empty=True))
        scheduler.start()
        assert scheduler.is_running() is True
        scheduler.stop()
        assert scheduler.is_running() is False

    def test_stop_ohne_start_kein_crash(self) -> None:
        scheduler = PatchScheduler(_service_mock(empty=True))
        scheduler.stop()  # darf nicht crashen
        assert scheduler.is_running() is False


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------


class TestKonfiguration:
    def test_custom_intervals_propagiert(self) -> None:
        scheduler = PatchScheduler(
            _service_mock(empty=False),
            daily_interval_hours=1,
            monthly_interval_days=7,
        )
        now = datetime.now(UTC)
        service = scheduler._service  # MagicMock # noqa: SLF001
        service.is_inventory_empty.return_value = False
        service.get_last_full_scan_at.return_value = now - timedelta(
            days=8
        )  # > 7 → faellig
        service.get_last_daily_refresh_at.return_value = None

        rec = _recorder()
        _connect(scheduler, rec)
        scheduler.tick_now()

        assert len(rec["monthly"]) == 1

    def test_default_intervals_konstanten(self) -> None:
        assert DEFAULT_DAILY_INTERVAL_HOURS == 24
        assert DEFAULT_MONTHLY_INTERVAL_DAYS == 31
