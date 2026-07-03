"""
test_light_siem_aggregator.

Tests fuer LightSiemAggregator: Adapter-Aufruf, Fail-Silently bei
defekten Adaptern, Bulk-Persistierung.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from tools.norisk_dashboard.application.light_siem_aggregator import (
    LightSiemAggregator,
    awareness_training_adapter,
    supply_chain_avv_adapter,
)
from tools.norisk_dashboard.data.light_siem_repository import (
    LightSiemRepository,
)
from tools.norisk_dashboard.domain.light_siem_models import (
    EventSeverity,
    EventSource,
    LightSiemEvent,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def repo() -> LightSiemRepository:
    return LightSiemRepository(db=_InMemoryDB())


NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


def _evt(summary: str = "Test event") -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=datetime.now(UTC),
        source=EventSource.OTHER,
        event_type="custom",
        severity=EventSeverity.INFO,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Adapter-Orchestrierung
# ---------------------------------------------------------------------------


class TestAggregatorRunIngest:
    def test_aggregiert_aus_mehreren_adaptern(
        self, repo: LightSiemRepository
    ) -> None:
        def adapter_a() -> list[LightSiemEvent]:
            return [_evt("a1"), _evt("a2")]

        def adapter_b() -> list[LightSiemEvent]:
            return [_evt("b1")]

        agg = LightSiemAggregator(
            repository=repo, adapters=[adapter_a, adapter_b]
        )
        added, skipped = agg.run_ingest()
        assert added == 3
        assert skipped == 0

    def test_dedup_wird_gezaehlt(self, repo: LightSiemRepository) -> None:
        def adapter() -> list[LightSiemEvent]:
            return [_evt("a"), _evt("a")]  # selber summary → Dedup-Hit

        agg = LightSiemAggregator(repository=repo, adapters=[adapter])
        added, skipped = agg.run_ingest()
        assert added == 1
        assert skipped == 1

    def test_defekter_adapter_blockt_andere_nicht(
        self, repo: LightSiemRepository
    ) -> None:
        def broken() -> list[LightSiemEvent]:
            raise RuntimeError("simuliert kaputt")

        def working() -> list[LightSiemEvent]:
            return [_evt("ok")]

        agg = LightSiemAggregator(
            repository=repo, adapters=[broken, working]
        )
        added, skipped = agg.run_ingest()
        # Broken liefert nichts, working liefert 1 → 1 added.
        assert added == 1

    def test_leere_adapter_liste(
        self, repo: LightSiemRepository
    ) -> None:
        agg = LightSiemAggregator(repository=repo, adapters=[])
        added, skipped = agg.run_ingest()
        assert added == 0
        assert skipped == 0


class TestAggregatorPassthrough:
    def test_list_recent_pass_through(
        self, repo: LightSiemRepository
    ) -> None:
        repo.add(_evt("a"))
        agg = LightSiemAggregator(repository=repo, adapters=[])
        events = agg.list_recent()
        assert len(events) == 1

    def test_summary_pass_through(
        self, repo: LightSiemRepository
    ) -> None:
        repo.add(_evt("a"))
        agg = LightSiemAggregator(repository=repo, adapters=[])
        summary = agg.summary()
        assert summary.total_events == 1

    def test_purge_pass_through(
        self, repo: LightSiemRepository
    ) -> None:
        now_live = datetime.now(UTC)
        old_evt = LightSiemEvent(
            id=None,
            timestamp=now_live - timedelta(days=400),
            source=EventSource.OTHER,
            event_type="x",
            severity=EventSeverity.INFO,
            summary="alt",
        )
        repo.add(old_evt)
        agg = LightSiemAggregator(repository=repo, adapters=[])
        deleted = agg.purge_older_than(retention_days=180)
        assert deleted == 1


# ---------------------------------------------------------------------------
# Default-Adapter — fail-silently wenn Source-Tool nicht importierbar
# ---------------------------------------------------------------------------


class TestDefaultAdaptersFailSilently:
    def test_supply_chain_adapter_haendelt_query_fehler(self) -> None:
        # Patche AvvService so dass list_all wirft.
        with patch(
            "tools.supply_chain_monitor.application.avv_service.AvvService"
        ) as mock_service:
            mock_service.return_value.list_all.side_effect = RuntimeError(
                "DB nicht da"
            )
            events = supply_chain_avv_adapter()
        assert events == []

    def test_awareness_adapter_haendelt_query_fehler(self) -> None:
        with patch(
            "tools.awareness_tracker.application.awareness_service.AwarenessService"
        ) as mock_service:
            mock_service.return_value.list_trainings_due_soon.side_effect = (
                RuntimeError("DB nicht da")
            )
            events = awareness_training_adapter()
        assert events == []


# ---------------------------------------------------------------------------
# Patch / System / Cert-Adapter + erweiterte Default-Liste
# ---------------------------------------------------------------------------


def test_default_adapters_enthaelt_alle_fuenf() -> None:
    """Default-Liste deckt jetzt alle 5 Source-Tools ab."""
    from tools.norisk_dashboard.application.light_siem_aggregator import (
        _default_adapters,
    )

    names = {a.__name__ for a in _default_adapters()}
    assert names == {
        "supply_chain_avv_adapter",
        "awareness_training_adapter",
        "patch_monitor_adapter",
        "system_scanner_adapter",
        "cert_monitor_adapter",
    }


def test_patch_adapter_eol_liefert_critical_event(monkeypatch) -> None:
    """EOL-Software erzeugt ein CRITICAL Patch-Event."""
    from types import SimpleNamespace

    from tools.norisk_dashboard.application import light_siem_aggregator as agg

    fake = SimpleNamespace(
        name="OldApp",
        installed_version="1.0",
        available_version="",
        eol=True,
        exploit_available=False,
        cvss_max=None,
    )

    class _FakeSvc:
        def load_from_db(self):  # noqa: ANN202
            return [fake]

    monkeypatch.setattr(
        "tools.patch_monitor.application.patch_inventory_service.PatchInventoryService",
        lambda: _FakeSvc(),
    )
    events = agg.patch_monitor_adapter()
    assert len(events) == 1
    assert events[0].severity == EventSeverity.CRITICAL
    assert events[0].source == EventSource.PATCH_MONITOR
    assert "End-of-Life" in events[0].summary


@pytest.mark.parametrize(
    ("adapter_name", "patch_target"),
    [
        (
            "patch_monitor_adapter",
            "tools.patch_monitor.application.patch_inventory_service.PatchInventoryService",
        ),
        (
            "system_scanner_adapter",
            "tools.system_scanner.data.scanner_repository.ScanRepository",
        ),
        (
            "cert_monitor_adapter",
            "tools.cert_monitor.application.cert_monitor_service.CertMonitorService.create_default",
        ),
    ],
)
def test_neue_adapter_sind_fail_soft(monkeypatch, adapter_name, patch_target) -> None:
    """Jeder neue Adapter liefert [] statt zu werfen, wenn die Quelle kaputt ist."""
    from tools.norisk_dashboard.application import light_siem_aggregator as agg

    def _boom(*_a, **_k):
        raise RuntimeError("quelle kaputt")

    monkeypatch.setattr(patch_target, _boom)
    assert getattr(agg, adapter_name)() == []


def test_system_adapter_ueberspringt_nicht_messbare_und_bestandene(monkeypatch) -> None:
    """Nur MESSBARE, NICHT bestandene Hardening-Checks werden zu Events.

    Nicht-messbare Checks (Mess-Fehlschlag) duerfen kein rotes Event erzeugen; bestandene Checks ebenfalls nicht.
    """
    from types import SimpleNamespace

    from core.security.severity import Severity
    from tools.norisk_dashboard.application import light_siem_aggregator as agg

    checks = [
        SimpleNamespace(  # messbar + nicht bestanden -> 1 Event
            check_id="SH-001", label="Firewall", passed=False,
            severity=Severity.HIGH, measurable=True, detail="aus",
        ),
        SimpleNamespace(  # NICHT messbar -> kein Event
            check_id="SH-002", label="BitLocker", passed=False,
            severity=Severity.CRITICAL, measurable=False, detail="",
        ),
        SimpleNamespace(  # bestanden -> kein Event
            check_id="SH-003", label="RDP", passed=True,
            severity=Severity.LOW, measurable=True, detail="",
        ),
    ]

    class _FakeRepo:
        def load_latest(self):  # noqa: ANN202
            return SimpleNamespace(hardening_checks=checks)

    monkeypatch.setattr(
        "tools.system_scanner.data.scanner_repository.ScanRepository",
        lambda: _FakeRepo(),
    )
    events = agg.system_scanner_adapter()
    assert len(events) == 1
    assert events[0].event_type == "hardening_sh-001"
    assert events[0].severity == EventSeverity.ERROR  # HIGH -> ERROR
    assert events[0].source == EventSource.SYSTEM_SCANNER
