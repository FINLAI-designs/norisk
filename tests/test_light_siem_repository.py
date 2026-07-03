"""
test_light_siem_repository.

Tests fuer das LightSiemRepository: CRUD, Dedup, Summary, Retention.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

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


def _event(
    *,
    source: EventSource = EventSource.AWARENESS_TRACKER,
    event_type: str = "training_expired",
    severity: EventSeverity = EventSeverity.WARN,
    summary: str = "Test event",
    timestamp: datetime = NOW,
) -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        severity=severity,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestSchemaInit:
    def test_leeres_repo_listet_nichts(self, repo: LightSiemRepository) -> None:
        assert repo.list_recent() == []

    def test_idempotent_init(self) -> None:
        db = _InMemoryDB()
        LightSiemRepository(db=db)
        LightSiemRepository(db=db)


# ---------------------------------------------------------------------------
# Add + Dedup
# ---------------------------------------------------------------------------


class TestAddAndDedup:
    def test_add_liefert_id(self, repo: LightSiemRepository) -> None:
        new_id = repo.add(_event())
        assert isinstance(new_id, int)
        assert new_id > 0

    def test_dedup_blockt_duplikat(
        self, repo: LightSiemRepository
    ) -> None:
        event = _event()
        first = repo.add(event)
        second = repo.add(event)
        assert first is not None
        assert second is None  # Dedup-Konflikt

    def test_dedup_pro_summary_unterschiedlich(
        self, repo: LightSiemRepository
    ) -> None:
        e1 = _event(summary="DATEV laeuft ab")
        e2 = _event(summary="M365 laeuft ab")
        assert repo.add(e1) is not None
        assert repo.add(e2) is not None  # andere summary → andere Hash

    def test_bulk_add_zaehlt_added_und_skipped(
        self, repo: LightSiemRepository
    ) -> None:
        e1 = _event(summary="A")
        e2 = _event(summary="B")
        e3 = _event(summary="A")  # Duplikat
        added, skipped = repo.bulk_add([e1, e2, e3])
        assert added == 2
        assert skipped == 1


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


class TestList:
    def test_list_recent_sortiert_neueste_zuerst(
        self, repo: LightSiemRepository
    ) -> None:
        # now=NOW injizieren — vorher rechnete der Test fixe
        # Event-Zeiten gegen die Wanduhr und kippte am 2026-06-10
        # (NOW-5d fiel aus dem 30d-Fenster-Klasse).
        repo.add(_event(summary="alt", timestamp=NOW - timedelta(days=5)))
        repo.add(_event(summary="neu", timestamp=NOW))
        rows = repo.list_recent(now=NOW)
        assert [r.summary for r in rows] == ["neu", "alt"]

    def test_list_recent_lookback_window(
        self, repo: LightSiemRepository
    ) -> None:
        # Datum im Repo ist live (NOW = jetzt), wir koennen kein injizieren.
        # Setze ein Event 100 Tage in der Vergangenheit relativ zu now.
        in_window = _event(
            summary="frisch",
            timestamp=datetime.now(UTC) - timedelta(days=5),
        )
        out_of_window = _event(
            summary="alt",
            timestamp=datetime.now(UTC) - timedelta(days=100),
        )
        repo.add(in_window)
        repo.add(out_of_window)
        recent = repo.list_recent(lookback_days=30)
        assert {r.summary for r in recent} == {"frisch"}


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_leere_summary(self, repo: LightSiemRepository) -> None:
        summary = repo.summary()
        assert summary.is_empty
        assert summary.total_events == 0
        assert summary.critical_count == 0
        assert summary.latest_timestamp is None

    def test_summary_zaehlt_severities(
        self, repo: LightSiemRepository
    ) -> None:
        now_live = datetime.now(UTC)
        repo.add(
            _event(
                summary="c1",
                severity=EventSeverity.CRITICAL,
                timestamp=now_live,
            )
        )
        repo.add(
            _event(
                summary="c2",
                severity=EventSeverity.CRITICAL,
                timestamp=now_live,
            )
        )
        repo.add(
            _event(
                summary="w1",
                severity=EventSeverity.WARN,
                timestamp=now_live,
            )
        )
        summary = repo.summary()
        assert summary.total_events == 3
        assert summary.critical_count == 2
        assert summary.by_severity[EventSeverity.WARN] == 1
        assert summary.by_severity[EventSeverity.INFO] == 0

    def test_summary_zaehlt_sources(
        self, repo: LightSiemRepository
    ) -> None:
        now_live = datetime.now(UTC)
        repo.add(
            _event(
                summary="s1",
                source=EventSource.SUPPLY_CHAIN_MONITOR,
                timestamp=now_live,
            )
        )
        repo.add(
            _event(
                summary="s2",
                source=EventSource.AWARENESS_TRACKER,
                timestamp=now_live,
            )
        )
        summary = repo.summary()
        assert summary.by_source[EventSource.SUPPLY_CHAIN_MONITOR] == 1
        assert summary.by_source[EventSource.AWARENESS_TRACKER] == 1


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


class TestRetention:
    def test_delete_older_than(self, repo: LightSiemRepository) -> None:
        now_live = datetime.now(UTC)
        repo.add(
            _event(
                summary="alt", timestamp=now_live - timedelta(days=200)
            )
        )
        repo.add(_event(summary="neu", timestamp=now_live))
        deleted = repo.delete_older_than(now_live - timedelta(days=100))
        assert deleted == 1
        recent = repo.list_recent(lookback_days=365)
        assert [r.summary for r in recent] == ["neu"]


# ---------------------------------------------------------------------------
# Dashboard-Bundle (Perf: 1 Connection statt 3) — verhaltensneutral
# ---------------------------------------------------------------------------


class TestLoadDashboardBundle:
    def test_bundle_equals_separate_calls(self, repo: LightSiemRepository) -> None:
        repo.bulk_add(
            [
                _event(
                    summary="recent-1",
                    timestamp=NOW - timedelta(days=1),
                    severity=EventSeverity.CRITICAL,
                ),
                _event(
                    summary="recent-2",
                    timestamp=NOW - timedelta(days=3),
                    severity=EventSeverity.WARN,
                ),
                _event(
                    summary="older-1",
                    timestamp=NOW - timedelta(days=10),
                    severity=EventSeverity.INFO,
                ),
            ]
        )
        summary, table, chart = repo.load_dashboard_bundle(
            table_limit=20, chart_lookback_days=7, chart_limit=2000, now=NOW
        )
        # Identisch zu den 3 separaten Aufrufen (nur 1 Connection statt 3).
        exp_summary = repo.summary(now=NOW)
        exp_table = repo.list_recent(limit=20, now=NOW)
        exp_chart = repo.list_recent(lookback_days=7, limit=2000, now=NOW)
        assert summary.total_events == exp_summary.total_events
        assert summary.by_severity == exp_summary.by_severity
        assert [e.summary for e in table] == [e.summary for e in exp_table]
        assert [e.summary for e in chart] == [e.summary for e in exp_chart]
        # 7-Tage-Chart nur die 2 recent; 30-Tage-Tabelle/Summary alle 3.
        assert {e.summary for e in chart} == {"recent-1", "recent-2"}
        assert {e.summary for e in table} == {"recent-1", "recent-2", "older-1"}
        assert summary.total_events == 3
