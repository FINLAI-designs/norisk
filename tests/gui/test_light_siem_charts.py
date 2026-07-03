"""Tests fuer die Light-SIEM-Chart-Helper.

Pure-Function-Tests fuer Donut-Segment-Berechnung und Daily-Stacked-Aggregation
(beide leben in ``tools/norisk_dashboard/gui/light_siem_section.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.norisk_dashboard.domain.light_siem_models import (
    EventSeverity,
    EventSource,
    LightSiemEvent,
    LightSiemSummary,
)
from tools.norisk_dashboard.gui.light_siem_section import (
    compute_daily_stacked_series,
    compute_severity_donut_segments,
)

pytestmark = pytest.mark.gui


def _summary(**by_severity: int) -> LightSiemSummary:
    full = {sev: 0 for sev in EventSeverity}
    label_map = {
        "info": EventSeverity.INFO,
        "warn": EventSeverity.WARN,
        "error": EventSeverity.ERROR,
        "critical": EventSeverity.CRITICAL,
    }
    for label, count in by_severity.items():
        full[label_map[label]] = count
    return LightSiemSummary(
        total_events=sum(full.values()),
        by_severity=full,
        by_source={},
        critical_count=full[EventSeverity.CRITICAL],
        latest_timestamp=None,
    )


def _event(ts: datetime, severity: EventSeverity) -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=ts,
        source=EventSource.OTHER,
        event_type="test",
        severity=severity,
        summary=f"event-{ts.isoformat()}-{severity.value}",
    )


class TestComputeSeverityDonutSegments:
    def test_empty_summary_returns_empty(self):
        assert compute_severity_donut_segments(_summary()) == []

    def test_skips_severities_with_zero_count(self):
        segments = compute_severity_donut_segments(_summary(warn=3, info=5))
        labels = [s.label for s in segments]
        assert labels == ["WARN", "INFO"]

    def test_order_is_critical_error_warn_info(self):
        segments = compute_severity_donut_segments(
            _summary(info=2, warn=3, error=4, critical=5)
        )
        assert [s.label for s in segments] == [
            "CRITICAL",
            "ERROR",
            "WARN",
            "INFO",
        ]

    def test_segment_values_match_counts(self):
        segments = compute_severity_donut_segments(_summary(critical=7))
        assert segments[0].value == 7.0


class TestComputeDailyStackedSeries:
    NOW = datetime(2026, 5, 27, 12, tzinfo=UTC)

    def test_zero_days_returns_empty(self):
        ts, series = compute_daily_stacked_series([], self.NOW, days=0)
        assert ts == []
        assert series == {}

    def test_empty_events_returns_zero_series(self):
        ts, series = compute_daily_stacked_series([], self.NOW, days=3)
        assert len(ts) == 3
        for label in ("CRITICAL", "ERROR", "WARN", "INFO"):
            assert series[label] == [0.0, 0.0, 0.0]

    def test_events_aggregated_by_day_and_severity(self):
        # 3 Events am gleichen Tag, 1 am Vortag
        today = self.NOW
        yesterday = self.NOW - timedelta(days=1)
        events = [
            _event(today, EventSeverity.CRITICAL),
            _event(today, EventSeverity.CRITICAL),
            _event(today, EventSeverity.INFO),
            _event(yesterday, EventSeverity.WARN),
        ]
        ts, series = compute_daily_stacked_series(events, today, days=2)
        assert len(ts) == 2
        # series[label] = [yesterday_count, today_count]
        assert series["CRITICAL"] == [0.0, 2.0]
        assert series["INFO"] == [0.0, 1.0]
        assert series["WARN"] == [1.0, 0.0]
        assert series["ERROR"] == [0.0, 0.0]

    def test_events_outside_window_ignored(self):
        too_old = self.NOW - timedelta(days=10)
        events = [_event(too_old, EventSeverity.CRITICAL)]
        ts, series = compute_daily_stacked_series(events, self.NOW, days=3)
        assert sum(series["CRITICAL"]) == 0.0

    def test_naive_timestamp_treated_as_utc(self):
        naive = datetime(2026, 5, 27, 6, 0)  # naive UTC
        events = [_event(naive, EventSeverity.ERROR)]
        ts, series = compute_daily_stacked_series(events, self.NOW, days=1)
        assert series["ERROR"] == [1.0]


def test_section_renders_with_chart_data(app, qtbot, monkeypatch):
    """End-to-End: LightSiemSection.reload rendert Donut + StackedArea.

    Wir injizieren einen Mini-Aggregator, der vordefinierte Daten liefert,
    und pruefen dass die Renderer nicht crashen.
    """
    from tools.norisk_dashboard.application.light_siem_aggregator import (
        LightSiemAggregator,
    )
    from tools.norisk_dashboard.gui.light_siem_section import LightSiemSection

    class _StubAggregator(LightSiemAggregator):
        def __init__(self):  # noqa: D401 — Stub
            pass

        def summary(self, lookback_days: int = 30):
            return _summary(critical=2, error=5, warn=12, info=88)

        def list_recent(self, lookback_days: int = 30, limit: int = 200):
            now = datetime.now(UTC)
            return [
                _event(now - timedelta(days=1), EventSeverity.CRITICAL),
                _event(now - timedelta(days=2), EventSeverity.WARN),
                _event(now, EventSeverity.INFO),
            ]

        def load_dashboard_bundle(
            self, *, table_limit, chart_lookback_days, chart_limit
        ):
            return (self.summary(), self.list_recent(), self.list_recent())

    section = LightSiemSection(aggregator=_StubAggregator(), auto_ingest=False)
    qtbot.addWidget(section)
    section.resize(900, 720)
    section.show()
    qtbot.waitExposed(section)
    section.repaint()
    # Donut hat 4 Segmente (alle Severities > 0)
    assert len(section._donut._segments) == 4
    # StackedArea hat 7 Timestamps
    assert len(section._stacked_area._timestamps) == 7
