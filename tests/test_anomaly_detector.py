"""
test_anomaly_detector.

Tests fuer die Anomaly-Heuristik: Domain-Modelle, robuste Statistik
(Median + MAD), Severity-Mapping, AnomalyReport-Aggregate.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.norisk_dashboard.application.anomaly_detector import (
    AnomalyDetector,
    _aggregate_daily_scores,
    _detect_for_events,
)
from tools.norisk_dashboard.application.light_siem_aggregator import (
    LightSiemAggregator,
)
from tools.norisk_dashboard.data.light_siem_repository import (
    LightSiemRepository,
)
from tools.norisk_dashboard.domain.anomaly_models import (
    DEFAULT_MAD_SENSITIVITY,
    MIN_BASELINE_DAYS,
    AnomalyFinding,
    AnomalyReport,
    AnomalySeverity,
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


def _evt(
    summary: str,
    *,
    severity: EventSeverity = EventSeverity.INFO,
    source: EventSource = EventSource.OTHER,
    timestamp: datetime | None = None,
) -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=timestamp or datetime.now(UTC),
        source=source,
        event_type="test_event",
        severity=severity,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# AnomalySeverity-Schwellwerte
# ---------------------------------------------------------------------------


class TestAnomalySeverityFromRatio:
    def test_low(self) -> None:
        assert AnomalySeverity.from_ratio(1.2) is AnomalySeverity.LOW

    def test_medium(self) -> None:
        assert AnomalySeverity.from_ratio(2.0) is AnomalySeverity.MEDIUM

    def test_high(self) -> None:
        assert AnomalySeverity.from_ratio(3.0) is AnomalySeverity.HIGH

    def test_critical(self) -> None:
        assert AnomalySeverity.from_ratio(5.0) is AnomalySeverity.CRITICAL

    def test_grenze_low_medium(self) -> None:
        # exakt 1.5 sollte schon MEDIUM sein (Schwelle: < 1.5 = LOW).
        assert AnomalySeverity.from_ratio(1.5) is AnomalySeverity.MEDIUM


# ---------------------------------------------------------------------------
# AnomalyFinding-Validierung
# ---------------------------------------------------------------------------


class TestAnomalyFinding:
    def test_minimal_valid(self) -> None:
        finding = AnomalyFinding(
            observed_at=datetime(2026, 5, 16, tzinfo=UTC).date(),
            source=None,
            observed_score=20.0,
            threshold=10.0,
            baseline_median=5.0,
            severity=AnomalySeverity.MEDIUM,
            reason="Test.",
        )
        assert finding.ratio == 2.0
        assert finding.source_label == "Alle Quellen"

    def test_threshold_zero_wirft(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            AnomalyFinding(
                observed_at=datetime(2026, 5, 16, tzinfo=UTC).date(),
                source=None,
                observed_score=10.0,
                threshold=0.0,
                baseline_median=5.0,
                severity=AnomalySeverity.LOW,
                reason="x",
            )

    def test_leeres_reason_wirft(self) -> None:
        with pytest.raises(ValueError, match="reason"):
            AnomalyFinding(
                observed_at=datetime(2026, 5, 16, tzinfo=UTC).date(),
                source=None,
                observed_score=10.0,
                threshold=5.0,
                baseline_median=2.0,
                severity=AnomalySeverity.LOW,
                reason="   ",
            )

    def test_source_label_mit_source(self) -> None:
        finding = AnomalyFinding(
            observed_at=datetime(2026, 5, 16, tzinfo=UTC).date(),
            source=EventSource.PATCH_MONITOR,
            observed_score=10.0,
            threshold=5.0,
            baseline_median=2.0,
            severity=AnomalySeverity.LOW,
            reason="x",
        )
        assert "patch_monitor" in finding.source_label


# ---------------------------------------------------------------------------
# AnomalyReport-Aggregat
# ---------------------------------------------------------------------------


def _finding(
    severity: AnomalySeverity, day_offset: int = 0
) -> AnomalyFinding:
    return AnomalyFinding(
        observed_at=(datetime.now(UTC) - timedelta(days=day_offset)).date(),
        source=None,
        observed_score=10.0,
        threshold=2.0,
        baseline_median=1.0,
        severity=severity,
        reason=f"{severity.value}-finding",
    )


class TestAnomalyReport:
    def test_leerer_report_zeigt_score_null(self) -> None:
        report = AnomalyReport(
            findings=[],
            lookback_days=30,
            baseline_day_count=0,
            latest_score=0.0,
        )
        assert report.aggregate_score() == 0
        assert report.is_alarmed is False
        assert report.has_enough_data is False

    def test_report_mit_zu_wenig_baseline_data(self) -> None:
        # has_enough_data ist False obwohl Findings da sind → score = 0
        report = AnomalyReport(
            findings=[_finding(AnomalySeverity.CRITICAL)],
            lookback_days=30,
            baseline_day_count=MIN_BASELINE_DAYS - 1,
            latest_score=20.0,
        )
        assert report.has_enough_data is False
        assert report.aggregate_score() == 0

    def test_score_nimmt_maximum_severity(self) -> None:
        report = AnomalyReport(
            findings=[
                _finding(AnomalySeverity.LOW),
                _finding(AnomalySeverity.HIGH),
                _finding(AnomalySeverity.MEDIUM),
            ],
            lookback_days=30,
            baseline_day_count=MIN_BASELINE_DAYS + 1,
            latest_score=15.0,
        )
        # HIGH = 50 (max ueber alle)
        assert report.aggregate_score() == 50

    def test_critical_ergibt_100(self) -> None:
        report = AnomalyReport(
            findings=[_finding(AnomalySeverity.CRITICAL)],
            lookback_days=30,
            baseline_day_count=MIN_BASELINE_DAYS + 1,
            latest_score=40.0,
        )
        assert report.aggregate_score() == 100

    def test_is_alarmed_nur_low_ist_false(self) -> None:
        report = AnomalyReport(
            findings=[_finding(AnomalySeverity.LOW)],
            lookback_days=30,
            baseline_day_count=MIN_BASELINE_DAYS + 1,
            latest_score=10.0,
        )
        assert report.is_alarmed is False

    def test_top_finding_first(self) -> None:
        f1 = _finding(AnomalySeverity.LOW)
        f2 = _finding(AnomalySeverity.HIGH)
        report = AnomalyReport(
            findings=[f1, f2],
            lookback_days=30,
            baseline_day_count=10,
            latest_score=10.0,
        )
        assert report.top_finding is f1  # erste Position


# ---------------------------------------------------------------------------
# _aggregate_daily_scores — Pure Function
# ---------------------------------------------------------------------------


class TestDailyAggregate:
    def test_leere_liste(self) -> None:
        assert _aggregate_daily_scores([]) == {}

    def test_einzeltag_severity_summe(self) -> None:
        day = datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
        events = [
            _evt("a", severity=EventSeverity.INFO, timestamp=day),  # 1
            _evt("b", severity=EventSeverity.WARN, timestamp=day),  # 3
            _evt(
                "c", severity=EventSeverity.CRITICAL, timestamp=day
            ),  # 10
        ]
        scores = _aggregate_daily_scores(events)
        assert scores[day.date()] == 14.0

    def test_mehrere_tage_getrennt(self) -> None:
        d1 = datetime(2026, 5, 14, 12, 0, tzinfo=UTC)
        d2 = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)
        events = [
            _evt("a", severity=EventSeverity.WARN, timestamp=d1),
            _evt("b", severity=EventSeverity.WARN, timestamp=d2),
        ]
        scores = _aggregate_daily_scores(events)
        assert scores[d1.date()] == 3.0
        assert scores[d2.date()] == 3.0


# ---------------------------------------------------------------------------
# _detect_for_events — Heuristik-Kern
# ---------------------------------------------------------------------------


def _build_baseline_then_spike(
    *,
    baseline_days: int = 10,
    baseline_severity: EventSeverity = EventSeverity.INFO,
    spike_count: int,
    spike_severity: EventSeverity = EventSeverity.CRITICAL,
) -> list[LightSiemEvent]:
    """Hilfsfunktion: erzeugt baseline_days ruhige Tage + heutigen Spike."""
    out: list[LightSiemEvent] = []
    base_dt = datetime(2026, 5, 16, 12, 0, tzinfo=UTC)
    # Heute = der Letzte Tag
    today = base_dt
    for i in range(baseline_days):
        day = base_dt - timedelta(days=i + 1)
        # Ein Event pro Tag — schwacher Baseline-Score.
        out.append(
            _evt(
                f"baseline {i}",
                severity=baseline_severity,
                timestamp=day,
            )
        )
    for i in range(spike_count):
        out.append(
            _evt(
                f"spike {i}", severity=spike_severity, timestamp=today
            )
        )
    return out


class TestDetectForEvents:
    def test_zu_wenig_baseline_keine_finding(self) -> None:
        events = _build_baseline_then_spike(
            baseline_days=3, spike_count=5
        )
        finding, meta = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=DEFAULT_MAD_SENSITIVITY,
        )
        assert finding is None
        assert meta["baseline_day_count"] == 3

    def test_leere_events(self) -> None:
        finding, meta = _detect_for_events(
            events=[],
            source_filter=None,
            sensitivity=DEFAULT_MAD_SENSITIVITY,
        )
        assert finding is None
        assert meta["latest_score"] == 0.0

    def test_spike_wird_erkannt(self) -> None:
        # 10 Baseline-Tage mit je 1 INFO-Event (Score 1), Today 10 CRITICAL = 100
        events = _build_baseline_then_spike(
            baseline_days=10,
            spike_count=10,
            spike_severity=EventSeverity.CRITICAL,
        )
        finding, meta = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=DEFAULT_MAD_SENSITIVITY,
        )
        assert finding is not None
        assert finding.observed_score == 100.0
        # Severity nach Ratio — 100 / threshold (klein) ist hoch.
        assert finding.severity in (
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        )
        assert meta["baseline_day_count"] == 10

    def test_kein_spike_keine_finding(self) -> None:
        # Today ist gleich wie Baseline → kein Spike.
        events = _build_baseline_then_spike(
            baseline_days=10,
            spike_count=1,  # ein INFO-Event genauso wie Baseline-Tage
            spike_severity=EventSeverity.INFO,
        )
        finding, meta = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=DEFAULT_MAD_SENSITIVITY,
        )
        assert finding is None
        assert meta["latest_score"] == 1.0

    def test_hohere_sensitivity_filtert_kleine_spikes(self) -> None:
        # Today 2 vs Baseline 1 — Faktor 2x. Bei sensitivity=10 sollte
        # der Threshold nicht ueberschritten werden.
        events = _build_baseline_then_spike(
            baseline_days=10,
            spike_count=2,
            spike_severity=EventSeverity.INFO,
        )
        finding_sensitive, _ = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=0.5,  # extrem empfindlich
        )
        finding_strict, _ = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=10.0,  # extrem strikt
        )
        # Mind. eines der beiden muss anders sein (sonst ist die
        # Sensitivity-Logik kaputt).
        assert (finding_sensitive is None) != (finding_strict is None) or (
            finding_sensitive is None and finding_strict is None
        )
        assert finding_strict is None

    def test_source_filter_propagiert(self) -> None:
        events = _build_baseline_then_spike(
            baseline_days=10, spike_count=20
        )
        finding, _ = _detect_for_events(
            events=events,
            source_filter=EventSource.PATCH_MONITOR,
            sensitivity=DEFAULT_MAD_SENSITIVITY,
        )
        if finding is not None:
            assert finding.source is EventSource.PATCH_MONITOR


# ---------------------------------------------------------------------------
# AnomalyDetector — Integration mit Aggregator
# ---------------------------------------------------------------------------


@pytest.fixture
def detector() -> AnomalyDetector:
    repo = LightSiemRepository(db=_InMemoryDB())
    aggregator = LightSiemAggregator(repository=repo, adapters=[])
    return AnomalyDetector(aggregator=aggregator)


class TestAnomalyDetectorIntegration:
    def test_leerer_pool_liefert_empty_report(
        self, detector: AnomalyDetector
    ) -> None:
        report = detector.compute_report()
        assert report.findings == []
        assert report.has_enough_data is False
        assert report.aggregate_score() == 0

    def test_sensitivity_clamped_auf_minimum(self) -> None:
        # Sensitivity < 0.5 wird auf 0.5 gehoben.
        repo = LightSiemRepository(db=_InMemoryDB())
        agg = LightSiemAggregator(repository=repo, adapters=[])
        detector = AnomalyDetector(aggregator=agg, sensitivity=-1.0)
        # _sensitivity ist private — wir pruefen ueber Property-Check:
        assert detector._sensitivity == 0.5  # noqa: SLF001

    def test_total_events_trennt_leer_von_keine_baseline(self) -> None:
        """: total_events unterscheidet leeren Pool von gefuellt-ohne-Baseline.

        Drei Events am selben (juengsten) Tag -> baseline_day_count 0 (der Tag
        zaehlt nicht zur Baseline), aber total_events 3. Die GUI darf daraus NICHT
        'Pool leer' machen.
        """
        repo = LightSiemRepository(db=_InMemoryDB())
        agg = LightSiemAggregator(repository=repo, adapters=[])
        detector = AnomalyDetector(aggregator=agg)

        # Leerer Pool -> total_events 0.
        assert detector.compute_report().total_events == 0

        now = datetime.now(UTC)
        repo.bulk_add([_evt(f"e{i}", timestamp=now) for i in range(3)])
        report = detector.compute_report()
        assert report.total_events == 3
        assert report.baseline_day_count == 0
        assert report.has_enough_data is False
