"""
anomaly_detector — Anomaly-Heuristik fuer den Light-SIEM-Event-Pool.

Iter 3e: Erkennt Tage mit ungewoehnlich hohen
severity-gewichteten Event-Counts. Nutzt **Median + MAD** (Median
Absolute Deviation) statt Mittelwert + Standardabweichung — robust
gegen Ausreisser.

Pipeline:
    1. Events aus dem:class:`LightSiemAggregator` ziehen (Lookback-Fenster).
    2. Pro Tag den severity-gewichteten Score bilden
       (``sum(event.severity.numeric_weight)``).
    3. Baseline-Statistik = (median, MAD) ueber alle Tage **ausser dem
       juengsten**.
    4. Threshold = ``median + sensitivity * MAD`` (Default sensitivity=2.5).
    5. Tage mit Score > Threshold →:class:`AnomalyFinding` mit Severity
       aus dem ``ratio = observed / threshold``.
    6. Zusaetzlich per-Source-Anomalies, damit wir sehen *woher* das kommt.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from core.logger import get_logger
from tools.norisk_dashboard.application.light_siem_aggregator import (
    LightSiemAggregator,
)
from tools.norisk_dashboard.domain.anomaly_models import (
    DEFAULT_ANOMALY_LOOKBACK_DAYS,
    DEFAULT_MAD_SENSITIVITY,
    MIN_BASELINE_DAYS,
    AnomalyFinding,
    AnomalyReport,
    AnomalySeverity,
)
from tools.norisk_dashboard.domain.light_siem_models import (
    EventSource,
    LightSiemEvent,
)

_log = get_logger(__name__)

# Wenn MAD == 0 (alle Werte identisch), nehmen wir eine Mindest-MAD von
# 1.0, damit Threshold == median + sensitivity (nicht median + 0).
_MIN_MAD: float = 1.0


class AnomalyDetector:
    """Berechnet:class:`AnomalyReport`s aus dem Event-Pool.

    Attributes:
        _aggregator: Quelle der Events (LightSiemAggregator).
        _sensitivity: MAD-Faktor; hoehere Werte = weniger empfindlich.
    """

    def __init__(
        self,
        aggregator: LightSiemAggregator | None = None,
        sensitivity: float = DEFAULT_MAD_SENSITIVITY,
    ) -> None:
        """Initialisiert den Detector.

        Args:
            aggregator: Optional vorgefertigter Aggregator (Tests). Default:
                neuer Aggregator auf der Produktiv-DB.
            sensitivity: MAD-Faktor. Niedriger = mehr false positives.
        """
        self._aggregator = aggregator or LightSiemAggregator()
        self._sensitivity = max(0.5, float(sensitivity))

    def compute_report(
        self,
        lookback_days: int = DEFAULT_ANOMALY_LOOKBACK_DAYS,
    ) -> AnomalyReport:
        """Erzeugt einen:class:`AnomalyReport` aus den letzten Events.

        Args:
            lookback_days: Zeitfenster fuer die Baseline (Default 30 Tage).

        Returns:
:class:`AnomalyReport`. Bei zu wenig Datenpunkten ist
            ``findings`` leer und ``has_enough_data`` False.
        """
        events = self._aggregator.list_recent(
            lookback_days=lookback_days,
            limit=10_000,  # Lookback ist primaere Grenze; Limit nur Schutz.
        )
        findings: list[AnomalyFinding] = []

        # 1) Globale Anomaly ueber alle Quellen.
        global_finding, global_meta = _detect_for_events(
            events=events,
            source_filter=None,
            sensitivity=self._sensitivity,
        )
        if global_finding is not None:
            findings.append(global_finding)
        baseline_day_count = global_meta["baseline_day_count"]
        latest_score = global_meta["latest_score"]

        # 2) Per-Source: nur Sources mit eigenen Anomalien zaehlen.
        by_source: dict[EventSource, list[LightSiemEvent]] = defaultdict(list)
        for event in events:
            by_source[event.source].append(event)
        for source, source_events in by_source.items():
            source_finding, _meta = _detect_for_events(
                events=source_events,
                source_filter=source,
                sensitivity=self._sensitivity,
            )
            if source_finding is not None:
                findings.append(source_finding)

        # Sortierung: CRITICAL > HIGH > MEDIUM > LOW, dann observed_at desc.
        _SEV_RANK = {
            AnomalySeverity.CRITICAL: 4,
            AnomalySeverity.HIGH: 3,
            AnomalySeverity.MEDIUM: 2,
            AnomalySeverity.LOW: 1,
        }
        findings.sort(
            key=lambda f: (_SEV_RANK[f.severity], f.observed_at),
            reverse=True,
        )

        return AnomalyReport(
            findings=findings,
            lookback_days=lookback_days,
            baseline_day_count=baseline_day_count,
            # echte Pool-Groesse mitgeben, damit die GUI "leer" von
            # "gefuellt aber noch keine Mehrtages-Baseline" unterscheiden kann.
            total_events=len(events),
            latest_score=latest_score,
            generated_at=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Reine Logik-Funktionen (testbar ohne Aggregator)
# ---------------------------------------------------------------------------


def _detect_for_events(
    events: list[LightSiemEvent],
    source_filter: EventSource | None,
    sensitivity: float,
) -> tuple[AnomalyFinding | None, dict[str, float]]:
    """Berechnet eine Anomaly-Heuristik fuer eine Event-Liste.

    Returns:
        ``(finding | None, meta)`` — ``meta`` enthaelt ``baseline_day_count``
        und ``latest_score`` fuer den Caller-Aggregat.
    """
    if not events:
        return (None, {"baseline_day_count": 0, "latest_score": 0.0})

    daily_scores = _aggregate_daily_scores(events)
    if not daily_scores:
        return (None, {"baseline_day_count": 0, "latest_score": 0.0})

    sorted_days = sorted(daily_scores.keys())
    latest_day = sorted_days[-1]
    latest_score = daily_scores[latest_day]
    baseline_days = sorted_days[:-1]  # juengsten Tag aus der Baseline raus.

    if len(baseline_days) < MIN_BASELINE_DAYS:
        return (
            None,
            {
                "baseline_day_count": len(baseline_days),
                "latest_score": float(latest_score),
            },
        )

    baseline_scores = [daily_scores[d] for d in baseline_days]
    median = statistics.median(baseline_scores)
    mad = max(
        _MIN_MAD,
        statistics.median(abs(s - median) for s in baseline_scores),
    )
    threshold = median + sensitivity * mad

    if latest_score <= threshold:
        return (
            None,
            {
                "baseline_day_count": len(baseline_days),
                "latest_score": float(latest_score),
            },
        )

    ratio = latest_score / threshold
    severity = AnomalySeverity.from_ratio(ratio)
    source_label = (
        "alle Quellen" if source_filter is None else source_filter.value
    )
    reason = (
        f"Score {latest_score:.0f} ueber Threshold {threshold:.1f} "
        f"(Median {median:.1f}, MAD {mad:.1f}, Faktor {ratio:.2f}x) "
        f"bei {source_label}."
    )
    finding = AnomalyFinding(
        observed_at=latest_day,
        source=source_filter,
        observed_score=float(latest_score),
        threshold=float(threshold),
        baseline_median=float(median),
        severity=severity,
        reason=reason,
    )
    return (
        finding,
        {
            "baseline_day_count": len(baseline_days),
            "latest_score": float(latest_score),
        },
    )


def _aggregate_daily_scores(events: list[LightSiemEvent]) -> dict:
    """Gruppiert Events nach Tag (UTC-Datum) und summiert severity-Gewichte.

    Returns:
        Mapping ``{date: float}`` — leer wenn ``events`` leer ist.
    """
    out: dict = defaultdict(float)
    for event in events:
        # Wir nehmen den UTC-Tag aus dem Event-Timestamp.
        day = event.timestamp.astimezone(UTC).date()
        out[day] += float(event.severity.numeric_weight)
    return dict(out)


# Re-Export fuer Test-Bequemlichkeit.
__all__ = ["AnomalyDetector", "timedelta"]
