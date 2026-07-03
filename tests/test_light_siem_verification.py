"""Verifikation Light-SIEM + Anomalie-Heuristik mit KÜNSTLICHEN Daten (Patrick-Auftrag).

Prüft End-to-End mit synthetischen Events über mehrere Tage, dass das Light-SIEM
und die Anomalie-Heuristik:
  (1) Events in der DB SPEICHERN und ABRUFEN,
  (2) sie korrekt im ZEITVERLAUF (Tages-Buckets) wiedergeben — mit einer
      SICHTBAREN Veränderung zwischen Tagen,
  (3) die Anomalie-Heuristik den Tageswechsel (Spike) als sichtbare Veränderung
      gegenüber der Baseline erkennt (vorher: ruhig, nachher: Alarm).

Isolierte In-Memory-DB (kein Zugriff auf echte Daten). Zeitanker = jetzt; der
jüngste „Spike"-Tag ist GESTERN (alle Events liegen in der Vergangenheit und im
30-Tage-Lookback der Heuristik).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.norisk_dashboard.application.anomaly_detector import AnomalyDetector
from tools.norisk_dashboard.application.light_siem_aggregator import LightSiemAggregator
from tools.norisk_dashboard.data.light_siem_repository import LightSiemRepository
from tools.norisk_dashboard.domain.anomaly_models import AnomalySeverity
from tools.norisk_dashboard.domain.light_siem_models import (
    EventSeverity,
    EventSource,
    LightSiemEvent,
)
from tools.norisk_dashboard.gui.light_siem_section import compute_daily_stacked_series


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


# --- Zeitanker: jüngster Tag = gestern (sicher in der Vergangenheit) -----------
_NOW = datetime.now(UTC)
_DAY = _NOW.replace(hour=12, minute=0, second=0, microsecond=0)
_SPIKE_DAY = _DAY - timedelta(days=1)  # gestern = jüngster Tag im Pool
_BASELINE_DAYS = [_DAY - timedelta(days=d) for d in range(2, 11)]  # 9 ruhige Tage


def _evt(
    summary: str,
    *,
    severity: EventSeverity,
    source: EventSource,
    timestamp: datetime,
) -> LightSiemEvent:
    return LightSiemEvent(
        id=None,
        timestamp=timestamp,
        source=source,
        event_type="synthetic",
        severity=severity,
        summary=summary,
    )


def _baseline_events() -> list[LightSiemEvent]:
    """9 ruhige Tage: je 2 INFO-Events (Tages-Score = 2)."""
    evs: list[LightSiemEvent] = []
    for i, day in enumerate(_BASELINE_DAYS):
        for j in range(2):
            evs.append(
                _evt(
                    f"baseline t{i}-{j}",
                    severity=EventSeverity.INFO,
                    source=EventSource.PATCH_MONITOR,
                    timestamp=day + timedelta(hours=j),
                )
            )
    return evs


def _spike_events() -> list[LightSiemEvent]:
    """Jüngster Tag: 1 CRITICAL + 3 ERROR (Tages-Score = 10 + 3*5 = 25)."""
    return [
        _evt("spike critical", severity=EventSeverity.CRITICAL,
             source=EventSource.SYSTEM_SCANNER, timestamp=_SPIKE_DAY + timedelta(hours=1)),
        _evt("spike error 1", severity=EventSeverity.ERROR,
             source=EventSource.PATCH_MONITOR, timestamp=_SPIKE_DAY + timedelta(hours=2)),
        _evt("spike error 2", severity=EventSeverity.ERROR,
             source=EventSource.PATCH_MONITOR, timestamp=_SPIKE_DAY + timedelta(hours=3)),
        _evt("spike error 3", severity=EventSeverity.ERROR,
             source=EventSource.CERT_MONITOR, timestamp=_SPIKE_DAY + timedelta(hours=4)),
    ]


def _fill(repo: LightSiemRepository, events: list[LightSiemEvent]) -> int:
    added = 0
    for e in events:
        if repo.add(e) is not None:
            added += 1
    return added


# ---------------------------------------------------------------------------
# (1) Speichern + Abrufen
# ---------------------------------------------------------------------------


class TestSpeichernAbrufen:
    def test_events_werden_gespeichert_und_abgerufen(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        events = _baseline_events() + _spike_events()
        added = _fill(repo, events)
        assert added == len(events)  # alle distinct -> alle gespeichert

        zurueck = repo.list_recent(lookback_days=30, limit=10_000)
        assert len(zurueck) == len(events)  # vollständig abgerufen
        # DESC nach timestamp
        ts = [e.timestamp for e in zurueck]
        assert ts == sorted(ts, reverse=True)

    def test_dedup_blockt_identische(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        e = _spike_events()[0]
        assert repo.add(e) is not None
        assert repo.add(e) is None  # identisch -> dedup

    def test_summary_aggregiert_korrekt(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        _fill(repo, _baseline_events() + _spike_events())
        s = repo.summary(lookback_days=30)
        assert s.total_events == len(_baseline_events()) + len(_spike_events())
        assert s.by_severity.get(EventSeverity.CRITICAL, 0) == 1
        assert s.by_severity.get(EventSeverity.ERROR, 0) == 3
        assert s.latest_timestamp is not None

    def test_dashboard_bundle_dreiteilig(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        _fill(repo, _baseline_events() + _spike_events())
        summary, table, chart = repo.load_dashboard_bundle(
            table_limit=100, chart_lookback_days=15, chart_limit=2000
        )
        assert summary.total_events > 0
        assert len(table) > 0
        assert len(chart) > 0


# ---------------------------------------------------------------------------
# (2) Zeitverlauf — sichtbare Veränderung zwischen Tagen
# ---------------------------------------------------------------------------


def _tagessumme(series: dict[str, list[float]], idx: int) -> float:
    return sum(reihe[idx] for reihe in series.values())


class TestZeitverlauf:
    def test_buckets_und_spike_am_letzten_tag(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        _fill(repo, _baseline_events() + _spike_events())
        _, _, chart = repo.load_dashboard_bundle(
            table_limit=100, chart_lookback_days=15, chart_limit=5000
        )
        # 10 Tages-Buckets endend am Spike-Tag -> Spike ist der letzte Bucket.
        ts, series = compute_daily_stacked_series(chart, end_date=_SPIKE_DAY, days=10)
        assert len(ts) == 10
        assert ts == sorted(ts)  # älteste zuerst
        # Sichtbare Veränderung: letzter Tag (Spike) >> ein Baseline-Tag.
        letzter = _tagessumme(series, 9)
        irgendein_baseline = _tagessumme(series, 2)
        assert letzter >= 4.0  # 1 CRITICAL + 3 ERROR
        assert letzter > irgendein_baseline
        assert series["CRITICAL"][9] >= 1.0
        assert series["ERROR"][9] >= 3.0

    def test_vorher_nachher_verlauf_unterscheidet_sich(self) -> None:
        repo = LightSiemRepository(db=_InMemoryDB())
        _fill(repo, _baseline_events() + _spike_events())
        _, _, chart = repo.load_dashboard_bundle(
            table_limit=100, chart_lookback_days=15, chart_limit=5000
        )
        # Fenster endend einen Tag VOR dem Spike vs. AM Spike-Tag.
        _, vorher = compute_daily_stacked_series(
            chart, end_date=_SPIKE_DAY - timedelta(days=1), days=7
        )
        _, nachher = compute_daily_stacked_series(
            chart, end_date=_SPIKE_DAY, days=7
        )
        # Der jeweils letzte Bucket unterscheidet sich sichtbar (Baseline vs Spike).
        assert _tagessumme(nachher, 6) > _tagessumme(vorher, 6)


# ---------------------------------------------------------------------------
# (3) Anomalie-Heuristik — vorher ruhig, nachher Alarm (sichtbare Veränderung)
# ---------------------------------------------------------------------------


class TestAnomalieVorherNachher:
    def _detector(self, events: list[LightSiemEvent]) -> AnomalyDetector:
        repo = LightSiemRepository(db=_InMemoryDB())
        _fill(repo, events)
        return AnomalyDetector(aggregator=LightSiemAggregator(repository=repo, adapters=[]))

    def test_baseline_ohne_spike_kein_alarm(self) -> None:
        report = self._detector(_baseline_events()).compute_report()
        assert report.total_events > 0
        assert report.has_enough_data  # >= 7 Baseline-Tage vorhanden
        assert not report.is_alarmed
        assert report.findings == []

    def test_mit_spike_alarm_am_jüngsten_tag(self) -> None:
        report = self._detector(_baseline_events() + _spike_events()).compute_report()
        assert report.has_enough_data
        assert report.baseline_day_count >= 7
        assert report.latest_score >= 25.0  # 10 + 3*5
        assert report.is_alarmed
        assert report.findings, "Spike nicht erkannt"
        top = report.findings[0]
        assert top.observed_at == _SPIKE_DAY.date()
        assert top.severity in (
            AnomalySeverity.MEDIUM,
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        )
        assert top.observed_score > top.baseline_median  # sichtbare Abweichung

    def test_sichtbare_veraenderung_im_aggregat_score(self) -> None:
        ruhig = self._detector(_baseline_events()).compute_report()
        laut = self._detector(_baseline_events() + _spike_events()).compute_report()
        # Der Dashboard-Aggregat-Score steigt sichtbar vom ruhigen zum lauten Pool.
        assert laut.aggregate_score() > ruhig.aggregate_score()


if __name__ == "__main__":  # pragma: no cover — manueller Report-Lauf
    pytest.main([__file__, "-v"])
