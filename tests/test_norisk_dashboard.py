"""
test_norisk_dashboard — Tests für das NoRisk-Gesamt-Dashboard (Phase 1).

Abdeckung:
  - TimeRange.days und.label
  - ChangeType.badge
  - DashboardAggregator ohne Quellen liefert leeren Datenstand
  - DashboardAggregator liest Score + CVEs + Scans
  - _compute_changes filtert korrekt nach Zeitraum
  - HeatmapWidget akzeptiert leere und befüllte Daten ohne Crash

Alle Tests verwenden Mock-Daten — kein Netzwerk, kein I/O.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.norisk_dashboard.application.dashboard_aggregator import (
    DashboardAggregator,
)
from tools.norisk_dashboard.domain.models import (
    ChangeType,
    ScanStatus,
    TimeRange,
)

# ---------------------------------------------------------------------------
# Domain-Modelle
# ---------------------------------------------------------------------------


def test_timerange_days_und_label() -> None:
    assert TimeRange.WEEK.days == 7
    assert TimeRange.MONTH.days == 30
    assert TimeRange.QUARTER.days == 90
    assert TimeRange.WEEK.label == "Woche"
    assert TimeRange.MONTH.label == "Monat"
    assert TimeRange.QUARTER.label == "Quartal"


def test_changetype_badge_labels() -> None:
    assert ChangeType.NEW.badge == "NEU"
    assert ChangeType.CHANGED.badge == "GEÄNDERT"
    assert ChangeType.DELETED.badge == "GELÖSCHT"


# ---------------------------------------------------------------------------
# Aggregator ohne Quellen
# ---------------------------------------------------------------------------


def test_aggregator_ohne_quellen_liefert_leeren_stand(tmp_path: Path) -> None:
    agg = DashboardAggregator(briefing_path=tmp_path / "nope.json")
    data = agg.aggregate(TimeRange.WEEK)
    assert data.time_range == TimeRange.WEEK
    assert data.changes == []
    assert data.cves == []
    assert data.scans == []
    assert data.score.current is None
    assert data.score.previous is None
    # Phase 4.5: ohne Provider bleibt hardening_score None
    assert data.hardening_score is None


# ---------------------------------------------------------------------------
# Phase 4.5 — Hardening-Score-Provider-Integration
# ---------------------------------------------------------------------------


def test_aggregator_hardening_score_provider_liefert_result(tmp_path: Path) -> None:
    """Wenn der Provider eine HardeningScoreResult liefert, landet
    sie in DashboardData.hardening_score."""
    from tools.security_scoring.domain.hardening_score import (
        HardeningScoreResult,
    )
    from tools.security_scoring.domain.hardening_stages import score_to_stage

    fake = HardeningScoreResult(
        overall_score=72.0,
        stage=score_to_stage(72.0),
        category_scores=(),
        missing_categories=(),
        hard_cap_events=(),
        raw_weighted_score=85.0,
    )

    agg = DashboardAggregator(
        briefing_path=tmp_path / "nope.json",
        hardening_score_provider=lambda: fake,
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.hardening_score is fake


def test_aggregator_hardening_score_provider_exception_tolerant(
    tmp_path: Path,
) -> None:
    """Provider-Exceptions duerfen das Dashboard NICHT crashen — Feld
    bleibt None, andere Daten kommen trotzdem an."""

    def broken_provider():
        raise RuntimeError("provider-bug")

    agg = DashboardAggregator(
        briefing_path=tmp_path / "nope.json",
        hardening_score_provider=broken_provider,
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.hardening_score is None
    assert data.time_range == TimeRange.WEEK


# Provider routet ueber die application-Schicht (ScoringService), nicht direkt
# auf das data-Repository — daher hier diese Methode mocken.
# P0-A: der Provider liest jetzt nur den GEMESSENEN (SELF-)Score, damit
# manuell fuer Kunden erfasste Eintraege die Eigen-System-Kachel nicht stellen.
_SERVICE_METHOD = (
    "tools.security_scoring.application.scoring_service."
    "ScoringService.lade_letztes_gemessenes_hardening_result"
)


def test_build_hardening_score_provider_no_persisted_returns_none() -> None:
    """: ohne persistierten Score liefert der Provider None (Empty-State)."""
    from unittest.mock import patch

    from tools.norisk_dashboard.tool import _build_hardening_score_provider

    # Service liefert None (leere hardening_scores-Tabelle / fail-soft).
    with patch(_SERVICE_METHOD, return_value=None):
        assert _build_hardening_score_provider()() is None


def test_build_hardening_score_provider_empty_categories_returns_none() -> None:
    """: persistierter Score ohne aktive Kategorien → None (Empty-State)."""
    from unittest.mock import patch

    from tools.norisk_dashboard.tool import _build_hardening_score_provider
    from tools.security_scoring.domain.hardening_categories import HardeningCategory
    from tools.security_scoring.domain.hardening_score import HardeningScoreResult
    from tools.security_scoring.domain.hardening_stages import score_to_stage

    leeres = HardeningScoreResult(
        overall_score=0.0,
        stage=score_to_stage(0),
        category_scores=(),
        missing_categories=tuple(HardeningCategory),
    )
    with patch(_SERVICE_METHOD, return_value=leeres):
        assert _build_hardening_score_provider()() is None


def test_build_hardening_score_provider_returns_persisted_result() -> None:
    """: mit persistiertem Score (aktive Kategorien) liefert der Provider ihn."""
    from unittest.mock import patch

    from tools.norisk_dashboard.tool import _build_hardening_score_provider
    from tools.security_scoring.domain.hardening_score import compute_hardening_score
    from tools.security_scoring.domain.models import ScoreComponent

    voll = compute_hardening_score(
        [
            ScoreComponent(
                name="X", score=80.0, weight=0.5, source_tool="cve_exposure"
            )
        ]
    )
    with patch(_SERVICE_METHOD, return_value=voll):
        result = _build_hardening_score_provider()()

    assert result is voll
    assert result.overall_score == 80.0


# ---------------------------------------------------------------------------
# Aggregator mit Score-Loader
# ---------------------------------------------------------------------------


def test_aggregator_score_mit_trend(tmp_path: Path) -> None:
    now = datetime.now()
    history = [
        SimpleNamespace(overall_score=82.0, timestamp=now.isoformat()),
        SimpleNamespace(
            overall_score=80.0, timestamp=(now - timedelta(days=7)).isoformat()
        ),
    ]
    agg = DashboardAggregator(
        score_loader=lambda _t: history,
        briefing_path=tmp_path / "nope.json",
    )
    data = agg.aggregate(TimeRange.WEEK, target_name="Kunde A")
    assert data.score.current == pytest.approx(82.0)
    assert data.score.previous == pytest.approx(80.0)
    assert data.score.delta == pytest.approx(2.0)
    assert data.score.target == "Kunde A"


def test_aggregator_score_ohne_vorgaenger(tmp_path: Path) -> None:
    history = [SimpleNamespace(overall_score=60.0, timestamp="")]
    agg = DashboardAggregator(
        score_loader=lambda _t: history,
        briefing_path=tmp_path / "nope.json",
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.score.current == pytest.approx(60.0)
    assert data.score.previous is None
    assert data.score.delta is None


# ---------------------------------------------------------------------------
# Aggregator mit Briefing-Cache
# ---------------------------------------------------------------------------


def test_aggregator_liest_cves_aus_briefing(tmp_path: Path) -> None:
    briefing = tmp_path / "cyber_briefing.json"
    today = datetime.now()
    briefing.write_text(
        json.dumps(
            {
                "techstack_eintraege": [
                    {
                        "produkt": "OpenSSL",
                        "cve_id": "CVE-2026-1111",
                        "beschreibung": "Pufferüberlauf in TLS-Handshake.",
                        "veroeffentlicht": today.isoformat(),
                    },
                    {
                        "produkt": "",
                        "cve_id": "",  # wird gefiltert (kein CVE-ID)
                        "beschreibung": "",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    agg = DashboardAggregator(briefing_path=briefing)
    data = agg.aggregate(TimeRange.WEEK)
    assert len(data.cves) == 1
    cve = data.cves[0]
    assert cve.cve_id == "CVE-2026-1111"
    assert cve.product == "OpenSSL"


def test_aggregator_ignoriert_kaputte_briefing_datei(tmp_path: Path) -> None:
    briefing = tmp_path / "cyber_briefing.json"
    briefing.write_text("KEIN JSON", encoding="utf-8")
    agg = DashboardAggregator(briefing_path=briefing)
    data = agg.aggregate(TimeRange.WEEK)
    assert data.cves == []


# ---------------------------------------------------------------------------
# Scan-Status
# ---------------------------------------------------------------------------


def test_aggregator_scan_status_ok_und_missing(tmp_path: Path) -> None:
    today = datetime.now()
    loaders = [
        ("sys", "System", lambda: today),
        ("net", "Netz", lambda: None),
        ("err", "Fehler", lambda: (_ for _ in ()).throw(RuntimeError("boom"))),
    ]
    agg = DashboardAggregator(
        scan_loaders=loaders,
        briefing_path=tmp_path / "nope.json",
    )
    data = agg.aggregate(TimeRange.WEEK)
    status_map = {s.tool_key: s.status for s in data.scans}
    assert status_map["sys"] == ScanStatus.OK
    assert status_map["net"] == ScanStatus.MISSING
    assert status_map["err"] == ScanStatus.MISSING


# ---------------------------------------------------------------------------
# Änderungen seit Zeitraum
# ---------------------------------------------------------------------------


def test_aggregator_changes_enthaelt_aktuelle_cves(tmp_path: Path) -> None:
    briefing = tmp_path / "cyber_briefing.json"
    today = datetime.now()
    briefing.write_text(
        json.dumps(
            {
                "techstack_eintraege": [
                    {
                        "produkt": "Django",
                        "cve_id": "CVE-2026-2222",
                        "beschreibung": "SQL-Injection.",
                        "veroeffentlicht": today.isoformat(),
                    },
                    {
                        "produkt": "Alt",
                        "cve_id": "CVE-2020-0001",
                        "beschreibung": "Alte CVE.",
                        "veroeffentlicht": (today - timedelta(days=400)).isoformat(),
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    agg = DashboardAggregator(briefing_path=briefing)
    data = agg.aggregate(TimeRange.WEEK)
    titles = [c.title for c in data.changes]
    assert "CVE-2026-2222" in titles
    assert "CVE-2020-0001" not in titles


def test_aggregator_changes_enthaelt_score_delta(tmp_path: Path) -> None:
    now = datetime.now()
    history = [
        SimpleNamespace(overall_score=85.0, timestamp=now.isoformat()),
        SimpleNamespace(
            overall_score=75.0, timestamp=(now - timedelta(days=2)).isoformat()
        ),
    ]
    agg = DashboardAggregator(
        score_loader=lambda _t: history,
        briefing_path=tmp_path / "nope.json",
    )
    data = agg.aggregate(TimeRange.WEEK)
    score_changes = [c for c in data.changes if c.source == "score"]
    assert len(score_changes) == 1
    assert "Δ" in score_changes[0].detail


# ---------------------------------------------------------------------------
# Heatmap-Widget (nur Nicht-Crash-Smoke)
# ---------------------------------------------------------------------------


def test_tiles_from_components_mappt_alle_vier_metriken() -> None:
    """: ScoreComponent.name aus org_security_service muss matchen.

    Vorher hatte das MFA-Tile UI-Label `"Multi-Factor Auth"` und matchte
    gegen denselben Wert, der `OrgSecurityService` liefert aber
    `"Multi-Factor Authentication"` aus `METRIK_ANZEIGENAME`. Folge:
    score=None, MFA-Tile zeigte dauerhaft "-". Test fixiert das Mapping
    explizit auf die Domain-Konstanten.
    """
    from tools.norisk_dashboard.application.dashboard_aggregator import (  # noqa: PLC0415
        tiles_from_components,
    )
    from tools.security_scoring.domain.models import ScoreComponent  # noqa: PLC0415
    from tools.security_scoring.domain.org_security import (  # noqa: PLC0415
        METRIK_ANZEIGENAME,
        METRIK_DSGVO,
        METRIK_MFA,
        METRIK_PASSWORT_MANAGER,
        METRIK_PHISHING,
    )

    # Komponente pro Metrik mit unterschiedlichem Score (so erkennen wir, ob
    # die richtige Komponente dem richtigen Tile zugeordnet wurde).
    components = [
        ScoreComponent(
            name=METRIK_ANZEIGENAME[METRIK_DSGVO],
            score=70.0,
            weight=0.25,
            findings_critical=0,
            findings_high=1,
            findings_medium=0,
        ),
        ScoreComponent(
            name=METRIK_ANZEIGENAME[METRIK_PHISHING],
            score=80.0,
            weight=0.25,
            findings_critical=0,
            findings_high=2,
            findings_medium=0,
        ),
        ScoreComponent(
            name=METRIK_ANZEIGENAME[METRIK_MFA],
            score=90.0,
            weight=0.25,
            findings_critical=0,
            findings_high=3,
            findings_medium=0,
        ),
        ScoreComponent(
            name=METRIK_ANZEIGENAME[METRIK_PASSWORT_MANAGER],
            score=60.0,
            weight=0.25,
            findings_critical=0,
            findings_high=4,
            findings_medium=0,
        ),
    ]

    tiles = tiles_from_components(components)
    by_key = {t.key: t for t in tiles}

    # Alle vier Tiles haben einen Score (kein None mehr).
    assert by_key["dsgvo"].score == 70.0
    assert by_key["phishing"].score == 80.0
    assert by_key["mfa"].score == 90.0  # Regression
    assert by_key["passwort_manager"].score == 60.0

    # UI-Labels bleiben kompakt.
    assert by_key["mfa"].label == "Multi-Factor Auth"

    # Findings durchgereicht.
    assert by_key["mfa"].findings_open == 3


@pytest.mark.gui
def test_heatmap_rendert_leer_und_mit_daten(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.domain.models import ScanEntry
    from tools.norisk_dashboard.gui.heatmap_widget import HeatmapWidget

    w = HeatmapWidget()
    qtbot.addWidget(w)
    w.update_data([], days=7)
    w.resize(600, 200)
    w.show()

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    entries = [
        ScanEntry("sys", "System-Scanner", today, ScanStatus.OK),
        ScanEntry(
            "net", "Netzwerk-Scanner", today - timedelta(days=1), ScanStatus.WARN
        ),
    ]
    w.update_data(entries, days=7)
    assert w.minimumHeight() > 0
