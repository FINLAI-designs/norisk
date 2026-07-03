"""test_dashboard_subject_selector — GUI-Test des Subjekt-Selektors, Step 5).

Abdeckung:
    * Mit verfügbaren Subjekten erscheint der Selektor (Allgemein + Subjekte).
    * Auswahl eines Subjekts ruft ``aggregate`` subjekt-bewusst auf
      (subject_id + Anzeige-Label).
    * Zurück auf "Allgemein" nutzt wieder den Default-Pfad (subject_id None).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from tools.norisk_dashboard.domain.models import (
    DashboardData,
    ScoreSnapshot,
    TimeRange,
)

pytestmark = pytest.mark.gui


def _empty_data() -> DashboardData:
    return DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="Allgemein"),
        generated=datetime(2026, 6, 4, 12, 0, 0),
    )


class _FakeAgg:
    """Aggregator-Fake mit Subjekt-Liste + aufzeichnendem aggregate."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def subjects(self) -> list[tuple[str, str]]:
        return [("s1", "Acme GmbH")]

    def aggregate(self, time_range, target_name="Allgemein", *, subject_id=None):  # noqa: ANN001, ANN202
        self.calls.append((target_name, subject_id))
        return _empty_data()


def _make_widget(qtbot, aggregator):
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    w = NoRiskDashboardWidget(aggregator=aggregator, export_service=MagicMock())
    qtbot.addWidget(w)
    return w


@pytest.mark.usefixtures("app")
class TestSubjectSelector:
    def test_selector_present_with_subjects(self, qtbot) -> None:
        w = _make_widget(qtbot, _FakeAgg())
        assert w._subject_selector is not None
        assert w._subject_selector.count() == 2  # Allgemein + Acme GmbH
        assert w._subject_selector.itemText(0) == "Allgemein"
        assert w._subject_selector.itemText(1) == "Acme GmbH"

    def test_selecting_subject_triggers_subject_aware_aggregate(self, qtbot) -> None:
        agg = _FakeAgg()
        w = _make_widget(qtbot, agg)
        agg.calls.clear()
        w._subject_selector.setCurrentIndex(1)  # → Acme GmbH, löst refresh aus
        assert agg.calls[-1] == ("Acme GmbH", "s1")

    def test_back_to_allgemein_uses_default_path(self, qtbot) -> None:
        agg = _FakeAgg()
        w = _make_widget(qtbot, agg)
        w._subject_selector.setCurrentIndex(1)
        agg.calls.clear()
        w._subject_selector.setCurrentIndex(0)  # → Allgemein
        assert agg.calls[-1] == ("Allgemein", None)

    def test_no_selector_when_no_subjects(self, qtbot) -> None:
        class _NoSubjects(_FakeAgg):
            def subjects(self) -> list[tuple[str, str]]:
                return []

        w = _make_widget(qtbot, _NoSubjects())
        assert w._subject_selector is None


def _real_hardening(overall: float = 90.0):
    from tools.security_scoring.domain.hardening_categories import HardeningCategory
    from tools.security_scoring.domain.hardening_score import (
        CategoryScore,
        HardeningScoreResult,
    )
    from tools.security_scoring.domain.hardening_stages import score_to_stage

    return HardeningScoreResult(
        overall_score=overall,
        stage=score_to_stage(overall),
        category_scores=(
            CategoryScore(
                category=HardeningCategory.CVE_PATCH,
                score=overall,
                weight=1.0,
                components_count=1,
            ),
        ),
        missing_categories=(),
        hard_cap_events=(),
        raw_weighted_score=overall,
    )


class _AggWithHardening(_FakeAgg):
    def aggregate(self, time_range, target_name="Allgemein", *, subject_id=None):  # noqa: ANN001, ANN202
        self.calls.append((target_name, subject_id))
        return DashboardData(
            time_range=TimeRange.WEEK,
            score=ScoreSnapshot(target=target_name, current=42.0),
            generated=datetime(2026, 6, 4, 12, 0, 0),
            hardening_score=_real_hardening(),
        )


@pytest.mark.usefixtures("app")
class TestCockpitBandAlwaysSelf:
    """ Phase 4): das Einstiegs-Band zeigt die EIGENE
    Sicherheitslage IMMER. Die „Messung (Hardening)"-Kachel bleibt auch bei
    gewähltem Kunden-Subjekt befüllt — anders als der frühere self-only-Hero,
    der sich bei Subjektwahl ausblendete (D3: Band ist self-scoped, die
    Kunden-Audit-Karte folgt dem Selektor separat)."""

    def test_band_shows_hardening_for_allgemein(self, qtbot) -> None:
        w = _make_widget(qtbot, _AggWithHardening())
        calls: list[tuple] = []
        w._cockpit_band.set_data = lambda *a: calls.append(a)  # Spy
        w.refresh()  # subject_id None → Default-Pfad
        # set_data(self_audit, hardening) — 2. Positionsarg ist der Hardening-Score.
        assert calls[-1][1] is not None

    def test_band_keeps_hardening_when_subject_selected(self, qtbot) -> None:
        w = _make_widget(qtbot, _AggWithHardening())
        calls: list[tuple] = []
        w._cockpit_band.set_data = lambda *a: calls.append(a)  # Spy
        w._subject_selector.setCurrentIndex(1)  # Acme → refresh → _apply
        assert calls[-1][1] is not None  # immer SELF — Band bleibt befüllt
