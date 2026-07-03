"""GUI-Smoke: Human-Risk-Gauge + Awareness-Uebersicht instanziieren.

Diese Tests instanziieren die Widgets WIRKLICH (offscreen) — genau die
Luecke, die den t.GRADE_D-Crash im Security-Scoring durchrutschen liess:
reine Helfer-Tests fangen Theme-Attribut-/_build_ui-Fehler nicht.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.domain.human_risk_score import RiskBand
from tools.awareness_tracker.domain.models import TrainingType
from tools.awareness_tracker.gui.awareness_widget import AwarenessWidget
from tools.awareness_tracker.gui.human_risk_gauge import HumanRiskGauge

pytestmark = pytest.mark.gui


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
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


def _service() -> AwarenessService:
    return AwarenessService(repository=AwarenessRepository(db=_InMemoryDB()))


class TestHumanRiskGauge:
    def test_instanziiert_und_leerzustand(self, app) -> None:
        gauge = HumanRiskGauge()
        gauge.set_score(None)
        assert gauge.current_score is None
        assert gauge.current_band is None

    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (95.0, RiskBand.SECURE),
            (70.0, RiskBand.MODERATE),
            (50.0, RiskBand.AT_RISK),
            (10.0, RiskBand.CRITICAL),
        ],
    )
    def test_set_score_leitet_band_ab(self, app, score: float, band: RiskBand) -> None:
        gauge = HumanRiskGauge()
        gauge.set_score(score)
        assert gauge.current_score == score
        assert gauge.current_band is band

    def test_explizites_band_wird_uebernommen(self, app) -> None:
        gauge = HumanRiskGauge()
        gauge.set_score(50.0, RiskBand.SECURE)
        assert gauge.current_band is RiskBand.SECURE


class TestAwarenessWidgetOverview:
    def test_widget_baut_ohne_crash(self, app) -> None:
        # _build_ui -> _build_overview -> _reload_human_risk muss komplett
        # durchlaufen (faengt Theme-/Layout-Fehler beim Oeffnen ab).
        widget = AwarenessWidget(service=_service())
        assert widget._risk_gauge is not None
        # Leere Datenbasis -> Gauge zeigt "keine Daten", Hinweis sichtbar.
        # isHidden statt isVisible: das Widget wird im Test nie.show'n,
        # daher prueft isHidden das explizite Sichtbar-Flag (nicht die
        # Anzeige-Hierarchie).
        assert widget._risk_gauge.current_score is None
        assert not widget._lbl_hint.isHidden()

    def test_overview_aktualisiert_nach_daten(self, app) -> None:
        service = _service()
        anna = service.add_employee(full_name="Anna", is_active=True)
        now = datetime.now(UTC)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO",
            completed_at=now - timedelta(days=10),
            valid_until=now + timedelta(days=365),
        )
        widget = AwarenessWidget(service=service)
        # 1/1 aktive MA abgedeckt -> Schulungs-Abdeckung 100 %, ABER ohne
        # Phishing-Simulation ist die Lage UNGETESTET (nicht "Stark/SECURE") —
        # 1 Mitarbeiter + 1 Schulung != 100 % Sicherheit (Patrick-Live-Test).
        assert widget._risk_gauge.current_score == pytest.approx(100.0)
        assert widget._risk_gauge.current_band is RiskBand.UNGETESTET

    def test_custom_label_zeile_nur_bei_custom_typ(self, app) -> None:
        # D8 (Patrick-Live-Test): die Custom-Label-Zeile war immer sichtbar,
        # nur ausgegraut -> wirkte wie ein kaputtes Feld. Jetzt erscheint sie
        # NUR bei Typ "Custom" (dort sichtbar + ausfuellbar).
        from tools.awareness_tracker.gui.training_form_dialog import (
            TrainingFormDialog,
        )

        service = _service()
        anna = service.add_employee(full_name="Anna", is_active=True)
        dlg = TrainingFormDialog(employees=[anna])
        combo = dlg._type_combo
        custom_idx = next(
            i
            for i in range(combo.count())
            if combo.itemData(i) is TrainingType.CUSTOM
        )
        other_idx = next(
            i
            for i in range(combo.count())
            if combo.itemData(i) is not TrainingType.CUSTOM
        )

        combo.setCurrentIndex(other_idx)
        assert dlg._custom_label_input.isHidden()  # nicht-Custom -> versteckt

        combo.setCurrentIndex(custom_idx)
        assert not dlg._custom_label_input.isHidden()  # Custom -> sichtbar
        assert dlg._custom_label_input.isEnabled()  # und ausfuellbar

    def test_tab_wechsel_aktualisiert_score(self, app) -> None:
        service = _service()
        widget = AwarenessWidget(service=service)
        assert widget._risk_gauge.current_score is None  # leer beim Bau

        # Daten NACH dem Bau erfassen -> erst der Tab-Wechsel triggert Refresh.
        anna = service.add_employee(full_name="Anna", is_active=True)
        now = datetime.now(UTC)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO",
            completed_at=now - timedelta(days=10),
            valid_until=now + timedelta(days=365),
        )
        widget._tabs.setCurrentIndex(1)  # currentChanged -> _reload_human_risk
        assert widget._risk_gauge.current_score == pytest.approx(100.0)
