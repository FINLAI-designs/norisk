"""Tests fuer den Human-Risk-Score (Domain, pur/headless) — IA-Welle 2."""

from __future__ import annotations

import pytest

from tools.awareness_tracker.domain.human_risk_score import (
    RiskBand,
    band_for_score,
    compute_human_risk_score,
)


class TestBandForScore:
    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (100.0, RiskBand.SECURE),
            (85.0, RiskBand.SECURE),
            (84.9, RiskBand.MODERATE),
            (65.0, RiskBand.MODERATE),
            (64.9, RiskBand.AT_RISK),
            (40.0, RiskBand.AT_RISK),
            (39.9, RiskBand.CRITICAL),
            (0.0, RiskBand.CRITICAL),
        ],
    )
    def test_schwellen(self, score: float, band: RiskBand) -> None:
        assert band_for_score(score) is band

    def test_labels_deutsch(self) -> None:
        assert RiskBand.SECURE.label == "Stark"
        assert RiskBand.CRITICAL.label == "Kritisch"


class TestComputeWithPhishing:
    def test_gewichtete_formel(self) -> None:
        # 0.40*50 + 0.35*(100-10) + 0.25*80 = 20 + 31.5 + 20 = 71.5
        risk = compute_human_risk_score(
            avg_report_rate=50.0,
            avg_click_rate=10.0,
            campaign_count=3,
            training_completion=80.0,
            active_employee_count=10,
            trend_delta=-3.0,
        )
        assert risk.score == pytest.approx(71.5)
        assert risk.band is RiskBand.MODERATE
        assert risk.has_phishing_data is True
        assert risk.report_component == pytest.approx(20.0)
        assert risk.click_avoidance_component == pytest.approx(31.5)
        assert risk.training_component == pytest.approx(20.0)

    def test_bestwerte_ergeben_100(self) -> None:
        risk = compute_human_risk_score(
            avg_report_rate=100.0,
            avg_click_rate=0.0,
            campaign_count=2,
            training_completion=100.0,
            active_employee_count=5,
        )
        assert risk.score == pytest.approx(100.0)
        assert risk.band is RiskBand.SECURE

    def test_clamping_ueber_100(self) -> None:
        # Defensive: Raten > 100 werden auf 100 geklemmt, Score bleibt <= 100.
        risk = compute_human_risk_score(
            avg_report_rate=150.0,
            avg_click_rate=-20.0,
            campaign_count=1,
            training_completion=130.0,
            active_employee_count=3,
        )
        assert 0.0 <= risk.score <= 100.0
        assert risk.report_rate == 100.0
        assert risk.click_rate == 0.0
        assert risk.training_completion == 100.0


class TestComputeWithoutPhishing:
    def test_score_faellt_auf_schulung_zurueck(self) -> None:
        risk = compute_human_risk_score(
            avg_report_rate=None,
            avg_click_rate=None,
            campaign_count=0,
            training_completion=72.0,
            active_employee_count=4,
        )
        assert risk.score == pytest.approx(72.0)
        assert risk.has_phishing_data is False
        # ADR-Awareness: ohne Phishing-Daten ist die Lage UNGETESTET, nicht
        # "Solide/Stark" — Schulungsquote allein ist keine Sicherheits-Ampel.
        assert risk.band is RiskBand.UNGETESTET
        assert risk.report_rate is None
        assert risk.click_rate is None
        assert risk.report_component is None
        assert risk.has_any_data is True

    def test_komplett_leer(self) -> None:
        risk = compute_human_risk_score(
            avg_report_rate=None,
            avg_click_rate=None,
            campaign_count=0,
            training_completion=0.0,
            active_employee_count=0,
        )
        assert risk.score == 0.0
        # Komplett leer = ebenfalls ungetestet (kein Phishing gemessen); die
        # GUI zeigt hier ohnehin den "noch keine Daten"-Leerzustand.
        assert risk.band is RiskBand.UNGETESTET
        assert risk.has_any_data is False


class TestTrendLabel:
    @pytest.mark.parametrize(
        ("delta", "needle"),
        [
            (-3.0, "besser"),
            (3.0, "schlechter"),
            (0.0, "stabil"),
        ],
    )
    def test_trend_label(self, delta: float, needle: str) -> None:
        risk = compute_human_risk_score(
            avg_report_rate=10.0,
            avg_click_rate=10.0,
            campaign_count=2,
            training_completion=10.0,
            active_employee_count=2,
            trend_delta=delta,
        )
        assert needle in risk.trend_label

    def test_trend_none(self) -> None:
        risk = compute_human_risk_score(
            avg_report_rate=10.0,
            avg_click_rate=10.0,
            campaign_count=1,
            training_completion=10.0,
            active_employee_count=2,
            trend_delta=None,
        )
        assert risk.trend_label == "—"
