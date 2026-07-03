"""GUI-Test E1: Abweichungs-Hinweis im Einstiegs-Cockpit (offscreen)."""

from __future__ import annotations

from tools.norisk_dashboard.domain.models import CustomerAuditSummary
from tools.norisk_dashboard.gui.security_cockpit_band import SecurityCockpitBand
from tools.security_scoring.domain.hardening_score import HardeningScoreResult
from tools.security_scoring.domain.hardening_stages import score_to_stage


def _audit(score: float) -> CustomerAuditSummary:
    return CustomerAuditSummary(
        subject_id="self",
        firmenname="Eigene Org",
        overall_score=score,
        risk_level="Mittel",
        created_at=None,
        audit_id="aud-1",
        audit_count=1,
    )


def _hard(score: float) -> HardeningScoreResult:
    return HardeningScoreResult(
        overall_score=score,
        stage=score_to_stage(score),
        category_scores=(),
        missing_categories=(),
    )


def test_drastische_abweichung_zeigt_hinweis(app) -> None:  # noqa: ANN001
    band = SecurityCockpitBand()
    band.set_data(_audit(85), _hard(40))
    assert band._lbl_abweichung.isHidden() is False
    assert "85" in band._lbl_abweichung.text()
    assert "40" in band._lbl_abweichung.text()


def test_geringe_abweichung_kein_hinweis(app) -> None:  # noqa: ANN001
    band = SecurityCockpitBand()
    band.set_data(_audit(78), _hard(72))
    assert band._lbl_abweichung.isHidden() is True


def test_fehlende_messung_kein_hinweis(app) -> None:  # noqa: ANN001
    band = SecurityCockpitBand()
    band.set_data(_audit(80), None)
    assert band._lbl_abweichung.isHidden() is True
