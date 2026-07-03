"""test_security_cockpit_band — Einstiegs-Cockpit-Band Phase 4).

Abdeckung:
    * ``set_data`` rendert beide Kacheln getrennt (Audit + Hardening),
      kein Misch-Score.
    * Empty-State je Kachel (``None`` → „—" + Start-CTA).
    * Score-Werte: Audit (gefärbt nach Risikostufe) + Hardening (Stage-Subline).
    * Beide Herkunfts-Badges („selbst deklariert" / „gemessen") sind sichtbar —
      die-Dimensionstrennung (self_declared vs. measured).
    * CTAs emittieren ``open_audit`` bzw. ``open_scoring`` (Navigation).
    * Subline rendert als PlainText (Markup-Härtung, Lehre/).

Author: Patrick Riederich
Version: 1.0 Phase 4)
"""

from __future__ import annotations

from datetime import datetime

import pytest
from PySide6.QtCore import Qt

from tools.norisk_dashboard.domain.models import CustomerAuditSummary

pytestmark = pytest.mark.gui


def _audit(score: float = 72.0, risk: str = "Mittel") -> CustomerAuditSummary:
    return CustomerAuditSummary(
        subject_id="self",
        firmenname="Mein System",
        overall_score=score,
        risk_level=risk,
        created_at=datetime(2026, 6, 27),
        audit_id="a1",
        audit_count=1,
    )


def _hardening(overall: float = 90.0):
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


@pytest.mark.usefixtures("app")
class TestSecurityCockpitBand:
    def _band(self, qtbot):
        from tools.norisk_dashboard.gui.security_cockpit_band import (
            SecurityCockpitBand,
        )

        band = SecurityCockpitBand()
        qtbot.addWidget(band)
        return band

    def test_empty_state_both_tiles(self, qtbot):
        band = self._band(qtbot)
        band.set_data(None, None)
        assert band._audit_tile._score.text() == "—"
        assert band._hardening_tile._score.text() == "—"
        assert "Audit starten" in band._audit_tile._cta.text()
        assert "Jetzt messen" in band._hardening_tile._cta.text()
        # Kein „— / 100": die Einheit ist im Empty-State ausgeblendet.
        assert band._audit_tile._unit.isHidden()
        assert band._hardening_tile._unit.isHidden()

    def test_unit_shown_again_after_value(self, qtbot):
        # Empty → Value: „/ 100" muss wieder erscheinen (kein Sticky-Hide).
        band = self._band(qtbot)
        band.set_data(None, None)
        band.set_data(_audit(score=72.0), None)
        assert not band._audit_tile._unit.isHidden()

    def test_audit_value_rendered(self, qtbot):
        band = self._band(qtbot)
        band.set_data(_audit(score=72.0, risk="Mittel"), None)
        assert band._audit_tile._score.text() == "72"
        assert "Mittel" in band._audit_tile._subtitle.text()
        assert "Zum Audit" in band._audit_tile._cta.text()
        # Hardening bleibt im Empty-State — kein Misch-Score.
        assert band._hardening_tile._score.text() == "—"

    def test_hardening_value_rendered(self, qtbot):
        band = self._band(qtbot)
        band.set_data(None, _hardening(overall=90.0))
        assert band._hardening_tile._score.text() == "90"
        assert "Secure" in band._hardening_tile._subtitle.text()
        assert "Zum Scoring" in band._hardening_tile._cta.text()
        # Audit bleibt im Empty-State.
        assert band._audit_tile._score.text() == "—"

    def test_both_dimensions_coexist(self, qtbot):
        band = self._band(qtbot)
        band.set_data(_audit(score=72.0), _hardening(overall=55.0))
        assert band._audit_tile._score.text() == "72"
        assert band._hardening_tile._score.text() == "55"
        assert "At Risk" in band._hardening_tile._subtitle.text()

    def test_herkunft_badges_visible(self, qtbot):
        """: jede Kachel weist ihre Dimension (Herkunft) aus."""
        band = self._band(qtbot)
        assert band._audit_tile._herkunft.text() == "selbst deklariert"
        assert band._hardening_tile._herkunft.text() == "gemessen"

    def test_subtitle_is_plaintext(self, qtbot):
        band = self._band(qtbot)
        band.set_data(_audit(), None)
        assert (
            band._audit_tile._subtitle.textFormat() == Qt.TextFormat.PlainText
        )

    def test_open_audit_signal_on_cta(self, qtbot):
        band = self._band(qtbot)
        band.set_data(_audit(), _hardening())
        with qtbot.waitSignal(band.open_audit, timeout=500):
            band._audit_tile._cta.click()

    def test_open_scoring_signal_on_cta(self, qtbot):
        band = self._band(qtbot)
        band.set_data(_audit(), _hardening())
        with qtbot.waitSignal(band.open_scoring, timeout=500):
            band._hardening_tile._cta.click()


def test_risk_color_mapping_covers_all_levels():
    """Drift-Wächter (Review-Nit): jede von ``score_to_risk_level`` erzeugte
    Stufe muss im Band-Farb-Mapping liegen.

    Sonst färbt die Audit-Kachel eine kritische Stufe still neutral
    (Risiko-Unterschätzung). Fängt eine Umbenennung der Stufen-Strings in
    ``customer_audit/domain`` im CI ab — analog ``test_customer_audit_card``.
    """
    from tools.customer_audit.domain.scoring_service import score_to_risk_level
    from tools.norisk_dashboard.gui.security_cockpit_band import _RISK_FARBE

    for score in range(0, 101, 5):
        level = score_to_risk_level(float(score)).casefold()
        assert level in _RISK_FARBE, f"Risikostufe '{level}' (Score {score}) ohne Farbe"
