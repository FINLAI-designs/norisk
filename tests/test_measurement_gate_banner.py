"""Tests fuer die reine Banner-Logik Phase 4 / D4).

Nur die testbaren Modul-Funktionen (Sichtbarkeit/Text) — keine Widget-Instanz,
daher keine QApplication noetig.
"""

from __future__ import annotations

from tools.security_scoring.gui.widgets.measurement_gate_banner import (
    GateBannerState,
    gate_banner_detail,
    gate_banner_title,
    gate_banner_visible,
    gate_state_detail,
    gate_state_title,
)
from tools.system_scanner.domain.entities import MeasurementDisposition


def _disp(*, open_remeasurable=0, opted_out=0):
    return MeasurementDisposition(
        open_remeasurable=open_remeasurable,
        blocked=0,
        opted_out=opted_out,
        not_applicable=0,
        measured=5,
    )


class TestGateBannerLogic:
    def test_hidden_when_none(self):
        assert gate_banner_visible(None) is False

    def test_hidden_when_no_open(self):
        assert gate_banner_visible(_disp(open_remeasurable=0)) is False

    def test_visible_when_open(self):
        assert gate_banner_visible(_disp(open_remeasurable=3)) is True

    def test_title_plural(self):
        assert "3 Härtungs-Checks noch" in gate_banner_title(
            _disp(open_remeasurable=3)
        )

    def test_title_singular(self):
        assert "1 Härtungs-Check noch" in gate_banner_title(
            _disp(open_remeasurable=1)
        )

    def test_detail_mentions_opted_out(self):
        d = gate_banner_detail(_disp(open_remeasurable=2, opted_out=3))
        assert "3" in d and "markiert" in d

    def test_detail_no_optout_note_when_zero(self):
        d = gate_banner_detail(_disp(open_remeasurable=2, opted_out=0))
        assert "markiert" not in d
        assert "gedeckelt" in d

    def test_detail_lists_affected_checks(self):
        # Transparenz: das Banner nennt, WAS geprueft wird.
        d = gate_banner_detail(
            _disp(open_remeasurable=2),
            open_labels=["Automatische Updates aktiv", "BitLocker aktiv auf C:"],
        )
        assert "Betrifft:" in d
        assert "Automatische Updates aktiv" in d

    def test_detail_no_betrifft_without_labels(self):
        d = gate_banner_detail(_disp(open_remeasurable=1))
        assert "Betrifft:" not in d


class TestGateStateText:
    """D6 Phase 2 — Texte der transienten/terminalen Zustaende (ohne Qt)."""

    def test_running(self):
        assert "läuft" in gate_state_title(GateBannerState.RUNNING)
        assert "Windows-Abfrage" in gate_state_detail(GateBannerState.RUNNING)

    def test_timeout_says_score_unchanged(self):
        d = gate_state_detail(GateBannerState.TIMEOUT)
        assert "90" in d
        assert "nicht verändert" in d

    def test_rejected_capitalizes_reason_and_keeps_score(self):
        d = gate_state_detail(
            GateBannerState.REJECTED, reason_text="die Messung ist fehlgeschlagen"
        )
        assert d.startswith("Die Messung")  # erster Buchstabe gross
        assert "nicht verändert" in d

    def test_rejected_has_fallback_without_reason(self):
        d = gate_state_detail(GateBannerState.REJECTED)
        assert "fehlgeschlagen" in d
