"""Tests fuer das NIS2-Reifegrad-Roll-up (core/compliance, pur) — IA-Welle 2 Phase 2."""

from __future__ import annotations

from core.compliance.nis2_maturity import (
    ALL_NIS2_CONTROLS,
    ControlFinding,
    MaturityLevel,
    compute_nis2_maturity,
    summarize_nis2_maturity,
)
from core.compliance.regulatory_mapping import RegReference


def _hc(check_id: str, *, passed: bool, measurable: bool = True) -> ControlFinding:
    return ControlFinding(
        category="system_hardening",
        check_id=check_id,
        passed=passed,
        measurable=measurable,
    )


class TestComputeMaturity:
    def test_alle_neun_controls_im_ergebnis(self) -> None:
        result = compute_nis2_maturity([])
        assert set(result) == set(ALL_NIS2_CONTROLS)
        # ohne Befunde: alle UNKNOWN (nicht NONE/rot)
        assert all(c.level is MaturityLevel.UNKNOWN for c in result.values())

    def test_erfuellter_check_hebt_control_auf_advanced(self) -> None:
        # SH-001 (Firewall) -> u.a. NIS2 2a. Ein erfuellter Befund -> ratio 1.0.
        result = compute_nis2_maturity([_hc("SH-001", passed=True)])
        cm = result[RegReference.NIS2_ART21_2A]
        assert cm.level is MaturityLevel.ADVANCED
        assert cm.passed == 1
        assert cm.total == 1

    def test_fehlgeschlagener_check_ist_none(self) -> None:
        result = compute_nis2_maturity([_hc("SH-001", passed=False)])
        assert result[RegReference.NIS2_ART21_2A].level is MaturityLevel.NONE

    def test_nicht_messbarer_check_zaehlt_nicht(self) -> None:
        # Konsistenz: nicht messbar -> Control bleibt UNKNOWN.
        result = compute_nis2_maturity([_hc("SH-001", passed=False, measurable=False)])
        assert result[RegReference.NIS2_ART21_2A].level is MaturityLevel.UNKNOWN
        assert result[RegReference.NIS2_ART21_2A].total == 0

    def test_teilweise_erfuellt_zwischenstufe(self) -> None:
        # SH-001 + SH-008 mappen beide u.a. auf 2a (SH-001->2a, SH-008->2a).
        # 1 von 2 erfuellt -> ratio 0.5 -> BASIC.
        result = compute_nis2_maturity(
            [_hc("SH-001", passed=True), _hc("SH-008", passed=False)]
        )
        cm = result[RegReference.NIS2_ART21_2A]
        assert cm.total == 2
        assert cm.passed == 1
        assert cm.level is MaturityLevel.BASIC


class TestSummary:
    def test_leer_ist_unknown(self) -> None:
        summary = summarize_nis2_maturity(compute_nis2_maturity([]))
        assert summary.overall is MaturityLevel.UNKNOWN
        assert summary.assessed_controls == 0
        assert summary.total_controls == 9

    def test_overall_mittelt_nur_erhobene(self) -> None:
        # Ein erfuelltes SH-010 (-> 2h ADVANCED=3). Nur 1 Control erhoben.
        summary = summarize_nis2_maturity(
            compute_nis2_maturity([_hc("SH-010", passed=True)])
        )
        assert summary.assessed_controls >= 1
        assert summary.overall is MaturityLevel.ADVANCED
        # nicht erhobene Controls liegen unter UNKNOWN
        assert summary.per_level[MaturityLevel.UNKNOWN] >= 1
