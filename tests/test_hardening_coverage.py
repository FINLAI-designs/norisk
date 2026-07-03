"""Tests fuer HardeningCoverage + Coverage-Stage-Guard Phase 3).

Pure Domain-Logik — kein I/O. Deckt ab:
    * compute_hardening_coverage: measured/applicable, NOT_APPLICABLE raus aus
      dem Nenner, USER_DECLINED/NEEDS_ADMIN druecken die ratio.
    * compute_hardening_score: Stage-Guard begrenzt bei < 70 % Coverage die
      Ampel auf At Risk (kein false-secure), Score bleibt sichtbar.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.security.severity import Severity
from tools.security_scoring.domain.hardening_aggregation import (
    build_system_scanner_component,
)
from tools.security_scoring.domain.hardening_score import (
    build_hardening_summary,
    compute_hardening_score,
)
from tools.security_scoring.domain.hardening_stages import (
    STAGE_AT_RISK,
    STAGE_SECURE,
)
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    OSInfo,
    ScanResult,
    compute_hardening_coverage,
    evaluate_measurement_disposition,
)
from tools.system_scanner.domain.enums import OSPlatform, UnmeasuredReason


def _chk(check_id, *, passed=True, measurable=True, reason=None):
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=passed,
        severity=Severity.MEDIUM,
        measurable=measurable,
        unmeasured_reason=reason,
    )


def _scan(checks):
    return ScanResult(
        scan_id="t",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=checks,
    )


class TestComputeHardeningCoverage:
    def test_all_measured_ratio_1(self):
        cov = compute_hardening_coverage([_chk(f"SH-{i}") for i in range(5)])
        assert cov.measured == 5
        assert cov.applicable == 5
        assert cov.ratio == 1.0

    def test_not_applicable_excluded_from_denominator(self):
        checks = [_chk(f"M-{i}") for i in range(5)]
        checks += [
            _chk(f"NA-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NOT_APPLICABLE)
            for i in range(2)
        ]
        cov = compute_hardening_coverage(checks)
        assert cov.not_applicable == 2
        assert cov.applicable == 5  # 7 gesamt - 2 n/a
        assert cov.measured == 5
        assert cov.ratio == 1.0

    def test_user_declined_lowers_ratio(self):
        checks = [_chk(f"M-{i}") for i in range(7)]
        checks += [
            _chk(f"D-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.USER_DECLINED)
            for i in range(3)
        ]
        cov = compute_hardening_coverage(checks)
        assert cov.opted_out == 3
        assert cov.applicable == 10
        assert cov.measured == 7
        assert abs(cov.ratio - 0.7) < 1e-9

    def test_needs_admin_lowers_ratio(self):
        checks = [_chk(f"M-{i}") for i in range(4)]
        checks += [
            _chk(f"A-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
            for i in range(6)
        ]
        cov = compute_hardening_coverage(checks)
        assert cov.applicable == 10
        assert cov.measured == 4
        assert abs(cov.ratio - 0.4) < 1e-9

    def test_empty_ratio_1(self):
        cov = compute_hardening_coverage([])
        assert cov.applicable == 0
        assert cov.ratio == 1.0

    def test_measurable_with_reason_counts_as_measured(self):
        # P2-Review: apply_manual_overrides hebt measurable=True, behaelt aber den
        # Alt-Reason. Der Check zaehlt als MESSBAR (im Nenner), NICHT als n/a.
        checks = [
            _chk("ALT", passed=True, measurable=True,
                 reason=UnmeasuredReason.NOT_APPLICABLE),
            _chk("M1", passed=True),
        ]
        cov = compute_hardening_coverage(checks)
        assert cov.not_applicable == 0  # measurable=True -> nicht als n/a
        assert cov.measured == 2
        assert cov.applicable == 2
        assert cov.ratio == 1.0


class TestCoverageStageGuard:
    def test_high_score_low_coverage_capped_to_at_risk(self):
        # 4 passed (messbar) + 6 NEEDS_ADMIN -> Cat-E 100, coverage 0.4.
        checks = [_chk(f"P-{i}", passed=True) for i in range(4)]
        checks += [
            _chk(f"A-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
            for i in range(6)
        ]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        assert result.overall_score >= 85  # gemessener Teil = Secure-Bereich
        assert result.stage == STAGE_AT_RISK  # aber Ampel begrenzt
        assert result.stage_capped_by_coverage is True
        assert result.coverage is not None
        assert abs(result.coverage.ratio - 0.4) < 1e-9

    def test_high_score_full_coverage_not_capped(self):
        checks = [_chk(f"P-{i}", passed=True) for i in range(10)]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        assert result.stage == STAGE_SECURE
        assert result.stage_capped_by_coverage is False

    def test_not_applicable_does_not_trigger_guard(self):
        # 7 passed + 3 NOT_APPLICABLE -> coverage 7/7 = 1.0 (n/a raus).
        checks = [_chk(f"P-{i}", passed=True) for i in range(7)]
        checks += [
            _chk(f"NA-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NOT_APPLICABLE)
            for i in range(3)
        ]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        assert result.stage == STAGE_SECURE
        assert result.stage_capped_by_coverage is False

    def test_no_scan_result_no_coverage(self):
        comp = build_system_scanner_component(
            [_chk(f"P-{i}", passed=True) for i in range(10)]
        )
        result = compute_hardening_score([comp], scan_result=None)
        assert result.coverage is None
        assert result.stage_capped_by_coverage is False


class TestMeasurementDisposition:
    def test_buckets_classified(self):
        checks = [_chk(f"M-{i}", passed=True) for i in range(3)]
        checks += [
            _chk("A1", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN),
            _chk("P1", passed=False, measurable=False,
                 reason=UnmeasuredReason.PARSE_FAILED),
            _chk("D1", passed=False, measurable=False,
                 reason=UnmeasuredReason.USER_DECLINED),
            _chk("N1", passed=False, measurable=False,
                 reason=UnmeasuredReason.NOT_APPLICABLE),
        ]
        d = evaluate_measurement_disposition(checks)
        assert d.measured == 3
        assert d.open_remeasurable == 1
        assert d.blocked == 1
        assert d.opted_out == 1
        assert d.not_applicable == 1

    def test_gate_open_when_needs_admin(self):
        checks = [
            _chk("A1", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
        ]
        assert evaluate_measurement_disposition(checks).gate_open is True

    def test_gate_closed_when_no_needs_admin(self):
        # USER_DECLINED + NOT_APPLICABLE sind dispositioniert -> Gate zu.
        checks = [_chk(f"M-{i}", passed=True) for i in range(3)]
        checks += [
            _chk("D1", passed=False, measurable=False,
                 reason=UnmeasuredReason.USER_DECLINED),
            _chk("N1", passed=False, measurable=False,
                 reason=UnmeasuredReason.NOT_APPLICABLE),
        ]
        d = evaluate_measurement_disposition(checks)
        assert d.gate_open is False
        assert d.opted_out == 1

    def test_parse_failed_blocked_not_open(self):
        # PARSE_FAILED ist nicht nutzer-behebbar -> kein Admin-Recheck -> nicht offen.
        checks = [
            _chk("P1", passed=False, measurable=False,
                 reason=UnmeasuredReason.PARSE_FAILED)
        ]
        d = evaluate_measurement_disposition(checks)
        assert d.blocked == 1
        assert d.gate_open is False

    def test_measurable_with_reason_counts_as_measured(self):
        # P2-Review: measurable=True + Alt-Reason -> measured, NICHT offen/n/a.
        checks = [
            _chk("ALT", passed=True, measurable=True,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
        ]
        d = evaluate_measurement_disposition(checks)
        assert d.measured == 1
        assert d.open_remeasurable == 0
        assert d.gate_open is False


class TestDispositionInScoreResult:
    def test_disposition_populated_with_scan_result(self):
        checks = [_chk(f"P-{i}", passed=True) for i in range(4)]
        checks += [
            _chk(f"A-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
            for i in range(6)
        ]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        assert result.disposition is not None
        assert result.disposition.open_remeasurable == 6
        assert result.disposition.gate_open is True

    def test_disposition_none_without_scan_result(self):
        comp = build_system_scanner_component(
            [_chk(f"P-{i}", passed=True) for i in range(10)]
        )
        result = compute_hardening_score([comp], scan_result=None)
        assert result.disposition is None


class TestSummaryCoverageHint:
    def test_summary_explains_capped_stage(self):
        # P3-Review: bei begrenzter Stufe MUSS der Summary-Text die niedrige
        # Abdeckung erklaeren (sonst wirkt "At Risk - 92/100" widerspruechlich).
        checks = [_chk(f"P-{i}", passed=True) for i in range(4)]
        checks += [
            _chk(f"A-{i}", passed=False, measurable=False,
                 reason=UnmeasuredReason.NEEDS_ADMIN)
            for i in range(6)
        ]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        summary = build_hardening_summary(result)
        assert "begrenzt" in summary.lower()
        assert "40" in summary  # 40 % gemessen

    def test_summary_no_hint_when_full_coverage(self):
        checks = [_chk(f"P-{i}", passed=True) for i in range(10)]
        comp = build_system_scanner_component(checks)
        result = compute_hardening_score([comp], scan_result=_scan(checks))
        assert "begrenzt" not in build_hardening_summary(result).lower()
