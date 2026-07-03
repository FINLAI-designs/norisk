"""Tests für validation_report — Datenklassen + Score-Aggregation."""

from __future__ import annotations

from pathlib import Path

from core.security.validation_report import (
    ImportType,
    Severity,
    Threat,
    ValidationReport,
)


class TestSeverityPoints:
    def test_info_zero(self):
        assert Severity.INFO.points == 0

    def test_monotonic(self):
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        points = [s.points for s in order]
        assert points == sorted(points)

    def test_critical_dominant(self):
        # Eine CRITICAL-Threat allein muss einen HIGH-Schwellwert überschreiten
        assert Severity.CRITICAL.points >= Severity.HIGH.points * 2


class TestValidationReportAdd:
    def _report(self):
        return ValidationReport(path=Path("x.txt"), declared_type=ImportType.TXT)

    def test_empty_report_is_safe(self):
        r = self._report()
        assert r.safe_to_parse is True
        assert r.risk_score == 0

    def test_add_low_keeps_safe(self):
        r = self._report()
        r.add(Threat(code="A", severity=Severity.LOW, message="x"))
        assert r.safe_to_parse is True
        assert r.risk_score == 10

    def test_add_high_keeps_safe(self):
        r = self._report()
        r.add(Threat(code="B", severity=Severity.HIGH, message="x"))
        assert r.safe_to_parse is True
        assert r.risk_score == 50

    def test_add_critical_flips_unsafe(self):
        r = self._report()
        r.add(Threat(code="C", severity=Severity.CRITICAL, message="x"))
        assert r.safe_to_parse is False
        assert r.risk_score == 100

    def test_risk_score_capped_at_100(self):
        r = self._report()
        for i in range(5):
            r.add(Threat(code=f"X{i}", severity=Severity.HIGH, message="x"))
        assert r.risk_score == 100

    def test_has_severity_positive(self):
        r = self._report()
        r.add(Threat(code="M", severity=Severity.MEDIUM, message="x"))
        assert r.has_severity(Severity.LOW) is True
        assert r.has_severity(Severity.MEDIUM) is True
        assert r.has_severity(Severity.HIGH) is False


class TestScanIncomplete:
    """Fail-Closed-Markierung unvollständiger Inspektion."""

    def _report(self):
        return ValidationReport(path=Path("x.pdf"), declared_type=ImportType.PDF)

    def test_leerer_report_ist_vollstaendig(self):
        assert self._report().scan_incomplete() is False

    def test_nur_inhaltliche_threats_sind_vollstaendig(self):
        r = self._report()
        r.add(Threat(code="PDF_JAVASCRIPT", severity=Severity.HIGH, message="x"))
        assert r.scan_incomplete() is False

    def test_deep_scan_error_markiert_unvollstaendig(self):
        r = self._report()
        r.add(Threat(code="PDF_DEEP_SCAN_ERROR", severity=Severity.MEDIUM, message="x"))
        assert r.scan_incomplete() is True

    def test_validator_fehler_per_konvention(self):
        # Kuenftige *_SCAN_ERROR/*_PARSE_ERROR/... sind automatisch fail-closed.
        for code in (
            "XLSX_MACRO_SCAN_ERROR",
            "OFFICE_SCAN_ERROR",
            "JSON_PARSE_ERROR",
            "JSON_SCHEMA_READ_ERROR",
            "PDF_DEEP_SCAN_UNAVAILABLE",
            "XLSX_FORMULA_SCAN_SKIPPED",
            "SUB_VALIDATOR_ERROR",
        ):
            r = self._report()
            r.add(Threat(code=code, severity=Severity.MEDIUM, message="x"))
            assert r.scan_incomplete() is True, code

    def test_encrypted_markiert_unvollstaendig(self):
        r = self._report()
        r.add(Threat(code="PDF_ENCRYPTED", severity=Severity.MEDIUM, message="x"))
        assert r.scan_incomplete() is True
