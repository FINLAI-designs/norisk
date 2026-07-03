"""
test_hardening_check_entity — pytest-Tests fuer
``tools.system_scanner.domain.entities.HardeningCheck`` +
``ScanResult.hardening_checks``.

Phase 3.1 des Hardening-Score-Sprints. Pure Logik,
keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.security.severity import Severity
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    OSInfo,
    ScanResult,
)
from tools.system_scanner.domain.enums import OSPlatform, UnmeasuredReason

# ===========================================================================
# HardeningCheck Dataclass
# ===========================================================================


class TestHardeningCheckDataclass:
    def test_basic_construction(self):
        check = HardeningCheck(
            check_id="SH-001",
            label="Windows Firewall aktiv",
            passed=True,
            severity=Severity.CRITICAL,
        )
        assert check.check_id == "SH-001"
        assert check.passed is True
        assert check.severity == Severity.CRITICAL
        assert check.detail == ""

    def test_frozen(self):
        check = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        with pytest.raises(Exception):  # noqa: B017, BLE001 — FrozenInstanceError
            check.passed = False  # type: ignore[misc]

    def test_hashable(self):
        a = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        b = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        assert hash(a) == hash(b)
        assert {a, b} == {a}

    def test_to_dict_roundtrip(self):
        original = HardeningCheck(
            check_id="SH-003",
            label="RDP",
            passed=False,
            severity=Severity.HIGH,
            detail="RDP aktiv, MFA fehlt",
        )
        restored = HardeningCheck.from_dict(original.to_dict())
        assert restored == original

    def test_to_dict_uses_severity_value(self):
        check = HardeningCheck("X", "y", True, Severity.MEDIUM, "")
        d = check.to_dict()
        assert d["severity"] == "medium"

    def test_from_dict_defaults_to_info_on_missing_severity(self):
        d = {
            "check_id": "X",
            "label": "y",
            "passed": True,
            "detail": "",
        }
        check = HardeningCheck.from_dict(d)
        assert check.severity == Severity.INFO

    # ---: unmeasured_reason / skip_reason (Phase 1) ----------------

    def test_default_unmeasured_reason_and_skip_reason(self):
        check = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        assert check.unmeasured_reason is None
        assert check.skip_reason == ""

    def test_roundtrip_with_unmeasured_reason(self):
        original = HardeningCheck(
            check_id="SH-010",
            label="BitLocker",
            passed=False,
            severity=Severity.MEDIUM,
            detail="nicht messbar",
            measurable=False,
            unmeasured_reason=UnmeasuredReason.NEEDS_ADMIN,
        )
        d = original.to_dict()
        assert d["unmeasured_reason"] == "needs_admin"  # StrEnum -> value
        assert HardeningCheck.from_dict(d) == original

    def test_roundtrip_user_declined_with_skip_reason(self):
        original = HardeningCheck(
            check_id="SH-005",
            label="SMBv1",
            passed=False,
            severity=Severity.CRITICAL,
            measurable=False,
            unmeasured_reason=UnmeasuredReason.USER_DECLINED,
            skip_reason="Vom Nutzer uebersprungen: nutzt anderes Tool",
        )
        assert HardeningCheck.from_dict(original.to_dict()) == original

    def test_to_dict_unmeasured_reason_none_serialises_none(self):
        check = HardeningCheck("X", "y", True, Severity.LOW)
        assert check.to_dict()["unmeasured_reason"] is None

    def test_from_dict_legacy_without_new_fields(self):
        # Alte JSON (vor) ohne die neuen Felder -> Defaults, kompatibel.
        d = {
            "check_id": "SH-002",
            "label": "UAC",
            "passed": True,
            "severity": "high",
            "detail": "",
            "measurable": True,
        }
        check = HardeningCheck.from_dict(d)
        assert check.unmeasured_reason is None
        assert check.skip_reason == ""

    # ---: Invariante strukturell erzwungen (__post_init__) ---------

    def test_measurable_false_without_reason_raises(self):
        # measurable=False ohne unmeasured_reason ist ein illegaler Zustand.
        with pytest.raises(ValueError, match="ADR-026-Invariante"):
            HardeningCheck(
                check_id="SH-001",
                label="FW",
                passed=False,
                severity=Severity.CRITICAL,
                measurable=False,
            )

    def test_measurable_false_with_reason_ok(self):
        check = HardeningCheck(
            check_id="SH-001",
            label="FW",
            passed=False,
            severity=Severity.CRITICAL,
            measurable=False,
            unmeasured_reason=UnmeasuredReason.NEEDS_ADMIN,
        )
        assert check.unmeasured_reason == UnmeasuredReason.NEEDS_ADMIN

    def test_measurable_true_with_reason_allowed_asymmetric(self):
        # Asymmetrie: measurable=True MIT Reason ist erlaubt (Alternative-Override
        # hebt measurable auf True, ohne den Reason zu loeschen).
        check = HardeningCheck(
            check_id="SH-001",
            label="FW",
            passed=True,
            severity=Severity.CRITICAL,
            measurable=True,
            unmeasured_reason=UnmeasuredReason.NOT_APPLICABLE,
        )
        assert check.measurable is True


# ===========================================================================
# ScanResult.hardening_checks
# ===========================================================================


class TestScanResultHardeningChecks:
    def _make_scan(self, *checks: HardeningCheck) -> ScanResult:
        return ScanResult(
            scan_id="test",
            timestamp=datetime(2026, 5, 11, tzinfo=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            hardening_checks=list(checks),
        )

    def test_default_empty_list(self):
        scan = ScanResult(
            scan_id="x",
            timestamp=datetime.now(UTC),
            os_info=OSInfo(platform=OSPlatform.UNKNOWN),
        )
        assert scan.hardening_checks == []

    def test_explicit_checks_preserved(self):
        c1 = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        c2 = HardeningCheck("SH-002", "UAC", False, Severity.HIGH)
        scan = self._make_scan(c1, c2)
        assert scan.hardening_checks == [c1, c2]

    def test_to_dict_serializes_checks(self):
        c = HardeningCheck("SH-005", "SMBv1", False, Severity.CRITICAL, "aktiv")
        scan = self._make_scan(c)
        d = scan.to_dict()
        assert "hardening_checks" in d
        assert len(d["hardening_checks"]) == 1
        assert d["hardening_checks"][0]["check_id"] == "SH-005"

    def test_from_dict_roundtrip(self):
        c1 = HardeningCheck("SH-001", "FW", True, Severity.CRITICAL)
        c2 = HardeningCheck("SH-003", "RDP", False, Severity.CRITICAL, "Port 3389")
        original = self._make_scan(c1, c2)
        restored = ScanResult.from_dict(original.to_dict())
        assert restored.hardening_checks == [c1, c2]

    def test_from_dict_without_hardening_checks_yields_empty(self):
        # Alte Scan-Results (vor Phase 3) haben kein hardening_checks-Feld
        old_dict = {
            "scan_id": "old",
            "timestamp": datetime(2026, 1, 1, tzinfo=UTC).isoformat(),
            "os_info": OSInfo(platform=OSPlatform.WINDOWS).to_dict(),
            "software_list": [],
            "security_components": [],
            "scan_duration_s": 0.0,
            "warnings": [],
        }
        restored = ScanResult.from_dict(old_dict)
        # Backwards-Compat: leere Liste statt Crash
        assert restored.hardening_checks == []
