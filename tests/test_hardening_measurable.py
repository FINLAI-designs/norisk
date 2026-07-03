"""Tests fuer den 3. Zustand 'measurable' + Alternative-Override.

Headless/pur — kein echtes winreg/subprocess (MockHardeningProbe), keine GUI.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.probes.mock_hardening_probe import MockHardeningProbe
from core.security.severity import Severity
from tools.system_scanner.application.hardening_overrides import (
    apply_manual_overrides,
)
from tools.system_scanner.application.storytelling_adapter import (
    hardening_checks_to_findings,
)
from tools.system_scanner.application.windows_hardening_scanner import (
    SH_001_FIREWALL,
    SH_010_BITLOCKER,
    WindowsHardeningScanner,
)
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    ManualScannerEntry,
    OSInfo,
    ScanResult,
)
from tools.system_scanner.domain.enums import (
    ComponentStatus,
    ComponentType,
    OSPlatform,
    UnmeasuredReason,
)

_UAC_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"


def _check(
    check_id="SH-001",
    *,
    passed=False,
    measurable=True,
    sev=Severity.CRITICAL,
    reason=UnmeasuredReason.NEEDS_ADMIN,
):
    # Invariante: measurable=False MUSS einen Reason tragen (sonst raised
    # __post_init__). Bei measurable=True bleibt der Reason None.
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=passed,
        severity=sev,
        measurable=measurable,
        unmeasured_reason=None if measurable else reason,
    )


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class TestHardeningCheckMeasurable:
    def test_default_true(self) -> None:
        assert _check().measurable is True

    def test_roundtrip_mit_measurable(self) -> None:
        c = _check(measurable=False)
        assert HardeningCheck.from_dict(c.to_dict()).measurable is False

    def test_from_dict_alt_json_ohne_feld_ist_messbar(self) -> None:
        # Rueckwaertskompat: alte JSON ohne 'measurable' -> True.
        old = {"check_id": "SH-001", "label": "x", "passed": False, "severity": "high"}
        assert HardeningCheck.from_dict(old).measurable is True


# ---------------------------------------------------------------------------
# Scanner: Probe-/Registry-Fehler -> measurable=False
# ---------------------------------------------------------------------------


class TestScannerMeasurable:
    def test_firewall_command_fehlt_ist_nicht_messbar(self) -> None:
        probe = MockHardeningProbe()  # nichts konfiguriert -> command fail
        check = WindowsHardeningScanner(probe).check_firewall()
        assert check.measurable is False
        assert "nicht messbar" in check.detail.lower()

    def test_uac_registry_fehlt_ist_nicht_messbar(self) -> None:
        probe = MockHardeningProbe()  # Registry leer
        check = WindowsHardeningScanner(probe).check_uac()
        assert check.measurable is False

    def test_uac_gelesen_ist_messbar(self) -> None:
        probe = MockHardeningProbe()
        probe.set_registry_value("HKLM", _UAC_KEY, "EnableLUA", "1")
        check = WindowsHardeningScanner(probe).check_uac()
        assert check.measurable is True
        assert check.passed is True

    def test_uac_aus_ist_messbarer_verstoss(self) -> None:
        probe = MockHardeningProbe()
        probe.set_registry_value("HKLM", _UAC_KEY, "EnableLUA", "0")
        check = WindowsHardeningScanner(probe).check_uac()
        assert check.measurable is True
        assert check.passed is False


# ---------------------------------------------------------------------------
# Aggregation: Nenner = messbare Checks
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_nenner_ignoriert_nicht_messbare(self) -> None:
        from tools.security_scoring.domain.hardening_aggregation import (
            build_system_scanner_component,
        )

        checks = [
            _check("SH-001", passed=True, measurable=True),
            _check("SH-002", passed=False, measurable=True, sev=Severity.HIGH),
            _check("SH-010", passed=False, measurable=False, sev=Severity.MEDIUM),
        ]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        # 1 von 2 MESSBAREN erfuellt -> 50.0 (der nicht-messbare zaehlt nicht)
        assert comp.score == 50.0
        # nicht-messbarer MEDIUM zaehlt NICHT als Finding
        assert comp.findings_medium == 0
        assert comp.findings_high == 1

    def test_alle_nicht_messbar_ist_none(self) -> None:
        from tools.security_scoring.domain.hardening_aggregation import (
            build_system_scanner_component,
        )

        checks = [_check("SH-010", measurable=False)]
        assert build_system_scanner_component(checks) is None


# ---------------------------------------------------------------------------
# Hard-Caps: nicht-messbar loest keinen Cap aus
# ---------------------------------------------------------------------------


def _scan_result(checks: list[HardeningCheck]) -> ScanResult:
    return ScanResult(
        scan_id="t",
        timestamp=datetime(2026, 6, 20, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=checks,
    )


class TestCapsGuard:
    def test_firewall_nicht_messbar_kein_cap(self) -> None:
        from tools.security_scoring.domain.hardening_caps import (
            _detect_no_firewall_cap,
        )

        sr = _scan_result([_check(SH_001_FIREWALL, passed=False, measurable=False)])
        assert _detect_no_firewall_cap(sr) is None

    def test_firewall_messbar_aus_loest_cap(self) -> None:
        from tools.security_scoring.domain.hardening_caps import (
            _detect_no_firewall_cap,
        )

        sr = _scan_result([_check(SH_001_FIREWALL, passed=False, measurable=True)])
        assert _detect_no_firewall_cap(sr) is not None


# ---------------------------------------------------------------------------
# Alternative-Override
# ---------------------------------------------------------------------------


def _entry(category: ComponentType, name: str, status=ComponentStatus.ACTIVE):
    return ManualScannerEntry(entry_id=1, category=category, name=name, status=status)


class TestManualOverrides:
    def test_encryption_alternative_hebt_nicht_messbaren_bitlocker(self) -> None:
        checks = [_check(SH_010_BITLOCKER, passed=False, measurable=False)]
        out = apply_manual_overrides(
            checks, [_entry(ComponentType.ENCRYPTION, "VeraCrypt")]
        )
        assert out[0].passed is True
        assert out[0].measurable is True
        assert "VeraCrypt" in out[0].detail

    def test_firewall_alternative_hebt_nicht_messbar(self) -> None:
        checks = [_check(SH_001_FIREWALL, passed=False, measurable=False)]
        out = apply_manual_overrides(checks, [_entry(ComponentType.FIREWALL, "Sophos")])
        assert out[0].passed is True

    def test_messbarer_check_wird_nicht_ueberschrieben(self) -> None:
        # Echte Messung gewinnt Patrick): messbar passed=False bleibt.
        checks = [_check(SH_010_BITLOCKER, passed=False, measurable=True)]
        out = apply_manual_overrides(
            checks, [_entry(ComponentType.ENCRYPTION, "VeraCrypt")]
        )
        assert out[0].passed is False

    def test_inaktive_alternative_ignoriert(self) -> None:
        checks = [_check(SH_010_BITLOCKER, passed=False, measurable=False)]
        out = apply_manual_overrides(
            checks,
            [_entry(ComponentType.ENCRYPTION, "VeraCrypt", ComponentStatus.INACTIVE)],
        )
        assert out[0].passed is False

    def test_antivirus_hat_keinen_partner(self) -> None:
        checks = [_check(SH_010_BITLOCKER, passed=False, measurable=False)]
        out = apply_manual_overrides(checks, [_entry(ComponentType.ANTIVIRUS, "ESET")])
        assert out[0].passed is False


# ---------------------------------------------------------------------------
# Findings-Filter: nicht-messbar erzeugt kein Finding (-> keine-Zeile)
# ---------------------------------------------------------------------------


class TestFindingsFilter:
    def test_nicht_messbar_kein_finding(self) -> None:
        checks = [
            _check("SH-001", passed=False, measurable=False),  # grau -> kein Finding
            _check("SH-002", passed=False, measurable=True, sev=Severity.HIGH),  # rot
            _check("SH-003", passed=True, measurable=True),  # gruen -> kein Finding
        ]
        findings = hardening_checks_to_findings(checks)
        ids = {f.evidence_id for f in findings}
        assert ids == {"SH-002"}
