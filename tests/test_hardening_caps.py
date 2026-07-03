"""
test_hardening_caps — pytest-Tests fuer
``tools.security_scoring.domain.hardening_caps``.

Phase 2 des Hardening-Score-Sprints v2 §3). Pure Logik,
keine I/O. Tests pro Detector + Kombinations-Test + Integration mit
:func:`compute_hardening_score`.

Test-Bereiche:
    * HardCapEvent-Dataclass
    * Detector 1: Critical CVE (cve_exposure / dependency_auditor)
    * Detector 2: Admin-PW-Breach (password_policy)
    * Detector 5: ≥ 3 kritische Findings (Aggregate)
    * Detector 3+4: Phase-3-Stubs (RDP, Firewall — returnen None)
    * apply_hard_caps: niedrigster Cap gewinnt, keine Events → Score unchanged
    * Integration: compute_hardening_score mit aktiven Caps

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.security.severity import Severity
from tools.security_scoring.domain.hardening_caps import (
    CAP_ADMIN_PW_BREACH,
    CAP_CRITICAL_CVE,
    CAP_NO_FIREWALL,
    CAP_RDP_NO_MFA,
    CAP_THREE_CRITICAL,
    HARDENING_CHECK_FIREWALL,
    HARDENING_CHECK_RDP,
    HardCapEvent,
    _detect_admin_pw_breach_cap,
    _detect_critical_cve_cap,
    _detect_no_firewall_cap,
    _detect_rdp_no_mfa_cap,
    _detect_three_critical_findings_cap,
    apply_hard_caps,
)
from tools.security_scoring.domain.hardening_score import compute_hardening_score
from tools.security_scoring.domain.models import ScoreComponent
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    OSInfo,
    ScanResult,
)
from tools.system_scanner.domain.enums import OSPlatform


def _scan_result(*checks: HardeningCheck) -> ScanResult:
    """Builder fuer ScanResult mit gegebenen HardeningChecks."""
    return ScanResult(
        scan_id="test",
        timestamp=datetime(2026, 5, 11, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=list(checks),
    )

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


def _comp(
    source_tool: str,
    score: float = 80.0,
    *,
    weight: float = 0.5,
    data_available: bool = True,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    name: str = "X",
) -> ScoreComponent:
    """Builder fuer ScoreComponent-Test-Daten mit Findings."""
    return ScoreComponent(
        name=name,
        score=score,
        weight=weight,
        source_tool=source_tool,
        data_available=data_available,
        findings_critical=critical,
        findings_high=high,
        findings_medium=medium,
    )


# ===========================================================================
# HardCapEvent Dataclass
# ===========================================================================


class TestHardCapEventDataclass:
    def test_frozen(self):
        event = HardCapEvent(label="X", cap_value=40, triggered_by="t")
        with pytest.raises(Exception):  # noqa: B017, BLE001 — FrozenInstanceError
            event.cap_value = 99  # type: ignore[misc]

    def test_default_details_empty(self):
        event = HardCapEvent(label="X", cap_value=40, triggered_by="t")
        assert event.details == ""

    def test_hashable(self):
        a = HardCapEvent("X", 40, "t")
        b = HardCapEvent("X", 40, "t")
        assert {a, b} == {a}


# ===========================================================================
# Detector 1: Critical CVE
# ===========================================================================


class TestCriticalCveDetector:
    def test_cve_exposure_with_critical_triggers(self):
        comps = [_comp("cve_exposure", critical=2)]
        event = _detect_critical_cve_cap(comps)
        assert event is not None
        assert event.cap_value == CAP_CRITICAL_CVE
        assert event.triggered_by == "cve_exposure"
        assert "2 kritische" in event.details

    def test_dependency_auditor_with_critical_triggers(self):
        comps = [_comp("dependency_auditor", critical=1)]
        event = _detect_critical_cve_cap(comps)
        assert event is not None
        assert event.triggered_by == "dependency_auditor"

    def test_zero_critical_does_not_trigger(self):
        comps = [_comp("cve_exposure", critical=0)]
        assert _detect_critical_cve_cap(comps) is None

    def test_only_high_does_not_trigger_cve_cap(self):
        # High != Critical (CVSS ≥ 9.0)
        comps = [_comp("cve_exposure", critical=0, high=5)]
        assert _detect_critical_cve_cap(comps) is None

    def test_other_source_tool_does_not_trigger(self):
        # api_security mit critical zaehlt nicht als CVE
        comps = [_comp("api_security", critical=5)]
        assert _detect_critical_cve_cap(comps) is None

    def test_empty_components(self):
        assert _detect_critical_cve_cap([]) is None


# ===========================================================================
# Detector 2: Admin-PW-Breach
# ===========================================================================


class TestAdminPwBreachDetector:
    def test_password_policy_with_critical_triggers(self):
        comps = [_comp("password_policy", critical=1)]
        event = _detect_admin_pw_breach_cap(comps)
        assert event is not None
        assert event.cap_value == CAP_ADMIN_PW_BREACH
        assert event.triggered_by == "password_policy"

    def test_zero_critical_does_not_trigger(self):
        comps = [_comp("password_policy", critical=0)]
        assert _detect_admin_pw_breach_cap(comps) is None

    def test_other_source_tool_does_not_trigger(self):
        comps = [_comp("cve_exposure", critical=5)]
        assert _detect_admin_pw_breach_cap(comps) is None


# ===========================================================================
# Detector 5: ≥ 3 kritische Findings (Aggregate)
# ===========================================================================


class TestThreeCriticalDetector:
    def test_exactly_three_critical_triggers(self):
        comps = [
            _comp("cve_exposure", critical=2),
            _comp("api_security", critical=1),
        ]
        event = _detect_three_critical_findings_cap(comps)
        assert event is not None
        assert event.cap_value == CAP_THREE_CRITICAL
        assert "3 kritische" in event.details

    def test_details_benennt_quellen_absteigend(self):
        """Cap-5-Details benennen WO die kritischen Findings liegen (Name + Anzahl)."""
        comps = [
            _comp("password_policy", critical=1, name="Passwoerter"),
            _comp("cve_exposure", critical=2, name="System-Hardening"),
        ]
        event = _detect_three_critical_findings_cap(comps)
        assert event is not None
        assert "System-Hardening (2)" in event.details
        assert "Passwoerter (1)" in event.details
        # absteigend nach Anzahl -> die groessere Quelle zuerst
        assert event.details.index("System-Hardening") < event.details.index(
            "Passwoerter"
        )

    def test_two_critical_does_not_trigger(self):
        comps = [
            _comp("cve_exposure", critical=1),
            _comp("password_policy", critical=1),
        ]
        assert _detect_three_critical_findings_cap(comps) is None

    def test_five_critical_triggers(self):
        comps = [
            _comp("cve_exposure", critical=3),
            _comp("api_security", critical=2),
        ]
        event = _detect_three_critical_findings_cap(comps)
        assert event is not None

    def test_unavailable_components_excluded(self):
        # data_available=False zaehlt nicht in der Aggregation
        comps = [
            _comp("cve_exposure",   critical=2, data_available=False),
            _comp("password_policy", critical=1),
        ]
        assert _detect_three_critical_findings_cap(comps) is None


# ===========================================================================
# Detector 3: RDP ohne MFA (aktiviert in Phase 3.1)
# ===========================================================================


class TestRdpNoMfaCap:
    def test_none_scan_result_inactive(self):
        # Kein Scan vorhanden → Cap inaktiv (sicherheitsneutraler Default)
        assert _detect_rdp_no_mfa_cap(None) is None

    def test_no_relevant_check_inactive(self):
        # Scan vorhanden aber kein SH-003 darin
        scan = _scan_result(
            HardeningCheck("SH-001", "FW", True, Severity.CRITICAL),
        )
        assert _detect_rdp_no_mfa_cap(scan) is None

    def test_rdp_check_passed_inactive(self):
        # SH-003 passed → RDP konform → Cap inaktiv
        scan = _scan_result(
            HardeningCheck(
                "SH-003", "RDP", passed=True, severity=Severity.CRITICAL,
            ),
        )
        assert _detect_rdp_no_mfa_cap(scan) is None

    def test_rdp_check_failed_triggers_cap(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-003",
                "RDP exponiert ohne MFA",
                passed=False,
                severity=Severity.CRITICAL,
                detail="RDP-Port 3389 offen, kein NLA",
            ),
        )
        event = _detect_rdp_no_mfa_cap(scan)
        assert event is not None
        assert event.cap_value == CAP_RDP_NO_MFA
        assert event.triggered_by == HARDENING_CHECK_RDP
        assert "RDP-Port" in event.details

    def test_rdp_in_use_high_does_not_trigger_cap(self):
        # nachweislich GENUTZTES RDP ist HIGH (sichtbarer Befund, aber
        # kein Hard-Cap) — nur die unnoetige Exposition (CRITICAL) deckelt.
        scan = _scan_result(
            HardeningCheck(
                "SH-003",
                "RDP deaktiviert",
                passed=False,
                severity=Severity.HIGH,
                detail="RDP aktiv und in Nutzung — absichern",
            ),
        )
        assert _detect_rdp_no_mfa_cap(scan) is None


# ===========================================================================
# Detector 4: Keine Firewall aktiv (aktiviert in Phase 3.1)
# ===========================================================================


class TestNoFirewallCap:
    def test_none_scan_result_inactive(self):
        assert _detect_no_firewall_cap(None) is None

    def test_no_relevant_check_inactive(self):
        scan = _scan_result(
            HardeningCheck("SH-002", "UAC", True, Severity.HIGH),
        )
        assert _detect_no_firewall_cap(scan) is None

    def test_firewall_check_passed_inactive(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-001", "FW", passed=True, severity=Severity.CRITICAL,
            ),
        )
        assert _detect_no_firewall_cap(scan) is None

    def test_firewall_check_failed_triggers_cap(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-001",
                "Windows Firewall aktiv",
                passed=False,
                severity=Severity.CRITICAL,
                detail="Domain-Profil deaktiviert",
            ),
        )
        event = _detect_no_firewall_cap(scan)
        assert event is not None
        assert event.cap_value == CAP_NO_FIREWALL
        assert event.triggered_by == HARDENING_CHECK_FIREWALL
        assert "Domain-Profil" in event.details


# ===========================================================================
# Integration Cap 3 + 4 mit apply_hard_caps + compute_hardening_score
# ===========================================================================


class TestCaps3And4Integration:
    def test_apply_hard_caps_with_failed_firewall_clamps_to_60(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-001", "FW", passed=False, severity=Severity.CRITICAL,
            ),
        )
        score, events = apply_hard_caps(95.0, [], scan_result=scan)
        assert score == 60.0
        assert len(events) == 1
        assert events[0].cap_value == 60

    def test_apply_hard_caps_with_failed_rdp_clamps_to_50(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-003", "RDP", passed=False, severity=Severity.CRITICAL,
            ),
        )
        score, events = apply_hard_caps(95.0, [], scan_result=scan)
        assert score == 50.0
        assert events[0].cap_value == 50

    def test_compute_hardening_score_with_failed_firewall(self):
        scan = _scan_result(
            HardeningCheck(
                "SH-001", "FW", passed=False, severity=Severity.CRITICAL,
            ),
        )
        result = compute_hardening_score(
            [_comp("cve_exposure", 100.0)],
            scan_result=scan,
        )
        assert result.raw_weighted_score == 100.0
        assert result.overall_score == 60.0
        assert any(
            e.triggered_by == HARDENING_CHECK_FIREWALL for e in result.hard_cap_events
        )

    def test_both_caps_3_and_4_failed_lowest_wins(self):
        # RDP (50) + Firewall (60) → niedrigster gewinnt: 50
        scan = _scan_result(
            HardeningCheck("SH-001", "FW", passed=False, severity=Severity.CRITICAL),
            HardeningCheck("SH-003", "RDP", passed=False, severity=Severity.CRITICAL),
        )
        score, events = apply_hard_caps(95.0, [], scan_result=scan)
        assert score == 50.0
        assert len(events) == 2
        cap_values = {e.cap_value for e in events}
        assert cap_values == {50, 60}


# ===========================================================================
# apply_hard_caps — niedrigster Cap gewinnt
# ===========================================================================


class TestApplyHardCaps:
    def test_no_active_caps_returns_score_unchanged(self):
        score, events = apply_hard_caps(75.0, [])
        assert score == 75.0
        assert events == []

    def test_critical_cve_caps_to_40(self):
        comps = [_comp("cve_exposure", critical=1)]
        score, events = apply_hard_caps(90.0, comps)
        assert score == 40.0
        assert len(events) == 1
        assert events[0].cap_value == 40

    def test_score_below_cap_not_raised(self):
        # Wenn Score schon 20 ist und Cap 40 — Score bleibt 20
        comps = [_comp("cve_exposure", critical=1)]
        score, events = apply_hard_caps(20.0, comps)
        assert score == 20.0
        assert len(events) == 1

    def test_multiple_caps_lowest_wins(self):
        # CVE-Cap 40 + Admin-PW-Cap 35 + Three-Critical-Cap 25 alle aktiv
        # → Score wird auf 25 geclampt (niedrigster), alle 3 Events in Liste
        comps = [
            _comp("cve_exposure",    critical=1),  # Cap 40
            _comp("password_policy", critical=1),  # Cap 35
            _comp("api_security",    critical=2),  # zusammen 3+ → Cap 25
        ]
        score, events = apply_hard_caps(95.0, comps)
        assert score == 25.0
        assert len(events) == 3
        cap_values = {e.cap_value for e in events}
        assert cap_values == {40, 35, 25}

    def test_admin_pw_breach_only(self):
        comps = [_comp("password_policy", critical=1)]
        score, events = apply_hard_caps(90.0, comps)
        assert score == 35.0
        assert events[0].cap_value == 35


# ===========================================================================
# Integration mit compute_hardening_score
# ===========================================================================


class TestComputeHardeningScoreWithCaps:
    """Phase-2-Caps werden in compute_hardening_score angewendet."""

    def test_high_score_capped_by_critical_cve(self):
        # 5 Kategorien voll mit Score 100 → 100 raw, aber 1 kritische CVE → Cap 40
        comps = [
            _comp("cve_exposure",    100.0, critical=1),
            _comp("network_scanner", 100.0),
            _comp("password_policy", 100.0),
            _comp("api_security",    100.0),
            _comp("system_scanner",  100.0),
        ]
        result = compute_hardening_score(comps)
        assert result.raw_weighted_score == 100.0  # vor Cap
        assert result.overall_score == 40.0       # nach Cap
        assert result.stage.label == "At Risk"     # 40 = "At Risk"
        assert len(result.hard_cap_events) >= 1
        cap_values = {e.cap_value for e in result.hard_cap_events}
        assert 40 in cap_values

    def test_no_caps_active_score_unchanged(self):
        # Alle Components ohne kritische Findings → kein Cap aktiv
        comps = [
            _comp("cve_exposure",    80.0),
            _comp("network_scanner", 80.0),
            _comp("password_policy", 80.0),
            _comp("api_security",    80.0),
            _comp("system_scanner",  80.0),
        ]
        result = compute_hardening_score(comps)
        assert result.raw_weighted_score == 80.0
        assert result.overall_score == 80.0
        assert result.hard_cap_events == ()

    def test_three_critical_cap_strongest(self):
        # 3 kritische Findings verteilt → Cap 25 (niedriger als Cap 40 CVE)
        comps = [
            _comp("cve_exposure",    100.0, critical=1),
            _comp("network_scanner", 100.0, critical=1),
            _comp("password_policy", 100.0, critical=1),
            _comp("api_security",    100.0),
            _comp("system_scanner",  100.0),
        ]
        result = compute_hardening_score(comps)
        # Caps aktiv: CVE (40) + Admin-PW (35) + Three-Critical (25)
        assert result.overall_score == 25.0
        assert result.stage.label == "Critical"
        cap_values = {e.cap_value for e in result.hard_cap_events}
        assert cap_values == {40, 35, 25}

    def test_raw_score_remembered_for_ui_hint(self):
        # GUI kann "von 92 → auf 40 gecappt" zeigen
        comps = [
            _comp("cve_exposure",    92.0, critical=1),
        ]
        result = compute_hardening_score(comps)
        assert result.raw_weighted_score == 92.0
        assert result.overall_score == 40.0

    def test_empty_components_still_evaluates_caps(self):
        # Edge: leerer Input → raw=0, kein Cap aktiv → 0 bleibt
        result = compute_hardening_score([])
        assert result.raw_weighted_score == 0.0
        assert result.overall_score == 0.0
        assert result.hard_cap_events == ()
