"""
test_hardening_service_integration — pytest-Tests fuer Phase 3.4.

Verbindet die domain-Bausteine (Phase 1+2+3.1-3.3) mit dem
``ScoringService.compute_hardening_score``-API.

Test-Bereiche:
    * build_system_scanner_component — Aggregation Checks → ScoreComponent
    * ScoringService.compute_hardening_score ohne scan_result
    * ScoringService.compute_hardening_score mit scan_result
    * Kategorie E erscheint im Result wenn Checks vorhanden
    * Caps 3+4 werden aus scan_result.hardening_checks abgeleitet

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.probes.hardening_probe import HIVE_HKLM
from core.probes.mock_hardening_probe import MockHardeningProbe
from core.security.severity import Severity
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.domain.hardening_aggregation import (
    build_system_scanner_component,
)
from tools.security_scoring.domain.hardening_categories import HardeningCategory
from tools.system_scanner.application.windows_hardening_scanner import (
    _PS_BITLOCKER_C,
    _PS_FIREWALL_PROFILES,
    _PS_GUEST_ACCOUNT,
    _PS_LOCAL_ADMINS_COUNT,
    _WU_LAST_SUCCESS_VALUE,
    _WU_RESULTS_DETECT_KEY,
    _WU_TIMESTAMP_FORMAT,
    _WUAUSERV_START_KEY,
    _WUAUSERV_START_VALUE,
    run_hardening_baseline_scan,
)
from tools.system_scanner.domain.entities import (
    HardeningCheck,
    OSInfo,
    ScanResult,
)
from tools.system_scanner.domain.enums import OSPlatform

# ===========================================================================
# Helpers
# ===========================================================================


def _check(
    check_id: str,
    *,
    passed: bool = True,
    severity: Severity = Severity.MEDIUM,
) -> HardeningCheck:
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=passed,
        severity=severity,
    )


def _scan(*checks: HardeningCheck) -> ScanResult:
    return ScanResult(
        scan_id="test",
        timestamp=datetime(2026, 5, 11, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=list(checks),
    )


# ===========================================================================
# build_system_scanner_component
# ===========================================================================


class TestBuildSystemScannerComponent:
    def test_empty_checks_returns_none(self):
        assert build_system_scanner_component([]) is None

    def test_all_passed_yields_score_100(self):
        checks = [_check(f"SH-00{i}", passed=True) for i in range(1, 6)]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        assert comp.score == 100.0
        assert comp.findings_critical == 0
        assert comp.findings_high == 0
        assert comp.source_tool == "system_scanner"
        assert comp.name == "System-Hardening"

    def test_all_failed_yields_score_0(self):
        checks = [_check(f"SH-00{i}", passed=False, severity=Severity.CRITICAL) for i in range(1, 6)]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        assert comp.score == 0.0
        assert comp.findings_critical == 5

    def test_partial_pass(self):
        # 3 passed, 2 failed (1 critical + 1 high) → score = 60.0
        checks = [
            _check("SH-001", passed=True),
            _check("SH-002", passed=True),
            _check("SH-003", passed=True),
            _check("SH-004", passed=False, severity=Severity.CRITICAL),
            _check("SH-005", passed=False, severity=Severity.HIGH),
        ]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        assert comp.score == 60.0
        assert comp.findings_critical == 1
        assert comp.findings_high == 1
        assert comp.findings_medium == 0

    def test_details_string(self):
        checks = [_check("SH-001", passed=True), _check("SH-002", passed=False)]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        assert "1/2 Checks" in comp.details

    def test_severity_medium_counted(self):
        checks = [
            _check("SH-006", passed=False, severity=Severity.MEDIUM),
            _check("SH-007", passed=False, severity=Severity.MEDIUM),
        ]
        comp = build_system_scanner_component(checks)
        assert comp is not None
        assert comp.findings_medium == 2


# ===========================================================================
# ScoringService.compute_hardening_score
# ===========================================================================


class TestScoringServiceCompute:
    def test_empty_service_no_scan(self):
        # Kein Sub-Service injiziert + kein scan_result → 0.0 Critical
        service = ScoringService()
        result = service.compute_hardening_score()
        assert result.overall_score == 0.0
        assert result.stage.label == "Critical"
        assert result.category_scores == ()

    def test_with_scan_result_adds_kategorie_e(self):
        # ScanResult mit 5 passed Checks → Kategorie E mit 100%
        # Andere Kategorien fehlen → Redistribute → Score = 100
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=True),
            _check("SH-002", passed=True),
            _check("SH-003", passed=True),
            _check("SH-004", passed=True),
            _check("SH-005", passed=True),
        )
        result = service.compute_hardening_score(scan_result=scan)
        assert result.overall_score == 100.0
        assert result.stage.label == "Secure"
        # Kategorie E ist anwesend
        present_categories = {cs.category for cs in result.category_scores}
        assert HardeningCategory.SYSTEM_HARDENING in present_categories

    def test_scan_with_failed_firewall_triggers_cap(self):
        # Base-Score hoch: 9 von 10 Checks passed = 90% → ueber Cap 4 (60)
        # SH-001 failed → Cap 4 clampt von 90 auf 60.
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=False, severity=Severity.CRITICAL),
            _check("SH-002", passed=True),
            _check("SH-003", passed=True),
            _check("SH-004", passed=True),
            _check("SH-005", passed=True),
            _check("SH-006", passed=True),
            _check("SH-007", passed=True),
            _check("SH-008", passed=True),
            _check("SH-009", passed=True),
            _check("SH-010", passed=True),
        )
        result = service.compute_hardening_score(scan_result=scan)
        # Base-Score = 90, Cap 4 = 60, clampt auf 60
        assert result.overall_score == 60.0
        cap_triggers = {e.triggered_by for e in result.hard_cap_events}
        assert "SH-001" in cap_triggers
        # Raw-Score erhalten fuer UI-Hinweis
        assert result.raw_weighted_score == 90.0

    def test_scan_with_failed_rdp_triggers_cap(self):
        # Base-Score 90 + SH-003 failed → Cap 3 clampt auf 50
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=True),
            _check("SH-002", passed=True),
            _check("SH-003", passed=False, severity=Severity.CRITICAL),
            _check("SH-004", passed=True),
            _check("SH-005", passed=True),
            _check("SH-006", passed=True),
            _check("SH-007", passed=True),
            _check("SH-008", passed=True),
            _check("SH-009", passed=True),
            _check("SH-010", passed=True),
        )
        result = service.compute_hardening_score(scan_result=scan)
        assert result.overall_score == 50.0
        cap_triggers = {e.triggered_by for e in result.hard_cap_events}
        assert "SH-003" in cap_triggers
        assert result.raw_weighted_score == 90.0

    def test_both_caps_3_and_4_lowest_wins(self):
        # Base hoch genug, beide Caps aktiv → niedrigster (Cap 3 = 50) gewinnt
        # 8 von 10 passed = 80%, beide Critical-Caps active aber das
        # Cap-5 (≥3 critical) feuert nicht (nur 2 critical).
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=False, severity=Severity.CRITICAL),
            _check("SH-002", passed=True),
            _check("SH-003", passed=False, severity=Severity.CRITICAL),
            _check("SH-004", passed=True),
            _check("SH-005", passed=True),
            _check("SH-006", passed=True),
            _check("SH-007", passed=True),
            _check("SH-008", passed=True),
            _check("SH-009", passed=True),
            _check("SH-010", passed=True),
        )
        result = service.compute_hardening_score(scan_result=scan)
        assert result.overall_score == 50.0
        cap_values = {e.cap_value for e in result.hard_cap_events}
        assert cap_values == {50, 60}
        assert result.raw_weighted_score == 80.0

    def test_no_scan_no_caps_3_or_4(self):
        service = ScoringService()
        result = service.compute_hardening_score()
        cap_triggers = {e.triggered_by for e in result.hard_cap_events}
        # Cap 3+4 sind nicht in den Triggern (kein scan_result)
        assert "SH-001" not in cap_triggers
        assert "SH-003" not in cap_triggers

    def test_partial_compliant_scan(self):
        # 2 von 5 Checks passed = 40% → Kategorie-E-Score = 40
        # Mit nur Kategorie E present → Redistribute → overall_score = 40
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=True),
            _check("SH-002", passed=True),
            _check("SH-006", passed=False, severity=Severity.MEDIUM),
            _check("SH-007", passed=False, severity=Severity.HIGH),
            _check("SH-008", passed=False, severity=Severity.MEDIUM),
        )
        result = service.compute_hardening_score(scan_result=scan)
        # Kategorie-E-Score = 40 (2/5 = 40%). Nur Kategorie E present, also
        # bekommt sie 100% Gewicht → overall = 40
        assert result.overall_score == 40.0
        assert result.stage.label == "At Risk"

    def test_result_has_raw_weighted_score(self):
        service = ScoringService()
        scan = _scan(
            _check("SH-001", passed=False, severity=Severity.CRITICAL),  # Cap 60
        )
        result = service.compute_hardening_score(scan_result=scan)
        # raw_weighted_score = 0.0 (1 failed Check, 0% passed)
        # overall_score wird auf min(0.0, 60) = 0.0 geclampt — der Cap
        # bringt es nicht hoch, sondern nur runter.
        assert result.raw_weighted_score == 0.0
        # In diesem Fall ist raw schon niedriger als Cap, kein Cap wirkt
        assert result.overall_score == 0.0


# ===========================================================================
# KiTodoEmitter-Hook
# ===========================================================================


class TestKiTodoEmitterHook:
    """Verifiziert dass fehlgeschlagene Hardening-Checks an den
    KI-Todo-Emitter weitergereicht werden."""

    def test_failed_checks_emitted_to_ki_todo(self) -> None:
        from unittest.mock import MagicMock

        emitter = MagicMock()
        service = ScoringService(ki_todo_emitter=emitter)
        scan = _scan(
            _check("SH-001", passed=False, severity=Severity.HIGH),
            _check("SH-002", passed=True),
            _check("SH-006", passed=False, severity=Severity.MEDIUM),
        )
        service.compute_hardening_score(scan_result=scan)

        assert emitter.emit.call_count == 1
        emitted = emitter.emit.call_args[0][0]
        ids = sorted(f.evidence_id for f in emitted)
        assert ids == ["SH-001", "SH-006"]

    def test_all_passed_no_emit(self) -> None:
        from unittest.mock import MagicMock

        emitter = MagicMock()
        service = ScoringService(ki_todo_emitter=emitter)
        scan = _scan(
            _check("SH-001", passed=True),
            _check("SH-002", passed=True),
        )
        service.compute_hardening_score(scan_result=scan)
        # Adapter liefert leere Liste → emit wird nicht aufgerufen
        # (oder mit leerer Liste — beides akzeptabel; Service-Code prueft).
        # Wir testen die schwaechere Garantie: keine Findings.
        if emitter.emit.called:
            emitted = emitter.emit.call_args[0][0]
            assert emitted == []

    def test_no_scan_no_emit(self) -> None:
        from unittest.mock import MagicMock

        emitter = MagicMock()
        service = ScoringService(ki_todo_emitter=emitter)
        service.compute_hardening_score(scan_result=None)
        emitter.emit.assert_not_called()

    def test_emit_exception_does_not_break_score(self) -> None:
        """Hook ist fail-soft: KI-Todo-Emit-Fehler darf den Score nicht
        crashen. ScoringService gibt trotzdem ein valides Result zurueck."""
        from unittest.mock import MagicMock

        emitter = MagicMock()
        emitter.emit.side_effect = RuntimeError("mainpage-DB weg")
        service = ScoringService(ki_todo_emitter=emitter)
        scan = _scan(_check("SH-001", passed=False, severity=Severity.HIGH))
        result = service.compute_hardening_score(scan_result=scan)
        assert result is not None
        assert result.overall_score >= 0


# ===========================================================================
# C0b: Headless Baseline-Scan + Verdrahtung Kategorie E
# ===========================================================================


def _probe_with_registry_passes() -> MockHardeningProbe:
    """MockHardeningProbe mit voller Coverage: 4 passed, 6 failed (alle messbar).

    SH-002 (UAC), SH-003 (RDP=deaktiviert → kein Cap 3), SH-004 (AutoUpdate),
    SH-008 (Autorun) → passed (Registry). Die 6 Command-/PowerShell-Checks
    werden MESSBAR auf "failt" gesetzt: unkonfiguriert waeren sie
    measurable=False und faelschlich aus dem Nenner → 100 %; explizit gemessen
    ergibt 4/10 = 40 % bei voller Coverage). Nicht durch Caps gedeckelt
    (SH-001 failt → Cap 4 = 60 > 40, ohne Wirkung).
    """
    probe = MockHardeningProbe(available=True)
    probe.set_registry_value(
        HIVE_HKLM,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "EnableLUA",
        "1",
    )
    probe.set_registry_value(
        HIVE_HKLM,
        "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        "fDenyTSConnections",
        "1",
    )
    # SH-004: Dienst nicht deaktiviert + frische letzte Suche -> passed.
    # AUOptions=4 bleibt als positiver Overlay (managed) gesetzt.
    probe.set_registry_value(
        HIVE_HKLM, _WUAUSERV_START_KEY, _WUAUSERV_START_VALUE, "2"
    )
    probe.set_registry_value(
        HIVE_HKLM,
        _WU_RESULTS_DETECT_KEY,
        _WU_LAST_SUCCESS_VALUE,
        (datetime.now(UTC) - timedelta(days=1)).strftime(_WU_TIMESTAMP_FORMAT),
    )
    probe.set_registry_value(
        HIVE_HKLM,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
        "AUOptions",
        "4",
    )
    probe.set_registry_value(
        HIVE_HKLM,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "NoDriveTypeAutoRun",
        "255",
    )
    # Die 6 Command-/PowerShell-Checks MESSBAR auf "failt" setzen (volle Coverage).
    probe.set_powershell_result(_PS_FIREWALL_PROFILES, stdout="1,0,1")  # SH-001
    probe.set_powershell_result(
        "(Get-SmbServerConfiguration).EnableSMB1Protocol", stdout="True"
    )  # SH-005
    probe.set_powershell_result(_PS_GUEST_ACCOUNT, stdout="enabled")  # SH-006
    probe.set_command_result(
        "net",
        ["accounts"],
        stdout="Minimum password length:                  4\n",
    )  # SH-007
    probe.set_powershell_result(_PS_LOCAL_ADMINS_COUNT, stdout="5")  # SH-009
    probe.set_powershell_result(_PS_BITLOCKER_C, stdout="Off")  # SH-010
    return probe


class TestRunHardeningBaselineScan:
    def test_non_windows_probe_returns_none(self):
        # Probe nicht verfuegbar (= Non-Windows) → kein irrefuehrendes
        # all-failed ScanResult, sondern None (Kategorie E bleibt leer).
        assert run_hardening_baseline_scan(MockHardeningProbe(available=False)) is None

    def test_available_probe_builds_scanresult_with_10_checks(self):
        scan = run_hardening_baseline_scan(MockHardeningProbe(available=True))
        assert scan is not None
        assert len(scan.hardening_checks) == 10
        assert scan.os_info.platform == OSPlatform.WINDOWS
        assert scan.scan_id  # nicht leer

    def test_configured_probe_propagates_passed_checks(self):
        scan = run_hardening_baseline_scan(_probe_with_registry_passes())
        assert scan is not None
        passed_ids = {c.check_id for c in scan.hardening_checks if c.passed}
        assert {"SH-002", "SH-003", "SH-004", "SH-008"} <= passed_ids


class TestBerechneUndPersistiereBaseline:
    def test_non_windows_keine_kategorie_e(self):
        from unittest.mock import MagicMock

        service = ScoringService(ki_todo_emitter=MagicMock())
        result = service.berechne_und_persistiere_baseline(
            "Test-Baseline", probe=MockHardeningProbe(available=False)
        )
        present = {cs.category for cs in result.category_scores}
        assert HardeningCategory.SYSTEM_HARDENING not in present
        assert HardeningCategory.SYSTEM_HARDENING in result.missing_categories

    def test_windows_probe_kategorie_e_present(self):
        from unittest.mock import MagicMock

        service = ScoringService(ki_todo_emitter=MagicMock())
        result = service.berechne_und_persistiere_baseline(
            "Test-Baseline", probe=_probe_with_registry_passes()
        )
        present = {cs.category for cs in result.category_scores}
        assert HardeningCategory.SYSTEM_HARDENING in present
        # 4/10 Checks passed = 40 %; SH-003 passed → kein Cap 3,
        # SH-001 failt → Cap 4 (60) > 40, also ungedeckelt.
        assert result.overall_score == 40.0

    def test_baseline_persisted_and_readable(self):
        # Voller headless-Pfad: scan → score → persist → wieder lesbar
        # (genau das, was der Fleet-SecurityScoringProvider liest).
        from unittest.mock import MagicMock

        target = "Test-Baseline-Persist"
        service = ScoringService(ki_todo_emitter=MagicMock())
        service.berechne_und_persistiere_baseline(
            target, probe=_probe_with_registry_passes()
        )
        geladen = service.lade_letztes_hardening_result(target)
        assert geladen is not None
        present = {cs.category for cs in geladen.category_scores}
        assert HardeningCategory.SYSTEM_HARDENING in present
