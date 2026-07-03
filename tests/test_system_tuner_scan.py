"""
test_system_tuner_scan — Read-only Scan (system_tuner Phase 1b).

Edition-Gate, Managed-Mode, Scan-Use-Case, Privacy-Score und Storytelling-
Adapter — alle gegen den deterministischen MockHardeningProbe (kein Windows).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from core.probes.hardening_probe import HIVE_HKLM
from core.probes.mock_hardening_probe import MockHardeningProbe
from core.storytelling.schemas import FindingInput
from tools.system_tuner.application.catalog_loader import load_catalog_from_mapping
from tools.system_tuner.application.edition_gate import EditionGate
from tools.system_tuner.application.managed_mode import ManagedModeDetector
from tools.system_tuner.application.storytelling_adapter import (
    FINDING_TYPE,
    TOOL_NAME,
    tweak_findings,
)
from tools.system_tuner.application.tuner_scan_use_case import TunerScanUseCase
from tools.system_tuner.domain.entities import Tweak, TweakState
from tools.system_tuner.domain.enums import TweakStatus
from tools.system_tuner.domain.interfaces import ITweakCatalog
from tools.system_tuner.domain.privacy_score import compute_privacy_score

_CV_KEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
_SERVICES = "SYSTEM\\CurrentControlSet\\Services"


@pytest.fixture(autouse=True)
def _no_ki_todo_writes(monkeypatch):
    """-Emit-Hook in Unit-Tests neutralisieren.

    ``TunerScanUseCase.scan`` emittiert offene Empfehlungen an den
    ``KiTodoEmitter`` (mainpage-"Was tun?"-Karten). In diesen Unit-Tests darf
    das die reale mainpage-DB nicht beschreiben — der Default-Emitter wird auf
    No-op gepatcht. Tests mit eigenem Spy-Emitter bleiben unberuehrt.
    """
    monkeypatch.setattr(
        "core.storytelling.ki_todo_emitter.KiTodoEmitter.emit",
        lambda self, *a, **k: None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reg_tweak(tweak_id: str = "TW-R") -> dict[str, Any]:
    return {
        "id": tweak_id,
        "title_de": "Reg-Tweak",
        "category": "telemetry",
        "risk_tier": "T1_safe",
        "recommend": "standard",
        "rationale_de": "x",
        "docs_url": "https://learn.microsoft.com/x",
        "compliance_relevance": ["Unterstuetzt DSGVO Art. 32 (TOM)"],
        "provenance": {"source": "MS"},
        "change": {
            "op": "registry_set",
            "hive": "HKLM",
            "key": "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            "value_name": "AllowTelemetry",
            "value_type": "REG_DWORD",
            "desired": 1,
        },
        "verify": {"expect_value": 1},
        "revert": {"kind": "restore_prior"},
    }


def _svc_tweak(tweak_id: str = "TW-S", service: str = "DiagTrack") -> dict[str, Any]:
    return {
        "id": tweak_id,
        "title_de": "Svc-Tweak",
        "category": "services",
        "risk_tier": "T2_caution",
        "recommend": "standard",
        "rationale_de": "x",
        "docs_url": "https://learn.microsoft.com/x",
        "compliance_relevance": ["Unterstuetzt DSGVO Art. 5 Abs. 1 lit. c"],
        "provenance": {"source": "MS"},
        "change": {
            "op": "service_startmode",
            "service_name": service,
            "desired_start_mode": "manual",
        },
        "verify": {"expect_start_mode": "manual"},
        "revert": {"kind": "restore_prior"},
    }


def _tweaks(*mappings: dict[str, Any]) -> list[Tweak]:
    return load_catalog_from_mapping(
        {"catalog_version": "1.0", "tweaks": list(mappings)}
    )


class _StubCatalog(ITweakCatalog):
    def __init__(self, tweaks: list[Tweak]) -> None:
        self._tweaks = tweaks

    def load(self) -> list[Tweak]:
        return self._tweaks


def _state(tweak_id: str, status: TweakStatus) -> TweakState:
    return TweakState(tweak_id=tweak_id, status=status)


# ---------------------------------------------------------------------------
# Edition-Gate
# ---------------------------------------------------------------------------


class TestEditionGate:
    def test_pro_telemetry_zero_not_supported(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, _CV_KEY, "EditionID", "Professional")
        probe.set_registry_value(HIVE_HKLM, _CV_KEY, "ProductName", "Windows 11 Pro")
        info = EditionGate(probe).detect()
        assert info.telemetry_zero_supported is False
        assert "Erforderlich" in info.banner_de

    def test_enterprise_supports_zero(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, _CV_KEY, "EditionID", "Enterprise")
        info = EditionGate(probe).detect()
        assert info.telemetry_zero_supported is True
        assert "Aus (0)" in info.banner_de

    def test_unavailable_probe_conservative(self):
        info = EditionGate(MockHardeningProbe(available=False)).detect()
        assert info.edition_id is None
        assert info.telemetry_zero_supported is False

    def test_missing_edition_conservative(self):
        info = EditionGate(MockHardeningProbe()).detect()
        assert info.telemetry_zero_supported is False
        assert "nicht ermittelt" in info.banner_de


# ---------------------------------------------------------------------------
# Managed-Mode
# ---------------------------------------------------------------------------


class TestManagedMode:
    def test_domain_joined(self):
        probe = MockHardeningProbe()
        probe.set_command_result(
            "dsregcmd",
            ["/status"],
            stdout="DomainJoined : YES\nAzureAdJoined : NO\n",
        )
        info = ManagedModeDetector(probe).detect()
        assert info.domain_joined is True
        assert info.is_managed is True

    def test_mdm_enrolled(self):
        probe = MockHardeningProbe()
        probe.set_command_result(
            "dsregcmd",
            ["/status"],
            stdout="AzureAdJoined : YES\nMdmUrl : https://enrollment.manage.microsoft.com\n",
        )
        info = ManagedModeDetector(probe).detect()
        assert info.azure_ad_joined is True
        assert info.mdm_enrolled is True

    def test_not_managed(self):
        probe = MockHardeningProbe()
        probe.set_command_result(
            "dsregcmd",
            ["/status"],
            stdout="DomainJoined : NO\nAzureAdJoined : NO\n",
        )
        info = ManagedModeDetector(probe).detect()
        assert info.is_managed is False
        assert "nicht zentral verwaltet" in info.detail_de

    def test_command_unavailable(self):
        info = ManagedModeDetector(MockHardeningProbe()).detect()
        assert info.is_managed is False
        assert "unbekannt" in info.detail_de


# ---------------------------------------------------------------------------
# Scan-Use-Case
# ---------------------------------------------------------------------------


class TestScanUseCase:
    def test_registry_applied(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            "AllowTelemetry",
            "1",
        )
        report = TunerScanUseCase(probe, _StubCatalog(_tweaks(_reg_tweak()))).scan()
        assert report.states[0].status is TweakStatus.APPLIED
        assert report.score.value == 100

    def test_registry_not_applied_when_missing(self):
        probe = MockHardeningProbe()
        report = TunerScanUseCase(probe, _StubCatalog(_tweaks(_reg_tweak()))).scan()
        assert report.states[0].status is TweakStatus.NOT_APPLIED
        assert report.score.value == 0

    def test_service_applied(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, f"{_SERVICES}\\DiagTrack", "Start", "3")
        report = TunerScanUseCase(probe, _StubCatalog(_tweaks(_svc_tweak()))).scan()
        assert report.states[0].status is TweakStatus.APPLIED
        assert report.states[0].current_value == "manual"

    def test_service_not_applied(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, f"{_SERVICES}\\DiagTrack", "Start", "2")
        report = TunerScanUseCase(probe, _StubCatalog(_tweaks(_svc_tweak()))).scan()
        assert report.states[0].status is TweakStatus.NOT_APPLIED

    def test_service_unknown_when_missing(self):
        probe = MockHardeningProbe()
        report = TunerScanUseCase(probe, _StubCatalog(_tweaks(_svc_tweak()))).scan()
        assert report.states[0].status is TweakStatus.UNKNOWN
        assert "nicht gefunden" in report.states[0].detail

    def test_non_windows_all_unknown(self):
        probe = MockHardeningProbe(available=False)
        report = TunerScanUseCase(
            probe, _StubCatalog(_tweaks(_reg_tweak(), _svc_tweak()))
        ).scan()
        assert all(s.status is TweakStatus.UNKNOWN for s in report.states)
        assert report.score.label_de == "Unbekannt"


# ---------------------------------------------------------------------------
# Privacy-Score
# ---------------------------------------------------------------------------


class TestPrivacyScore:
    def test_all_applied(self):
        score = compute_privacy_score(
            [_state("a", TweakStatus.APPLIED), _state("b", TweakStatus.APPLIED)]
        )
        assert score.value == 100
        assert score.label_de == "Gut"

    def test_half_applied(self):
        score = compute_privacy_score(
            [_state("a", TweakStatus.APPLIED), _state("b", TweakStatus.NOT_APPLIED)]
        )
        assert score.value == 50
        assert score.label_de == "Ausbaufaehig"

    def test_none_applied(self):
        score = compute_privacy_score([_state("a", TweakStatus.NOT_APPLIED)])
        assert score.value == 0
        assert score.label_de == "Schwach"

    def test_all_unknown(self):
        score = compute_privacy_score([_state("a", TweakStatus.UNKNOWN)])
        assert score.applicable == 0
        assert score.label_de == "Unbekannt"

    def test_disclaimer_present(self):
        score = compute_privacy_score([_state("a", TweakStatus.APPLIED)])
        assert "kein Compliance-Nachweis" in score.disclaimer_de


# ---------------------------------------------------------------------------
# Storytelling-Adapter
# ---------------------------------------------------------------------------


class TestStorytellingAdapter:
    def test_only_not_applied_becomes_finding(self):
        tweaks = _tweaks(_reg_tweak("TW-A"), _svc_tweak("TW-B"))
        states = [
            _state("TW-A", TweakStatus.NOT_APPLIED),
            _state("TW-B", TweakStatus.APPLIED),
        ]
        findings = tweak_findings(tweaks, states)
        assert len(findings) == 1
        assert findings[0].evidence_id == "TW-A"
        assert findings[0].tool == TOOL_NAME
        assert findings[0].finding_type == FINDING_TYPE
        assert isinstance(findings[0], FindingInput)

    def test_unknown_produces_no_finding(self):
        tweaks = _tweaks(_reg_tweak("TW-A"))
        findings = tweak_findings(tweaks, [_state("TW-A", TweakStatus.UNKNOWN)])
        assert findings == []

    def test_details_carry_rationale_and_docs(self):
        tweaks = _tweaks(_reg_tweak("TW-A"))
        findings = tweak_findings(tweaks, [_state("TW-A", TweakStatus.NOT_APPLIED)])
        assert "rationale" in findings[0].details
        assert findings[0].details["docs_url"].startswith("https://")


def test_scan_emits_open_recommendations_to_ki_emitter() -> None:
    """scan reicht die offene Empfehlungsmenge an den KiTodoEmitter.

    Voll-Sync ueber ``reconcile_tool`` -> erledigte "Was tun?"-Karten schliessen
    beim naechsten Scan. Der Spy-Emitter ist von der autouse-Fixture unberuehrt.
    """
    spy = MagicMock()
    use_case = TunerScanUseCase(
        MockHardeningProbe(),
        _StubCatalog(_tweaks(_reg_tweak("TW-A"))),
        ki_todo_emitter=spy,
    )
    use_case.scan()
    spy.emit.assert_called_once()
    assert spy.emit.call_args.kwargs.get("reconcile_tool") == TOOL_NAME
