"""
test_patch_storytelling_adapter — Tests fuer den patch_monitor → KI-Todo-
Adapter.

Deckt:
    *:func:`patch_results_to_findings` — Recommendation → finding_type
      mapping, severity-Default, ``up_to_date``/``pinned``/``notify_only``
      werden geskippt.
    * Dedup-Strategie: ``evidence_id = winget_id`` (oder
      ``normalized_name``-Fallback bei Registry-/MSIX-Apps).
    * Volle Pipeline: Rule-Engine matched die ``patch_monitor.yaml``-Regeln.
    * Storytelling-Template ``_render_patch_recommendation`` rendert
      tonal unterschiedliche Headlines pro Recommendation-Klasse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.patch_result import PatchScanResult, Recommendation
from core.rules.rule_engine import RuleEngine
from core.storytelling.narrative_builder import build_story
from core.vulnerability.domain.severity import Severity
from tools.patch_monitor.application.storytelling_adapter import (
    TOOL_NAME,
    patch_results_to_findings,
)


def _result(
    name: str,
    recommendation: Recommendation,
    *,
    winget_id: str | None = "Vendor.Pkg",
    available: str | None = "2.0",
    cve_ids: tuple = (),
    cvss: float | None = None,
    eol: bool = False,
) -> PatchScanResult:
    return PatchScanResult(
        name=name,
        normalized_name=name.lower(),
        vendor="Vendor",
        winget_id=winget_id,
        source="winget",
        installed_version="1.0",
        available_version=available,
        channel="stable",
        policy_source="default",
        cve_ids=cve_ids,
        cvss_max=cvss,
        exploit_available=bool(cve_ids),
        eol=eol,
        confidence_score=1.0,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


class TestRecommendationMapping:
    def test_update_urgent_maps_to_high_severity(self) -> None:
        r = _result("Firefox", "update_urgent")
        findings = patch_results_to_findings([r])
        assert len(findings) == 1
        assert findings[0].finding_type == "patch_update_urgent"
        assert findings[0].severity == Severity.HIGH

    def test_eol_no_patch_maps_to_high_severity(self) -> None:
        r = _result("Old SW", "eol_no_patch", available=None, eol=True)
        findings = patch_results_to_findings([r])
        assert len(findings) == 1
        assert findings[0].finding_type == "patch_eol_no_patch"
        assert findings[0].severity == Severity.HIGH

    def test_workaround_available_maps_to_medium(self) -> None:
        r = _result("OpenSSL", "workaround_available")
        findings = patch_results_to_findings([r])
        assert findings[0].finding_type == "patch_workaround_available"
        assert findings[0].severity == Severity.MEDIUM

    def test_patch_with_csaf_context_maps_to_medium(self) -> None:
        r = _result("Cisco-X", "patch_available_with_csaf_context")
        findings = patch_results_to_findings([r])
        assert findings[0].finding_type == "patch_with_csaf_context"
        assert findings[0].severity == Severity.MEDIUM

    def test_update_maps_to_update_available(self) -> None:
        r = _result("VLC", "update")
        findings = patch_results_to_findings([r])
        assert findings[0].finding_type == "patch_update_available"

    def test_update_available_maps_to_update_available(self) -> None:
        r = _result("VLC", "update_available")
        findings = patch_results_to_findings([r])
        assert findings[0].finding_type == "patch_update_available"


# ---------------------------------------------------------------------------
# Skip-Klassen
# ---------------------------------------------------------------------------


class TestSkippedRecommendations:
    @pytest.mark.parametrize("rec", ["up_to_date", "pinned", "notify_only"])
    def test_non_actionable_recommendations_skipped(
        self, rec: Recommendation,
    ) -> None:
        r = _result("X", rec)
        assert patch_results_to_findings([r]) == []

    def test_mixed_batch_only_actionable_emitted(self) -> None:
        results = [
            _result("A", "update_urgent", winget_id="Vendor.A"),
            _result("B", "up_to_date", winget_id="Vendor.B"),
            _result("C", "eol_no_patch", winget_id="Vendor.C"),
            _result("D", "pinned", winget_id="Vendor.D"),
            _result("E", "notify_only", winget_id="Vendor.E"),
            _result("F", "update_available", winget_id="Vendor.F"),
        ]
        findings = patch_results_to_findings(results)
        ids = [f.evidence_id for f in findings]
        assert ids == ["Vendor.A", "Vendor.C", "Vendor.F"]


# ---------------------------------------------------------------------------
# Evidence-ID
# ---------------------------------------------------------------------------


class TestEvidenceId:
    def test_winget_id_preferred(self) -> None:
        r = _result("X", "update_urgent", winget_id="Vendor.X")
        findings = patch_results_to_findings([r])
        assert findings[0].evidence_id == "Vendor.X"

    def test_normalized_name_fallback_when_no_winget_id(self) -> None:
        """Registry-/MSIX-Apps haben kein winget_id → normalized_name nutzen."""
        r = _result("RegistryApp", "update_urgent", winget_id=None)
        findings = patch_results_to_findings([r])
        # _result setzt normalized_name = name.lower
        assert findings[0].evidence_id == "registryapp"

    def test_no_evidence_id_skipped(self) -> None:
        """Wenn weder winget_id noch normalized_name vorhanden ist (edge
        case), wird der Result uebersprungen statt mit leerem evidence_id
        zu crashen (Pydantic min_length=1)."""
        r = PatchScanResult(
            name="ghost",
            normalized_name="",  # leer
            vendor=None,
            winget_id=None,
            source="winget",
            installed_version="1.0",
            available_version="2.0",
            channel="stable",
            policy_source="default",
            cve_ids=(),
            cvss_max=None,
            exploit_available=False,
            eol=False,
            confidence_score=1.0,
            recommendation="update_urgent",
        )
        assert patch_results_to_findings([r]) == []


# ---------------------------------------------------------------------------
# Rule-Engine match
# ---------------------------------------------------------------------------


class TestRuleEngineMatch:
    def test_update_urgent_matches_rule(self) -> None:
        eng = RuleEngine.from_directory(Path("configs/rules"))
        r = _result("Firefox", "update_urgent")
        finding = patch_results_to_findings([r])[0]
        actions = eng.evaluate(finding)
        assert len(actions) == 1
        assert actions[0].rule_id == "patch_update_urgent"

    def test_eol_matches_rule(self) -> None:
        eng = RuleEngine.from_directory(Path("configs/rules"))
        r = _result("Old SW", "eol_no_patch", available=None, eol=True)
        finding = patch_results_to_findings([r])[0]
        actions = eng.evaluate(finding)
        assert len(actions) == 1
        assert actions[0].rule_id == "patch_eol_no_patch"

    def test_workaround_matches_rule(self) -> None:
        eng = RuleEngine.from_directory(Path("configs/rules"))
        r = _result("OpenSSL", "workaround_available")
        finding = patch_results_to_findings([r])[0]
        actions = eng.evaluate(finding)
        assert actions[0].rule_id == "patch_workaround_available"

    def test_update_available_matches_rule(self) -> None:
        eng = RuleEngine.from_directory(Path("configs/rules"))
        r = _result("VLC", "update_available")
        finding = patch_results_to_findings([r])[0]
        actions = eng.evaluate(finding)
        assert actions[0].rule_id == "patch_update_available"


# ---------------------------------------------------------------------------
# Storytelling-Render
# ---------------------------------------------------------------------------


class TestStorytellingRender:
    def test_update_urgent_template_includes_winget_command(self) -> None:
        r = _result(
            "Firefox", "update_urgent",
            cve_ids=("CVE-2024-1234",), cvss=8.5,
        )
        finding = patch_results_to_findings([r])[0]
        story = build_story(finding)
        assert "Firefox" in story.headline
        assert "winget upgrade" in story.action
        assert story.urgency.value == "akut"
        # CVE-Hinweis in der Explanation
        assert "CVE-2024-1234" in story.explanation

    def test_eol_template_recommends_migration(self) -> None:
        r = _result("Old SW", "eol_no_patch", available=None, eol=True)
        finding = patch_results_to_findings([r])[0]
        story = build_story(finding)
        assert "End-of-Life" in story.headline or "EOL" in story.headline
        assert "migrieren" in story.action.lower() or "ersetz" in story.action.lower()

    def test_workaround_template_mentions_csaf_advisor(self) -> None:
        r = _result(
            "OpenSSL", "workaround_available",
            cve_ids=("CVE-2024-5678",),
        )
        finding = patch_results_to_findings([r])[0]
        story = build_story(finding)
        assert "Workaround" in story.headline or "workaround" in story.action.lower()

    def test_update_available_template_is_less_urgent(self) -> None:
        r = _result("VLC", "update_available", available="3.0.21")
        finding = patch_results_to_findings([r])[0]
        story = build_story(finding)
        assert story.urgency.value in ("trend", "kontext")
        assert "3.0.21" in story.headline


# ---------------------------------------------------------------------------
# Tool-name constant
# ---------------------------------------------------------------------------


class TestToolName:
    def test_tool_name_is_patch_monitor(self) -> None:
        assert TOOL_NAME == "patch_monitor"

    def test_findings_carry_tool_name(self) -> None:
        r = _result("X", "update_urgent")
        findings = patch_results_to_findings([r])
        assert findings[0].tool == "patch_monitor"
