"""
test_hardening_storytelling_adapter — Tests fuer den system_scanner →
KI-Todo-Adapter.

Deckt:
    *:func:`hardening_checks_to_findings` — nur ``passed=False`` wird
      konvertiert, Reihenfolge bleibt erhalten.
    * Finding-Felder: tool/finding_type/severity/subject/evidence_id +
      ``details["check_id"|"label"|"detail"]``.
    * Pydantic-Validierungs-Fehler eines einzelnen Checks killt nicht
      den ganzen Batch.
    * Volle Pipeline: Rule-Engine matched das ``hardening.yaml``-Match.
    * Storytelling-Template ``_render_hardening_check_failed`` rendert
      sinnvolle Headline/Explanation/Action.
"""

from __future__ import annotations

from pathlib import Path

from core.rules.rule_engine import RuleEngine
from core.security.severity import Severity
from core.storytelling.narrative_builder import build_story
from tools.system_scanner.application.storytelling_adapter import (
    FINDING_TYPE,
    TOOL_NAME,
    hardening_checks_to_findings,
)
from tools.system_scanner.domain.entities import HardeningCheck


def _check(check_id: str, passed: bool, *, severity: Severity = Severity.HIGH) -> HardeningCheck:
    return HardeningCheck(
        check_id=check_id,
        label=f"Check {check_id}",
        passed=passed,
        severity=severity,
        detail=f"detail-{check_id}",
    )


class TestHardeningChecksToFindings:
    def test_only_failed_checks_become_findings(self) -> None:
        checks = [
            _check("SH-001", passed=False),
            _check("SH-002", passed=True),
            _check("SH-003", passed=False),
        ]
        findings = hardening_checks_to_findings(checks)
        ids = [f.evidence_id for f in findings]
        assert ids == ["SH-001", "SH-003"]

    def test_empty_input_returns_empty(self) -> None:
        assert hardening_checks_to_findings([]) == []

    def test_all_passed_returns_empty(self) -> None:
        checks = [_check("SH-001", passed=True), _check("SH-002", passed=True)]
        assert hardening_checks_to_findings(checks) == []

    def test_finding_fields_mapped_correctly(self) -> None:
        check = HardeningCheck(
            check_id="SH-006",
            label="UAC aktiv",
            passed=False,
            severity=Severity.MEDIUM,
            detail="EnableLUA=0",
        )
        findings = hardening_checks_to_findings([check])
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == TOOL_NAME == "system_scanner"
        assert f.finding_type == FINDING_TYPE == "hardening_check_failed"
        assert f.severity == Severity.MEDIUM
        assert f.subject == "UAC aktiv"
        assert f.evidence_id == "SH-006"
        assert f.details == {
            "check_id": "SH-006",
            "label": "UAC aktiv",
            "detail": "EnableLUA=0",
        }

    def test_check_with_empty_label_falls_back_to_check_id(self) -> None:
        check = HardeningCheck(
            check_id="SH-007",
            label="",
            passed=False,
            severity=Severity.LOW,
            detail="",
        )
        findings = hardening_checks_to_findings([check])
        assert len(findings) == 1
        # subject muss non-empty sein (pydantic min_length=1)
        assert findings[0].subject == "SH-007"

    def test_order_preserved(self) -> None:
        checks = [
            _check("SH-005", passed=False),
            _check("SH-001", passed=False),
            _check("SH-009", passed=False),
        ]
        findings = hardening_checks_to_findings(checks)
        assert [f.evidence_id for f in findings] == ["SH-005", "SH-001", "SH-009"]


class TestRuleEngineMatch:
    """Volle Pipeline: Adapter-Output → RuleEngine matches die
    ``configs/rules/hardening.yaml``-Regel."""

    def test_high_severity_finding_matches_hardening_rule(self) -> None:
        eng = RuleEngine.from_directory(Path("configs/rules"))
        check = _check("SH-001", passed=False, severity=Severity.HIGH)
        finding = hardening_checks_to_findings([check])[0]
        actions = eng.evaluate(finding)
        assert len(actions) == 1
        assert actions[0].rule_id == "hardening_check_failed"

    def test_low_severity_finding_does_not_match(self) -> None:
        """Rule hat ``min_severity: medium`` — LOW darf nicht matchen."""
        eng = RuleEngine.from_directory(Path("configs/rules"))
        check = _check("SH-010", passed=False, severity=Severity.LOW)
        finding = hardening_checks_to_findings([check])[0]
        actions = eng.evaluate(finding)
        assert actions == []


class TestStorytellingTemplate:
    def test_template_renders_full_story(self) -> None:
        check = HardeningCheck(
            check_id="SH-001",
            label="Firewall aktiv",
            passed=False,
            severity=Severity.HIGH,
            detail="Domain-Profil deaktiviert",
        )
        finding = hardening_checks_to_findings([check])[0]
        story = build_story(finding)
        assert "Firewall aktiv" in story.headline
        assert "SH-001" in story.explanation
        assert "Domain-Profil deaktiviert" in story.explanation
        assert "Firewall aktiv" in story.action
        # Urgency aus Severity HIGH → wichtig (laut _urgency_from_severity).
        assert story.urgency.value in ("wichtig", "akut")

    def test_template_handles_missing_detail_gracefully(self) -> None:
        check = HardeningCheck(
            check_id="SH-002",
            label="Defender aktiv",
            passed=False,
            severity=Severity.HIGH,
            detail="",
        )
        finding = hardening_checks_to_findings([check])[0]
        story = build_story(finding)
        # Ohne detail bleibt die Headline + Action sinnvoll.
        assert "Defender aktiv" in story.headline
        assert "Defender aktiv" in story.action
