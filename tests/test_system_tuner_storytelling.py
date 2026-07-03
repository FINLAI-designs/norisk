"""
test_system_tuner_storytelling — Template-Rendering (system_tuner Phase 1c).

Verifiziert, dass der finding_type ``privacy_default_risky`` registriert ist
und der:func:`core.storytelling.narrative_builder.build_story` daraus eine
sinnvolle Story (Headline/Explanation/Action) baut.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any

from core.storytelling.finding_templates import TEMPLATES
from core.storytelling.narrative_builder import build_story
from tools.system_tuner.application.catalog_loader import load_catalog_from_mapping
from tools.system_tuner.application.storytelling_adapter import (
    FINDING_TYPE,
    TOOL_NAME,
    tweak_findings,
)
from tools.system_tuner.domain.entities import TweakState
from tools.system_tuner.domain.enums import TweakStatus


def _tweak() -> Any:
    mapping = {
        "catalog_version": "1.0",
        "tweaks": [
            {
                "id": "TW-X",
                "title_de": "Windows-Telemetrie auf Minimum",
                "category": "telemetry",
                "risk_tier": "T1_safe",
                "recommend": "standard",
                "rationale_de": "Reduziert optionale Diagnosedaten.",
                "docs_url": "https://learn.microsoft.com/x",
                "compliance_relevance": ["Unterstuetzt DSGVO Art. 32 (TOM)"],
                "provenance": {"source": "MS"},
                "change": {
                    "op": "registry_set",
                    "hive": "HKLM",
                    "key": "SOFTWARE\\X",
                    "value_name": "V",
                    "value_type": "REG_DWORD",
                    "desired": 1,
                },
                "verify": {"expect_value": 1},
                "revert": {"kind": "restore_prior"},
            }
        ],
    }
    return load_catalog_from_mapping(mapping)


def test_template_registered() -> None:
    assert (TOOL_NAME, FINDING_TYPE) in TEMPLATES


def test_build_story_from_not_applied_finding() -> None:
    tweaks = _tweak()
    states = [TweakState(tweak_id="TW-X", status=TweakStatus.NOT_APPLIED)]
    findings = tweak_findings(tweaks, states)
    assert len(findings) == 1
    story = build_story(findings[0])
    assert "Windows-Telemetrie auf Minimum" in story.headline
    assert story.explanation
    assert "System optimieren" in story.action
    assert story.evidence_finding_id == "TW-X"
