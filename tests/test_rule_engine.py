"""Tests für die Regel-Engine + Klassifikator (Sprint S2a).

Pure-Python-Tests — kein PySide6, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.rules.classifier import classify, severity_class_distribution
from core.rules.models import ClassifierHint, Rule, RuleMatch
from core.rules.rule_engine import RuleEngine, RuleLoadError
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity

# ---------------------------------------------------------------------------
# Klassifikator H1–H12
# ---------------------------------------------------------------------------


def test_classify_quick_win_alle_h1_h2_h3():
    """Quick-Indikatoren: Action-Keyword + asset_count=1 + kein Block-Wort."""
    text = "Auf Version 1.1.1z updaten."
    hint = ClassifierHint(asset_count=1)
    assert classify(text, hint) == "quick"


def test_classify_quick_win_via_hint_keywords():
    """Hint-Keywords werden virtuell an den Action-Text angehängt."""
    text = "Erneuern."  # weder 'update' noch 'renew' im Text direkt
    hint = ClassifierHint(asset_count=1, action_keywords=["renew"])
    assert classify(text, hint) == "quick"


def test_classify_blockt_quick_bei_schulung_h3():
    """Selbst mit Update-Verb fällt 'Schulung' auf Mittel zurück (H3)."""
    text = "Update-Schulung fuer Admins."
    hint = ClassifierHint(asset_count=1, action_keywords=["update"])
    # 'Schulung' triggert _QUICK_BLOCKLIST → H3 false → Default 'mittel'
    assert classify(text, hint) == "mittel"


def test_classify_mittel_via_keywords_h5():
    """'Migriere' triggert Mittel auch bei Single-Asset."""
    text = "Migriere die API auf neuen Auth-Provider."
    hint = ClassifierHint(asset_count=1)
    assert classify(text, hint) == "mittel"


def test_classify_mittel_via_asset_count_h6():
    """Asset-Count 2..50 trifft Mittel-Bucket."""
    text = "Update OpenSSL."  # eigentlich Quick-Keyword
    hint = ClassifierHint(asset_count=10)
    assert classify(text, hint) == "mittel"


def test_classify_langfrist_iso_h9():
    """ISO 27001 ist organisationale Aufgabe → langfrist."""
    text = "ISO 27001-Zertifizierung anstreben."
    assert classify(text) == "langfrist"


def test_classify_langfrist_vendor_h10():
    """Enterprise-Vendor (z. B. Splunk) → langfrist."""
    text = "Splunk-Cluster aufsetzen."
    assert classify(text) == "langfrist"


def test_classify_langfrist_timeword_h11():
    """Wiederkehrungs-Marker → langfrist."""
    text = "Quartalsweise Pen-Tests etablieren."
    assert classify(text) == "langfrist"


def test_classify_langfrist_asset_count_h12():
    """asset_count > 50 → langfrist (egal welches Wort)."""
    text = "Update on every machine."
    hint = ClassifierHint(asset_count=80)
    assert classify(text, hint) == "langfrist"


def test_classify_default_mittel_tiebreaker():
    """Tiebreaker laut AI_TODO 4.2: konservativer = Mittel."""
    text = "Etwas tun, das keine Heuristik anspricht."
    hint = ClassifierHint(asset_count=1)
    assert classify(text, hint) == "mittel"


def test_severity_class_distribution_default():
    """severity_class_distribution liefert die AI_TODO 4.3-Defaults."""
    assert severity_class_distribution(Severity.CRITICAL) == "quick"
    assert severity_class_distribution(Severity.HIGH) == "mittel"
    assert severity_class_distribution(Severity.MEDIUM) == "mittel"
    assert severity_class_distribution(Severity.LOW) == "langfrist"
    assert severity_class_distribution(Severity.INFO) == "langfrist"


# ---------------------------------------------------------------------------
# YAML-Lader
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, name: str, content: object) -> Path:
    """Schreibt eine YAML-Datei ins ``tmp_path`` und gibt den Pfad zurück."""
    path = tmp_path / name
    path.write_text(yaml.safe_dump(content, allow_unicode=True), encoding="utf-8")
    return path


def test_engine_laedt_aus_konfigverzeichnis(tmp_path: Path):
    """Engine liest alle ``*.yaml``-Dateien rekursiv ein."""
    _write_yaml(
        tmp_path,
        "a.yaml",
        {
            "rules": [
                {
                    "id": "r1",
                    "match": {"tool": "cert_monitor", "finding_type": "x"},
                }
            ]
        },
    )
    _write_yaml(
        tmp_path,
        "b.yaml",
        [
            {
                "id": "r2",
                "match": {"tool": "api_security", "finding_type": "y"},
            }
        ],
    )

    engine = RuleEngine.from_directory(tmp_path)
    assert engine.rule_count() == 2


def test_engine_ignoriert_kaputtes_yaml(tmp_path: Path):
    """Eine kaputte YAML-Datei darf den Lader nicht crashen."""
    (tmp_path / "broken.yaml").write_text("rules: [: this is not yaml", encoding="utf-8")
    _write_yaml(
        tmp_path,
        "ok.yaml",
        [{"id": "r1", "match": {"tool": "cert_monitor", "finding_type": "x"}}],
    )

    engine = RuleEngine.from_directory(tmp_path)
    assert engine.rule_count() == 1


def test_engine_leeres_verzeichnis(tmp_path: Path):
    """Existierender, aber leerer Ordner → Engine ohne Regeln, kein Crash."""
    engine = RuleEngine.from_directory(tmp_path)
    assert engine.rule_count() == 0


def test_engine_nicht_existierendes_verzeichnis(tmp_path: Path):
    """Nicht-existierendes Verzeichnis → leere Engine + Warnung."""
    engine = RuleEngine.from_directory(tmp_path / "nicht-da")
    assert engine.rule_count() == 0


def test_engine_yaml_mit_invalidem_match_raised_via_load(tmp_path: Path):
    """Schema-Verletzung wird vom Lader gefangen — Engine lädt Datei nicht."""
    _write_yaml(
        tmp_path,
        "bad.yaml",
        [{"id": "r1", "match": {"tool": ""}}],  # tool zu leer, finding_type fehlt
    )
    # ``from_directory`` fängt ``RuleLoadError`` und überspringt → Engine leer.
    engine = RuleEngine.from_directory(tmp_path)
    assert engine.rule_count() == 0


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


def _engine_with_one_rule(rule_id: str = "r1") -> RuleEngine:
    rule = Rule(
        id=rule_id,
        match=RuleMatch(
            tool="cert_monitor",
            finding_type="cert_expiring",
            min_severity=Severity.MEDIUM,
        ),
        classifier_hint=ClassifierHint(
            asset_count=1, action_keywords=["renew"]
        ),
    )
    return RuleEngine([rule])


def _finding(
    severity: Severity = Severity.HIGH,
    tool: str = "cert_monitor",
    finding_type: str = "cert_expiring",
) -> FindingInput:
    return FindingInput(
        tool=tool,
        finding_type=finding_type,
        severity=severity,
        subject="example.com",
        evidence_id="cert-1",
        details={"days_left": 5, "expires_at": "2026-05-04"},
    )


def test_evaluate_match_liefert_action():
    """Bei passender Tool/Type/Severity-Kombination kommt eine RuleAction zurück."""
    engine = _engine_with_one_rule()
    actions = engine.evaluate(_finding())
    assert len(actions) == 1
    assert actions[0].rule_id == "r1"
    assert actions[0].urgency == "quick"


def test_evaluate_severity_unter_min_kein_match():
    """Findings unter ``min_severity`` werden ignoriert."""
    engine = _engine_with_one_rule()
    actions = engine.evaluate(_finding(severity=Severity.LOW))
    assert actions == []


def test_evaluate_falsches_tool_kein_match():
    """Anderes Tool als in der Regel → keine Aktion."""
    engine = _engine_with_one_rule()
    actions = engine.evaluate(
        _finding(tool="dependency_auditor", finding_type="cert_expiring")
    )
    assert actions == []


def test_evaluate_falscher_finding_type_kein_match():
    """Anderer finding_type → keine Aktion."""
    engine = _engine_with_one_rule()
    actions = engine.evaluate(_finding(finding_type="cert_expired"))
    assert actions == []


def test_evaluate_mehrere_regeln_pro_finding():
    """Zwei Regeln auf demselben Tool/Type matchen beide."""
    rule_a = Rule(
        id="ra",
        match=RuleMatch(
            tool="cert_monitor", finding_type="cert_expiring",
        ),
    )
    rule_b = Rule(
        id="rb",
        match=RuleMatch(
            tool="cert_monitor", finding_type="cert_expiring",
        ),
    )
    engine = RuleEngine([rule_a, rule_b])
    actions = engine.evaluate(_finding())
    assert {a.rule_id for a in actions} == {"ra", "rb"}


# ---------------------------------------------------------------------------
# Default-Regeln aus configs/rules/
# ---------------------------------------------------------------------------


def test_default_regeln_existieren_und_laden():
    """``configs/rules/`` enthaelt alle dokumentierten Regeln.

    Stand: 24 Regeln (10 Pilot + 1 hardening +
    5 patch_monitor + 2 supply_chain_monitor + 6 network_monitor). Bei
    neuem yaml-File muss die erwartete Zahl mitziehen.
    """
    repo_root = Path(__file__).resolve().parents[1]
    rules_dir = repo_root / "configs" / "rules"
    engine = RuleEngine.from_directory(rules_dir)
    assert engine.rule_count() == 24


def test_default_regeln_decken_alle_aktiven_tools_ab():
    """Jedes aktive Tool hat mindestens 1 Regel.

    Stand: 5 Pilot-Tools + system_scanner
    (hardening) + patch_monitor + supply_chain_monitor + network_monitor.
    """
    repo_root = Path(__file__).resolve().parents[1]
    rules_dir = repo_root / "configs" / "rules"
    engine = RuleEngine.from_directory(rules_dir)
    expected_tools = {
        "cert_monitor",
        "api_security",
        "network_scanner",
        "csaf_advisor",
        "dependency_auditor",
        "system_scanner",  #
        "patch_monitor",  #
        "supply_chain_monitor",  # ii
        "network_monitor",  #
    }
    # Privater Index — Tests duerfen den nutzen.
    assert set(engine._rules_by_tool.keys()) == expected_tools  # noqa: SLF001


# ---------------------------------------------------------------------------
# RuleLoadError
# ---------------------------------------------------------------------------


def test_rule_load_error_ist_value_error_subclass():
    """``RuleLoadError`` erbt von ``ValueError`` — Konsumenten können beides fangen."""
    assert issubclass(RuleLoadError, ValueError)


@pytest.fixture(autouse=True)
def _no_log_capture():  # noqa: PT004 -- intentional autouse without param
    """Pytest darf Logger-Warnungen nicht als Test-Fehler interpretieren."""
    yield
