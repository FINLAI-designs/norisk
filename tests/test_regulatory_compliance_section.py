"""Tests fuer die pure Display-Logik des Regulatorik-Panels W2).

Testet die Qt-freien Helfer (severity_label, format_compliance_row) headless —
das QWidget selbst (Thread/Layout) wird nicht instanziiert (braucht QApplication).
"""

from __future__ import annotations

from core.rules.models import ClassifierHint, Rule, RuleMatch
from core.rules.rule_engine import RuleEngine
from core.security.severity import Severity

# Kanonische Verbots-Tokens (UWG) — geteilt mit test_regulatory_mapping.
from tests.test_regulatory_mapping import _FORBIDDEN_CLAIM_TOKENS
from tools.security_scoring.gui.widgets.regulatory_compliance_section import (
    _severity_color,
    format_compliance_row,
    severity_label,
)
from tools.system_scanner.application.compliance_report_service import (
    build_hardening_compliance_rows,
)
from tools.system_scanner.domain.entities import HardeningCheck


def _engine() -> RuleEngine:
    return RuleEngine(
        [
            Rule(
                id="hardening_check_failed",
                match=RuleMatch(
                    tool="system_scanner",
                    finding_type="hardening_check_failed",
                    min_severity=Severity.INFO,
                ),
                classifier_hint=ClassifierHint(asset_count=1),
            )
        ]
    )


def _row(check_id: str = "SH-010", severity: Severity = Severity.MEDIUM):
    checks = [
        HardeningCheck(check_id, "BitLocker aktiv auf C:", False, severity, "aus")
    ]
    return build_hardening_compliance_rows(checks, _engine())[0]


class TestSeverityLabel:
    def test_alle_severities_deutsch(self) -> None:
        assert severity_label(Severity.CRITICAL) == "Kritisch"
        assert severity_label(Severity.HIGH) == "Hoch"
        assert severity_label(Severity.MEDIUM) == "Mittel"
        assert severity_label(Severity.LOW) == "Niedrig"
        assert severity_label(Severity.INFO) == "Info"


class TestFormatComplianceRow:
    def test_felder_vollstaendig(self) -> None:
        data = format_compliance_row(_row())
        assert set(data) == {"check", "severity", "norm", "priority", "capacity"}
        assert "SH-010" in data["check"]
        assert data["severity"] == "Mittel"
        assert "indikativ" in data["norm"].lower()
        assert data["priority"].startswith("Prioritaet")
        assert "fixbar" in data["capacity"].lower()

    def test_kein_konformitaets_wording(self) -> None:
        # UWG: kein Anzeige-String darf eine Erfuellungs-Behauptung enthalten.
        data = format_compliance_row(_row(severity=Severity.CRITICAL))
        for value in data.values():
            low = value.lower()
            for token in _FORBIDDEN_CLAIM_TOKENS:
                assert token not in low, f"verbotenes Wort {token!r} in {value!r}"

    def test_norm_join_mehrere_referenzen(self) -> None:
        # SH-010 hat zwei Referenzen (Krypto + DSGVO) -> Join mit Separator.
        data = format_compliance_row(_row("SH-010"))
        assert " · " in data["norm"]


class TestSeverityColor:
    def test_alle_severities_liefern_farbe(self) -> None:
        # Regressionsguard: _severity_color nutzt die MODUL-Konstanten
        # theme.GRADE_* — NICHT t.GRADE_* (existiert nicht am ThemeColors-Objekt;
        # t.GRADE_D crashte das Security-Scoring-Tab beim Oeffnen). Der Dict wird
        # eager evaluiert -> ein Aufruf triggert alle GRADE-Zugriffe.
        for sev in Severity:
            color = _severity_color(sev)
            assert isinstance(color, str) and color.startswith("#")
