"""Tests fuer den Hardening-Compliance-Report-Service Wiring W1).

Deckt die Daten-Bruecke ab: fehlgeschlagene HardeningChecks -> pro-Check
ComplianceRow (Norm-Bezuege + KMU-Prioritaet), Sortierung, check_id-spezifische
Referenzen, Fallback-urgency, und den Scan-Orchestrator via MockHardeningProbe.
Plattform-/DB-frei (kein echter Windows-Scan).
"""

from __future__ import annotations

from core.compliance.regulatory_mapping import RegReference
from core.probes.mock_hardening_probe import MockHardeningProbe
from core.rules.models import ClassifierHint, Rule, RuleMatch
from core.rules.rule_engine import RuleEngine
from core.security.severity import Severity
from tools.system_scanner.application.compliance_report_service import (
    COMPLIANCE_TABLE_HEADER,
    ComplianceRow,
    build_hardening_compliance_rows,
    collect_hardening_compliance,
    compliance_rows_to_table,
    severity_label,
)
from tools.system_scanner.domain.entities import HardeningCheck


def _engine() -> RuleEngine:
    """Minimale RuleEngine, die alle SH-Checks (hardening_check_failed) matcht."""
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


def _checks() -> list[HardeningCheck]:
    return [
        HardeningCheck(
            "SH-001",
            "Windows Firewall aktiv",
            False,
            Severity.CRITICAL,
            "Domain-Profil aus",
        ),
        HardeningCheck(
            "SH-010", "BitLocker aktiv auf C:", False, Severity.MEDIUM, "kein BitLocker"
        ),
        HardeningCheck(
            "SH-002", "UAC aktiviert", True, Severity.HIGH, "OK"
        ),  # passed -> raus
    ]


class TestBuildHardeningComplianceRows:
    def test_nur_fehlgeschlagene_checks(self) -> None:
        rows = build_hardening_compliance_rows(_checks(), _engine())
        assert all(isinstance(r, ComplianceRow) for r in rows)
        ids = {r.check_id for r in rows}
        assert ids == {"SH-001", "SH-010"}  # SH-002 passed -> nicht enthalten

    def test_sortierung_nach_prioritaet_absteigend(self) -> None:
        rows = build_hardening_compliance_rows(_checks(), _engine())
        prios = [r.view.kmu_priority for r in rows]
        assert prios == sorted(prios, reverse=True)
        # CRITICAL-Firewall vor MEDIUM-BitLocker.
        assert rows[0].check_id == "SH-001"

    def test_check_id_spezifische_norm_referenzen(self) -> None:
        rows = {
            r.check_id: r for r in build_hardening_compliance_rows(_checks(), _engine())
        }
        # SH-010 BitLocker -> Kryptografie/DSGVO (Check-Override, nicht Kategorie-Default).
        assert rows["SH-010"].view.reg_refs == (
            RegReference.NIS2_ART21_2H,
            RegReference.DSGVO_ART32,
        )
        # SH-001 Firewall -> NIS2 2a + IT-SiG.
        assert rows["SH-001"].view.reg_refs == (
            RegReference.NIS2_ART21_2A,
            RegReference.ITSIG_BSIG_8A_ABS1,
        )

    def test_jede_row_traegt_disclaimer_und_kapazitaet(self) -> None:
        for row in build_hardening_compliance_rows(_checks(), _engine()):
            assert row.view.disclaimer  # Pflicht-Disclaimer immer dabei
            assert row.view.capacity_hint
            assert row.urgency in {"quick", "mittel", "langfrist"}
            assert row.view.reg_labels  # SH-001/SH-010 haben Bezuege

    def test_alle_passed_leere_liste(self) -> None:
        checks = [HardeningCheck("SH-001", "Firewall", True, Severity.CRITICAL, "OK")]
        assert build_hardening_compliance_rows(checks, _engine()) == []

    def test_fallback_urgency_ohne_regel(self) -> None:
        # Leere Engine -> keine Regel matcht -> Fallback 'mittel', kein Crash.
        rows = build_hardening_compliance_rows(_checks(), RuleEngine([]))
        assert rows
        assert all(r.urgency == "mittel" for r in rows)

    def test_deterministisch(self) -> None:
        a = build_hardening_compliance_rows(_checks(), _engine())
        b = build_hardening_compliance_rows(_checks(), _engine())
        assert [(r.check_id, r.view.kmu_priority) for r in a] == [
            (r.check_id, r.view.kmu_priority) for r in b
        ]


class TestCollectHardeningCompliance:
    def test_scan_via_mock_probe_liefert_rows(self) -> None:
        # Leere Mock-Probe -> die meisten Checks scheitern -> Rows entstehen.
        rows = collect_hardening_compliance(MockHardeningProbe(), _engine())
        assert isinstance(rows, list)
        assert all(isinstance(r, ComplianceRow) for r in rows)
        assert all(r.check_id.startswith("SH-") for r in rows)
        # Sortierung absteigend nach Prioritaet.
        prios = [r.view.kmu_priority for r in rows]
        assert prios == sorted(prios, reverse=True)


class TestComplianceRowsToTable:
    def test_header_und_zeilenzahl(self) -> None:
        rows = build_hardening_compliance_rows(_checks(), _engine())
        table = compliance_rows_to_table(rows)
        assert table[0] == list(COMPLIANCE_TABLE_HEADER)
        assert len(table) == len(rows) + 1
        assert all(len(r) == len(COMPLIANCE_TABLE_HEADER) for r in table)

    def test_zelleninhalt_erste_datenzeile(self) -> None:
        table = compliance_rows_to_table(
            build_hardening_compliance_rows(_checks(), _engine())
        )
        first = table[1]  # hoechste Prioritaet -> SH-001 (CRITICAL)
        assert "SH-001" in first[0]
        assert first[1] == "Kritisch"
        assert "indikativ" in first[2].lower()
        assert first[3].endswith("/100")
        assert "fixbar" in first[4].lower()

    def test_severity_label_mapping(self) -> None:
        assert severity_label(Severity.CRITICAL) == "Kritisch"
        assert severity_label(Severity.INFO) == "Info"

    def test_leere_rows_nur_header(self) -> None:
        assert compliance_rows_to_table([]) == [list(COMPLIANCE_TABLE_HEADER)]
