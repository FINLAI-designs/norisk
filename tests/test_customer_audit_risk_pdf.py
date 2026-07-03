"""
test_customer_audit_risk_pdf-ii.

Tests fuer die Risk-Integration in:
- ``recommendation_engine._risk_recommendations``
- ``generate_recommendations(... risk_assessments=...)``
- ``report_generator._build_risk_rows`` + ``_calculate_risk_section_score``
- ``CustomerReportGenerator.generate(..., risk_assessments=...)`` (PDF-Smoke)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.customer_audit.data.report_generator import (
    CustomerReportGenerator,
    _build_risk_rows,
    _calculate_risk_section_score,
)
from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    CategoryScore,
    CustomerAuditResult,
    CustomerData,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.recommendation_engine import (
    _risk_recommendations,
    generate_recommendations,
)
from tools.customer_audit.domain.risk_entities import (
    RiskAssessment,
    RiskCategory,
    RiskImpact,
    RiskLevel,
    RiskProbability,
)


def _risk(
    catalog_key: str = "ransomware",
    prob: RiskProbability = RiskProbability.MITTEL,
    impact: RiskImpact = RiskImpact.BETRAECHTLICH,
    is_accepted: bool = False,
    is_custom: bool = False,
    custom_title: str = "",
    custom_category: RiskCategory | None = None,
) -> RiskAssessment:
    return RiskAssessment(
        id=None,
        audit_id="audit-1",
        catalog_key="" if is_custom else catalog_key,
        probability=prob,
        impact=impact,
        custom_title=custom_title,
        custom_category=custom_category,
        is_custom=is_custom,
        is_accepted=is_accepted,
    )


# ---------------------------------------------------------------------------
# _risk_recommendations
# ---------------------------------------------------------------------------


class TestRiskRecommendations:
    def test_none_liefert_leere_liste(self) -> None:
        assert _risk_recommendations(None) == []
        assert _risk_recommendations([]) == []

    def test_gering_wird_geskipped(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    prob=RiskProbability.SELTEN,
                    impact=RiskImpact.VERNACHLAESSIGBAR,
                )
            ]
        )
        assert recs == []

    def test_akzeptiertes_risiko_wird_geskipped(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                    is_accepted=True,
                )
            ]
        )
        # Akzeptiertes Risiko erzeugt KEINE Empfehlung, auch bei SEHR_HOCH.
        assert recs == []

    def test_sehr_hoch_wird_kritisch(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                )
            ]
        )
        assert len(recs) == 1
        assert recs[0].priority == "Kritisch"
        assert "Ransomware" in recs[0].title

    def test_hoch_wird_hoch_prio(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    prob=RiskProbability.HAEUFIG,
                    impact=RiskImpact.BETRAECHTLICH,
                )
            ]
        )
        # 3*3 = 9 → HOCH
        assert recs[0].priority == "Hoch"

    def test_mittel_wird_mittel_prio(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    prob=RiskProbability.MITTEL, impact=RiskImpact.BEGRENZT
                )  # 2*2 = 4 → MITTEL
            ]
        )
        assert recs[0].priority == "Mittel"

    def test_tool_empfehlung_eingebettet(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                )
            ]
        )
        # Ransomware-Catalog-Eintrag empfiehlt Patch-Monitor + CSAF + System-Scanner + Email.
        desc = recs[0].description
        assert "Patch-Monitor" in desc
        assert "Advisory-Monitor" in desc  # csaf_advisor → display name

    def test_custom_risiko_keine_tools(self) -> None:
        recs = _risk_recommendations(
            [
                _risk(
                    is_custom=True,
                    custom_title="Lieferketten-Ausfall",
                    custom_category=RiskCategory.EXTERN,
                    prob=RiskProbability.HAEUFIG,
                    impact=RiskImpact.BETRAECHTLICH,
                )
            ]
        )
        # Custom hat keine Tool-Empfehlung.
        assert "Empfohlene Tools" not in recs[0].description
        assert recs[0].title == "Lieferketten-Ausfall"


# ---------------------------------------------------------------------------
# generate_recommendations integration
# ---------------------------------------------------------------------------


def _empty_audit_inputs() -> dict:
    """Minimaler Audit-Input fuer generate_recommendations."""
    return dict(
        infrastructure=InfrastructureData(
            betriebssysteme=["Windows 11"],
            antivirus_status="aktiv",
            firewall_status="aktiv",
        ),
        organizational=OrganizationalData(),
        network=NetworkData(),
    )


class TestGenerateRecommendationsIntegration:
    def test_ohne_risks_keine_risk_recs(self) -> None:
        recs = generate_recommendations(**_empty_audit_inputs())
        risk_recs = [r for r in recs if r.category == "Risiko-Bewertung"]
        assert risk_recs == []

    def test_mit_risks_inkl_risk_recs(self) -> None:
        risks = [
            _risk(
                catalog_key="ransomware",
                prob=RiskProbability.SEHR_HAEUFIG,
                impact=RiskImpact.EXISTENZBEDROHEND,
            ),
            _risk(
                catalog_key="phishing",
                prob=RiskProbability.HAEUFIG,
                impact=RiskImpact.BETRAECHTLICH,
            ),
        ]
        recs = generate_recommendations(
            **_empty_audit_inputs(), risk_assessments=risks
        )
        risk_recs = [r for r in recs if r.category == "Risiko-Bewertung"]
        assert len(risk_recs) == 2
        # Kritisch zuerst sortiert (durch generate_recommendations).
        first_risk = next(r for r in recs if r.category == "Risiko-Bewertung")
        assert first_risk.priority == "Kritisch"


# ---------------------------------------------------------------------------
# Report-Generator-Hilfsfunktionen
# ---------------------------------------------------------------------------


class TestRiskRows:
    def test_leere_liste(self) -> None:
        assert _build_risk_rows([]) == []

    def test_sortierung_score_desc(self) -> None:
        rows = _build_risk_rows(
            [
                _risk(
                    catalog_key="stromausfall",
                    prob=RiskProbability.SELTEN,
                    impact=RiskImpact.VERNACHLAESSIGBAR,
                ),  # 1
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                ),  # 16
            ]
        )
        # Ransomware muss vor Stromausfall stehen.
        assert "Ransomware" in rows[0]["label"]
        assert "Stromausfall" in rows[1]["label"]

    def test_akzeptiertes_risiko_hat_ok_status(self) -> None:
        rows = _build_risk_rows(
            [
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                    is_accepted=True,
                )
            ]
        )
        assert rows[0]["status"] == "ok"
        assert "akzeptiert" in rows[0]["value"]

    def test_sehr_hoch_status_kritisch(self) -> None:
        rows = _build_risk_rows(
            [
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                )
            ]
        )
        assert rows[0]["status"] == "Kritisch"


class TestRiskSectionScore:
    def test_leere_liste(self) -> None:
        score, label = _calculate_risk_section_score([])
        assert score == 0.0
        assert label == "Info"

    def test_alle_gering_ist_100_prozent(self) -> None:
        score, label = _calculate_risk_section_score(
            [
                _risk(
                    catalog_key="stromausfall",
                    prob=RiskProbability.SELTEN,
                    impact=RiskImpact.VERNACHLAESSIGBAR,
                )
            ]
        )
        assert score == 100.0
        assert label == "Niedrig"

    def test_alle_hoch_und_nicht_akzeptiert_ist_null_prozent(self) -> None:
        score, label = _calculate_risk_section_score(
            [
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                )
            ]
        )
        assert score == 0.0
        assert label == "Kritisch"

    def test_akzeptiertes_risiko_zaehlt_handled(self) -> None:
        # 1 akzeptiert + 1 GERING = 100% handled
        score, label = _calculate_risk_section_score(
            [
                _risk(
                    catalog_key="ransomware",
                    prob=RiskProbability.SEHR_HAEUFIG,
                    impact=RiskImpact.EXISTENZBEDROHEND,
                    is_accepted=True,
                ),
                _risk(
                    catalog_key="stromausfall",
                    prob=RiskProbability.SELTEN,
                    impact=RiskImpact.VERNACHLAESSIGBAR,
                ),
            ]
        )
        assert score == 100.0


# ---------------------------------------------------------------------------
# PDF-Smoke
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_audit_result() -> CustomerAuditResult:
    return CustomerAuditResult(
        audit_id="audit-1",
        customer_data=CustomerData(firmenname="Demo-Kanzlei"),
        infrastructure_data=InfrastructureData(
            betriebssysteme=["Windows 11"],
            antivirus_status="aktiv",
            firewall_status="aktiv",
        ),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        audit_mode=AuditMode.CUSTOMER,
        backup_audit=BackupAuditResult(),
        sovereignty_audit=SovereigntyAuditResult(),
        incident_response_plan=IncidentResponsePlan(),
        category_scores=[
            CategoryScore(
                name="IT-Infrastruktur",
                score=85.0,
                label="Niedrig",
            )
        ],
        overall_score=85.0,
        risk_level="Niedrig",
        recommendations=[],
        created_at="2026-05-16T08:00:00+00:00",
    )


@pytest.mark.slow
class TestReportGeneratorWithRisks:
    def test_pdf_wird_ohne_risks_gebaut(
        self, minimal_audit_result: CustomerAuditResult, tmp_path: Path
    ) -> None:
        out = tmp_path / "no_risks.pdf"
        CustomerReportGenerator().generate(minimal_audit_result, out)
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"

    def test_pdf_mit_risks_enthaelt_risk_sektion(
        self, minimal_audit_result: CustomerAuditResult, tmp_path: Path
    ) -> None:
        risks = [
            _risk(
                catalog_key="ransomware",
                prob=RiskProbability.SEHR_HAEUFIG,
                impact=RiskImpact.EXISTENZBEDROHEND,
            ),
            _risk(
                catalog_key="stromausfall",
                prob=RiskProbability.SELTEN,
                impact=RiskImpact.VERNACHLAESSIGBAR,
            ),
        ]
        out = tmp_path / "with_risks.pdf"
        CustomerReportGenerator().generate(
            minimal_audit_result, out, risk_assessments=risks
        )
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"
        # Mit Risks ist die PDF groesser als ohne (Risk-Sektion).
        out_no = tmp_path / "no_risks_2.pdf"
        CustomerReportGenerator().generate(minimal_audit_result, out_no)
        assert out.stat().st_size > out_no.stat().st_size


# ---------------------------------------------------------------------------
# Drift / RiskLevel-Mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "level,expected_priority",
    [
        (RiskLevel.SEHR_HOCH, "Kritisch"),
        (RiskLevel.HOCH, "Hoch"),
        (RiskLevel.MITTEL, "Mittel"),
        (RiskLevel.GERING, "Niedrig"),
    ],
)
def test_level_zu_priority_mapping_komplett(
    level: RiskLevel, expected_priority: str
) -> None:
    """Alle 4 Levels haben einen Priority-Mapping-Eintrag (keine Lookup-
    Lucke). GERING wird zwar geskipped, das Mapping muss aber existieren,
    damit zukuenftige Refactorings das Verhalten leicht aendern koennen."""
    from tools.customer_audit.domain.recommendation_engine import (
        _RISK_LEVEL_TO_PRIO,
    )

    assert _RISK_LEVEL_TO_PRIO[level] == expected_priority
