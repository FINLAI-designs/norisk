"""
test_audit_score_integration.

Tests fuer die Integration der drei neuen Audit-Kategorien (Backup,
Sovereignty, IR-Plan) in den Gesamtscore + Report.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from tools.customer_audit.application.create_audit_use_case import (
    CreateAuditUseCase,
)
from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    CustomerData,
    DetectedProvider,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.scoring_service import (
    WEIGHT_BACKUP,
    WEIGHT_INCIDENT_RESPONSE,
    WEIGHT_INFRASTRUCTURE,
    WEIGHT_NETWORK,
    WEIGHT_ORGANIZATIONAL,
    WEIGHT_SOVEREIGNTY,
    build_category_scores,
    calculate_backup_audit_score,
    calculate_ir_plan_score,
    calculate_overall_score,
    calculate_sovereignty_audit_score,
)


def test_gewichte_summieren_zu_eins() -> None:
    """Sicherheits-Invariante: alle 6 Gewichte ergeben 1.0."""
    total = (
        WEIGHT_INFRASTRUCTURE
        + WEIGHT_ORGANIZATIONAL
        + WEIGHT_NETWORK
        + WEIGHT_BACKUP
        + WEIGHT_SOVEREIGNTY
        + WEIGHT_INCIDENT_RESPONSE
    )
    assert abs(total - 1.0) < 0.001


def test_backup_score_normalized() -> None:
    """Backup-Score 15/15 (komplett konform) → 100.0 normalisiert."""
    today = datetime.now(UTC).date()
    drill = (today - timedelta(days=30)).isoformat()
    audit = BackupAuditResult(
        detection_enabled=True,
        detected_tools=["Veeam Agent"],
        rule_3_2_1_1_0={
            "3_copies": True, "2_media": True, "1_offsite": True,
            "1_immutable": True, "0_restore_tested": True,
        },
        rpo_hours=24,
        rto_hours=8,
        encryption_enabled=True,
        key_separately_stored=True,
        konzept_pdf_uploaded=True,
        last_restore_test=drill,
        info_block_shown=True,
    )
    assert calculate_backup_audit_score(audit) == 100.0


def test_backup_score_leeres_audit_ist_null() -> None:
    """Default-Audit (nicht durchlaufen) liefert 0.0, nicht 50."""
    assert calculate_backup_audit_score(BackupAuditResult()) == 0.0


def test_ir_score_normalized() -> None:
    today = datetime.now(UTC).date()
    drill = (today - timedelta(days=30)).isoformat()
    plan = IncidentResponsePlan(
        coordinator_name="X",
        coordinator_contact="y",
        escalation_chain=["A", "B", "C", "D"],
        critical_systems="z",
        backup_location_ref="r",
        forensic_vendor="f",
        forensic_vendor_contact="c",
        cyber_insurance=True,
        cyber_insurance_policy="p",
        last_drill_date=drill,
        info_block_shown=True,
    )
    assert calculate_ir_plan_score(plan) == 100.0


def test_ir_score_leerer_plan_ist_null() -> None:
    assert calculate_ir_plan_score(IncidentResponsePlan()) == 0.0


def test_sovereignty_score_normalized_alles_eu() -> None:
    """Score 0 (alles EU-souveraen) → 83 normalisiert."""
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        detected=[
            DetectedProvider(
                name="Hetzner", status="eu_sovereign", category="saas_other",
                via="dns_mx", evidence="mx.hetzner.com",
            ),
        ],
        info_block_shown=True,
    )
    # raw score = 0, normalisiert (0 - (-50)) / 60 * 100 = 83.3
    assert calculate_sovereignty_audit_score(audit) == 83.3


def test_sovereignty_score_leeres_audit_ist_null() -> None:
    """Default-Audit → 0.0 (nicht 83)."""
    assert calculate_sovereignty_audit_score(SovereigntyAuditResult()) == 0.0


def test_overall_score_mit_neuen_kategorien() -> None:
    # 100 in allen 6 = 100
    assert calculate_overall_score(100, 100, 100, 100, 100, 100) == 100.0
    # 50 in allen 6 = 50
    assert calculate_overall_score(50, 50, 50, 50, 50, 50) == 50.0


def test_overall_score_alte_drei_argumente_normalisiert_auf_100() -> None:
    """-Review-Followup: 3 Pflicht-Kategorien werden auf den
    aktiven Gewichts-Gesamtbetrag normalisiert (0.70 -> 1.0).
    Alte Audits ohne neue Sub-Audits behalten dadurch ihren Score.
    """
    assert calculate_overall_score(100, 100, 100) == 100.0
    assert calculate_overall_score(80, 70, 60) == 70.7  # gewichtet & normiert


def test_overall_score_score_0_in_neuer_kategorie_zaehlt_mit() -> None:
    """Echter Score 0 (Audit durchlaufen, miserables Ergebnis) muss
    in den Gesamtscore eingerechnet werden — anders als ``None``."""
    # Backup-Score 0 (Audit gelaufen, alles schlecht) zieht den
    # Gesamtscore nach unten.
    with_backup_zero = calculate_overall_score(100, 100, 100, backup=0.0)
    only_three = calculate_overall_score(100, 100, 100)
    assert with_backup_zero < only_three


def test_build_category_scores_inkludiert_neue_wenn_befuellt() -> None:
    scores = build_category_scores(80, 70, 60, 50, 40, 30)
    namen = {s.name for s in scores}
    assert "IT-Infrastruktur" in namen
    assert "Organisatorische Sicherheit" in namen
    assert "Netzwerksicherheit" in namen
    assert "Backup-Audit" in namen
    assert "Datensouveraenitaet" in namen
    assert "Incident-Response-Plan" in namen
    assert len(scores) == 6


def test_build_category_scores_ohne_neue_wenn_none() -> None:
    """``None`` blendet die Kategorie aus, ``0.0`` zeigt sie als "schlecht"."""
    assert len(build_category_scores(80, 70, 60)) == 3
    assert len(build_category_scores(80, 70, 60, None, None, None)) == 3
    # Echter Score 0.0 ergibt eine Kategorie mit Status "kritisch".
    scores = build_category_scores(80, 70, 60, 0.0, None, None)
    assert len(scores) == 4
    assert any(s.name == "Backup-Audit" and s.score == 0.0 for s in scores)


def test_use_case_mit_neuen_audits_inkludiert_kategorien() -> None:
    repo = MagicMock()
    use_case = CreateAuditUseCase(repo)
    today = datetime.now(UTC).date()
    drill = (today - timedelta(days=30)).isoformat()
    result = use_case.execute(
        customer_data=CustomerData(firmenname="Eigene Kanzlei"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        audit_mode=AuditMode.SELF,
        backup_audit=BackupAuditResult(
            detection_enabled=True,
            detected_tools=["Veeam Agent"],
            rule_3_2_1_1_0={
                "3_copies": True, "2_media": True, "1_offsite": True,
                "1_immutable": True, "0_restore_tested": True,
            },
            rpo_hours=24,
            rto_hours=8,
            encryption_enabled=True,
            key_separately_stored=True,
            konzept_pdf_uploaded=True,
            last_restore_test=drill,
            info_block_shown=True,
        ),
        sovereignty_audit=SovereigntyAuditResult(
            detection_enabled=True,
            detected=[
                DetectedProvider(
                    name="Hetzner", status="eu_sovereign", category="saas_other",
                    via="dns_mx", evidence="mx.hetzner.com",
                ),
            ],
            info_block_shown=True,
        ),
        incident_response_plan=IncidentResponsePlan(
            coordinator_name="RA Dr. M",
            coordinator_contact="x@y.at",
            escalation_chain=["A", "B", "C", "D"],
            critical_systems="RA-MICRO, Mail",
            backup_location_ref="Hetzner",
            forensic_vendor="MSP GmbH",
            forensic_vendor_contact="hotline",
            cyber_insurance=True,
            cyber_insurance_policy="Generali",
            last_drill_date=drill,
            info_block_shown=True,
        ),
    )
    namen = {s.name for s in result.category_scores}
    assert "Backup-Audit" in namen
    assert "Datensouveraenitaet" in namen
    assert "Incident-Response-Plan" in namen
    assert result.audit_mode == AuditMode.SELF
    # Score ist sinnvoll im Bereich 0..100
    assert 0 <= result.overall_score <= 100


def test_use_case_ohne_neue_audits_backwards_compat() -> None:
    repo = MagicMock()
    use_case = CreateAuditUseCase(repo)
    result = use_case.execute(
        customer_data=CustomerData(firmenname="Test"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
    )
    # Default-Mode = CUSTOMER
    assert result.audit_mode == AuditMode.CUSTOMER
    # Keine neuen Kategorien in Score-Liste (Defaults waren leer)
    namen = {s.name for s in result.category_scores}
    assert "Backup-Audit" not in namen
    assert "Datensouveraenitaet" not in namen
    assert "Incident-Response-Plan" not in namen
