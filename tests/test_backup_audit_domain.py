"""
test_backup_audit_domain.

Tests fuer die neuen Audit-Domain-Entities: AuditMode-Enum,
BackupAuditResult-Dataclass + ``compute_backup_score``-Logik. Reine
Domain-Tests ohne Windows/Registry-Bezug.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    CustomerAuditResult,
    CustomerData,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    compute_backup_score,
)


def test_audit_mode_werte() -> None:
    assert AuditMode.SELF.value == "self"
    assert AuditMode.CUSTOMER.value == "customer"


def test_backup_audit_default_leer() -> None:
    audit = BackupAuditResult()
    assert audit.detection_enabled is False
    assert audit.detected_tools == []
    assert audit.score == 0
    assert audit.rpo_hours is None


def test_backup_audit_roundtrip() -> None:
    """to_dict + from_dict ist verlustfrei."""
    src = BackupAuditResult(
        detection_enabled=True,
        detected_tools=["Veeam Agent 12.1"],
        last_successful_runs={"Veeam Agent 12.1": "2026-05-14"},
        rule_3_2_1_1_0={"3_copies": True, "2_media": True, "1_offsite": True},
        rpo_hours=24,
        rto_hours=8,
        encryption_enabled=True,
        key_separately_stored=True,
        konzept_pdf_uploaded=True,
        last_restore_test="2026-04-10",
        score=14,
        info_block_shown=False,
    )
    again = BackupAuditResult.from_dict(src.to_dict())
    assert again == src


def test_compute_score_komplett_konform() -> None:
    """Volles Set + Detection + Test-Restore < 1 Jahr → 15 Punkte."""
    today = datetime.now(UTC).date()
    test_date = (today - timedelta(days=90)).isoformat()
    audit = BackupAuditResult(
        detection_enabled=True,
        detected_tools=["Veeam Agent 12.1"],
        rule_3_2_1_1_0={
            "3_copies": True,
            "2_media": True,
            "1_offsite": True,
            "1_immutable": True,
            "0_restore_tested": True,
        },
        rpo_hours=24,
        rto_hours=8,
        encryption_enabled=True,
        key_separately_stored=True,
        konzept_pdf_uploaded=True,
        last_restore_test=test_date,
    )
    assert compute_backup_score(audit) == 15


def test_compute_score_ohne_detection_cap_50_prozent() -> None:
    """Detection AUS + keine Tools erkannt → 50 % Cap auch bei
    sonst voller Selbst-Deklaration."""
    today = datetime.now(UTC).date()
    test_date = (today - timedelta(days=90)).isoformat()
    audit = BackupAuditResult(
        detection_enabled=False,
        detected_tools=[],
        rule_3_2_1_1_0={
            "3_copies": True,
            "2_media": True,
            "1_offsite": True,
            "1_immutable": True,
            "0_restore_tested": True,
        },
        rpo_hours=24,
        rto_hours=8,
        encryption_enabled=True,
        key_separately_stored=True,
        konzept_pdf_uploaded=True,
        last_restore_test=test_date,
    )
    s = compute_backup_score(audit)
    assert s == 7  # 15 * 0.5 = 7.5 → int round-down nach Cap


def test_compute_score_leer_ergibt_0() -> None:
    assert compute_backup_score(BackupAuditResult()) == 0


def test_compute_score_alter_restore_test_keine_punkte() -> None:
    """Test-Restore aelter als 2 Jahre → 0 Punkte fuer den Test-Slot."""
    audit = BackupAuditResult(
        detection_enabled=True,
        detected_tools=["Veeam"],
        rule_3_2_1_1_0={"3_copies": True, "2_media": True},
        last_restore_test="2020-01-01",
    )
    s = compute_backup_score(audit)
    # rule_score=8*2/5=3.2 → gerundet auf 3, sonst 0. Detection on, kein
    # Cap. Erwartet zwischen 3 und 4.
    assert s in (3, 4)


def test_customer_assessment_default_mode_customer() -> None:
    """Backwards-Compat: bestehende Records ohne audit_mode-Wert
    bleiben CUSTOMER."""
    result = CustomerAuditResult(
        audit_id="abc",
        customer_data=CustomerData(firmenname="Test GmbH"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
    )
    assert result.audit_mode == AuditMode.CUSTOMER
    assert result.backup_audit == BackupAuditResult()


def test_customer_assessment_to_dict_enthaelt_neue_felder() -> None:
    result = CustomerAuditResult(
        audit_id="abc",
        audit_mode=AuditMode.SELF,
        customer_data=CustomerData(firmenname="Eigene Kanzlei"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        backup_audit=BackupAuditResult(detection_enabled=True),
    )
    d = result.to_dict()
    assert d["audit_mode"] == "self"
    assert d["backup_audit"]["detection_enabled"] is True


def test_customer_assessment_from_dict_invalid_mode_default_customer() -> None:
    """Defekter audit_mode-Wert → CUSTOMER (kein Crash)."""
    src_dict = {
        "audit_id": "abc",
        "audit_mode": "kaputt_irgendwas",
        "customer_data": {"firmenname": "x"},
        "infrastructure_data": {},
        "organizational_data": {},
        "network_data": {},
        "backup_audit": {},
        "category_scores": [],
    }
    result = CustomerAuditResult.from_dict(src_dict)
    assert result.audit_mode == AuditMode.CUSTOMER
