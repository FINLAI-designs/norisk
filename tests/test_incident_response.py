"""
test_incident_response.

Tests fuer IncidentResponsePlan-Dataclass, compute_ir_score und
ir_plan_generator (Markdown-Export).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from tools.customer_audit.application.ir_plan_generator import (
    export_plan,
    render_plan_markdown,
)
from tools.customer_audit.domain.entities import (
    IR_PHASEN,
    MELDEKANAELE,
    CustomerAuditResult,
    CustomerData,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    compute_ir_score,
)


def test_meldekanaele_und_phasen_konstanten() -> None:
    assert len(MELDEKANAELE) >= 6
    assert "Datenschutzbehoerde (DSGVO Art. 33: 72 h)" in MELDEKANAELE
    assert "Mandanten (DSGVO Art. 34, falls hohes Risiko)" in MELDEKANAELE
    assert len(IR_PHASEN) == 6


def test_default_ir_plan() -> None:
    plan = IncidentResponsePlan()
    assert plan.coordinator_name == ""
    assert plan.escalation_chain == []
    assert plan.score == 0


def test_compute_score_leer() -> None:
    assert compute_ir_score(IncidentResponsePlan()) == 0


def test_compute_score_komplett() -> None:
    today = datetime.now(UTC).date()
    drill = (today - timedelta(days=30)).isoformat()
    plan = IncidentResponsePlan(
        coordinator_name="RA Dr. Mueller",
        coordinator_contact="+43 1 234 5678",
        escalation_chain=MELDEKANAELE[:5],  # >= 3
        critical_systems="RA-MICRO, Mail, beA",
        backup_location_ref="Hetzner Storage Box",
        forensic_vendor="lokaler MSP GmbH",
        forensic_vendor_contact="+43 1 999 1111",
        cyber_insurance=True,
        cyber_insurance_policy="Generali Cyber Pro #12345",
        last_drill_date=drill,
        drill_findings="Mail-Wiederherstellung dauerte 4h statt 2h",
    )
    # 3 + 3 + 2 + 1 + 2 + 1 + 3 = 15
    assert compute_ir_score(plan) == 15


def test_compute_score_alte_uebung_2_jahre() -> None:
    """Drill > 12 Monate aber <= 24 Monate -> 2 Punkte statt 3."""
    today = datetime.now(UTC).date()
    drill = (today - timedelta(days=400)).isoformat()
    plan = IncidentResponsePlan(
        coordinator_name="A",
        coordinator_contact="b",
        escalation_chain=MELDEKANAELE[:3],
        critical_systems="x",
        last_drill_date=drill,
    )
    # 3 + 3 + 2 + 2 = 10
    assert compute_ir_score(plan) == 10


def test_roundtrip() -> None:
    plan = IncidentResponsePlan(
        coordinator_name="X",
        escalation_chain=["A", "B"],
        cyber_insurance=True,
        score=7,
    )
    again = IncidentResponsePlan.from_dict(plan.to_dict())
    assert again == plan


def test_audit_result_default_hat_ir_plan() -> None:
    result = CustomerAuditResult(
        audit_id="abc",
        customer_data=CustomerData(firmenname="Kanzlei Mueller"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
    )
    assert result.incident_response_plan == IncidentResponsePlan()


def test_audit_result_serialisiert_ir_plan() -> None:
    plan = IncidentResponsePlan(coordinator_name="X", cyber_insurance=True)
    result = CustomerAuditResult(
        audit_id="abc",
        customer_data=CustomerData(firmenname="K"),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        incident_response_plan=plan,
    )
    d = result.to_dict()
    assert "incident_response_plan" in d
    again = CustomerAuditResult.from_dict(d)
    assert again.incident_response_plan == plan


# ---------------------------------------------------------------------------
# Markdown-Generator
# ---------------------------------------------------------------------------


def test_render_markdown_enthaelt_pflichtkapitel() -> None:
    plan = IncidentResponsePlan(
        coordinator_name="Dr. Mueller",
        coordinator_contact="+43 1 234 5678",
        escalation_chain=[
            "Geschaeftsfuehrung / Kanzlei-Inhaber",
            "Datenschutzbeauftragter (intern oder extern)",
        ],
        critical_systems="RA-MICRO, beA, Mail",
        backup_location_ref="Hetzner Storage Box, taeglich",
        forensic_vendor="Cyber Forensik GmbH",
        cyber_insurance=True,
    )
    md = render_plan_markdown(plan, firmenname="Kanzlei Mueller", audit_id="abc-123")
    assert "Incident-Response-Plan" in md
    assert "Kanzlei Mueller" in md
    assert "Dr. Mueller" in md
    assert "Datenschutzbehoerde" in md or "Datenschutzbeauftragter" in md
    assert "RA-MICRO" in md
    assert "Hetzner" in md
    # 6-Phasen-Checkliste
    assert "Vorbereitung" in md
    assert "Eindaemmung" in md
    # Meldepflicht-Vorlagen
    assert "DSGVO Art. 33" in md
    assert "72 Stunden" in md or "72-Stunden" in md or "72-Stunden-Meldepflicht" in md
    assert "Mandanten" in md  # Art. 34
    assert "NIS2" in md
    assert "BRAO" in md or "RAO" in md or "Rechtsanwaltskammer" in md


def test_render_markdown_leerer_plan() -> None:
    md = render_plan_markdown(IncidentResponsePlan())
    # Kein Crash, Pflicht-Kapitel trotzdem da
    assert "Incident-Response-Plan" in md
    assert "(nicht ausgefuellt)" in md or "—" in md


def test_export_markdown_schreibt_datei(tmp_path: Path) -> None:
    plan = IncidentResponsePlan(coordinator_name="X")
    target = tmp_path / "ir.md"
    ok = export_plan(plan, target, fmt="markdown", firmenname="Test GmbH")
    assert ok
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "Test GmbH" in content


def test_export_unbekanntes_format_returns_false(tmp_path: Path) -> None:
    plan = IncidentResponsePlan()
    target = tmp_path / "ir.txt"
    ok = export_plan(plan, target, fmt="ungueltig")  # type: ignore[arg-type]
    assert ok is False
