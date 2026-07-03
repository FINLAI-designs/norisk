"""
test_supply_chain_storytelling_adapter-ii.

Tests fuer den:func:`expiring_avvs_to_findings`-Adapter, der
:class:`ExpiringAvv`-Eintraege in:class:`FindingInput`-Objekte fuer den
KiTodoEmitter konvertiert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.supply_chain_monitor.application.avv_service import ExpiringAvv
from tools.supply_chain_monitor.application.storytelling_adapter import (
    TOOL_NAME,
    expiring_avvs_to_findings,
)
from tools.supply_chain_monitor.domain.models import (
    AvvDocument,
    AvvDocumentStatus,
    RenewalStatus,
)

NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _make_expiring(
    avv_id: int = 1,
    vendor_id: int = 10,
    days_remaining: int = 30,
    status: RenewalStatus = RenewalStatus.EXPIRING_SOON,
) -> ExpiringAvv:
    return ExpiringAvv(
        avv=AvvDocument(
            id=avv_id,
            vendor_id=vendor_id,
            file_path=f"/tmp/{avv_id}.pdf",
            sha256="a" * 64,
            size_bytes=10,
            original_filename=f"avv_{avv_id}.pdf",
            valid_from=NOW - timedelta(days=365),
            valid_until=NOW + timedelta(days=days_remaining),
            status=AvvDocumentStatus.ACTIVE,
        ),
        days_remaining=days_remaining,
        status=status,
    )


def test_expiring_soon_wird_zu_medium_finding() -> None:
    findings = expiring_avvs_to_findings(
        [_make_expiring(status=RenewalStatus.EXPIRING_SOON, days_remaining=45)]
    )
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, FindingInput)
    assert f.tool == TOOL_NAME
    assert f.finding_type == "avv_renewal_soon"
    assert f.severity is Severity.MEDIUM
    assert f.evidence_id == "avv:1"
    assert f.details["days_remaining"] == 45
    assert f.details["renewal_status"] == "expiring_soon"


def test_overdue_wird_zu_high_finding() -> None:
    findings = expiring_avvs_to_findings(
        [_make_expiring(status=RenewalStatus.OVERDUE, days_remaining=-7)]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "avv_renewal_overdue"
    assert f.severity is Severity.HIGH
    assert f.details["days_remaining"] == -7


def test_ok_wird_uebersprungen() -> None:
    findings = expiring_avvs_to_findings(
        [_make_expiring(status=RenewalStatus.OK, days_remaining=200)]
    )
    assert findings == []


def test_vendor_name_lookup_landet_als_subject() -> None:
    findings = expiring_avvs_to_findings(
        [_make_expiring(vendor_id=42)],
        vendor_name_lookup={42: "Microsoft"},
    )
    assert findings[0].subject == "Microsoft"
    assert findings[0].details["vendor_name"] == "Microsoft"


def test_fehlender_vendor_name_fallback() -> None:
    findings = expiring_avvs_to_findings(
        [_make_expiring(vendor_id=99)],
        vendor_name_lookup={},
    )
    assert findings[0].subject == "Vendor #99"


def test_evidence_id_dedupt_auf_avv() -> None:
    """Bei einem AVV bleibt evidence_id konstant — Wechsel von SOON zu
    OVERDUE ueberschreibt die Task, statt eine neue zu erzeugen."""
    soon = _make_expiring(avv_id=7, status=RenewalStatus.EXPIRING_SOON)
    overdue = _make_expiring(
        avv_id=7, status=RenewalStatus.OVERDUE, days_remaining=-1
    )
    f_soon = expiring_avvs_to_findings([soon])[0]
    f_overdue = expiring_avvs_to_findings([overdue])[0]
    assert f_soon.evidence_id == f_overdue.evidence_id == "avv:7"
    assert f_soon.finding_type != f_overdue.finding_type
