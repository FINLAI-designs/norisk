"""
storytelling_adapter — supply_chain_monitor Renewal-Findings → FindingInput.

Iter 2c-ii: Konvertiert:class:`ExpiringAvv`-Objekte
aus:meth:`AvvService.list_expiring` in:class:`FindingInput`-Objekte
fuer den:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`. Damit
erscheinen ablaufende/abgelaufene AVVs als Welcome-Page-Tasks
(analog Patch-Monitor / CSAF-Advisor).

**Status → Finding-Type-Mapping:**

================== ============================ ==========
RenewalStatus finding_type severity
================== ============================ ==========
OVERDUE avv_renewal_overdue HIGH
EXPIRING_SOON avv_renewal_soon MEDIUM
OK (SKIP — keine User-Aktion) n/a
================== ============================ ==========

**Dedup-Strategie:** ``evidence_id = f"avv:{avv_id}"``. Damit dedupt
der KiTodoService auf den AVV-Datensatz (nicht auf den Renewal-Status)
— wenn der AVV den Status wechselt (z. B. von SOON zu OVERDUE), wird
NICHT eine neue Task angelegt sondern die bestehende bleibt; die
Action-Beschreibung wird beim naechsten Re-Run aktualisiert.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein data/).

Author: Patrick Riederich
Version: 1.0-ii, 2026-05-15)
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from core.logger import get_logger
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.supply_chain_monitor.application.avv_service import ExpiringAvv
from tools.supply_chain_monitor.application.customer_avv_service import (
    ExpiringCustomerAvv,
)
from tools.supply_chain_monitor.domain.models import RenewalStatus

_log = get_logger(__name__)

TOOL_NAME: Final[str] = "supply_chain_monitor"

# Mapping ``RenewalStatus → (finding_type, severity)``. ``None`` = SKIP.
_STATUS_MAP: Final[dict[RenewalStatus, tuple[str, Severity] | None]] = {
    RenewalStatus.OVERDUE: ("avv_renewal_overdue", Severity.HIGH),
    RenewalStatus.EXPIRING_SOON: ("avv_renewal_soon", Severity.MEDIUM),
    RenewalStatus.OK: None,
}

# Kunden-Perspektive: eigener finding_type-Namespace, damit Kunden- und
# Lieferanten-AVV-Tasks getrennt bleiben.
_CUSTOMER_STATUS_MAP: Final[dict[RenewalStatus, tuple[str, Severity] | None]] = {
    RenewalStatus.OVERDUE: ("avv_customer_renewal_overdue", Severity.HIGH),
    RenewalStatus.EXPIRING_SOON: ("avv_customer_renewal_soon", Severity.MEDIUM),
    RenewalStatus.OK: None,
}


def expiring_avvs_to_findings(
    items: Iterable[ExpiringAvv],
    *,
    vendor_name_lookup: dict[int, str] | None = None,
) -> list[FindingInput]:
    """Konvertiert:class:`ExpiringAvv`-Eintraege zu:class:`FindingInput`.

    Args:
        items: Result von:meth:`AvvService.list_expiring`.
        vendor_name_lookup: Optionales Mapping ``vendor_id → name``. Wenn
            uebergeben, wird der Vendor-Name als ``subject`` genutzt
            (besseres Story-Headline); sonst Fallback auf
            ``"Vendor #<id>"``.

    Returns:
        Liste von:class:`FindingInput`. Items mit ``RenewalStatus.OK``
        werden uebersprungen (sollten gar nicht erst in der Eingabe sein,
        aber wir sind defensiv).
    """
    lookup = vendor_name_lookup or {}
    findings: list[FindingInput] = []
    for item in items:
        mapping = _STATUS_MAP.get(item.status)
        if mapping is None:
            continue
        finding_type, severity = mapping
        vendor_name = lookup.get(item.avv.vendor_id, f"Vendor #{item.avv.vendor_id}")
        details: dict[str, object] = {
            "vendor_name": vendor_name,
            "vendor_id": item.avv.vendor_id,
            "original_filename": item.avv.original_filename,
            "days_remaining": item.days_remaining,
            "valid_until": item.avv.valid_until.isoformat(),
            "renewal_status": item.status.value,
        }
        findings.append(
            FindingInput(
                tool=TOOL_NAME,
                finding_type=finding_type,
                severity=severity,
                subject=vendor_name,
                evidence_id=f"avv:{item.avv.id}",
                details=details,
            )
        )
    return findings


def expiring_customer_avvs_to_findings(
    items: Iterable[ExpiringCustomerAvv],
    *,
    subject_name_lookup: dict[str, str] | None = None,
) -> list[FindingInput]:
    """Konvertiert:class:`ExpiringCustomerAvv`-Eintraege zu:class:`FindingInput`.

    Gegenstueck zu:func:`expiring_avvs_to_findings` fuer die Kunden-Perspektive. Dedup-Strategie ``evidence_id = f"avv_customer:{avv_id}"`` — ein
    eigener Namespace, der die Lieferanten-Findings (``avv:{id}``) nicht beruehrt.

    Args:
        items: Result von:meth:`CustomerAvvService.list_expiring`.
        subject_name_lookup: Optionales Mapping ``subject_id → Kundenname``. Wenn
            uebergeben, wird der Kundenname als ``subject`` genutzt; sonst
            Fallback auf ``"Kunde <subject_id>"``.

    Returns:
        Liste von:class:`FindingInput`. ``RenewalStatus.OK`` wird uebersprungen.
    """
    lookup = subject_name_lookup or {}
    findings: list[FindingInput] = []
    for item in items:
        mapping = _CUSTOMER_STATUS_MAP.get(item.status)
        if mapping is None:
            continue
        finding_type, severity = mapping
        customer_name = lookup.get(item.avv.subject_id, f"Kunde {item.avv.subject_id}")
        details: dict[str, object] = {
            "customer_name": customer_name,
            "subject_id": item.avv.subject_id,
            "original_filename": item.avv.original_filename,
            "days_remaining": item.days_remaining,
            "valid_until": item.avv.valid_until.isoformat(),
            "renewal_status": item.status.value,
        }
        findings.append(
            FindingInput(
                tool=TOOL_NAME,
                finding_type=finding_type,
                severity=severity,
                subject=customer_name,
                evidence_id=f"avv_customer:{item.avv.id}",
                details=details,
            )
        )
    return findings
