"""self_audit_query — Application-Fassade fuer das juengste SELF-Audit.

Read-only Query: liefert das **juengste SELF-CustomerAuditResult** eines Subjekts,
SELF-gegated (fail-closed). Existiert, damit Cross-Tool-Konsumenten (z. B. das
Risikobriefing in ``cyber_dashboard``) NICHT direkt auf die ``data``-Schicht von
``customer_audit`` greifen muessen — der Zugriff laeuft ueber diese
application-Fassade (Hexagonal: ``data`` ist kein oeffentlicher Port).

 /: nur ``AuditMode.SELF`` speist das eigene Risikobild; ein
CUSTOMER-Audit wird hier fail-closed verworfen.
"""

from __future__ import annotations

from tools.customer_audit.data.customer_audit_repository import (
    CustomerAuditRepository,
)
from tools.customer_audit.domain.entities import AuditMode, CustomerAuditResult


def lade_self_audit_result(
    subject_id: str,
    repo: CustomerAuditRepository | None = None,
) -> CustomerAuditResult | None:
    """Laedt das juengste SELF-Audit eines Subjekts (fail-closed SELF-Gate).

    Args:
        subject_id: UUID des eigenen (SELF-)Subjekts.
        repo: Optionales Repository (Tests injizieren ein Surrogat).

    Returns:
        Das juengste:class:`CustomerAuditResult` mit ``audit_mode == SELF``,
        oder ``None`` (kein Subjekt / kein Audit / CUSTOMER-Audit / Lesefehler
        beim Aufrufer).
    """
    if not subject_id:
        return None
    repo = repo or CustomerAuditRepository()
    summary = repo.latest_summary_by_subject(subject_id)
    if not summary or not summary.get("audit_id"):
        return None
    audit = repo.load_by_id(str(summary["audit_id"]))
    # Fail-closed: nie aus einem Kunden-Audit auf die eigene Lage schliessen.
    if audit is None or audit.audit_mode is not AuditMode.SELF:
        return None
    return audit


def lade_top_risiken(
    audit_id: str,
    service: object | None = None,
) -> tuple[tuple[str, str], ...]:
    """Top-Risiken eines Audits als ``(titel, risiko_level_label)`` (BSI 200-3).

    Liefert die Top-3 der Risiko-Matrix (nach Score ``Wahrscheinlichkeit x
    Schadenshoehe``). Der Aufrufer (Risikobriefing) filtert daraus die hohen
    Stufen. Fail-soft: leere Tupel bei fehlenden Daten.

    Args:
        audit_id: Audit-UUID (aus einem zuvor SELF-gegateten Ergebnis).
        service: Optionaler ``RiskAssessmentService`` (Tests injizieren ein Surrogat).
    """
    if not audit_id:
        return ()
    from tools.customer_audit.application.risk_assessment_service import (
        RiskAssessmentService,
    )
    from tools.customer_audit.domain.risk_entities import (
        DEFAULT_RISK_CATALOG_BY_KEY,
    )

    svc = service or RiskAssessmentService()
    summary = svc.summary(audit_id)
    ergebnis: list[tuple[str, str]] = []
    for a in summary.top_risks:
        if getattr(a, "is_custom", False):
            titel = a.custom_title
        else:
            entry = DEFAULT_RISK_CATALOG_BY_KEY.get(a.catalog_key)
            titel = entry.title if entry is not None else a.catalog_key
        ergebnis.append((titel, a.level.label()))
    return tuple(ergebnis)
