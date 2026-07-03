"""services — Composition-Root fuer das Customer-Audit-Service-Buendel.

Bietet die zentrale Factory ``create_customer_audit_services``, die
alle Use-Cases auf einem geteilten Repository verdrahtet. Dies ist die
einzige Stelle, an der ``application/`` die konkrete ``data/``-
Implementierung ueberhaupt anfasst — die Use-Cases selbst nehmen das
Port:class:`tools.customer_audit.domain.repository.AuditRepository`.

Review-Followup:
    - Factory umbenannt zu ``create_customer_audit_services``-
      Rename-Folge). Alter Name ``create_customer_assessment_services``
      bleibt als Backwards-Compat-Alias.
    - Repository-Parameter akzeptiert jetzt das Port-Interface.

Schichtzugehoerigkeit: ``application/`` (orchestriert nur).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tools.customer_audit.application.create_audit_use_case import (
    CreateAuditUseCase,
)
from tools.customer_audit.application.create_version_use_case import (
    CreateVersionUseCase,
)
from tools.customer_audit.application.export_audit_use_case import (
    ExportAuditUseCase,
)
from tools.customer_audit.application.generate_report_use_case import (
    GenerateReportUseCase,
)
from tools.customer_audit.application.load_audit_use_case import (
    LoadAuditUseCase,
)
from tools.customer_audit.domain.repository import AuditRepository

if TYPE_CHECKING:
    from core.scan_prefill.ports import ScanDataPort
    from core.security_subject.ports import SubjectStore


@dataclass(frozen=True, slots=True)
class CustomerAuditServices:
    """Buendel der Customer-Audit-Use-Cases fuer die GUI.

    ``frozen=True``, weil das Buendel selbst ein Value Object ist —
    die Use-Cases sind weiter stateful (sie halten das Repository), aber
    die Zuordnung Buendel→Services veraendert sich zur Laufzeit nicht.
    """

    create: CreateAuditUseCase
    create_version: CreateVersionUseCase
    load: LoadAuditUseCase
    export: ExportAuditUseCase
    report: GenerateReportUseCase
    # Phase 3: gemessene SELF-Vorbefuellung ueber den core-Port
    # (security_scoring-Adapter, lazy via core-Resolver). ``None`` = nicht
    # verfuegbar (fail-soft) → der Wizard zeigt keine Auto-Vorbefuellung.
    scan_prefill: ScanDataPort | None = None


def create_customer_audit_services(
    repository: AuditRepository | None = None,
    subject_store: SubjectStore | None = None,
    scan_prefill: ScanDataPort | None = None,
) -> CustomerAuditServices:
    """Baut das Use-Case-Buendel auf einem geteilten Repository.

    Args:
        repository: Optional. Wenn ``None``, wird die konkrete
:class:`CustomerAuditRepository` aus der ``data``-Schicht
            instanziiert (Composition-Root-Pattern). Tests injizieren
            hier ein Mock, das das Port:class:`AuditRepository`
            erfuellt.
        subject_store: Optionaler:class:`SubjectStore` (core-Port)
            fuer die Subjekt-Verknuepfung beim Audit-Save. Wird nur im
            Produktionspfad (``repository is None``) automatisch ueber den
            core-Resolver bezogen; bei injiziertem Repository (Test) bleibt
            er ``None``, sofern nicht explizit uebergeben.

    Returns:
        ``CustomerAuditServices``-Buendel mit Create/Load/Export/Report.
    """
    if repository is None:
        # Lokaler Import: Composition-Root darf data anfassen.
        from tools.customer_audit.data.customer_audit_repository import (  # noqa: PLC0415
            CustomerAuditRepository,
        )

        repository = CustomerAuditRepository()
        if subject_store is None:
            # core-Resolver: kein tool→tool-Import §3.2), fail-soft.
            from core.security_subject.resolver import (  # noqa: PLC0415
                create_subject_store,
            )

            subject_store = create_subject_store()
        if scan_prefill is None:
            # Phase 3: core-Resolver liefert den security_scoring-
            # Adapter lazy (kein tool→tool-Import), fail-soft → None.
            from core.scan_prefill.resolver import (  # noqa: PLC0415
                create_scan_data_provider,
            )

            scan_prefill = create_scan_data_provider()
    # Iter 2e-ii: RiskAssessmentService wird im GenerateReportUseCase
    # injiziert, damit der PDF-Report eine Risiko-Sektion bekommt. Lazy-
    # Import, damit Tests ohne Risk-Backend nicht crashen.
    from tools.customer_audit.application.risk_assessment_service import (  # noqa: PLC0415
        RiskAssessmentService,
    )

    return CustomerAuditServices(
        create=CreateAuditUseCase(repository, subject_store=subject_store),
        create_version=CreateVersionUseCase(repository, subject_store=subject_store),
        load=LoadAuditUseCase(repository, subject_store=subject_store),
        export=ExportAuditUseCase(),
        report=GenerateReportUseCase(
            repository,
            risk_service=RiskAssessmentService(),
        ),
        scan_prefill=scan_prefill,
    )


# Backwards-Compat: alter Name, deprecated mit-Rename.
create_customer_assessment_services = create_customer_audit_services
