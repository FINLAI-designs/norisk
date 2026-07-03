"""
create_version_use_case — Bestehendes Audit als neue Version speichern.

Statt ein Audit in-place zu ändern (verletzt die Immutabilität), erzeugt dieser
Use Case eine **neue Version**: neue ``audit_id``, Verkettung über
``supersedes_audit_id`` und ``root_audit_id``, der Vorgänger wird
``is_latest=0``. Das kanonische Subjekt (``subject_id``/) und die
Ketten-Wurzel werden vom Original geerbt. Das Scoring teilt sich die Logik mit
:func:`create_audit_use_case.score_audit` (Regel 2).

Schichtzugehörigkeit: application/ — keine GUI-Imports, keine direkten DB-Calls.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.logger import get_logger
from tools.customer_audit.application.create_audit_use_case import score_audit
from tools.customer_audit.domain.entities import (
    AuditMode,
    BackupAuditResult,
    CustomerAuditResult,
    CustomerData,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    PhishingData,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.exceptions import AuditNotFoundError
from tools.customer_audit.domain.mode_gate import (
    assert_customer_audit_has_no_scan_data,
)
from tools.customer_audit.domain.repository import AuditRepository

if TYPE_CHECKING:
    from core.security_subject.ports import SubjectStore

log = get_logger(__name__)


class CreateVersionUseCase:
    """Speichert ein editiertes Audit als neue Version.

    Attributes:
        _repository: Persistenz-Adapter (Port:class:`AuditRepository`).
    """

    def __init__(
        self,
        repository: AuditRepository,
        subject_store: SubjectStore | None = None,
    ) -> None:
        """Initialisiert den Use Case.

        Args:
            repository: Repository-Adapter, implementiert:class:`AuditRepository`.
            subject_store: Optionaler:class:`SubjectStore` — zieht
                editierte Stammdaten beim Versions-Save ins bestehende Subjekt
                nach (fail-soft). ``None`` → kein Nachziehen.
        """
        self._repository = repository
        self._subject_store = subject_store

    def execute(
        self,
        base_audit_id: str,
        customer_data: CustomerData,
        infrastructure_data: InfrastructureData,
        organizational_data: OrganizationalData,
        network_data: NetworkData,
        *,
        audit_mode: AuditMode = AuditMode.CUSTOMER,
        backup_audit: BackupAuditResult | None = None,
        sovereignty_audit: SovereigntyAuditResult | None = None,
        incident_response_plan: IncidentResponsePlan | None = None,
        risk_assessments: list | None = None,
        phishing_data: PhishingData | None = None,
    ) -> CustomerAuditResult:
        """Erzeugt aus einem bestehenden Audit eine neue, neu bewertete Version.

        Das Original bleibt unverändert erhalten; die neue Version erbt das
        Subjekt (``subject_id``) und die Ketten-Wurzel (``root_audit_id``) vom
        Vorgänger, zählt ``version`` hoch und verweist via ``supersedes_audit_id``
        zurück. Nach dem Speichern wird der Vorgänger ``is_latest=0``.

        Args:
            base_audit_id: UUID des zu überarbeitenden Audits (Vorgänger der
                neuen Version — beliebige Version der Kette).
            customer_data: (ggf. editierte) Kundenstammdaten.
            infrastructure_data: (ggf. editierte) IT-Infrastruktur.
            organizational_data: (ggf. editierte) organisatorische Sicherheit.
            network_data: (ggf. editierte) Netzwerksicherheit.
            audit_mode: Selbst- vs. Kunden-Audit.
            backup_audit: Backup-Audit-Eintrag.
            sovereignty_audit: Datensouveränitäts-Audit.
            incident_response_plan: IR-Plan.
            risk_assessments: Optionale BSI-200-3-Risiko-Bewertungen.

        Returns:
            Die gespeicherte neue Version.

        Raises:
            AuditNotFoundError: Wenn ``base_audit_id`` nicht existiert.
        """
        base = self._repository.load_by_id(base_audit_id)
        if base is None:
            raise AuditNotFoundError(
                f"Basis-Audit {base_audit_id[:8]} für neue Version nicht gefunden"
            )

        backup_audit = backup_audit or BackupAuditResult()
        sovereignty_audit = sovereignty_audit or SovereigntyAuditResult()
        incident_response_plan = incident_response_plan or IncidentResponsePlan()
        phishing_data = phishing_data or base.phishing_data

        # Phase 1: auch eine neue Version eines Kunden-Audits darf keine
        # Eigenscan-Daten tragen — fail-closed VOR Persistenz/mark_superseded.
        assert_customer_audit_has_no_scan_data(
            audit_mode, backup_audit, sovereignty_audit
        )

        category_scores, overall, risk_level, recommendations = score_audit(
            infrastructure_data,
            organizational_data,
            network_data,
            backup_audit=backup_audit,
            sovereignty_audit=sovereignty_audit,
            incident_response_plan=incident_response_plan,
            risk_assessments=risk_assessments,
            ist_privatperson=customer_data.ist_privatperson,
        )

        new_version = CustomerAuditResult(
            audit_id=str(uuid.uuid4()),
            customer_data=customer_data,
            infrastructure_data=infrastructure_data,
            organizational_data=organizational_data,
            network_data=network_data,
            audit_mode=audit_mode,
            backup_audit=backup_audit,
            sovereignty_audit=sovereignty_audit,
            incident_response_plan=incident_response_plan,
            phishing_data=phishing_data,
            category_scores=category_scores,
            overall_score=overall,
            risk_level=risk_level,
            recommendations=recommendations,
            created_at=datetime.now(tz=UTC).isoformat(),
            subject_id=base.subject_id,
            version=base.version + 1,
            supersedes_audit_id=base.audit_id,
            root_audit_id=base.root_audit_id or base.audit_id,
        )

        self._repository.save(new_version)
        self._repository.mark_superseded(base.audit_id)
        self._propagate_stammdaten(base.subject_id, audit_mode, customer_data)
        # DSGVO Art. 5: Firmennamen NICHT in den App-Log — audit_id-Prefix reicht.
        log.info(
            "Audit-Version erstellt: %s v%d (supersedes %s)",
            new_version.audit_id[:8],
            new_version.version,
            base.audit_id[:8],
        )
        return new_version

    def _propagate_stammdaten(
        self,
        subject_id: str,
        audit_mode: AuditMode,
        customer_data: CustomerData,
    ) -> None:
        """Zieht editierte Kundenstammdaten ins bestehende Subjekt nach.

        Anders als:class:`CreateAuditUseCase` wird die ``subject_id`` NICHT neu
        aufgelöst (Subjekt-Stabilität über die Versionskette) — nur
        branche/groesse/contact des bereits verknüpften Subjekts werden
        aktualisiert. Nur für CUSTOMER-Audits, fail-soft.

        Args:
            subject_id: Vom Vorgänger geerbte Subjekt-UUID.
            audit_mode: Selbst- vs. Kunden-Audit.
            customer_data: Die (ggf. editierten) Kundenstammdaten.
        """
        if (
            self._subject_store is None
            or not subject_id
            or audit_mode is not AuditMode.CUSTOMER
        ):
            return
        try:
            self._subject_store.update_stammdaten(
                subject_id,
                branche=customer_data.branche,
                groesse=customer_data.unternehmensgroesse,
                contact=customer_data.ansprechpartner_name,
            )
        except Exception as exc:  # noqa: BLE001 — Nachziehen fail-soft
            log.warning(
                "Subjekt-Stammdaten-Nachzug beim Versions-Save fehlgeschlagen: %s",
                type(exc).__name__,
            )
