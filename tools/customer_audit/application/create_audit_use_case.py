"""
create_audit_use_case — Use Case: Kunden-Audit berechnen und speichern.

Orchestriert: Scoring → Empfehlungen → Persistenz.

Schichtzugehörigkeit: application/ — keine GUI-Imports, keine direkten DB-Calls.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.logger import get_logger
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
    PhishingData,
    SovereigntyAuditResult,
)
from tools.customer_audit.domain.mode_gate import (
    assert_customer_audit_has_no_scan_data,
)
from tools.customer_audit.domain.recommendation_engine import (
    recommendations_as_strings,
)
from tools.customer_audit.domain.repository import AuditRepository
from tools.customer_audit.domain.scoring_service import (
    build_category_scores,
    calculate_backup_audit_score,
    calculate_infrastructure_score,
    calculate_ir_plan_score,
    calculate_network_score,
    calculate_organizational_score,
    calculate_overall_score,
    calculate_sovereignty_audit_score,
    score_to_risk_level,
)

if TYPE_CHECKING:
    from core.security_subject.ports import SubjectStore

log = get_logger(__name__)

#: Fallback-Name für das eigene Subjekt, falls ein Self-Audit ohne Firmenname
#: gespeichert wird und noch kein eigenes Profil existiert.
_DEFAULT_SELF_NAME = "Mein System"


def score_audit(
    infrastructure_data: InfrastructureData,
    organizational_data: OrganizationalData,
    network_data: NetworkData,
    *,
    backup_audit: BackupAuditResult,
    sovereignty_audit: SovereigntyAuditResult,
    incident_response_plan: IncidentResponsePlan,
    risk_assessments: list | None = None,
    ist_privatperson: bool = False,
) -> tuple[list[CategoryScore], float, str, list[str]]:
    """Berechnet Kategorie-Scores, Gesamtscore, Risikostufe und Empfehlungen.

    Gemeinsame Scoring-Orchestrierung für Neu-Audit (:class:`CreateAuditUseCase`)
    und Neu-Version (:class:`CreateVersionUseCase`) — eine Quelle für die
    Logik (Regel 2). Sub-Audits mit ``info_block_shown == False`` gelten als
    „nicht durchlaufen" (Gewicht 0) und fallen aus Score und Report-Liste.

    Args:
        infrastructure_data: IT-Infrastruktur.
        organizational_data: Organisatorische Sicherheit.
        network_data: Netzwerksicherheit.
        backup_audit: Backup-Audit.
        sovereignty_audit: Datensouveränitäts-Audit.
        incident_response_plan: IR-Plan.
        risk_assessments: Optionale BSI-200-3-Risiko-Bewertungen.

    Returns:
        Tuple ``(category_scores, overall_score, risk_level, recommendations)``.
    """
    infra_score = calculate_infrastructure_score(infrastructure_data)
    org_score = calculate_organizational_score(
        organizational_data, ist_privatperson=ist_privatperson
    )
    net_score = calculate_network_score(
        network_data, ist_privatperson=ist_privatperson
    )

    backup_score = (
        calculate_backup_audit_score(backup_audit)
        if backup_audit.info_block_shown
        else None
    )
    sovereignty_score = (
        calculate_sovereignty_audit_score(sovereignty_audit)
        if sovereignty_audit.info_block_shown
        else None
    )
    ir_score = (
        calculate_ir_plan_score(
            incident_response_plan, ist_privatperson=ist_privatperson
        )
        if incident_response_plan.info_block_shown
        else None
    )

    overall = calculate_overall_score(
        infra_score, org_score, net_score,
        backup=backup_score,
        sovereignty=sovereignty_score,
        incident_response=ir_score,
    )
    risk_level = score_to_risk_level(overall)
    category_scores = build_category_scores(
        infra_score, org_score, net_score,
        backup_score=backup_score,
        sovereignty_score=sovereignty_score,
        ir_score=ir_score,
    )
    recommendations = recommendations_as_strings(
        infrastructure_data,
        organizational_data,
        network_data,
        backup=backup_audit if backup_audit.info_block_shown else None,
        sovereignty=(
            sovereignty_audit if sovereignty_audit.info_block_shown else None
        ),
        incident_response=(
            incident_response_plan
            if incident_response_plan.info_block_shown
            else None
        ),
        risk_assessments=risk_assessments,
    )
    return category_scores, overall, risk_level, recommendations


class CreateAuditUseCase:
    """Berechnet einen vollständigen Audit-Score und speichert das Ergebnis.

    Attributes:
        _repository: Persistenz-Adapter.
    """

    def __init__(
        self,
        repository: AuditRepository,
        subject_store: SubjectStore | None = None,
    ) -> None:
        """Initialisiert den Use Case.

        Args:
            repository: Repository-Adapter, implementiert das Port
:class:`AuditRepository` aus ``domain.repository``.
            subject_store: Optionaler:class:`SubjectStore` (core-Port)
                zum Anlegen/Finden des kanonischen Subjekts beim Speichern.
                ``None`` (Default) → fail-soft, ``subject_id`` bleibt leer.
        """
        self._repository = repository
        self._subject_store = subject_store

    def _resolve_subject_id(
        self, audit_mode: AuditMode, customer_data: CustomerData
    ) -> str:
        """Findet/erzeugt das kanonische Subjekt für ein Audit (fail-soft).

        ``SELF`` → eigenes Singleton-Subjekt; ``CUSTOMER`` → Kunden-Subjekt
        per ``firmenname`` (find-or-create, Dedup per Name) inkl. Nachziehen
        von ``branche``/``groesse``/Ansprechpartner ins Subjekt. Ohne
        SubjectStore oder bei DB-Fehlern bleibt die ``subject_id`` leer; das
        Audit wird trotzdem gespeichert: Soft-Key, fail-soft).

        Args:
            audit_mode: Selbst- vs. Kunden-Audit.
            customer_data: Kundenstammdaten (Firmenname/Branche/Größe).

        Returns:
            UUID des verknüpften Subjekts oder leerer String (fail-soft).
        """
        if self._subject_store is None:
            return ""
        try:
            if audit_mode is AuditMode.SELF:
                subject = self._subject_store.ensure_self_subject(
                    customer_data.firmenname or _DEFAULT_SELF_NAME
                )
            else:
                if not customer_data.firmenname.strip():
                    return ""
                subject = self._subject_store.find_or_create_client(
                    customer_data.firmenname
                )
                self._subject_store.update_stammdaten(
                    subject.subject_id,
                    branche=customer_data.branche,
                    groesse=customer_data.unternehmensgroesse,
                    contact=customer_data.ansprechpartner_name,
                )
            return subject.subject_id
        except Exception as exc:  # noqa: BLE001 — Subjekt-Verknüpfung fail-soft
            log.warning(
                "Subjekt-Verknüpfung beim Audit-Save fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return ""

    def execute(
        self,
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
        """Berechnet Score und Empfehlungen, speichert das Ergebnis.

        Args:
            customer_data: Kundenstammdaten.
            infrastructure_data: IT-Infrastruktur.
            organizational_data: Organisatorische Sicherheit.
            network_data: Netzwerksicherheit.
            audit_mode: Selbst- vs. Kunden-Audit.
            backup_audit: Backup-Audit-Eintrag.
            sovereignty_audit: Datensouveraenitaets-Audit.
            incident_response_plan: IR-Plan.
            risk_assessments: BSI-200-3-Risiko-Bewertungen-ii).
                Liste der:class:`RiskAssessment`-Objekte. Optional —
                Audits vor 2e haben keine Risk-Liste.

        Returns:
            Vollständiges CustomerAuditResult.
        """
        backup_audit = backup_audit or BackupAuditResult()
        sovereignty_audit = sovereignty_audit or SovereigntyAuditResult()
        incident_response_plan = incident_response_plan or IncidentResponsePlan()
        phishing_data = phishing_data or PhishingData()

        # Phase 1: ein Kunden-Audit darf keine Eigenscan-Daten tragen.
        # Fail-closed VOR Scoring/Persistenz (autoritatives Gate, nicht nur GUI).
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

        result = CustomerAuditResult(
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
            subject_id=self._resolve_subject_id(audit_mode, customer_data),
        )

        try:
            self._repository.save(result)
            # DSGVO Art. 5: Firmennamen NICHT in den App-Log (Anwalts-
            # geheimnis). Identifikation ueber audit_id-Prefix reicht.
            log.info(
                "Audit erstellt: %s (Score %.1f, Risiko: %s)",
                result.audit_id[:8],
                overall,
                risk_level,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Audit-Speicherung fehlgeschlagen: %s", exc)

        return result
