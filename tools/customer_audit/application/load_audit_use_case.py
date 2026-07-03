"""
load_audit_use_case — Use Case: Kunden-Audits laden.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.security_subject.ports import SubjectStore
from tools.customer_audit.domain.entities import CustomerAuditResult
from tools.customer_audit.domain.repository import AuditRepository

_log = get_logger(__name__)


class LoadAuditUseCase:
    """Lädt gespeicherte Kunden-Audits aus dem Repository.

    Attributes:
        _repository: Persistenz-Adapter.
        _subject_store: Optionaler SubjectStore für den DSGVO-Art.-17-Orphan-
            Cleanup beim Löschen.
    """

    def __init__(
        self,
        repository: AuditRepository,
        *,
        subject_store: SubjectStore | None = None,
    ) -> None:
        """Initialisiert den Use Case.

        Args:
            repository: Repository-Adapter, implementiert das Port
:class:`AuditRepository` aus ``domain.repository``.
            subject_store: Optionaler:class:`SubjectStore` (core-Port)
                für den DSGVO-Art.-17-Orphan-Cleanup beim Löschen. ``None``
                deaktiviert den Cleanup (Tests/headless ohne Scoring-Backend).
        """
        self._repository = repository
        self._subject_store = subject_store

    def get_all_summaries(self, limit: int = 50) -> list[dict]:
        """Gibt kompakte Zusammenfassungen aller Audits zurück.

        Args:
            limit: Maximale Anzahl.

        Returns:
            Liste von Summary-Dicts.
        """
        return self._repository.list_summaries(limit=limit)

    def get_by_id(self, audit_id: str) -> CustomerAuditResult | None:
        """Lädt ein Audit anhand seiner ID.

        Args:
            audit_id: UUID des Audits.

        Returns:
            CustomerAuditResult oder None.
        """
        return self._repository.load_by_id(audit_id)

    def get_all(self, limit: int = 50) -> list[CustomerAuditResult]:
        """Lädt alle Audits (neueste zuerst).

        Args:
            limit: Maximale Anzahl.

        Returns:
            Liste von CustomerAuditResult.
        """
        return self._repository.load_all(limit=limit)

    def delete(self, audit_id: str) -> bool:
        """Löscht ein Audit, anonymisiert NIS2-Incidents, räumt PII-Reste auf.

        Das Audit wird samt **ganzer Versionskette** (root_audit_id)
        physisch gelöscht (DSGVO Art. 17). Die zugehörigen NIS2-Incidents werden
        gemäß §5 NICHT gelöscht, sondern PII-anonymisiert — der
        manipulationssichere Trail + Phasen-/Frist-Historie bleiben als
        Compliance-Nachweis erhalten.

        Reihenfolge ist sicherheitskritisch: **ZUERST** werden ALLE Incidents
        ALLER Ketten-``audit_id`` anonymisiert (sonst bleiben PII von Vorgänger-
        Versionen verwaist), **DANN** wird das Audit gelöscht. Die Anonymisierung
        ist **fail-LOUD**: schlägt sie fehl, wird das Audit NICHT gelöscht und
        der Fehler propagiert — es darf kein stiller PII-Rest zurückbleiben.

        **DSGVO Art. 17 — Subjekt-PII:** Kunden-Stammdaten
        (Firmenname/Ansprechpartner/Branche) werden beim Speichern in das
        kanonische Subjekt (``system_profiles``) denormalisiert. Hält nach dem
        Löschen KEIN Audit mehr dieses Subjekt UND ist es scoring-seitig
        unreferenziert, wird das Subjekt-PII entfernt (Orphan-Cleanup,
        ``best-effort`` — ein noch von Scores/anderen Audits genutztes Subjekt
        bleibt unangetastet, das eigene System nie). Nur wirksam, wenn ein
        ``subject_store`` injiziert ist.

        Args:
            audit_id: UUID (beliebige Version der Kette).

        Returns:
            True wenn das Audit gelöscht wurde, False wenn es nicht existierte.

        Raises:
            Exception: Wenn die NIS2-Anonymisierung fehlschlägt — die Löschung
                wird dann bewusst NICHT ausgeführt (kein PII-Rest).
        """
        chain_ids = self._repository.list_chain_audit_ids(audit_id)
        if not chain_ids:
            return False
        # subject_id VOR dem Löschen erfassen (für den Orphan-Cleanup danach).
        audit = self._repository.load_by_id(audit_id)
        subject_id = audit.subject_id if audit is not None else ""

        from tools.customer_audit.application.nis2_incident_service import (  # noqa: PLC0415
            Nis2IncidentService,
        )

        service = Nis2IncidentService()
        for chain_audit_id in chain_ids:
            service.anonymize_for_audit(chain_audit_id)
        deleted = self._repository.delete(audit_id)
        if deleted and subject_id:
            self._cleanup_orphan_subject(subject_id)
        return deleted

    def delete_version(self, audit_id: str) -> bool:
        """Löscht NUR die eine ausgewählte Version; andere Versionen bleiben (I).

        Im Gegensatz zu:meth:`delete` (ganze Kette, DSGVO Art. 17) entfernt
        dies genau die Version mit PK ``audit_id``. Anonymisiert werden daher
        NUR die NIS2-Incidents DIESER Version — die Incidents der erhalten
        bleibenden Versionen behalten ihren Compliance-Trail unverändert (ein
        Ketten-weites Anonymisieren würde deren Nachweise fälschlich löschen).

        Reihenfolge wie bei:meth:`delete` sicherheitskritisch: **ZUERST**
        anonymisieren (fail-LOUD — schlägt es fehl, wird NICHT gelöscht),
        **DANN** löschen. Der Orphan-Subject-Cleanup (DSGVO Art. 17)
        greift nur, wenn nach dem Löschen KEINE Version mehr das Subjekt hält
        (``count_for_subject`` == 0).

        Args:
            audit_id: UUID der zu löschenden Einzelversion (PK).

        Returns:
            True wenn die Version gelöscht wurde, False wenn sie nicht existierte.

        Raises:
            Exception: Wenn die NIS2-Anonymisierung fehlschlägt — die Löschung
                wird dann bewusst NICHT ausgeführt (kein PII-Rest).
        """
        audit = self._repository.load_by_id(audit_id)
        if audit is None:
            return False
        subject_id = audit.subject_id

        from tools.customer_audit.application.nis2_incident_service import (  # noqa: PLC0415
            Nis2IncidentService,
        )

        service = Nis2IncidentService()
        # NUR diese Version anonymisieren — nicht die ganze Kette.
        service.anonymize_for_audit(audit_id)
        deleted = self._repository.delete_version(audit_id)
        if deleted and subject_id:
            self._cleanup_orphan_subject(subject_id)
        return deleted

    def _cleanup_orphan_subject(self, subject_id: str) -> None:
        """Entfernt das Subjekt-PII, wenn es nach der Löschung verwaist ist.

        Verwaist = kein Audit hält es mehr (customer_audit-Seite, geprüft hier)
        UND es ist scoring-seitig unreferenziert (geprüft im SubjectStore). Der
        Cleanup ist **best-effort**: ein Fehler nimmt das bereits erfolgreiche
        Audit-Löschen NICHT zurück (DSGVO Art. 17 ist für Audit + NIS2 bereits
        erfüllt; das Subjekt-PII wird beim nächsten passenden Löschvorgang erneut
        geprüft).

        Args:
            subject_id: UUID des zuvor verknüpften Subjekts.
        """
        if self._subject_store is None:
            return
        try:
            if self._repository.count_for_subject(subject_id) == 0:
                removed = self._subject_store.delete_subject_if_unreferenced(
                    subject_id
                )
                if removed:
                    _log.info(
                        "DSGVO Art. 17: verwaistes Kunden-Subjekt %s nach "
                        "Audit-Löschung entfernt.",
                        subject_id,
                    )
        except Exception as exc:  # noqa: BLE001 — Cleanup best-effort
            _log.warning(
                "Orphan-Subjekt-Cleanup übersprungen (%s).",
                type(exc).__name__,
            )
