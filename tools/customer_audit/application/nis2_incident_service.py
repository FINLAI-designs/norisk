"""nis2_incident_service — Use-Case-Schicht fuer den NIS2-Incident-Tracker.

Drei zentrale Workflows:

1. ``open_incident`` — Vorfall anlegen, initiales DETECT-Event schreiben.
2. ``advance_phase`` — Phasen-Statuswechsel mit Append-only-Audit-Trail
   und automatischer Header-Mutation, wenn die Phase abgeschlossen wird.
3. ``close_incident`` — Vorfall schliessen + POST_INCIDENT-Event.

Die ``advance_phase``-Methode ist die einzige Schreib-API fuer
Phasen-Events. Sie garantiert die Append-only-Invariante (kein UPDATE/
DELETE auf ``nis2_phase_events``).

Schichtzugehoerigkeit: application/ — darf domain + data + core, keine GUI.

ADR-Bezug: docs/adr/-nis2-incident-tracker.md §2.5.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.logger import get_logger
from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain import nis2_phase_schema
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
    PhaseStatus,
    next_phase,
)

_log = get_logger(__name__)


def _current_actor() -> str:
    """Liefert den Login des aktiven Benutzers fuer den Audit-Trail.

    Fail-soft: ohne aktive Session (z. B. Tests, Headless) wird ``""``
    zurueckgegeben — der Audit-Trail bleibt schreibbar, nur ohne Akteur.

    Returns:
        ``Session.current_user.username`` oder ``""``.
    """
    try:
        from core.auth.session import Session  # noqa: PLC0415

        user = Session().current_user
        return user.username if user is not None else ""
    except Exception:  # noqa: BLE001 -- Accountability ist best-effort.
        return ""


class Nis2IncidentService:
    """Use-Case-Schicht fuer den NIS2-Incident-Tracker."""

    def __init__(
        self, repository: DbNis2IncidentRepository | None = None
    ) -> None:
        self._repo = repository or DbNis2IncidentRepository()

    # ------------------------------------------------------------------
    # Open / Close
    # ------------------------------------------------------------------

    def open_incident(
        self,
        audit_id: str,
        title: str,
        severity: IncidentSeverity,
        description: str = "",
        detected_at: datetime | None = None,
        actor: str | None = None,
        personenbezug: bool = False,
    ) -> Nis2Incident:
        """Legt einen neuen Vorfall an und schreibt das initiale DETECT-Event.

        Args:
            audit_id: Soft-FK zum betroffenen Customer-Audit.
            title: Kurztitel des Vorfalls (1..200 Zeichen).
            severity: IncidentSeverity (LOW/MEDIUM/HIGH/CRITICAL).
            description: Optionale Beschreibung (max. 1000 Zeichen).
            detected_at: Zeitpunkt der Bekanntwerdung (Default: jetzt UTC).
                Die NIS2-Fristen werden ab diesem Zeitpunkt berechnet.
            actor: Benutzername fuer den Audit-Trail. ``None`` (Default)
                zieht den Login aus:class:`~core.auth.session.Session`
 §6, Accountability).
            personenbezug: True, wenn personenbezogene Daten betroffen sind
                (steuert die DSGVO-Art.33-Verzweigung).

        Returns:
            Der angelegte Vorfall samt initialem DETECT-Event in ``events``.
        """
        if actor is None:
            actor = _current_actor()
        now = datetime.now(UTC)
        detected = detected_at or now
        incident = Nis2Incident(
            incident_id=str(uuid.uuid4()),
            audit_id=audit_id,
            title=title,
            description=description,
            severity=severity,
            detected_at=detected,
            current_phase=IncidentPhase.DETECT,
            closed_at=None,
            personenbezug=personenbezug,
            created_at=now,
            updated_at=now,
        )
        self._repo.add_incident(incident)
        # Initiales DETECT-Event als IN_PROGRESS
        initial_event = PhaseEvent(
            event_id=None,
            incident_id=incident.incident_id,
            phase=IncidentPhase.DETECT,
            status=PhaseStatus.IN_PROGRESS,
            actor=actor,
            note=f"Vorfall angelegt: {title}",
            occurred_at=now,
        )
        self._repo.append_phase_event(initial_event)
        _log.info(
            "nis2_incident_opened id=%s audit=%s severity=%s",
            incident.incident_id,
            audit_id,
            severity.value,
        )
        # Re-Fetch damit ``events`` befuellt zurueckkommt
        return self._repo.get_incident(incident.incident_id) or incident

    def close_incident(
        self,
        incident_id: str,
        actor: str | None = None,
        note: str = "Vorfall abgeschlossen",
    ) -> None:
        """Schliesst einen Vorfall + schreibt POST_INCIDENT-DONE-Event.

        ``actor=None`` (Default) zieht den Login aus der Session §6).
        """
        if actor is None:
            actor = _current_actor()
        now = datetime.now(UTC)
        self._repo.append_phase_event(
            PhaseEvent(
                event_id=None,
                incident_id=incident_id,
                phase=IncidentPhase.POST_INCIDENT,
                status=PhaseStatus.DONE,
                actor=actor,
                note=note,
                occurred_at=now,
            )
        )
        self._repo.update_incident_header(
            incident_id,
            current_phase=IncidentPhase.POST_INCIDENT,
            closed_at=now,
            updated_at=now,
        )
        _log.info("nis2_incident_closed id=%s actor=%s", incident_id, actor)

    # ------------------------------------------------------------------
    # Phase Progression
    # ------------------------------------------------------------------

    def advance_phase(
        self,
        incident_id: str,
        phase: IncidentPhase,
        status: PhaseStatus,
        actor: str | None = None,
        note: str = "",
        payload: dict | None = None,
    ) -> None:
        """Schreibt ein Phasen-Event (Append-only, verkettet) und mutiert den Header.

        Der Header-Field ``current_phase`` wird auf ``phase`` gesetzt
        wenn ``status`` IN_PROGRESS ist. Wenn ``status`` DONE oder SKIPPED
        ist, wird der Header auf die naechste Phase weitergeschaltet
        (sofern vorhanden).

        Pflichtfeld-Validierung §1): Wird ein ``payload`` uebergeben,
        prueft:func:`nis2_phase_schema.validate` die Pflichtfelder der Phase.
        Beim Schwaerzen/Ueberspringen (``status == SKIPPED``) entfaellt die
        Pflichtpruefung. Ohne ``payload`` (einfacher Statuswechsel) wird nicht
        validiert und ein leeres Payload gespeichert.

        Args:
            incident_id: UUIDv4 des Vorfalls.
            phase: Welche Phase betroffen ist.
            status: Neuer Status.
            actor: Benutzername fuer den Audit-Trail. ``None`` (Default)
                zieht den Login aus der Session §6).
            note: Optionale Notiz (max. 2000 Zeichen).
            payload: Strukturierte Formulardaten der Phase §1).

        Raises:
            ValueError: Pflichtfelder der Phase fehlen im ``payload``.
        """
        if actor is None:
            actor = _current_actor()
        if payload is not None and status is not PhaseStatus.SKIPPED:
            missing = nis2_phase_schema.validate(phase, payload)
            if missing:
                raise ValueError(
                    f"Pflichtfelder fuer Phase '{phase.value}' fehlen: "
                    f"{', '.join(missing)}."
                )
        now = datetime.now(UTC)
        self._repo.append_phase_event(
            PhaseEvent(
                event_id=None,
                incident_id=incident_id,
                phase=phase,
                status=status,
                actor=actor,
                note=note,
                occurred_at=now,
                payload=payload or {},
            )
        )
        # Header-Mutation nach Status entscheiden.
        # - IN_PROGRESS → current_phase:= phase (User arbeitet daran)
        # - DONE/SKIPPED → current_phase:= next_phase(phase) oder phase
        # (Terminal-Fallback: POST_INCIDENT bleibt POST_INCIDENT)
        # - OPEN → kein Header-Update (nur Audit-Event)
        new_phase: IncidentPhase | None
        if status is PhaseStatus.IN_PROGRESS:
            new_phase = phase
        elif status in (PhaseStatus.DONE, PhaseStatus.SKIPPED):
            new_phase = next_phase(phase) or phase
        else:
            new_phase = None
        if new_phase is not None:
            self._repo.update_incident_header(
                incident_id,
                current_phase=new_phase,
                updated_at=now,
            )
        else:
            self._repo.update_incident_header(
                incident_id, updated_at=now
            )
        _log.info(
            "nis2_phase_advanced incident=%s phase=%s status=%s actor=%s",
            incident_id,
            phase.value,
            status.value,
            actor,
        )

    # ------------------------------------------------------------------
    # Drafts §2)
    # ------------------------------------------------------------------

    def save_draft(
        self,
        incident_id: str,
        phase: IncidentPhase,
        payload: dict,
        actor: str | None = None,
    ) -> None:
        """Speichert/aktualisiert einen editierbaren Phasen-Draft (mutabel)."""
        if actor is None:
            actor = _current_actor()
        self._repo.save_draft(incident_id, phase, payload, actor=actor)

    def load_draft(
        self, incident_id: str, phase: IncidentPhase
    ) -> dict | None:
        """Laedt den Draft-Payload je (incident, phase) oder ``None``."""
        return self._repo.load_draft(incident_id, phase)

    def submit_draft(
        self,
        incident_id: str,
        phase: IncidentPhase,
        status: PhaseStatus,
        actor: str | None = None,
    ) -> int:
        """Reicht einen Draft ein: validiert, append-only Event, Draft weg.

        Pflichtfeld-Validierung §1) ausser bei ``status == SKIPPED``.

        Raises:
            ValueError: Kein Draft vorhanden ODER Pflichtfelder fehlen.
        """
        if actor is None:
            actor = _current_actor()
        if status is not PhaseStatus.SKIPPED:
            payload = self._repo.load_draft(incident_id, phase) or {}
            missing = nis2_phase_schema.validate(phase, payload)
            if missing:
                raise ValueError(
                    f"Pflichtfelder fuer Phase '{phase.value}' fehlen: "
                    f"{', '.join(missing)}."
                )
        return self._repo.submit_draft(incident_id, phase, status, actor=actor)

    def is_phase_draft_ready(self, incident: Nis2Incident | None) -> bool:
        """True wenn der Entwurf der AKTUELLEN Phase alle Pflichtfelder erfuellt,
        die Phase aber noch nicht eingereicht ist (= bereit zum Einreichen).

        Reines Anzeige-Derivat (D5b, Komitee 2026-06-26, Weg A): aendert NICHTS
        am Header und schreibt KEIN Event — der offizielle Status wechselt
        weiterhin NUR beim Submit (verkettetes Event). Damit bleibt die
        HMAC-Hashkette unberuehrt; ``status`` darf kein live-
        abgeleitetes Feld in der gehashten Kette werden (Lehre P0 beim 1. echten
        DSGVO-Vorfall).

        Effekt: die nis2_incidents-GUI (``Nis2IncidentTimeline.set_incident``)
        zeigt bei ``True`` "Entwurf vollstaendig — bereit zum Einreichen" im
        Status-Pill + Button-Nudge, sodass der Nutzer den noch fehlenden
        Submit-Schritt sieht (sonst wirkt der Vorfall haengengeblieben, obwohl
        nur die Einreichung fehlt — Patrick-Live-Test 2026-06-25).

        Args:
            incident: Der aktuelle Vorfall (oder ``None``).

        Returns:
            ``True`` nur wenn: Vorfall offen, aktuelle Phase noch nicht
            eingereicht (kein DONE), ein Draft existiert UND der Draft alle
            Pflichtfelder der Phase erfuellt.
        """
        if incident is None or not incident.is_open():
            return False
        phase = incident.current_phase
        # Bereits eingereicht? Dann ist nichts mehr "bereit zum Einreichen".
        if incident.status_for_phase(phase) is PhaseStatus.DONE:
            return False
        draft = self._repo.load_draft(incident.incident_id, phase)
        if not draft:
            return False
        # Keine fehlenden Pflichtfelder == bereit.
        return not nis2_phase_schema.validate(phase, draft)

    # ------------------------------------------------------------------
    # Tamper-Evidence / Anonymisierung §3, §5)
    # ------------------------------------------------------------------

    def verify_chain(self, incident_id: str) -> tuple[bool, int | None]:
        """Verifiziert die HMAC-Hashkette eines Incidents §3).

        Returns:
            ``(True, None)`` bei intakter Kette, sonst ``(False, event_id)``.
        """
        return self._repo.verify_chain(incident_id)

    def anonymize_for_audit(self, audit_id: str) -> int:
        """Anonymisiert alle Incidents eines Audits (DSGVO Art.17 §5).

        Returns:
            Anzahl der anonymisierten Incidents.
        """
        return self._repo.anonymize_for_audit(audit_id)

    def advance_header_after_submit(
        self, incident_id: str, submitted_phase: IncidentPhase
    ) -> IncidentPhase:
        """Schaltet ``current_phase`` nach einem Draft-Submit weiter §2).

        ``submit_draft`` schreibt nur das unveraenderliche Phasen-Event und
        loescht den Draft — es mutiert den Header bewusst NICHT (Append-only-
        Trennung). Damit der Workflow nach dem Einreichen sichtbar fortschreitet,
        schaltet diese Methode den Header auf die naechste Phase weiter. Schreibt
        KEIN zusaetzliches Event (kein Doppel-Eintrag im Trail).

        Args:
            incident_id: UUIDv4 des Vorfalls.
            submitted_phase: Die soeben eingereichte (abgeschlossene) Phase.

        Returns:
            Die neue ``current_phase`` (naechste Phase oder die letzte, wenn
            ``submitted_phase`` bereits terminal war).
        """
        new_phase = next_phase(submitted_phase) or submitted_phase
        self._repo.update_incident_header(
            incident_id,
            current_phase=new_phase,
            updated_at=datetime.now(UTC),
        )
        _log.info(
            "nis2_header_advanced incident=%s from=%s to=%s",
            incident_id,
            submitted_phase.value,
            new_phase.value,
        )
        return new_phase

    def set_personenbezug(self, incident_id: str, personenbezug: bool) -> None:
        """Synchronisiert das harte Personenbezug-Header-Flag §4).

        Wird aus dem NOTIFICATION-Phasenformular aufgerufen, wenn der Bearbeiter
        das gleichnamige Payload-Feld setzt: das Flag steuert die DSGVO-Art.33-
        72h-Verzweigung und ist deshalb als indizierte Header-Spalte gefuehrt,
        nicht nur als Payload-Wert.

        Args:
            incident_id: UUIDv4 des Vorfalls.
            personenbezug: True, wenn personenbezogene Daten betroffen sind.
        """
        self._repo.update_incident_header(
            incident_id,
            personenbezug=personenbezug,
            updated_at=datetime.now(UTC),
        )
        _log.info(
            "nis2_personenbezug_set incident=%s value=%s",
            incident_id,
            personenbezug,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def load_incident(self, incident_id: str) -> Nis2Incident | None:
        return self._repo.get_incident(incident_id)

    def list_open_incidents(
        self, audit_id: str | None = None
    ) -> list[Nis2Incident]:
        return self._repo.list_open_incidents(audit_id=audit_id)

    def list_closed_incidents(
        self, audit_id: str | None = None
    ) -> list[Nis2Incident]:
        return self._repo.list_closed_incidents(audit_id=audit_id)
