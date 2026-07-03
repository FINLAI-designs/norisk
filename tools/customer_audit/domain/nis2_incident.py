"""nis2_incident — Domain-Modell fuer den NIS2 Art. 23 Incident-Tracker.

Sechs-Phasen-Workflow nach EU-Richtlinie 2022/2555 Art. 23 Abs. 4:
``Detect → Triage → 24h-Early-Warning → 72h-Notification → 30d-Final-Report
→ Post-Incident``.

Fristen werden relativ zu ``detected_at`` berechnet:
- 24h fuer EARLY_WARNING
- 72h fuer NOTIFICATION
- 30d (= 720h) fuer FINAL_REPORT

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

ADR-Bezug: docs/adr/-nis2-incident-tracker.md

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

MAX_TITLE_LENGTH: Final[int] = 200
MAX_DESCRIPTION_LENGTH: Final[int] = 1000
MAX_NOTE_LENGTH: Final[int] = 2000
MAX_ACTOR_LENGTH: Final[int] = 100


class IncidentPhase(StrEnum):
    """NIS2-Reporting-Pipeline (Art. 23 Abs. 4)."""

    DETECT = "detect"
    TRIAGE = "triage"
    EARLY_WARNING = "early_warning"  # 24h ab detected_at
    NOTIFICATION = "notification"  # 72h ab detected_at
    FINAL_REPORT = "final_report"  # 30 Tage ab detected_at
    POST_INCIDENT = "post_incident"


class PhaseStatus(StrEnum):
    """Lebenszyklus einer einzelnen Phase."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    SKIPPED = "skipped"


class IncidentSeverity(StrEnum):
    """Schweregrad einer NIS2-Meldung.

    Anlehnung an Glocert-Playbook 2026 — vier Stufen, damit der Auditor-
    Report eine differenzierte Klassifikation erhaelt.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_PHASE_ORDER: Final[tuple[IncidentPhase, ...]] = (
    IncidentPhase.DETECT,
    IncidentPhase.TRIAGE,
    IncidentPhase.EARLY_WARNING,
    IncidentPhase.NOTIFICATION,
    IncidentPhase.FINAL_REPORT,
    IncidentPhase.POST_INCIDENT,
)


_PHASE_DEADLINES: Final[dict[IncidentPhase, timedelta]] = {
    IncidentPhase.EARLY_WARNING: timedelta(hours=24),
    IncidentPhase.NOTIFICATION: timedelta(hours=72),
    IncidentPhase.FINAL_REPORT: timedelta(days=30),
}


def deadline_for_phase(
    detected_at: datetime, phase: IncidentPhase
) -> datetime | None:
    """Pure: NIS2-Frist fuer eine Phase relativ zu ``detected_at``.

    Returns None fuer Phasen ohne harte Frist (DETECT, TRIAGE, POST_INCIDENT).
    """
    offset = _PHASE_DEADLINES.get(phase)
    if offset is None:
        return None
    return detected_at + offset


def next_phase(current: IncidentPhase) -> IncidentPhase | None:
    """Pure: liefert die naechste Phase in der NIS2-Pipeline.

    POST_INCIDENT ist der Endzustand → None.
    """
    idx = _PHASE_ORDER.index(current)
    if idx + 1 >= len(_PHASE_ORDER):
        return None
    return _PHASE_ORDER[idx + 1]


def phase_order() -> tuple[IncidentPhase, ...]:
    """Pure: liefert die kanonische Phasen-Reihenfolge."""
    return _PHASE_ORDER


@dataclass(frozen=True)
class PhaseEvent:
    """Ein einzelner Statuswechsel in der Phasen-Historie (Append-only).

    Wird ausschliesslich per ``INSERT`` in die ``nis2_phase_events``-Tabelle
    geschrieben — kein UPDATE/DELETE. Auditor-Sichtbarkeit der vollstaendigen
    Vorfalls-Historie ist Pflicht nach NIS2.

    Attributes:
        event_id: DB-ID (None vor INSERT).
        incident_id: UUIDv4 des zugehoerigen Vorfalls.
        phase: Welche Phase wurde gewechselt.
        status: Neuer Status der Phase.
        actor: Benutzername / Login des Bearbeiters (Audit-Trail).
        note: Optionale Freitext-Notiz (max. 2000 Zeichen).
        occurred_at: UTC-Zeitstempel.
        payload: Strukturierte Phasen-Formulardaten (JSON-Map §1).
                     Default: leeres Dict (Alt-Events / phasen ohne Formular).
        payload_schema_version: Schema-Version des ``payload`` §1).
        prev_hash: HMAC-Hash des Vorgaenger-Events der Kette §3).
                     Leerer String fuer Alt-Events ohne Hashkette (legacy).
        event_hash: HMAC-Hash dieses Events ueber ``prev_hash || canonical``
 §3). Leerer String fuer Alt-Events (legacy).
    """

    event_id: int | None
    incident_id: str
    phase: IncidentPhase
    status: PhaseStatus
    actor: str
    note: str
    occurred_at: datetime
    payload: dict = field(default_factory=dict)
    payload_schema_version: int = 1
    prev_hash: str = ""
    event_hash: str = ""

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError("PhaseEvent.incident_id darf nicht leer sein.")
        if len(self.actor) > MAX_ACTOR_LENGTH:
            raise ValueError(
                f"PhaseEvent.actor darf max. {MAX_ACTOR_LENGTH} Zeichen haben."
            )
        if len(self.note) > MAX_NOTE_LENGTH:
            raise ValueError(
                f"PhaseEvent.note darf max. {MAX_NOTE_LENGTH} Zeichen haben."
            )


@dataclass(frozen=True)
class Nis2Incident:
    """Ein NIS2-Vorfall mit Header + Phasen-Historie.

    ``current_phase`` ist die aktuell offene oder zuletzt aktive Phase
    (laeuft ueblicherweise sequenziell durch ``_PHASE_ORDER``).
    ``closed_at`` wird gesetzt, wenn der Vorfall offiziell abgeschlossen
    ist (Final-Report eingereicht oder als "kein erheblicher Vorfall"
    geschlossen).

    Die ``events``-Liste ist eine Read-Only-Sicht auf den Audit-Trail —
    Mutationen erfolgen ausschliesslich ueber das Repository.

    Attributes:
        incident_id: UUIDv4 (Primary Key).
        audit_id: Soft-FK zu ``customer_audits.audit_id``.
        title: Kurztitel (1..200 Zeichen).
        description: Mehrzeiliger Vorfall-Beschreibung (max. 1000 Zeichen).
        severity: IncidentSeverity.
        detected_at: Fristen-Anker (UTC).
        current_phase: aktuelle Phase im Lifecycle.
        closed_at: UTC-Stamp wenn geschlossen, sonst None.
        personenbezug: True, wenn der Vorfall personenbezogene Daten betrifft
                       (steuert die DSGVO-Art.33-72h-Verzweigung §4).
                       Harte Header-Spalte (indexiert).
        events: Phasen-Events (Read-Only-Sicht, append-only).
        created_at: Anlage-Zeit (UTC).
        updated_at: Letzte Mutation (UTC).
    """

    incident_id: str
    audit_id: str
    title: str
    description: str
    severity: IncidentSeverity
    detected_at: datetime
    current_phase: IncidentPhase = IncidentPhase.DETECT
    closed_at: datetime | None = None
    personenbezug: bool = False
    events: tuple[PhaseEvent, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.incident_id.strip():
            raise ValueError("Nis2Incident.incident_id darf nicht leer sein.")
        title = self.title.strip()
        if not title:
            raise ValueError("Nis2Incident.title darf nicht leer sein.")
        if len(title) > MAX_TITLE_LENGTH:
            raise ValueError(
                f"Nis2Incident.title darf max. {MAX_TITLE_LENGTH} Zeichen haben."
            )
        if title != self.title:
            object.__setattr__(self, "title", title)
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            raise ValueError(
                f"Nis2Incident.description darf max. {MAX_DESCRIPTION_LENGTH} "
                "Zeichen haben."
            )

    def deadline_for(self, phase: IncidentPhase) -> datetime | None:
        """Bequemer Instance-Wrapper um ``deadline_for_phase``."""
        return deadline_for_phase(self.detected_at, phase)

    def is_open(self) -> bool:
        """True solange der Vorfall nicht offiziell geschlossen ist."""
        return self.closed_at is None

    def status_for_phase(self, phase: IncidentPhase) -> PhaseStatus:
        """Liefert den letzten persistierten Status der gegebenen Phase.

        Wenn die Phase noch kein Event hat, gilt:
        - vor ``current_phase`` → DONE (wir muessen sie passiert haben)
        - = ``current_phase`` → IN_PROGRESS
        - nach ``current_phase`` → OPEN
        """
        latest = None
        for event in self.events:
            if event.phase is phase:
                latest = event
        if latest is not None:
            return latest.status
        target_idx = _PHASE_ORDER.index(phase)
        current_idx = _PHASE_ORDER.index(self.current_phase)
        if target_idx < current_idx:
            return PhaseStatus.DONE
        if target_idx == current_idx:
            return PhaseStatus.IN_PROGRESS
        return PhaseStatus.OPEN
