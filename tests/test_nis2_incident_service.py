"""Service-Tests fuer Nis2IncidentService (Use-Cases + Append-only-Garantie)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    PhaseStatus,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def service():
    return Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )


class TestOpenIncident:
    def test_creates_with_detect_event(self, service):
        incident = service.open_incident(
            audit_id="audit-1",
            title="Verdaechtige Datei-Verschluesselung",
            severity=IncidentSeverity.HIGH,
            actor="patrick",
        )
        assert incident.current_phase is IncidentPhase.DETECT
        assert incident.is_open()
        assert len(incident.events) == 1
        assert incident.events[0].phase is IncidentPhase.DETECT
        assert incident.events[0].status is PhaseStatus.IN_PROGRESS

    def test_detected_at_defaults_to_now(self, service):
        before = datetime.now(UTC)
        incident = service.open_incident(
            audit_id="x", title="t", severity=IncidentSeverity.LOW
        )
        after = datetime.now(UTC)
        assert before <= incident.detected_at <= after

    def test_explicit_detected_at_is_used(self, service):
        anchor = datetime(2026, 5, 27, 8, 0, tzinfo=UTC)
        incident = service.open_incident(
            audit_id="x",
            title="t",
            severity=IncidentSeverity.LOW,
            detected_at=anchor,
        )
        assert incident.detected_at == anchor
        # Deadlines ergeben sich relativ
        assert incident.deadline_for(
            IncidentPhase.EARLY_WARNING
        ) == anchor + timedelta(hours=24)


class TestAdvancePhase:
    def test_in_progress_sets_current_phase(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.TRIAGE,
            PhaseStatus.IN_PROGRESS,
            actor="patrick",
        )
        reloaded = service.load_incident(incident.incident_id)
        assert reloaded is not None
        assert reloaded.current_phase is IncidentPhase.TRIAGE

    def test_done_advances_to_next_phase(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.DETECT,
            PhaseStatus.DONE,
            actor="patrick",
        )
        reloaded = service.load_incident(incident.incident_id)
        assert reloaded is not None
        assert reloaded.current_phase is IncidentPhase.TRIAGE

    def test_skipped_advances_to_next_phase(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.TRIAGE,
            PhaseStatus.SKIPPED,
            actor="patrick",
            note="kein erheblicher Vorfall",
        )
        reloaded = service.load_incident(incident.incident_id)
        assert reloaded is not None
        assert reloaded.current_phase is IncidentPhase.EARLY_WARNING

    def test_post_incident_done_does_not_advance(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.POST_INCIDENT,
            PhaseStatus.DONE,
            actor="patrick",
        )
        reloaded = service.load_incident(incident.incident_id)
        # Header bleibt auf POST_INCIDENT (next_phase liefert None)
        assert reloaded is not None
        assert reloaded.current_phase is IncidentPhase.POST_INCIDENT

    def test_event_appended_each_call(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.DETECT,
            PhaseStatus.DONE,
            actor="patrick",
        )
        service.advance_phase(
            incident.incident_id,
            IncidentPhase.TRIAGE,
            PhaseStatus.IN_PROGRESS,
            actor="patrick",
        )
        reloaded = service.load_incident(incident.incident_id)
        assert reloaded is not None
        # 1 initial DETECT-Event + 2 advance_phase-Events = 3
        assert len(reloaded.events) == 3


class TestCloseIncident:
    def test_closes_with_post_incident_event(self, service):
        incident = service.open_incident(
            "audit-1", "t", IncidentSeverity.HIGH
        )
        service.close_incident(
            incident.incident_id, actor="patrick", note="auditiert"
        )
        reloaded = service.load_incident(incident.incident_id)
        assert reloaded is not None
        assert reloaded.is_open() is False
        assert reloaded.current_phase is IncidentPhase.POST_INCIDENT
        last_event = reloaded.events[-1]
        assert last_event.phase is IncidentPhase.POST_INCIDENT
        assert last_event.status is PhaseStatus.DONE


class TestListOpenIncidents:
    def test_excludes_closed(self, service):
        a = service.open_incident("aud", "open", IncidentSeverity.HIGH)
        b = service.open_incident("aud", "closing", IncidentSeverity.LOW)
        service.close_incident(b.incident_id)
        open_list = service.list_open_incidents()
        assert len(open_list) == 1
        assert open_list[0].incident_id == a.incident_id

    def test_filter_by_audit_id(self, service):
        service.open_incident("aud-1", "x", IncidentSeverity.LOW)
        b = service.open_incident("aud-2", "y", IncidentSeverity.LOW)
        in_aud_1 = service.list_open_incidents(audit_id="aud-1")
        assert len(in_aud_1) == 1
        assert in_aud_1[0].audit_id == "aud-1"
        # b ist nicht enthalten
        assert b.incident_id not in {i.incident_id for i in in_aud_1}


class TestIsPhaseDraftReady:
    """D5b — abgeleiteter "Entwurf vollstaendig, bereit zum Einreichen"-Zustand.

    Reines Anzeige-Derivat: schreibt nichts, beruehrt die Hashkette nicht.
    """

    def _full_payload(self, phase) -> dict:  # noqa: ANN001
        from tools.customer_audit.domain import nis2_phase_schema  # noqa: PLC0415

        return {key: "x" for key in nis2_phase_schema.required_keys(phase)}

    def test_none_incident_returns_false(self, service):
        assert service.is_phase_draft_ready(None) is False

    def test_no_draft_returns_false(self, service):
        inc = service.open_incident("aud", "x", IncidentSeverity.HIGH)
        full = service.load_incident(inc.incident_id)
        assert service.is_phase_draft_ready(full) is False

    def test_incomplete_draft_returns_false(self, service):
        inc = service.open_incident("aud", "x", IncidentSeverity.HIGH)
        # Leerer Draft -> Pflichtfelder fehlen.
        service.save_draft(inc.incident_id, inc.current_phase, {}, actor="t")
        full = service.load_incident(inc.incident_id)
        assert service.is_phase_draft_ready(full) is False

    def test_complete_draft_returns_true(self, service):
        inc = service.open_incident("aud", "x", IncidentSeverity.HIGH)
        phase = inc.current_phase
        service.save_draft(
            inc.incident_id, phase, self._full_payload(phase), actor="t"
        )
        full = service.load_incident(inc.incident_id)
        assert service.is_phase_draft_ready(full) is True

    def test_closed_incident_returns_false(self, service):
        inc = service.open_incident("aud", "x", IncidentSeverity.HIGH)
        phase = inc.current_phase
        service.save_draft(
            inc.incident_id, phase, self._full_payload(phase), actor="t"
        )
        service.close_incident(inc.incident_id, actor="t")
        full = service.load_incident(inc.incident_id)
        assert service.is_phase_draft_ready(full) is False

    def test_submitted_phase_returns_false(self, service):
        # Phase eingereicht (DONE-Event) -> nichts mehr "bereit zum Einreichen".
        inc = service.open_incident("aud", "x", IncidentSeverity.HIGH)
        phase = inc.current_phase
        payload = self._full_payload(phase)
        service.save_draft(inc.incident_id, phase, payload, actor="t")
        service.submit_draft(inc.incident_id, phase, PhaseStatus.DONE, actor="t")
        full = service.load_incident(inc.incident_id)
        # Nach Submit ist die eingereichte Phase DONE; der Helfer prueft die
        # (ggf. weitergerueckte) current_phase, fuer die es keinen Draft gibt.
        assert service.is_phase_draft_ready(full) is False
