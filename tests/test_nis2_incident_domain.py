"""Domain-Tests fuer NIS2-Incident-Modell (Pure-Function + Dataclass-Invarianten)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
    PhaseStatus,
    deadline_for_phase,
    next_phase,
    phase_order,
)


class TestDeadlineForPhase:
    DETECTED = datetime(2026, 5, 27, 8, 0, tzinfo=UTC)

    def test_early_warning_is_24h(self):
        assert deadline_for_phase(
            self.DETECTED, IncidentPhase.EARLY_WARNING
        ) == self.DETECTED + timedelta(hours=24)

    def test_notification_is_72h(self):
        assert deadline_for_phase(
            self.DETECTED, IncidentPhase.NOTIFICATION
        ) == self.DETECTED + timedelta(hours=72)

    def test_final_report_is_30d(self):
        assert deadline_for_phase(
            self.DETECTED, IncidentPhase.FINAL_REPORT
        ) == self.DETECTED + timedelta(days=30)

    def test_detect_has_no_deadline(self):
        assert deadline_for_phase(self.DETECTED, IncidentPhase.DETECT) is None

    def test_triage_has_no_deadline(self):
        assert deadline_for_phase(self.DETECTED, IncidentPhase.TRIAGE) is None

    def test_post_incident_has_no_deadline(self):
        assert (
            deadline_for_phase(self.DETECTED, IncidentPhase.POST_INCIDENT) is None
        )


class TestNextPhase:
    def test_detect_to_triage(self):
        assert next_phase(IncidentPhase.DETECT) is IncidentPhase.TRIAGE

    def test_full_pipeline(self):
        order = [IncidentPhase.DETECT]
        current = IncidentPhase.DETECT
        while (n := next_phase(current)) is not None:
            order.append(n)
            current = n
        assert order == list(phase_order())

    def test_post_incident_is_terminal(self):
        assert next_phase(IncidentPhase.POST_INCIDENT) is None


class TestPhaseEvent:
    def test_valid_event(self):
        event = PhaseEvent(
            event_id=None,
            incident_id="abc",
            phase=IncidentPhase.DETECT,
            status=PhaseStatus.IN_PROGRESS,
            actor="patrick",
            note="erstes Detect",
            occurred_at=datetime.now(UTC),
        )
        assert event.actor == "patrick"

    def test_empty_incident_id_raises(self):
        with pytest.raises(ValueError):
            PhaseEvent(
                event_id=None,
                incident_id="",
                phase=IncidentPhase.DETECT,
                status=PhaseStatus.IN_PROGRESS,
                actor="patrick",
                note="",
                occurred_at=datetime.now(UTC),
            )

    def test_note_too_long_raises(self):
        with pytest.raises(ValueError):
            PhaseEvent(
                event_id=None,
                incident_id="x",
                phase=IncidentPhase.DETECT,
                status=PhaseStatus.IN_PROGRESS,
                actor="x",
                note="x" * 5000,
                occurred_at=datetime.now(UTC),
            )

    def test_actor_too_long_raises(self):
        with pytest.raises(ValueError):
            PhaseEvent(
                event_id=None,
                incident_id="x",
                phase=IncidentPhase.DETECT,
                status=PhaseStatus.IN_PROGRESS,
                actor="x" * 200,
                note="",
                occurred_at=datetime.now(UTC),
            )


def _incident(**overrides) -> Nis2Incident:
    defaults = {
        "incident_id": str(uuid.uuid4()),
        "audit_id": "audit-1",
        "title": "Ransomware-Verdacht",
        "description": "Verdaechtige Datei-Verschluesselung",
        "severity": IncidentSeverity.HIGH,
        "detected_at": datetime(2026, 5, 27, 8, 0, tzinfo=UTC),
        "current_phase": IncidentPhase.DETECT,
    }
    defaults.update(overrides)
    return Nis2Incident(**defaults)


class TestNis2IncidentValidation:
    def test_valid_incident(self):
        incident = _incident()
        assert incident.title == "Ransomware-Verdacht"
        assert incident.is_open() is True

    def test_empty_id_raises(self):
        with pytest.raises(ValueError):
            _incident(incident_id="")

    def test_empty_title_raises(self):
        with pytest.raises(ValueError):
            _incident(title="   ")

    def test_title_too_long_raises(self):
        with pytest.raises(ValueError):
            _incident(title="X" * 201)

    def test_description_too_long_raises(self):
        with pytest.raises(ValueError):
            _incident(description="X" * 1001)

    def test_title_is_stripped(self):
        incident = _incident(title="  has trailing whitespace   ")
        assert incident.title == "has trailing whitespace"


class TestStatusForPhase:
    DETECTED = datetime(2026, 5, 27, 8, 0, tzinfo=UTC)

    def test_open_for_phase_after_current(self):
        incident = _incident(current_phase=IncidentPhase.TRIAGE)
        assert (
            incident.status_for_phase(IncidentPhase.EARLY_WARNING)
            is PhaseStatus.OPEN
        )

    def test_in_progress_for_current_phase(self):
        incident = _incident(current_phase=IncidentPhase.EARLY_WARNING)
        assert (
            incident.status_for_phase(IncidentPhase.EARLY_WARNING)
            is PhaseStatus.IN_PROGRESS
        )

    def test_done_for_phase_before_current(self):
        incident = _incident(current_phase=IncidentPhase.NOTIFICATION)
        assert (
            incident.status_for_phase(IncidentPhase.DETECT) is PhaseStatus.DONE
        )

    def test_event_status_overrides_default(self):
        events = (
            PhaseEvent(
                event_id=1,
                incident_id="x",
                phase=IncidentPhase.TRIAGE,
                status=PhaseStatus.SKIPPED,
                actor="patrick",
                note="kein erheblicher Vorfall",
                occurred_at=self.DETECTED,
            ),
        )
        incident = _incident(
            current_phase=IncidentPhase.NOTIFICATION,
            events=events,
        )
        assert (
            incident.status_for_phase(IncidentPhase.TRIAGE)
            is PhaseStatus.SKIPPED
        )

    def test_latest_event_wins_when_multiple(self):
        events = (
            PhaseEvent(
                event_id=1,
                incident_id="x",
                phase=IncidentPhase.EARLY_WARNING,
                status=PhaseStatus.IN_PROGRESS,
                actor="patrick",
                note="started",
                occurred_at=self.DETECTED,
            ),
            PhaseEvent(
                event_id=2,
                incident_id="x",
                phase=IncidentPhase.EARLY_WARNING,
                status=PhaseStatus.DONE,
                actor="patrick",
                note="filed",
                occurred_at=self.DETECTED + timedelta(hours=1),
            ),
        )
        incident = _incident(
            current_phase=IncidentPhase.NOTIFICATION, events=events
        )
        assert (
            incident.status_for_phase(IncidentPhase.EARLY_WARNING)
            is PhaseStatus.DONE
        )


def test_deadline_for_instance_wrapper():
    incident = _incident()
    expected = incident.detected_at + timedelta(hours=24)
    assert incident.deadline_for(IncidentPhase.EARLY_WARNING) == expected


def test_is_open_false_when_closed_at_set():
    incident = _incident(closed_at=datetime.now(UTC))
    assert incident.is_open() is False
