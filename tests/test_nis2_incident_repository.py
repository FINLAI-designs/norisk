"""Repository-Tests fuer DbNis2IncidentRepository (Schema + Append-only)."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
    PhaseEvent,
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
    """SQLite-in-Memory-Stub fuer Repository-Tests (kein SQLCipher noetig)."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def tmp_repo():
    """Frischer In-Memory-Repo pro Test."""
    return DbNis2IncidentRepository(db=_InMemoryDB())


def _make_incident(**overrides) -> Nis2Incident:
    now = datetime.now(UTC)
    defaults = {
        "incident_id": str(uuid.uuid4()),
        "audit_id": "audit-1",
        "title": "Ransomware-Verdacht",
        "description": "Verdaechtige Datei-Verschluesselung",
        "severity": IncidentSeverity.HIGH,
        "detected_at": now,
        "current_phase": IncidentPhase.DETECT,
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(overrides)
    return Nis2Incident(**defaults)


def _make_event(incident_id: str, **overrides) -> PhaseEvent:
    defaults = {
        "event_id": None,
        "incident_id": incident_id,
        "phase": IncidentPhase.DETECT,
        "status": PhaseStatus.IN_PROGRESS,
        "actor": "patrick",
        "note": "started",
        "occurred_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return PhaseEvent(**defaults)


class TestSchemaInit:
    def test_init_creates_tables(self, tmp_repo):
        with tmp_repo._db.connection() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('nis2_incidents', 'nis2_phase_events')"
            ).fetchall()
        names = {row[0] for row in rows}
        assert names == {"nis2_incidents", "nis2_phase_events"}

    def test_init_is_idempotent(self, tmp_repo):
        # Zweiter Repo auf gleicher DB → kein Crash
        DbNis2IncidentRepository(db=tmp_repo._db)


class TestAddIncident:
    def test_add_then_get_returns_same(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        fetched = tmp_repo.get_incident(incident.incident_id)
        assert fetched is not None
        assert fetched.title == incident.title
        assert fetched.severity is IncidentSeverity.HIGH
        assert fetched.current_phase is IncidentPhase.DETECT
        assert fetched.closed_at is None
        assert fetched.events == ()

    def test_get_missing_returns_none(self, tmp_repo):
        assert tmp_repo.get_incident("nonexistent") is None


class TestAppendPhaseEvent:
    def test_event_returns_id_and_persisted(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        event = _make_event(incident.incident_id)
        event_id = tmp_repo.append_phase_event(event)
        assert event_id > 0
        events = tmp_repo.list_events_for(incident.incident_id)
        assert len(events) == 1
        assert events[0].phase is IncidentPhase.DETECT
        assert events[0].actor == "patrick"

    def test_multiple_events_ordered_chronologically(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        t0 = datetime.now(UTC)
        for offset, phase, status in [
            (timedelta(seconds=0), IncidentPhase.DETECT, PhaseStatus.IN_PROGRESS),
            (timedelta(seconds=1), IncidentPhase.DETECT, PhaseStatus.DONE),
            (timedelta(seconds=2), IncidentPhase.TRIAGE, PhaseStatus.IN_PROGRESS),
        ]:
            tmp_repo.append_phase_event(
                _make_event(
                    incident.incident_id,
                    phase=phase,
                    status=status,
                    occurred_at=t0 + offset,
                )
            )
        events = tmp_repo.list_events_for(incident.incident_id)
        assert len(events) == 3
        assert events[0].status is PhaseStatus.IN_PROGRESS
        assert events[1].status is PhaseStatus.DONE
        assert events[2].phase is IncidentPhase.TRIAGE


class TestAppendOnlyInvariant:
    """Beweist: das Repository hat keine UPDATE/DELETE-Methode auf nis2_phase_events."""

    def test_no_update_or_delete_method_for_events(self, tmp_repo):
        for forbidden in (
            "update_phase_event",
            "delete_phase_event",
            "modify_phase_event",
        ):
            assert not hasattr(tmp_repo, forbidden), (
                f"Repository darf keine {forbidden}-Methode haben "
                "(Append-only-Invariante, ADR-010 §2.2)."
            )

    def test_events_persist_across_repo_recreations(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        tmp_repo.append_phase_event(
            _make_event(incident.incident_id, note="initial")
        )
        # Repo neu erzeugen (Simulation App-Restart)
        new_repo = DbNis2IncidentRepository(db=tmp_repo._db)
        events = new_repo.list_events_for(incident.incident_id)
        assert len(events) == 1
        assert events[0].note == "initial"


class TestUpdateIncidentHeader:
    def test_phase_progression_persists(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        tmp_repo.update_incident_header(
            incident.incident_id,
            current_phase=IncidentPhase.TRIAGE,
            updated_at=datetime.now(UTC),
        )
        fetched = tmp_repo.get_incident(incident.incident_id)
        assert fetched is not None
        assert fetched.current_phase is IncidentPhase.TRIAGE

    def test_closed_at_sets_closure(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        closure = datetime.now(UTC)
        tmp_repo.update_incident_header(
            incident.incident_id, closed_at=closure
        )
        fetched = tmp_repo.get_incident(incident.incident_id)
        assert fetched is not None
        assert fetched.closed_at is not None
        assert fetched.is_open() is False

    def test_no_args_is_noop(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        # Soll nicht crashen, aber auch nichts verändern
        tmp_repo.update_incident_header(incident.incident_id)
        fetched = tmp_repo.get_incident(incident.incident_id)
        assert fetched is not None
        assert fetched.current_phase is IncidentPhase.DETECT


class TestListOpenIncidents:
    def test_lists_only_open(self, tmp_repo):
        a = _make_incident(title="Open A")
        b = _make_incident(title="Closed B")
        tmp_repo.add_incident(a)
        tmp_repo.add_incident(b)
        tmp_repo.update_incident_header(
            b.incident_id, closed_at=datetime.now(UTC)
        )
        open_list = tmp_repo.list_open_incidents()
        assert len(open_list) == 1
        assert open_list[0].title == "Open A"

    def test_filter_by_audit_id(self, tmp_repo):
        a = _make_incident(audit_id="audit-1")
        b = _make_incident(audit_id="audit-2")
        tmp_repo.add_incident(a)
        tmp_repo.add_incident(b)
        filtered = tmp_repo.list_open_incidents(audit_id="audit-1")
        assert len(filtered) == 1
        assert filtered[0].audit_id == "audit-1"

    def test_list_groups_events_per_incident(self, tmp_repo):
        """N+1-Fix: list_open_incidents laedt Events ALLER Incidents in EINER
        Query und gruppiert korrekt je Incident (keine Cross-Contamination)."""
        a = _make_incident(title="A")
        b = _make_incident(title="B")
        tmp_repo.add_incident(a)
        tmp_repo.add_incident(b)
        tmp_repo.append_phase_event(_make_event(a.incident_id))
        tmp_repo.append_phase_event(
            _make_event(
                a.incident_id,
                phase=IncidentPhase.TRIAGE,
                status=PhaseStatus.IN_PROGRESS,
                occurred_at=datetime.now(UTC) + timedelta(seconds=1),
            )
        )
        tmp_repo.append_phase_event(_make_event(b.incident_id))

        by_id = {inc.incident_id: inc for inc in tmp_repo.list_open_incidents()}
        assert len(by_id[a.incident_id].events) == 2
        assert len(by_id[b.incident_id].events) == 1
        assert all(
            e.incident_id == a.incident_id for e in by_id[a.incident_id].events
        )
        assert all(
            e.incident_id == b.incident_id for e in by_id[b.incident_id].events
        )

    def test_get_incident_includes_events(self, tmp_repo):
        incident = _make_incident()
        tmp_repo.add_incident(incident)
        tmp_repo.append_phase_event(_make_event(incident.incident_id))
        tmp_repo.append_phase_event(
            _make_event(
                incident.incident_id,
                phase=IncidentPhase.TRIAGE,
                status=PhaseStatus.IN_PROGRESS,
                occurred_at=datetime.now(UTC) + timedelta(seconds=1),
            )
        )
        fetched = tmp_repo.get_incident(incident.incident_id)
        assert fetched is not None
        assert len(fetched.events) == 2
