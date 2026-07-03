"""
test_awareness_tracker_repository.

Tests fuer:class:`AwarenessRepository`. Verwendet einen In-Memory-SQLite-
Stub (gleicher Trick wie ``test_supply_chain_repository``) — damit testen
wir den Repository-Vertrag ohne SQLCipher-Setup.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.domain.models import (
    Employee,
    Training,
    TrainingType,
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
        # ON DELETE CASCADE braucht foreign_keys=ON pro Connection.
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def repo() -> AwarenessRepository:
    return AwarenessRepository(db=_InMemoryDB())


NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


def _make_employee(
    name: str = "Anna Schmidt",
    is_active: bool = True,
) -> Employee:
    return Employee(
        id=None,
        full_name=name,
        email=f"{name.lower().replace(' ', '.')}@kanzlei.example",
        role="Anwaltsfachangestellte",
        department="Linz",
        is_active=is_active,
    )


def _make_training(
    employee_id: int,
    title: str = "DSGVO-Grundlagen",
    valid_until: datetime | None = None,
    training_type: TrainingType = TrainingType.DSGVO_BASICS,
) -> Training:
    return Training(
        id=None,
        employee_id=employee_id,
        training_type=training_type,
        title=title,
        completed_at=NOW - timedelta(days=30),
        valid_until=valid_until,
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestSchemaInit:
    def test_leeres_repo_listet_nichts(
        self, repo: AwarenessRepository
    ) -> None:
        assert repo.list_employees() == []
        assert repo.list_trainings() == []

    def test_schema_init_ist_idempotent(self) -> None:
        db = _InMemoryDB()
        AwarenessRepository(db=db)
        AwarenessRepository(db=db)


# ---------------------------------------------------------------------------
# Employee CRUD
# ---------------------------------------------------------------------------


class TestEmployeeCrud:
    def test_add_liefert_neue_id(self, repo: AwarenessRepository) -> None:
        new_id = repo.add_employee(_make_employee())
        assert isinstance(new_id, int)
        assert new_id > 0

    def test_add_und_get_round_trip(
        self, repo: AwarenessRepository
    ) -> None:
        new_id = repo.add_employee(
            _make_employee(name="Bernd Mueller")
        )
        fetched = repo.get_employee(new_id)
        assert fetched is not None
        assert fetched.id == new_id
        assert fetched.full_name == "Bernd Mueller"
        assert fetched.is_active is True

    def test_get_unbekannte_id_liefert_none(
        self, repo: AwarenessRepository
    ) -> None:
        assert repo.get_employee(9999) is None

    def test_list_sortiert_alphabetisch(
        self, repo: AwarenessRepository
    ) -> None:
        repo.add_employee(_make_employee(name="Zacharias"))
        repo.add_employee(_make_employee(name="anna"))
        repo.add_employee(_make_employee(name="Bernd"))
        names = [e.full_name for e in repo.list_employees()]
        # COLLATE NOCASE — case-insensitive Sortierung.
        assert names == ["anna", "Bernd", "Zacharias"]

    def test_list_ohne_inactive(self, repo: AwarenessRepository) -> None:
        repo.add_employee(_make_employee(name="Aktive Anna"))
        repo.add_employee(
            _make_employee(name="Inaktive Inge", is_active=False)
        )
        active_only = repo.list_employees(include_inactive=False)
        assert {e.full_name for e in active_only} == {"Aktive Anna"}

    def test_update_funktioniert(self, repo: AwarenessRepository) -> None:
        new_id = repo.add_employee(_make_employee())
        existing = repo.get_employee(new_id)
        assert existing is not None
        from dataclasses import replace  # noqa: PLC0415

        updated = replace(
            existing, role="Senior-Partnerin", department="Wien"
        )
        repo.update_employee(updated)
        refetched = repo.get_employee(new_id)
        assert refetched is not None
        assert refetched.role == "Senior-Partnerin"
        assert refetched.department == "Wien"

    def test_update_ohne_id_wirft(
        self, repo: AwarenessRepository
    ) -> None:
        with pytest.raises(ValueError, match="id"):
            repo.update_employee(_make_employee())

    def test_update_unbekannte_id_wirft(
        self, repo: AwarenessRepository
    ) -> None:
        from dataclasses import replace  # noqa: PLC0415

        ghost = replace(_make_employee(), id=99999)
        with pytest.raises(ValueError, match="9999"):
            repo.update_employee(ghost)

    def test_delete_liefert_true_bei_hit(
        self, repo: AwarenessRepository
    ) -> None:
        new_id = repo.add_employee(_make_employee())
        assert repo.delete_employee(new_id) is True
        assert repo.get_employee(new_id) is None

    def test_delete_liefert_false_bei_miss(
        self, repo: AwarenessRepository
    ) -> None:
        assert repo.delete_employee(99999) is False


# ---------------------------------------------------------------------------
# Training CRUD
# ---------------------------------------------------------------------------


class TestTrainingCrud:
    def test_add_und_get_round_trip(
        self, repo: AwarenessRepository
    ) -> None:
        emp_id = repo.add_employee(_make_employee())
        training_id = repo.add_training(_make_training(emp_id))
        fetched = repo.get_training(training_id)
        assert fetched is not None
        assert fetched.employee_id == emp_id
        assert fetched.title == "DSGVO-Grundlagen"
        assert fetched.training_type is TrainingType.DSGVO_BASICS

    def test_valid_until_optional_persistiert(
        self, repo: AwarenessRepository
    ) -> None:
        emp_id = repo.add_employee(_make_employee())
        permanent_id = repo.add_training(
            _make_training(emp_id, valid_until=None)
        )
        renewable_id = repo.add_training(
            _make_training(emp_id, valid_until=NOW + timedelta(days=365))
        )
        permanent = repo.get_training(permanent_id)
        renewable = repo.get_training(renewable_id)
        assert permanent is not None
        assert renewable is not None
        assert permanent.valid_until is None
        assert renewable.valid_until is not None

    def test_list_for_employee_sortiert_neueste_zuerst(
        self, repo: AwarenessRepository
    ) -> None:
        emp_id = repo.add_employee(_make_employee())
        repo.add_training(
            Training(
                id=None,
                employee_id=emp_id,
                training_type=TrainingType.DSGVO_BASICS,
                title="alt",
                completed_at=NOW - timedelta(days=730),
            )
        )
        repo.add_training(
            Training(
                id=None,
                employee_id=emp_id,
                training_type=TrainingType.DSGVO_BASICS,
                title="neu",
                completed_at=NOW - timedelta(days=10),
            )
        )
        titles = [
            t.title for t in repo.list_trainings_for_employee(emp_id)
        ]
        assert titles == ["neu", "alt"]

    def test_list_for_employee_isoliert_andere_employees(
        self, repo: AwarenessRepository
    ) -> None:
        emp_a = repo.add_employee(_make_employee(name="A"))
        emp_b = repo.add_employee(_make_employee(name="B"))
        repo.add_training(_make_training(emp_a, title="A1"))
        repo.add_training(_make_training(emp_b, title="B1"))
        titles_a = [
            t.title for t in repo.list_trainings_for_employee(emp_a)
        ]
        assert titles_a == ["A1"]

    def test_update_training(self, repo: AwarenessRepository) -> None:
        from dataclasses import replace  # noqa: PLC0415

        emp_id = repo.add_employee(_make_employee())
        training_id = repo.add_training(_make_training(emp_id))
        original = repo.get_training(training_id)
        assert original is not None
        updated = replace(original, title="Neuer Titel")
        repo.update_training(updated)
        refetched = repo.get_training(training_id)
        assert refetched is not None
        assert refetched.title == "Neuer Titel"

    def test_update_training_ohne_id_wirft(
        self, repo: AwarenessRepository
    ) -> None:
        with pytest.raises(ValueError, match="id"):
            repo.update_training(_make_training(1))

    def test_update_unbekannte_id_wirft(
        self, repo: AwarenessRepository
    ) -> None:
        from dataclasses import replace  # noqa: PLC0415

        emp_id = repo.add_employee(_make_employee())
        ghost = replace(_make_training(emp_id), id=9999)
        with pytest.raises(ValueError, match="9999"):
            repo.update_training(ghost)

    def test_delete_training_einzeln(
        self, repo: AwarenessRepository
    ) -> None:
        emp_id = repo.add_employee(_make_employee())
        training_id = repo.add_training(_make_training(emp_id))
        assert repo.delete_training(training_id) is True
        assert repo.get_training(training_id) is None

    def test_delete_employee_cascade_loescht_trainings(
        self, repo: AwarenessRepository
    ) -> None:
        emp_id = repo.add_employee(_make_employee())
        repo.add_training(_make_training(emp_id, title="T1"))
        repo.add_training(_make_training(emp_id, title="T2"))
        repo.delete_employee(emp_id)
        assert repo.list_trainings_for_employee(emp_id) == []
