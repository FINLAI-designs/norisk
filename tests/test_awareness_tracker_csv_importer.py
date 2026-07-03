"""
test_awareness_tracker_csv_importer.

Tests fuer Bulk-Import von Mitarbeitern + Schulungen aus CSV.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.application.csv_importer import (
    EMPLOYEE_HEADER,
    TRAINING_HEADER,
    import_employees_from_csv,
    import_trainings_from_csv,
)
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
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
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def service() -> AwarenessService:
    repo = AwarenessRepository(db=_InMemoryDB())
    return AwarenessService(repository=repo)


# ---------------------------------------------------------------------------
# Employee-Import
# ---------------------------------------------------------------------------


class TestEmployeeImport:
    def test_minimaler_import(self, service: AwarenessService) -> None:
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            "Anna Schmidt,anna@k.example,AFA,Linz,true,onboard 2026\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 1
        assert result.skipped_count == 0
        assert not result.errors
        assert len(service.list_employees()) == 1
        anna = service.list_employees()[0]
        assert anna.email == "anna@k.example"

    def test_mehrere_zeilen(self, service: AwarenessService) -> None:
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            "Anna,,,,,\n"
            "Bernd,,,,,\n"
            "Caro,,,,,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 3

    def test_duplikat_wird_uebersprungen(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            "Anna,,,,,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 0
        assert result.skipped_count == 1
        assert len(result.warnings) == 1

    def test_duplikat_case_insensitive(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            "ANNA,,,,,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.skipped_count == 1

    def test_is_active_truthy_strings(
        self, service: AwarenessService
    ) -> None:
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            "Anna,,,,true,\n"
            "Bernd,,,,false,\n"
            "Caro,,,,1,\n"
            "Dora,,,,nein,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 4
        status = {e.full_name: e.is_active for e in service.list_employees()}
        assert status == {
            "Anna": True,
            "Bernd": False,
            "Caro": True,
            "Dora": False,
        }

    def test_leerer_csv(self, service: AwarenessService) -> None:
        result = import_employees_from_csv("", service)
        assert result.added_count == 0
        assert len(result.errors) == 1
        assert "leer" in result.errors[0][1].lower()

    def test_fehlender_header(self, service: AwarenessService) -> None:
        result = import_employees_from_csv(
            "full_name\nAnna\n", service
        )
        assert result.added_count == 0
        assert any("Header" in msg for _, msg in result.errors)

    def test_leerer_full_name_ist_fehler(
        self, service: AwarenessService
    ) -> None:
        csv_text = (
            "full_name,email,role,department,is_active,notes\n"
            ",,,,,\n"
            "Anna,,,,,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 1
        assert len(result.errors) == 1
        assert result.errors[0][0] == 2  # Erste Daten-Zeile

    def test_header_konstante(self) -> None:
        assert EMPLOYEE_HEADER == (
            "full_name",
            "email",
            "role",
            "department",
            "is_active",
            "notes",
        )


# ---------------------------------------------------------------------------
# Training-Import
# ---------------------------------------------------------------------------


class TestTrainingImport:
    def test_minimaler_import(self, service: AwarenessService) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,dsgvo_basics,DSGVO 2026,2026-01-15,2028-01-15,DATEV,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 1
        assert not result.errors
        trainings = service.list_trainings()
        assert len(trainings) == 1
        assert trainings[0].title == "DSGVO 2026"
        assert trainings[0].valid_until is not None

    def test_unbekannter_employee_ist_fehler(
        self, service: AwarenessService
    ) -> None:
        # KEIN Mitarbeiter angelegt
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Geist,dsgvo_basics,DSGVO,2026-01-15,,,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 0
        assert len(result.errors) == 1
        assert "Geist" in result.errors[0][1]

    def test_unbekannter_training_type_faellt_auf_custom(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,unknown_type,xyz,2026-01-15,,,Unknown-Schulung,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        # unknown_type -> CUSTOM, braucht custom_type_label -> gegeben.
        assert result.added_count == 1

    def test_completed_at_datum_only(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,dsgvo_basics,DSGVO,2026-01-15,,,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 1
        training = service.list_trainings()[0]
        assert training.completed_at == datetime(2026, 1, 15, tzinfo=UTC)

    def test_completed_at_invalid_ist_fehler(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,dsgvo_basics,DSGVO,nope,,,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 0
        assert any("completed_at" in msg for _, msg in result.errors)

    def test_dedup_per_employee_title_completedat(
        self, service: AwarenessService
    ) -> None:
        emp = service.add_employee(full_name="Anna")
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=__import__(
                "tools.awareness_tracker.domain.models", fromlist=["TrainingType"]
            ).TrainingType.DSGVO_BASICS,
            title="DSGVO",
            completed_at=datetime(2026, 1, 15, tzinfo=UTC),
        )
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,dsgvo_basics,DSGVO,2026-01-15,,,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 0
        assert result.skipped_count == 1

    def test_leerer_title(self, service: AwarenessService) -> None:
        service.add_employee(full_name="Anna")
        csv_text = (
            "employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes\n"
            "Anna,dsgvo_basics,,2026-01-15,,,,\n"
        )
        result = import_trainings_from_csv(csv_text, service)
        assert result.added_count == 0
        assert any("title" in msg for _, msg in result.errors)

    def test_header_konstante(self) -> None:
        assert TRAINING_HEADER == (
            "employee_full_name",
            "training_type",
            "title",
            "completed_at",
            "valid_until",
            "provider",
            "custom_type_label",
            "notes",
        )


# ---------------------------------------------------------------------------
# Header-Robustheit
# ---------------------------------------------------------------------------


class TestHeaderRobust:
    def test_extra_spalten_ignoriert(
        self, service: AwarenessService
    ) -> None:
        csv_text = (
            "full_name,email,role,department,is_active,notes,extra_col\n"
            "Anna,,,,,,ignored\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 1

    def test_fehlende_pflicht_spalte(
        self, service: AwarenessService
    ) -> None:
        csv_text = (
            # 'role' fehlt
            "full_name,email,department,is_active,notes\n"
            "Anna,,,true,\n"
        )
        result = import_employees_from_csv(csv_text, service)
        assert result.added_count == 0
        assert any("role" in msg for _, msg in result.errors)
