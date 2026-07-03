"""
test_awareness_tracker_service.

Tests fuer:class:`AwarenessService`. Verwendet ein leichtgewichtiges
In-Memory-Repo-Stub, damit die UseCases isoliert getestet werden.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.domain.models import (
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
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def service() -> AwarenessService:
    repo = AwarenessRepository(db=_InMemoryDB())
    return AwarenessService(repository=repo)


NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Employee-UseCases
# ---------------------------------------------------------------------------


class TestEmployeeService:
    def test_add_employee_persistiert(
        self, service: AwarenessService
    ) -> None:
        emp = service.add_employee(
            full_name="Anna Schmidt", role="AFA", department="Linz"
        )
        assert emp.id is not None
        assert emp.full_name == "Anna Schmidt"

    def test_list_und_get(self, service: AwarenessService) -> None:
        anna = service.add_employee(full_name="Anna")
        bernd = service.add_employee(full_name="Bernd")
        ids = {e.id for e in service.list_employees()}
        assert ids == {anna.id, bernd.id}
        assert service.get_employee(anna.id).full_name == "Anna"  # type: ignore[union-attr]

    def test_update_employee(self, service: AwarenessService) -> None:
        from dataclasses import replace  # noqa: PLC0415

        emp = service.add_employee(full_name="Anna")
        updated = replace(emp, role="Senior")
        service.update_employee(updated)
        fetched = service.get_employee(emp.id)  # type: ignore[arg-type]
        assert fetched is not None
        assert fetched.role == "Senior"

    def test_delete_employee(self, service: AwarenessService) -> None:
        emp = service.add_employee(full_name="Anna")
        assert service.delete_employee(emp.id) is True  # type: ignore[arg-type]
        assert service.get_employee(emp.id) is None  # type: ignore[arg-type]

    def test_add_employee_propagiert_value_error(
        self, service: AwarenessService
    ) -> None:
        with pytest.raises(ValueError, match="full_name"):
            service.add_employee(full_name="   ")

    def test_list_employees_filter_inactive(
        self, service: AwarenessService
    ) -> None:
        service.add_employee(full_name="Aktive Anna", is_active=True)
        service.add_employee(full_name="Inaktive Inge", is_active=False)
        names = {
            e.full_name
            for e in service.list_employees(include_inactive=False)
        }
        assert names == {"Aktive Anna"}


# ---------------------------------------------------------------------------
# Training-UseCases
# ---------------------------------------------------------------------------


class TestTrainingService:
    def test_add_training_persistiert(
        self, service: AwarenessService
    ) -> None:
        emp = service.add_employee(full_name="Anna")
        training = service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO 2026",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=730),
        )
        assert training.id is not None
        assert training.employee_id == emp.id
        assert training.training_type is TrainingType.DSGVO_BASICS

    def test_add_training_unbekannter_employee_wirft(
        self, service: AwarenessService
    ) -> None:
        with pytest.raises(ValueError, match="Employee"):
            service.add_training(
                employee_id=9999,
                training_type=TrainingType.DSGVO_BASICS,
                title="x",
                completed_at=NOW,
            )

    def test_list_trainings_for_employee(
        self, service: AwarenessService
    ) -> None:
        emp = service.add_employee(full_name="Anna")
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.IT_SECURITY,
            title="IT-Sec",
            completed_at=NOW,
        )
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.PHISHING_AWARENESS,
            title="Phishing",
            completed_at=NOW,
        )
        trainings = service.list_trainings_for_employee(emp.id)  # type: ignore[arg-type]
        assert len(trainings) == 2

    def test_list_trainings_global(
        self, service: AwarenessService
    ) -> None:
        anna = service.add_employee(full_name="Anna")
        bernd = service.add_employee(full_name="Bernd")
        service.add_training(
            employee_id=anna.id,  # type: ignore[arg-type]
            training_type=TrainingType.DSGVO_BASICS,
            title="A",
            completed_at=NOW,
        )
        service.add_training(
            employee_id=bernd.id,  # type: ignore[arg-type]
            training_type=TrainingType.DSGVO_BASICS,
            title="B",
            completed_at=NOW,
        )
        assert len(service.list_trainings()) == 2

    def test_delete_training(self, service: AwarenessService) -> None:
        emp = service.add_employee(full_name="Anna")
        training = service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.DSGVO_BASICS,
            title="x",
            completed_at=NOW,
        )
        assert service.delete_training(training.id) is True  # type: ignore[arg-type]
        assert service.get_training(training.id) is None  # type: ignore[arg-type]

    def test_add_training_custom_braucht_label(
        self, service: AwarenessService
    ) -> None:
        emp = service.add_employee(full_name="Anna")
        with pytest.raises(ValueError, match="custom_type_label"):
            service.add_training(
                employee_id=emp.id,  # type: ignore[arg-type]
                training_type=TrainingType.CUSTOM,
                title="x",
                completed_at=NOW,
                custom_type_label="",
            )

    def test_default_repository_typ(
        self, service: AwarenessService
    ) -> None:
        # Smoke: AwarenessService ohne explizites Repo waere zwar moeglich,
        # baut aber die echte EncryptedDatabase auf. Wir pruefen hier nur,
        # dass die Service-Klasse einen Repo-Slot exponiert.
        assert hasattr(service, "_repo")
        assert isinstance(service._repo, AwarenessRepository)  # noqa: SLF001
        _ = Training  # silence ruff fuer unused-import-Diagnose


# ---------------------------------------------------------------------------
# 3b — update_training + Renewal-Queries + employee_lookup
# ---------------------------------------------------------------------------


class TestTrainingUpdate:
    def test_update_setzt_neue_felder(
        self, service: AwarenessService
    ) -> None:
        from dataclasses import replace  # noqa: PLC0415

        emp = service.add_employee(full_name="Anna")
        training = service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.IT_SECURITY,
            title="Alte Bezeichnung",
            completed_at=NOW,
        )
        updated = replace(training, title="Neue Bezeichnung")
        service.update_training(updated)
        refetched = service.get_training(training.id)  # type: ignore[arg-type]
        assert refetched is not None
        assert refetched.title == "Neue Bezeichnung"


class TestRenewalQueries:
    def test_list_due_soon_filtert_permanent(
        self, service: AwarenessService
    ) -> None:
        from datetime import timedelta  # noqa: PLC0415

        emp = service.add_employee(full_name="Anna")
        # Permanent — soll NICHT in der Renewal-Liste auftauchen.
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.DSGVO_BASICS,
            title="Permanent",
            completed_at=NOW,
        )
        # Auslaufend — soll auftauchen.
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.IT_SECURITY,
            title="ExpiringSoon",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=10),
        )
        # Abgelaufen — soll auftauchen.
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.PHISHING_AWARENESS,
            title="Expired",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=5),  # in der Zukunft relativ
            # zum Default-NOW, aber wir testen mit injected now unten.
        )
        # Aktuell (genug Puffer) — soll NICHT auftauchen.
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.COMPLIANCE_BRAO,
            title="Valid",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=365),
        )
        due = service.list_trainings_due_soon(now=NOW)
        titles = {t.title for t in due}
        # ExpiringSoon (10 Tage < 60 Default-Warn-Fenster) + Expired
        # (auch noch in Zukunft, aber < 60 Tage Puffer).
        assert "Permanent" not in titles
        assert "Valid" not in titles
        assert "ExpiringSoon" in titles

    def test_list_due_soon_sortiert_aufsteigend_nach_valid_until(
        self, service: AwarenessService
    ) -> None:
        from datetime import timedelta  # noqa: PLC0415

        emp = service.add_employee(full_name="Anna")
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.IT_SECURITY,
            title="LaterExp",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=50),
        )
        service.add_training(
            employee_id=emp.id,  # type: ignore[arg-type]
            training_type=TrainingType.PHISHING_AWARENESS,
            title="EarlierExp",
            completed_at=NOW,
            valid_until=NOW + timedelta(days=10),
        )
        due = service.list_trainings_due_soon(now=NOW)
        # EarlierExp muss vor LaterExp stehen.
        assert [t.title for t in due] == ["EarlierExp", "LaterExp"]

    def test_employee_lookup_liefert_mapping(
        self, service: AwarenessService
    ) -> None:
        anna = service.add_employee(full_name="Anna")
        bernd = service.add_employee(full_name="Bernd")
        lookup = service.employee_lookup()
        assert lookup[anna.id] == "Anna"  # type: ignore[index]
        assert lookup[bernd.id] == "Bernd"  # type: ignore[index]
