"""
test_awareness_tracker_domain.

Tests fuer die Domain-Modelle des Awareness-Trackers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.awareness_tracker.domain.models import (
    MAX_CUSTOM_TYPE_LABEL_LENGTH,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    TRAINING_VALIDITY_WARNING_DAYS_DEFAULT,
    Employee,
    Training,
    TrainingType,
    ValidityStatus,
)

NOW = datetime(2026, 5, 16, 8, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# TrainingType
# ---------------------------------------------------------------------------


class TestTrainingType:
    def test_from_value_bekannter_wert(self) -> None:
        assert (
            TrainingType.from_value("dsgvo_basics") is TrainingType.DSGVO_BASICS
        )
        assert (
            TrainingType.from_value("phishing_awareness")
            is TrainingType.PHISHING_AWARENESS
        )

    def test_from_value_unbekannt_faellt_auf_custom(self) -> None:
        assert TrainingType.from_value("does_not_exist") is TrainingType.CUSTOM

    def test_from_value_leerstring_faellt_auf_custom(self) -> None:
        assert TrainingType.from_value("") is TrainingType.CUSTOM


# ---------------------------------------------------------------------------
# Employee
# ---------------------------------------------------------------------------


class TestEmployee:
    def test_minimal_employee_valid(self) -> None:
        emp = Employee(id=None, full_name="Anna Schmidt")
        assert emp.full_name == "Anna Schmidt"
        assert emp.is_active is True
        assert emp.email == ""

    def test_leerer_name_wirft(self) -> None:
        with pytest.raises(ValueError, match="full_name"):
            Employee(id=None, full_name="   ")

    def test_zu_langer_name_wirft(self) -> None:
        with pytest.raises(ValueError, match="full_name"):
            Employee(id=None, full_name="x" * (MAX_NAME_LENGTH + 1))

    def test_name_wird_getrimmt(self) -> None:
        emp = Employee(id=None, full_name="  Anna Schmidt  ")
        assert emp.full_name == "Anna Schmidt"

    def test_zu_langes_notes_wirft(self) -> None:
        with pytest.raises(ValueError, match="notes"):
            Employee(id=None, full_name="x", notes="y" * (MAX_NOTES_LENGTH + 1))

    def test_full_fields_roundtrip(self) -> None:
        emp = Employee(
            id=42,
            full_name="Anna",
            email="anna@example.com",
            role="Anwaltsfachangestellte",
            department="Linz",
            is_active=False,
            notes="Onboarding 2026-01-15",
        )
        assert emp.id == 42
        assert emp.is_active is False
        assert emp.role == "Anwaltsfachangestellte"


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


class TestTraining:
    def test_minimal_training_valid(self) -> None:
        training = Training(
            id=None,
            employee_id=1,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO-Grundlagen",
            completed_at=NOW,
        )
        assert training.valid_until is None
        assert training.provider == ""

    def test_leerer_title_wirft(self) -> None:
        with pytest.raises(ValueError, match="title"):
            Training(
                id=None,
                employee_id=1,
                training_type=TrainingType.DSGVO_BASICS,
                title="   ",
                completed_at=NOW,
            )

    def test_valid_until_vor_completed_wirft(self) -> None:
        with pytest.raises(ValueError, match="valid_until"):
            Training(
                id=None,
                employee_id=1,
                training_type=TrainingType.DSGVO_BASICS,
                title="x",
                completed_at=NOW,
                valid_until=NOW - timedelta(days=1),
            )

    def test_custom_ohne_label_wirft(self) -> None:
        with pytest.raises(ValueError, match="custom_type_label"):
            Training(
                id=None,
                employee_id=1,
                training_type=TrainingType.CUSTOM,
                title="x",
                completed_at=NOW,
                custom_type_label="   ",
            )

    def test_custom_label_zu_lang_wirft(self) -> None:
        with pytest.raises(ValueError, match="custom_type_label"):
            Training(
                id=None,
                employee_id=1,
                training_type=TrainingType.CUSTOM,
                title="x",
                completed_at=NOW,
                custom_type_label="y" * (MAX_CUSTOM_TYPE_LABEL_LENGTH + 1),
            )

    def test_non_custom_loescht_custom_label_leise(self) -> None:
        # custom_type_label wird auf Non-CUSTOM-Trainings auf "" normalisiert
        # (Datenhygiene), kein Wurf.
        training = Training(
            id=None,
            employee_id=1,
            training_type=TrainingType.IT_SECURITY,
            title="x",
            completed_at=NOW,
            custom_type_label="Unrelated",
        )
        assert training.custom_type_label == ""


# ---------------------------------------------------------------------------
# Training.validity_status
# ---------------------------------------------------------------------------


class TestTrainingValidity:
    def _make(self, valid_until: datetime | None) -> Training:
        return Training(
            id=None,
            employee_id=1,
            training_type=TrainingType.DSGVO_BASICS,
            title="x",
            completed_at=NOW - timedelta(days=365),
            valid_until=valid_until,
        )

    def test_permanent_ohne_valid_until(self) -> None:
        training = self._make(valid_until=None)
        assert training.validity_status(now=NOW) is ValidityStatus.PERMANENT

    def test_expired_wenn_valid_until_in_vergangenheit(self) -> None:
        training = self._make(valid_until=NOW - timedelta(days=10))
        assert training.validity_status(now=NOW) is ValidityStatus.EXPIRED

    def test_expiring_soon_innerhalb_warn_window(self) -> None:
        training = self._make(
            valid_until=NOW
            + timedelta(days=TRAINING_VALIDITY_WARNING_DAYS_DEFAULT - 1)
        )
        assert (
            training.validity_status(now=NOW) is ValidityStatus.EXPIRING_SOON
        )

    def test_valid_wenn_genug_puffer(self) -> None:
        training = self._make(
            valid_until=NOW
            + timedelta(days=TRAINING_VALIDITY_WARNING_DAYS_DEFAULT + 30)
        )
        assert training.validity_status(now=NOW) is ValidityStatus.VALID

    def test_custom_warning_days(self) -> None:
        training = self._make(valid_until=NOW + timedelta(days=30))
        assert (
            training.validity_status(now=NOW, warning_days=15)
            is ValidityStatus.VALID
        )
        assert (
            training.validity_status(now=NOW, warning_days=45)
            is ValidityStatus.EXPIRING_SOON
        )


class TestTrainingDisplayLabel:
    def test_standard_typ_wird_titlecase(self) -> None:
        training = Training(
            id=None,
            employee_id=1,
            training_type=TrainingType.PHISHING_AWARENESS,
            title="x",
            completed_at=NOW,
        )
        assert training.display_type_label == "Phishing Awareness"

    def test_custom_typ_zeigt_label(self) -> None:
        training = Training(
            id=None,
            employee_id=1,
            training_type=TrainingType.CUSTOM,
            title="x",
            completed_at=NOW,
            custom_type_label="DATEV-Schulung",
        )
        assert training.display_type_label == "DATEV-Schulung"
