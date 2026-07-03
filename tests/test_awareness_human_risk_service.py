"""Service-Tests fuer Human-Risk-Score + Schulungs-Quote (IA-Welle 2).

Nutzt dasselbe In-Memory-Repo-Muster wie test_awareness_tracker_service.
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
from tools.awareness_tracker.domain.human_risk_score import RiskBand
from tools.awareness_tracker.domain.models import (
    PhishingSimVendor,
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


NOW = datetime(2026, 6, 19, 8, 0, tzinfo=UTC)


class TestTrainingCompletion:
    def test_leer(self, service: AwarenessService) -> None:
        completion, active = service.training_completion(now=NOW)
        assert completion == 0.0
        assert active == 0

    def test_quote_nur_aktive_und_gueltige(self, service: AwarenessService) -> None:
        anna = service.add_employee(full_name="Anna", is_active=True)
        bernd = service.add_employee(full_name="Bernd", is_active=True)
        service.add_employee(full_name="Carla", is_active=False)  # zaehlt nicht

        # Anna: gueltige Schulung -> abgedeckt.
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO 2026",
            completed_at=NOW - timedelta(days=30),
            valid_until=NOW + timedelta(days=365),
        )
        # Bernd: abgelaufene Schulung -> NICHT abgedeckt.
        service.add_training(
            employee_id=bernd.id,
            training_type=TrainingType.IT_SECURITY,
            title="IT-Sec alt",
            completed_at=NOW - timedelta(days=800),
            valid_until=NOW - timedelta(days=10),
        )

        completion, active = service.training_completion(now=NOW)
        assert active == 2  # Carla (inaktiv) nicht im Nenner
        assert completion == pytest.approx(50.0)  # nur Anna abgedeckt

    def test_permanent_schulung_zaehlt_als_abgedeckt(
        self, service: AwarenessService
    ) -> None:
        anna = service.add_employee(full_name="Anna", is_active=True)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.IT_SECURITY,
            title="Onboarding",
            completed_at=NOW - timedelta(days=100),
            valid_until=None,  # PERMANENT -> nie abgelaufen
        )
        completion, active = service.training_completion(now=NOW)
        assert active == 1
        assert completion == pytest.approx(100.0)

    def test_expiring_soon_zaehlt_als_abgedeckt(
        self, service: AwarenessService
    ) -> None:
        anna = service.add_employee(full_name="Anna", is_active=True)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO",
            completed_at=NOW - timedelta(days=300),
            valid_until=NOW + timedelta(days=5),  # bald faellig, aber gueltig
        )
        completion, _ = service.training_completion(now=NOW)
        # Nur EXPIRED schliesst aus -> EXPIRING_SOON zaehlt als abgedeckt.
        assert completion == pytest.approx(100.0)


class TestComputeHumanRiskScore:
    def test_leer_keine_daten(self, service: AwarenessService) -> None:
        risk = service.compute_human_risk_score(now=NOW)
        assert risk.score == 0.0
        assert risk.has_any_data is False
        assert risk.has_phishing_data is False

    def test_integration_mit_phishing_und_schulung(
        self, service: AwarenessService
    ) -> None:
        anna = service.add_employee(full_name="Anna", is_active=True)
        service.add_employee(full_name="Bernd", is_active=True)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.PHISHING_AWARENESS,
            title="Phishing 2026",
            completed_at=NOW - timedelta(days=10),
            valid_until=NOW + timedelta(days=365),
        )
        # 1 Kampagne: 10 Ziele, 1 Klick (10 %), 5 Meldungen (50 %).
        service.add_phishing_sim(
            name="Welle 1",
            vendor=PhishingSimVendor.CUSTOM,
            run_date=NOW - timedelta(days=5),
            target_count=10,
            click_count=1,
            report_count=5,
            custom_vendor_label="Intern",
        )

        risk = service.compute_human_risk_score(now=NOW)
        # training_completion = 1/2 = 50 %
        # score = 0.4*50 + 0.35*(100-10) + 0.25*50 = 20 + 31.5 + 12.5 = 64.0
        assert risk.has_phishing_data is True
        assert risk.report_rate == pytest.approx(50.0)
        assert risk.click_rate == pytest.approx(10.0)
        assert risk.training_completion == pytest.approx(50.0)
        assert risk.score == pytest.approx(64.0)
        assert risk.band is RiskBand.AT_RISK

    def test_ohne_phishing_nur_schulung(self, service: AwarenessService) -> None:
        anna = service.add_employee(full_name="Anna", is_active=True)
        service.add_training(
            employee_id=anna.id,
            training_type=TrainingType.DSGVO_BASICS,
            title="DSGVO",
            completed_at=NOW - timedelta(days=10),
            valid_until=NOW + timedelta(days=365),
        )
        risk = service.compute_human_risk_score(now=NOW)
        assert risk.has_phishing_data is False
        assert risk.score == pytest.approx(100.0)  # 1/1 aktive MA abgedeckt
        assert risk.has_any_data is True
