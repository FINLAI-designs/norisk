"""
test_supply_chain_offboarding-i.

Tests fuer Off-Boarding-Domain + Repository + Service. In-Memory-SQLite-
Stub (analog ``test_supply_chain_avv_repository``).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from tools.supply_chain_monitor.application.offboarding_service import (
    OffBoardingService,
)
from tools.supply_chain_monitor.data.offboarding_repository import (
    OffBoardingRepository,
)
from tools.supply_chain_monitor.domain.models import (
    MAX_OFFBOARDING_REASON_LENGTH,
    OffBoarding,
    OffBoardingCheck,
    OffBoardingChecklistEntry,
    OffBoardingStatus,
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


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class TestOffBoardingDomain:
    def test_default_offboarding_ist_in_progress(self) -> None:
        offb = OffBoarding(id=None, vendor_id=1)
        assert offb.status is OffBoardingStatus.IN_PROGRESS
        assert offb.is_open() is True

    def test_completed_ohne_completed_at_wirft(self) -> None:
        with pytest.raises(ValueError, match="completed_at"):
            OffBoarding(
                id=None,
                vendor_id=1,
                status=OffBoardingStatus.COMPLETED,
            )

    def test_zu_langer_reason_wirft(self) -> None:
        with pytest.raises(ValueError, match=f"max. {MAX_OFFBOARDING_REASON_LENGTH}"):
            OffBoarding(
                id=None,
                vendor_id=1,
                reason="x" * (MAX_OFFBOARDING_REASON_LENGTH + 1),
            )

    def test_10_default_checks(self) -> None:
        assert len(list(OffBoardingCheck)) == 10

    def test_from_value_robust(self) -> None:
        assert OffBoardingCheck.from_value("data_export") is OffBoardingCheck.DATA_EXPORT
        assert OffBoardingCheck.from_value("nicht_existent") is None


class TestOffBoardingChecklistEntry:
    def test_default_entry_ist_gueltig(self) -> None:
        e = OffBoardingChecklistEntry(
            id=None,
            offboarding_id=1,
            is_done=False,
            check_key=OffBoardingCheck.DATA_EXPORT,
        )
        assert e.is_custom is False
        assert "Data Export" in e.display_label

    def test_custom_entry_ist_gueltig(self) -> None:
        e = OffBoardingChecklistEntry(
            id=None,
            offboarding_id=1,
            is_done=False,
            custom_label="Eigene Frage",
            is_custom=True,
        )
        assert e.display_label == "Eigene Frage"

    def test_default_ohne_key_wirft(self) -> None:
        with pytest.raises(ValueError, match="check_key ist Pflicht"):
            OffBoardingChecklistEntry(
                id=None,
                offboarding_id=1,
                is_done=False,
            )

    def test_custom_ohne_label_wirft(self) -> None:
        with pytest.raises(ValueError, match="custom_label"):
            OffBoardingChecklistEntry(
                id=None,
                offboarding_id=1,
                is_done=False,
                is_custom=True,
            )

    def test_custom_mit_key_wirft(self) -> None:
        with pytest.raises(ValueError, match="schliesst check_key aus"):
            OffBoardingChecklistEntry(
                id=None,
                offboarding_id=1,
                is_done=False,
                check_key=OffBoardingCheck.DATA_EXPORT,
                custom_label="X",
                is_custom=True,
            )


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


@pytest.fixture
def repo() -> OffBoardingRepository:
    return OffBoardingRepository(db=_InMemoryDB())


class TestRepositoryOffBoarding:
    def test_add_roundtrip(self, repo: OffBoardingRepository) -> None:
        new_id = repo.add(OffBoarding(id=None, vendor_id=42, reason="Migration"))
        assert new_id > 0
        fetched = repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.vendor_id == 42
        assert fetched.reason == "Migration"

    def test_unique_pro_vendor(self, repo: OffBoardingRepository) -> None:
        repo.add(OffBoarding(id=None, vendor_id=1))
        with pytest.raises(ValueError, match="existiert bereits"):
            repo.add(OffBoarding(id=None, vendor_id=1))

    def test_get_for_vendor(self, repo: OffBoardingRepository) -> None:
        repo.add(OffBoarding(id=None, vendor_id=5))
        fetched = repo.get_for_vendor(5)
        assert fetched is not None
        assert fetched.vendor_id == 5
        assert repo.get_for_vendor(999) is None

    def test_delete_entfernt_checklist_mit(
        self, repo: OffBoardingRepository
    ) -> None:
        new_id = repo.add(OffBoarding(id=None, vendor_id=1))
        entries = [
            OffBoardingChecklistEntry(
                id=None, offboarding_id=new_id, is_done=False, check_key=c
            )
            for c in OffBoardingCheck
        ]
        repo.replace_checklist(new_id, entries)
        assert len(repo.list_checklist(new_id)) == 10

        assert repo.delete(new_id) is True
        assert repo.list_checklist(new_id) == []


class TestRepositoryChecklist:
    def test_replace_atomar(self, repo: OffBoardingRepository) -> None:
        new_id = repo.add(OffBoarding(id=None, vendor_id=1))
        # Erst 10 Defaults
        defaults = [
            OffBoardingChecklistEntry(
                id=None, offboarding_id=new_id, is_done=False, check_key=c
            )
            for c in OffBoardingCheck
        ]
        repo.replace_checklist(new_id, defaults)
        assert len(repo.list_checklist(new_id)) == 10

        # Replace mit nur 1 Custom
        repo.replace_checklist(
            new_id,
            [
                OffBoardingChecklistEntry(
                    id=None, offboarding_id=new_id, is_done=True,
                    custom_label="Eigene Frage", is_custom=True,
                )
            ],
        )
        rest = repo.list_checklist(new_id)
        assert len(rest) == 1
        assert rest[0].is_custom is True
        assert rest[0].custom_label == "Eigene Frage"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> OffBoardingService:
    return OffBoardingService(repository=OffBoardingRepository(db=_InMemoryDB()))


class TestOffBoardingService:
    def test_start_legt_offboarding_und_defaults_an(
        self, service: OffBoardingService
    ) -> None:
        offb = service.start(vendor_id=1, reason="Migration")
        assert offb.id is not None
        assert offb.status is OffBoardingStatus.IN_PROGRESS
        assert offb.reason == "Migration"
        checks = service.get_checklist(offb.id)
        assert len(checks) == 10
        assert all(not c.is_done for c in checks)
        assert {c.check_key for c in checks} == set(OffBoardingCheck)

    def test_start_zweimal_pro_vendor_wirft(
        self, service: OffBoardingService
    ) -> None:
        service.start(vendor_id=1)
        with pytest.raises(ValueError, match="existiert bereits"):
            service.start(vendor_id=1)

    def test_complete_blockiert_wenn_defaults_offen(
        self, service: OffBoardingService
    ) -> None:
        offb = service.start(vendor_id=1)
        with pytest.raises(ValueError, match="kann nicht abgeschlossen"):
            service.complete(offb.id)  # type: ignore[arg-type]

    def test_complete_geht_wenn_alle_defaults_erledigt(
        self, service: OffBoardingService
    ) -> None:
        offb = service.start(vendor_id=1)
        assert offb.id is not None
        all_done = [
            OffBoardingChecklistEntry(
                id=None,
                offboarding_id=offb.id,
                is_done=True,
                check_key=c,
            )
            for c in OffBoardingCheck
        ]
        service.update_checklist(offb.id, all_done)
        done = service.complete(offb.id)
        assert done.status is OffBoardingStatus.COMPLETED
        assert done.completed_at is not None

    def test_cancel_setzt_status(self, service: OffBoardingService) -> None:
        offb = service.start(vendor_id=1)
        assert offb.id is not None
        cancelled = service.cancel(offb.id, reason="Vendor wechselt zurueck")
        assert cancelled.status is OffBoardingStatus.CANCELLED
        assert cancelled.completed_at is not None
        assert cancelled.reason == "Vendor wechselt zurueck"

    def test_progress_for_vendor_ohne_offboarding_ist_none(
        self, service: OffBoardingService
    ) -> None:
        assert service.progress_for_vendor(999) is None

    def test_progress_zaehlt_done_und_completable(
        self, service: OffBoardingService
    ) -> None:
        offb = service.start(vendor_id=1)
        assert offb.id is not None
        # 5 Defaults done
        cls = service.get_checklist(offb.id)
        partial = [
            OffBoardingChecklistEntry(
                id=e.id,
                offboarding_id=e.offboarding_id,
                is_done=(idx < 5),
                check_key=e.check_key,
                custom_label=e.custom_label,
                is_custom=e.is_custom,
                notes=e.notes,
            )
            for idx, e in enumerate(cls)
        ]
        service.update_checklist(offb.id, partial)

        prog = service.progress_for_vendor(1)
        assert prog is not None
        assert prog.done == 5
        assert prog.total == 10
        assert prog.completable is False

    def test_progress_per_vendor_aggregiert(
        self, service: OffBoardingService
    ) -> None:
        service.start(vendor_id=1)
        service.start(vendor_id=2)
        per_vendor = service.progress_per_vendor()
        assert set(per_vendor.keys()) == {1, 2}
        for prog in per_vendor.values():
            assert prog.total == 10
            assert prog.status is OffBoardingStatus.IN_PROGRESS


def test_started_at_utc(service: OffBoardingService) -> None:
    before = datetime.now(UTC)
    offb = service.start(vendor_id=1)
    after = datetime.now(UTC)
    assert before <= offb.started_at <= after
    assert offb.started_at.tzinfo is not None
