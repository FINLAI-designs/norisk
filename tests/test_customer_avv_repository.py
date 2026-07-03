"""
test_customer_avv_repository.

Tests fuer CustomerAvvRepository (Kunden-Perspektive). Inkl. additivem
Migrations-Test gegen eine genuine Bestands-DB (R-Mig): die neuen
``customer_avv_*``-Tabellen muessen sich neben bestehenden Lieferanten-AVVs
anlegen lassen, ohne den Bestand zu beruehren.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.data.avv_repository import AvvRepository
from tools.supply_chain_monitor.data.customer_avv_repository import (
    CustomerAvvRepository,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
    AvvDocument,
    AvvDocumentStatus,
    CustomerAvvDocument,
)

_SHA = "a" * 64


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    """Ein einziges:memory:-Handle — geteilt zwischen Repos = eine DB."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def customer_repo() -> CustomerAvvRepository:
    return CustomerAvvRepository(db=_InMemoryDB())


def _make_customer_avv(
    subject_id: str = "subj-1",
    sha: str = "a",
    days_until: int = 365,
) -> CustomerAvvDocument:
    now = datetime.now(UTC)
    return CustomerAvvDocument(
        id=None,
        subject_id=subject_id,
        file_path=f"/tmp/{sha}.pdf.enc",
        sha256=sha * 64,
        size_bytes=1024,
        original_filename=f"{sha}_kunden_dpa.pdf",
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=days_until),
    )


def _make_vendor_avv(vendor_id: int = 7) -> AvvDocument:
    now = datetime.now(UTC)
    return AvvDocument(
        id=None,
        vendor_id=vendor_id,
        file_path="/tmp/vendor.pdf.enc",
        sha256=_SHA,
        size_bytes=2048,
        original_filename="vendor_dpa.pdf",
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=200),
    )


class TestCustomerAvvCRUD:
    def test_add_und_roundtrip(self, customer_repo: CustomerAvvRepository) -> None:
        new_id = customer_repo.add(_make_customer_avv())
        assert new_id > 0
        fetched = customer_repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.subject_id == "subj-1"
        assert fetched.original_filename == "a_kunden_dpa.pdf"
        assert fetched.status is AvvDocumentStatus.ACTIVE

    def test_list_for_customer_filtert_korrekt(
        self, customer_repo: CustomerAvvRepository
    ) -> None:
        customer_repo.add(_make_customer_avv(subject_id="subj-1", sha="a"))
        customer_repo.add(_make_customer_avv(subject_id="subj-1", sha="b"))
        customer_repo.add(_make_customer_avv(subject_id="subj-2", sha="c"))
        assert len(customer_repo.list_for_customer("subj-1")) == 2
        assert len(customer_repo.list_for_customer("subj-2")) == 1
        assert customer_repo.list_for_customer("unbekannt") == []

    def test_update_aendert_dates(self, customer_repo: CustomerAvvRepository) -> None:
        new_id = customer_repo.add(_make_customer_avv())
        existing = customer_repo.get_by_id(new_id)
        assert existing is not None
        new_until = existing.valid_until + timedelta(days=365)
        customer_repo.update(
            CustomerAvvDocument(
                id=existing.id,
                subject_id=existing.subject_id,
                file_path=existing.file_path,
                sha256=existing.sha256,
                size_bytes=existing.size_bytes,
                original_filename=existing.original_filename,
                valid_from=existing.valid_from,
                valid_until=new_until,
                status=existing.status,
                notes="aktualisiert",
            )
        )
        reloaded = customer_repo.get_by_id(new_id)
        assert reloaded is not None
        assert reloaded.notes == "aktualisiert"
        assert reloaded.valid_until.date() == new_until.date()

    def test_delete_kaskadiert_checkliste(
        self, customer_repo: CustomerAvvRepository
    ) -> None:
        new_id = customer_repo.add(_make_customer_avv())
        customer_repo.replace_checklist(
            new_id,
            [
                AvvChecklistEntry(
                    id=None,
                    avv_id=new_id,
                    is_present=True,
                    art28_check=Art28Check.TOMS,
                )
            ],
        )
        assert len(customer_repo.list_checklist(new_id)) == 1
        assert customer_repo.delete(new_id) is True
        assert customer_repo.get_by_id(new_id) is None
        assert customer_repo.list_checklist(new_id) == []


class TestChecklistRoundtrip:
    def test_replace_und_list(self, customer_repo: CustomerAvvRepository) -> None:
        avv_id = customer_repo.add(_make_customer_avv())
        entries = [
            AvvChecklistEntry(
                id=None, avv_id=avv_id, is_present=None, art28_check=check
            )
            for check in Art28Check
        ]
        customer_repo.replace_checklist(avv_id, entries)
        loaded = customer_repo.list_checklist(avv_id)
        assert len(loaded) == 10
        assert {e.art28_check for e in loaded} == set(Art28Check)


class TestReferenzCheck:
    """DSGVO-Loesch-Block-Grundlage E4)."""

    def test_has_references_und_count(
        self, customer_repo: CustomerAvvRepository
    ) -> None:
        assert customer_repo.has_references("subj-1") is False
        assert customer_repo.count_for_subject("subj-1") == 0
        customer_repo.add(_make_customer_avv(subject_id="subj-1", sha="a"))
        customer_repo.add(_make_customer_avv(subject_id="subj-1", sha="b"))
        assert customer_repo.has_references("subj-1") is True
        assert customer_repo.count_for_subject("subj-1") == 2
        assert customer_repo.has_references("subj-2") is False


class TestAdditiveMigration:
    """R-Mig: neue Tabellen muessen sich neben Bestand additiv anlegen lassen."""

    def test_koexistenz_mit_bestehenden_vendor_avvs(self) -> None:
        db = _InMemoryDB()
        # 1) Bestands-DB: Lieferanten-AVV-Schema + eine Zeile (wie beim Bestandskunden).
        vendor_repo = AvvRepository(db=db)
        old_id = vendor_repo.add(_make_vendor_avv())
        assert vendor_repo.get_by_id(old_id) is not None

        # 2) Neue Kunden-Tabellen ADDITIV dazu (kein Rebuild, kein no-such-table).
        customer_repo = CustomerAvvRepository(db=db)
        new_id = customer_repo.add(_make_customer_avv())

        # 3) Bestand unberuehrt + neue Tabelle nutzbar (beide koexistieren).
        assert vendor_repo.get_by_id(old_id) is not None
        assert customer_repo.get_by_id(new_id) is not None
        assert len(vendor_repo.list_all()) == 1
        assert len(customer_repo.list_all()) == 1

        # 4) Beide Tabellensaetze existieren physisch nebeneinander.
        with db.connection() as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert {"avv_documents", "customer_avv_documents"} <= tables
        assert {
            "avv_checklist_entries",
            "customer_avv_checklist_entries",
        } <= tables

    def test_init_schema_idempotent(self) -> None:
        db = _InMemoryDB()
        repo = CustomerAvvRepository(db=db)
        repo.add(_make_customer_avv())
        # Zweite Konstruktion = erneutes _init_schema; darf nichts loeschen/werfen.
        repo2 = CustomerAvvRepository(db=db)
        assert len(repo2.list_all()) == 1
