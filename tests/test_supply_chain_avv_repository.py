"""
test_supply_chain_avv_repository.

Tests fuer AvvRepository + SubprocessorRepository.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.data.avv_repository import AvvRepository
from tools.supply_chain_monitor.data.subprocessor_repository import (
    SubprocessorRepository,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
    AvvDocument,
    AvvDocumentStatus,
    Subprocessor,
    VendorCategory,
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
# AvvRepository
# ---------------------------------------------------------------------------


@pytest.fixture
def avv_repo() -> AvvRepository:
    return AvvRepository(db=_InMemoryDB())


def _make_avv(
    vendor_id: int = 1,
    sha: str = "a",
    days_until: int = 365,
) -> AvvDocument:
    now = datetime.now(UTC)
    return AvvDocument(
        id=None,
        vendor_id=vendor_id,
        file_path=f"/tmp/{sha}.pdf",
        sha256=sha * 64,
        size_bytes=1024,
        original_filename=f"{sha}_dpa.pdf",
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=days_until),
    )


class TestAvvCRUD:
    def test_add_und_roundtrip(self, avv_repo: AvvRepository) -> None:
        new_id = avv_repo.add(_make_avv())
        assert new_id > 0
        fetched = avv_repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.original_filename == "a_dpa.pdf"
        assert fetched.status is AvvDocumentStatus.ACTIVE

    def test_list_for_vendor_filtert_korrekt(self, avv_repo: AvvRepository) -> None:
        avv_repo.add(_make_avv(vendor_id=1, sha="a"))
        avv_repo.add(_make_avv(vendor_id=1, sha="b"))
        avv_repo.add(_make_avv(vendor_id=2, sha="c"))
        assert len(avv_repo.list_for_vendor(1)) == 2
        assert len(avv_repo.list_for_vendor(2)) == 1

    def test_update_aendert_dates(self, avv_repo: AvvRepository) -> None:
        new_id = avv_repo.add(_make_avv())
        existing = avv_repo.get_by_id(new_id)
        assert existing is not None
        new_until = existing.valid_until + timedelta(days=365)
        updated = AvvDocument(
            id=existing.id,
            vendor_id=existing.vendor_id,
            file_path=existing.file_path,
            sha256=existing.sha256,
            size_bytes=existing.size_bytes,
            original_filename=existing.original_filename,
            valid_from=existing.valid_from,
            valid_until=new_until,
            status=existing.status,
            notes="Verlaengert.",
            uploaded_at=existing.uploaded_at,
        )
        avv_repo.update(updated)
        again = avv_repo.get_by_id(new_id)
        assert again is not None
        assert again.notes == "Verlaengert."
        assert again.valid_until.date() == new_until.date()

    def test_update_ohne_id_wirft(self, avv_repo: AvvRepository) -> None:
        with pytest.raises(ValueError, match="gesetzte id"):
            avv_repo.update(_make_avv())

    def test_delete_entfernt_avv_und_checklist(
        self, avv_repo: AvvRepository
    ) -> None:
        new_id = avv_repo.add(_make_avv())
        entries = [
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=True, art28_check=c
            )
            for c in Art28Check
        ]
        avv_repo.replace_checklist(new_id, entries)
        assert len(avv_repo.list_checklist(new_id)) == 10

        assert avv_repo.delete(new_id) is True
        assert avv_repo.get_by_id(new_id) is None
        assert avv_repo.list_checklist(new_id) == []


class TestChecklist:
    def test_replace_checklist_atomar(self, avv_repo: AvvRepository) -> None:
        new_id = avv_repo.add(_make_avv())
        # 1. Default + 2 Custom
        e1 = [
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=True, art28_check=c
            )
            for c in Art28Check
        ]
        e1 += [
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=False,
                custom_label="Eigene Frage 1", is_custom=True,
            )
        ]
        avv_repo.replace_checklist(new_id, e1)
        assert len(avv_repo.list_checklist(new_id)) == 11

        # Replace mit weniger Eintraegen → alte sind weg.
        e2 = [
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=None,
                art28_check=Art28Check.TOMS,
            )
        ]
        avv_repo.replace_checklist(new_id, e2)
        rest = avv_repo.list_checklist(new_id)
        assert len(rest) == 1
        assert rest[0].art28_check is Art28Check.TOMS

    def test_is_present_tri_state_roundtrip(self, avv_repo: AvvRepository) -> None:
        new_id = avv_repo.add(_make_avv())
        entries = [
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=True,
                art28_check=Art28Check.WEISUNGSBINDUNG,
            ),
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=False,
                art28_check=Art28Check.TOMS,
            ),
            AvvChecklistEntry(
                id=None, avv_id=new_id, is_present=None,
                art28_check=Art28Check.AUDIT_RECHTE,
            ),
        ]
        avv_repo.replace_checklist(new_id, entries)
        result = avv_repo.list_checklist(new_id)
        states = {e.art28_check: e.is_present for e in result}
        assert states[Art28Check.WEISUNGSBINDUNG] is True
        assert states[Art28Check.TOMS] is False
        assert states[Art28Check.AUDIT_RECHTE] is None


# ---------------------------------------------------------------------------
# SubprocessorRepository
# ---------------------------------------------------------------------------


@pytest.fixture
def sub_repo() -> SubprocessorRepository:
    return SubprocessorRepository(db=_InMemoryDB())


def _make_sub(name: str = "AWS", country: str = "US") -> Subprocessor:
    return Subprocessor(
        id=None,
        name=name,
        country=country,
        category=VendorCategory.CLOUD,
    )


class TestSubprocessorCRUD:
    def test_add_und_get(self, sub_repo: SubprocessorRepository) -> None:
        new_id = sub_repo.add(_make_sub())
        fetched = sub_repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.name == "AWS"

    def test_unique_name(self, sub_repo: SubprocessorRepository) -> None:
        sub_repo.add(_make_sub("AWS"))
        with pytest.raises(ValueError, match="existiert bereits"):
            sub_repo.add(_make_sub("aws"))  # COLLATE NOCASE

    def test_list_sortiert(self, sub_repo: SubprocessorRepository) -> None:
        sub_repo.add(_make_sub("Zeppelin"))
        sub_repo.add(_make_sub("alpha"))
        sub_repo.add(_make_sub("Beta"))
        names = [s.name for s in sub_repo.list_all()]
        assert names == ["alpha", "Beta", "Zeppelin"]

    def test_delete_cascadiert_links(self, sub_repo: SubprocessorRepository) -> None:
        sub_id = sub_repo.add(_make_sub())
        sub_repo.link(vendor_id=1, subprocessor_id=sub_id, role="Storage")
        sub_repo.link(vendor_id=2, subprocessor_id=sub_id, role="CDN")
        assert sub_repo.delete(sub_id) is True
        assert sub_repo.list_links_for_subprocessor(sub_id) == []


class TestLinking:
    def test_link_idempotent(self, sub_repo: SubprocessorRepository) -> None:
        sub_id = sub_repo.add(_make_sub())
        l1 = sub_repo.link(1, sub_id, role="Storage")
        l2 = sub_repo.link(1, sub_id, role="Storage")
        # Gleicher Link → gleiche ID.
        assert l1 == l2

    def test_unterschiedliche_rolle_separater_link(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub_id = sub_repo.add(_make_sub())
        l1 = sub_repo.link(1, sub_id, role="Storage")
        l2 = sub_repo.link(1, sub_id, role="CDN")
        assert l1 != l2

    def test_links_for_vendor(self, sub_repo: SubprocessorRepository) -> None:
        sub1 = sub_repo.add(_make_sub("AWS"))
        sub2 = sub_repo.add(_make_sub("Cloudflare"))
        sub_repo.link(vendor_id=1, subprocessor_id=sub1, role="Storage")
        sub_repo.link(vendor_id=1, subprocessor_id=sub2, role="CDN")
        sub_repo.link(vendor_id=2, subprocessor_id=sub1, role="CDN")
        assert len(sub_repo.list_links_for_vendor(1)) == 2

    def test_konzentrations_aggregat(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub1 = sub_repo.add(_make_sub("AWS"))
        sub2 = sub_repo.add(_make_sub("Cloudflare"))
        sub_repo.link(vendor_id=1, subprocessor_id=sub1)
        sub_repo.link(vendor_id=2, subprocessor_id=sub1)
        sub_repo.link(vendor_id=3, subprocessor_id=sub1)
        sub_repo.link(vendor_id=1, subprocessor_id=sub2)
        concentration = sub_repo.concentration()
        assert concentration[sub1] == 3  # 3 distinct vendors
        assert concentration[sub2] == 1


class TestCustomerLinking:
    """H (Live-Test 2026-07-01): Kunden (subject_id, Cross-DB-Soft-FK) mit
    Subprocessors verknuepfen — parallel zur Vendor-Verknuepfung, additiv."""

    def test_link_customer_idempotent(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub_id = sub_repo.add(_make_sub())
        l1 = sub_repo.link_customer("subj-1", sub_id, role="Storage")
        l2 = sub_repo.link_customer("subj-1", sub_id, role="Storage")
        assert l1 == l2

    def test_link_customer_rolle_separater_link(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub_id = sub_repo.add(_make_sub())
        assert sub_repo.link_customer(
            "subj-1", sub_id, role="Storage"
        ) != sub_repo.link_customer("subj-1", sub_id, role="CDN")

    def test_list_customer_links_for_subprocessor(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub_id = sub_repo.add(_make_sub())
        sub_repo.link_customer("subj-1", sub_id, role="Storage")
        sub_repo.link_customer("subj-2", sub_id, role="CDN")
        links = sub_repo.list_customer_links_for_subprocessor(sub_id)
        assert {link.subject_id for link in links} == {"subj-1", "subj-2"}

    def test_has_customer_references(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        # DSGVO-Loesch-Block (H): blockiert die Kunden-Loeschung, solange
        # Subunternehmer-Links auf den Kunden verweisen.
        sub_id = sub_repo.add(_make_sub())
        assert sub_repo.has_customer_references("subj-1") is False
        link_id = sub_repo.link_customer("subj-1", sub_id, role="Storage")
        assert sub_repo.has_customer_references("subj-1") is True
        assert sub_repo.has_customer_references("subj-2") is False
        sub_repo.unlink_customer(link_id)
        assert sub_repo.has_customer_references("subj-1") is False

    def test_unlink_customer(self, sub_repo: SubprocessorRepository) -> None:
        sub_id = sub_repo.add(_make_sub())
        link_id = sub_repo.link_customer("subj-1", sub_id, role="Storage")
        assert sub_repo.unlink_customer(link_id) is True
        assert sub_repo.list_customer_links_for_subprocessor(sub_id) == []

    def test_delete_cascadiert_customer_links(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        sub_id = sub_repo.add(_make_sub())
        sub_repo.link(vendor_id=1, subprocessor_id=sub_id, role="Storage")
        sub_repo.link_customer("subj-1", sub_id, role="CDN")
        assert sub_repo.delete(sub_id) is True
        assert sub_repo.list_links_for_subprocessor(sub_id) == []
        assert sub_repo.list_customer_links_for_subprocessor(sub_id) == []

    def test_konzentration_zaehlt_nur_vendoren(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        # Semantik-Entscheid: Konzentrationsrisiko bleibt vendor-basiert;
        # Kunden-Links zaehlen NICHT mit.
        sub_id = sub_repo.add(_make_sub())
        sub_repo.link(vendor_id=1, subprocessor_id=sub_id)
        sub_repo.link_customer("subj-1", sub_id)
        assert sub_repo.concentration().get(sub_id) == 1  # nur der Vendor
        assert len(sub_repo.list_customer_links_for_subprocessor(sub_id)) == 1

    def test_service_link_customer_delegiert(
        self, sub_repo: SubprocessorRepository
    ) -> None:
        from tools.supply_chain_monitor.application.subprocessor_service import (
            SubprocessorService,
        )

        service = SubprocessorService(repository=sub_repo)
        sub = service.add_subprocessor(
            name="AWS", country="US", category=VendorCategory.CLOUD
        )
        assert sub.id is not None
        service.link_customer("subj-1", sub.id, role="Storage")
        links = service.customer_links_for_subprocessor(sub.id)
        assert len(links) == 1
        assert links[0].subject_id == "subj-1"
