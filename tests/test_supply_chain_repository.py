"""
test_supply_chain_repository.

Tests fuer:class:`VendorRepository`. Verwendet einen In-Memory-SQLite-Stub
analog ``test_document_scanner_history`` — damit testen wir den
Repository-Vertrag ohne SQLCipher-Setup.
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory


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


@pytest.fixture
def repo() -> VendorRepository:
    return VendorRepository(db=_InMemoryDB())


def _make_vendor(
    name: str = "DATEV",
    category: VendorCategory = VendorCategory.KANZLEISOFTWARE,
    criticality_score: int = 5,
    notes: str = "",
) -> Vendor:
    return Vendor(
        id=None,
        name=name,
        category=category,
        criticality_score=criticality_score,
        notes=notes,
    )


class TestSchemaInit:
    def test_leeres_repo_listet_nichts(self, repo: VendorRepository) -> None:
        assert repo.list_all() == []

    def test_schema_init_ist_idempotent(self) -> None:
        # Zweiter Konstruktor auf derselben DB darf nicht crashen.
        db = _InMemoryDB()
        VendorRepository(db=db)
        VendorRepository(db=db)


class TestAdd:
    def test_add_liefert_neue_id(self, repo: VendorRepository) -> None:
        new_id = repo.add(_make_vendor())
        assert isinstance(new_id, int)
        assert new_id > 0

    def test_add_und_get_round_trip(self, repo: VendorRepository) -> None:
        new_id = repo.add(_make_vendor(name="M365", category=VendorCategory.CLOUD, criticality_score=4))
        fetched = repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.id == new_id
        assert fetched.name == "M365"
        assert fetched.category is VendorCategory.CLOUD
        assert fetched.criticality_score == 4

    def test_get_unbekannte_id_liefert_none(self, repo: VendorRepository) -> None:
        assert repo.get_by_id(9999) is None


class TestList:
    def test_list_all_sortiert_nach_kritikalitaet_desc(self, repo: VendorRepository) -> None:
        repo.add(_make_vendor(name="LowCrit", criticality_score=1))
        repo.add(_make_vendor(name="HighCrit", criticality_score=5))
        repo.add(_make_vendor(name="MidCrit", criticality_score=3))

        vendors = repo.list_all()

        assert [v.name for v in vendors] == ["HighCrit", "MidCrit", "LowCrit"]

    def test_list_all_sortiert_namen_alphabetisch_bei_gleichem_score(
        self, repo: VendorRepository
    ) -> None:
        repo.add(_make_vendor(name="Zebra", criticality_score=3))
        repo.add(_make_vendor(name="alpha", criticality_score=3))
        repo.add(_make_vendor(name="Beta", criticality_score=3))

        vendors = repo.list_all()

        # COLLATE NOCASE → unabhaengig von Gross-/Kleinschreibung
        assert [v.name for v in vendors] == ["alpha", "Beta", "Zebra"]


class TestUpdate:
    def test_update_aendert_felder(self, repo: VendorRepository) -> None:
        new_id = repo.add(_make_vendor(name="Alt", criticality_score=2))
        original = repo.get_by_id(new_id)
        assert original is not None

        updated = Vendor(
            id=new_id,
            name="Neu",
            category=VendorCategory.MSP,
            criticality_score=5,
            notes="Wichtiger MSP",
            created_at=original.created_at,
            updated_at=original.updated_at,
        )
        repo.update(updated)

        roundtripped = repo.get_by_id(new_id)
        assert roundtripped is not None
        assert roundtripped.name == "Neu"
        assert roundtripped.category is VendorCategory.MSP
        assert roundtripped.criticality_score == 5
        assert roundtripped.notes == "Wichtiger MSP"
        # updated_at wird vom Repository neu gesetzt — muss >= original sein.
        assert roundtripped.updated_at >= original.updated_at

    def test_update_ohne_id_wirft_value_error(self, repo: VendorRepository) -> None:
        vendor = _make_vendor()
        with pytest.raises(ValueError, match="gesetzte id"):
            repo.update(vendor)

    def test_update_unbekannte_id_wirft_value_error(self, repo: VendorRepository) -> None:
        vendor = Vendor(
            id=99999,
            name="X",
            category=VendorCategory.SPEZIAL,
            criticality_score=1,
        )
        with pytest.raises(ValueError, match="Kein Vendor mit id"):
            repo.update(vendor)


class TestDelete:
    def test_delete_entfernt_eintrag(self, repo: VendorRepository) -> None:
        new_id = repo.add(_make_vendor())
        assert repo.delete(new_id) is True
        assert repo.get_by_id(new_id) is None

    def test_delete_unbekannte_id_liefert_false(self, repo: VendorRepository) -> None:
        assert repo.delete(99999) is False


class TestRobustheit:
    def test_unbekannte_kategorie_in_db_faellt_auf_spezial_zurueck(
        self, repo: VendorRepository
    ) -> None:
        # Direkt mit unbekanntem Kategorie-String einfuegen (DB-Tampering /
        # alte Schema-Version).
        with repo._db.connection() as conn:  # noqa: SLF001 — gezielter Test-Eingriff
            conn.execute(
                """
                INSERT INTO vendors (name, category, criticality_score, notes,
                                      created_at, updated_at)
                VALUES ('Mystery', 'irgendwas_unbekanntes', 3, '',
                        '2026-05-15T00:00:00+00:00', '2026-05-15T00:00:00+00:00')
                """
            )
            conn.commit()

        vendors = repo.list_all()
        assert len(vendors) == 1
        assert vendors[0].category is VendorCategory.SPEZIAL
