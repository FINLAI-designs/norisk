"""
test_supply_chain_catalog_repository.

Tests fuer VendorCatalogRepository + VendorDetectionRepository. Verwendet
einen In-Memory-SQLite-Stub.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.data.vendor_detection_repository import (
    VendorDetectionRepository,
)
from tools.supply_chain_monitor.domain.models import (
    DetectionSource,
    DetectionStatus,
    VendorCatalogEntry,
    VendorCategory,
    VendorDetection,
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
# VendorCatalogRepository
# ---------------------------------------------------------------------------


@pytest.fixture
def catalog_repo() -> VendorCatalogRepository:
    return VendorCatalogRepository(db=_InMemoryDB())


def _make_entry(name: str = "Microsoft") -> VendorCatalogEntry:
    return VendorCatalogEntry(
        id=None,
        canonical_name=name,
        default_category=VendorCategory.CLOUD,
        aliases=("msft",),
        app_name_patterns=("microsoft", "onedrive"),
        mx_hostname_patterns=("protection.outlook.com",),
        cert_issuer_patterns=("microsoft",),
        notes="Test-Eintrag",
    )


class TestCatalogRepositoryAdd:
    def test_add_und_roundtrip(self, catalog_repo: VendorCatalogRepository) -> None:
        entry_id = catalog_repo.add(_make_entry())
        assert entry_id > 0
        fetched = catalog_repo.get_by_id(entry_id)
        assert fetched is not None
        assert fetched.canonical_name == "Microsoft"
        assert fetched.aliases == ("msft",)
        assert fetched.app_name_patterns == ("microsoft", "onedrive")
        assert fetched.mx_hostname_patterns == ("protection.outlook.com",)
        assert fetched.cert_issuer_patterns == ("microsoft",)
        assert fetched.notes == "Test-Eintrag"

    def test_add_duplikat_wirft_value_error(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        catalog_repo.add(_make_entry("Microsoft"))
        with pytest.raises(ValueError, match="existiert bereits"):
            catalog_repo.add(_make_entry("Microsoft"))


class TestCatalogRepositoryLookup:
    def test_get_by_canonical_name_case_insensitive(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        catalog_repo.add(_make_entry("Hetzner"))
        fetched = catalog_repo.get_by_canonical_name("hetzner")
        assert fetched is not None
        assert fetched.canonical_name == "Hetzner"

    def test_list_all_sortiert_alphabetisch(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        catalog_repo.add(_make_entry("Hetzner"))
        catalog_repo.add(_make_entry("apple"))
        catalog_repo.add(_make_entry("DATEV"))
        names = [e.canonical_name for e in catalog_repo.list_all()]
        assert names == ["apple", "DATEV", "Hetzner"]

    def test_count(self, catalog_repo: VendorCatalogRepository) -> None:
        assert catalog_repo.count() == 0
        catalog_repo.add(_make_entry("A"))
        catalog_repo.add(_make_entry("B"))
        assert catalog_repo.count() == 2


class TestCatalogRepositoryUpdate:
    def test_update_aendert_felder(self, catalog_repo: VendorCatalogRepository) -> None:
        entry_id = catalog_repo.add(_make_entry("Microsoft"))
        existing = catalog_repo.get_by_id(entry_id)
        assert existing is not None
        updated = VendorCatalogEntry(
            id=entry_id,
            canonical_name="Microsoft Cloud",  # Rename
            default_category=VendorCategory.MSP,
            aliases=("ms-cloud",),
            app_name_patterns=("microsoft cloud",),
            notes="Aktualisiert",
            created_at=existing.created_at,
            updated_at=existing.updated_at,
        )
        catalog_repo.update(updated)
        fetched = catalog_repo.get_by_id(entry_id)
        assert fetched is not None
        assert fetched.canonical_name == "Microsoft Cloud"
        assert fetched.default_category is VendorCategory.MSP
        assert fetched.aliases == ("ms-cloud",)

    def test_update_ohne_id_wirft(self, catalog_repo: VendorCatalogRepository) -> None:
        with pytest.raises(ValueError, match="gesetzte id"):
            catalog_repo.update(_make_entry())

    def test_update_unbekannte_id_wirft(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        ghost = VendorCatalogEntry(
            id=999,
            canonical_name="X",
            default_category=VendorCategory.SPEZIAL,
        )
        with pytest.raises(ValueError, match="Kein Catalog"):
            catalog_repo.update(ghost)


class TestCatalogRepositoryDelete:
    def test_delete_entfernt_eintrag(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        entry_id = catalog_repo.add(_make_entry())
        assert catalog_repo.delete(entry_id) is True
        assert catalog_repo.get_by_id(entry_id) is None

    def test_delete_unbekannte_id_liefert_false(
        self, catalog_repo: VendorCatalogRepository
    ) -> None:
        assert catalog_repo.delete(9999) is False


# ---------------------------------------------------------------------------
# VendorDetectionRepository
# ---------------------------------------------------------------------------


@pytest.fixture
def detection_repo() -> VendorDetectionRepository:
    return VendorDetectionRepository(db=_InMemoryDB())


def _make_detection(
    catalog_entry_id: int = 1,
    source: DetectionSource = DetectionSource.INSTALLED_APP,
    raw_match: str = "Microsoft OneDrive",
    detected_at: datetime | None = None,
) -> VendorDetection:
    return VendorDetection(
        id=None,
        catalog_entry_id=catalog_entry_id,
        source=source,
        raw_match=raw_match,
        detected_at=detected_at or datetime.now(UTC),
    )


class TestDetectionRepositoryUpsert:
    def test_upsert_neu_legt_an(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        new_id = detection_repo.upsert(_make_detection())
        assert new_id > 0
        fetched = detection_repo.get_by_id(new_id)
        assert fetched is not None
        assert fetched.status is DetectionStatus.PENDING

    def test_upsert_existing_aktualisiert_nur_detected_at(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        # 1. Insert
        det1 = _make_detection(detected_at=datetime(2026, 1, 1, tzinfo=UTC))
        id1 = detection_repo.upsert(det1)
        first = detection_repo.get_by_id(id1)
        assert first is not None
        # User rejected den Treffer.
        detection_repo.set_status(id1, DetectionStatus.REJECTED)
        # 2. Re-Scan mit gleichem (catalog, source, raw_match) — neuer Stamp
        det2 = _make_detection(detected_at=datetime(2026, 5, 1, tzinfo=UTC))
        id2 = detection_repo.upsert(det2)
        assert id2 == id1  # gleiche Zeile
        updated = detection_repo.get_by_id(id1)
        assert updated is not None
        # Status BLEIBT rejected — Re-Scan reaktiviert nicht.
        assert updated.status is DetectionStatus.REJECTED
        # detected_at wurde aktualisiert.
        assert updated.detected_at == datetime(2026, 5, 1, tzinfo=UTC)


class TestDetectionRepositoryListing:
    def test_list_actionable_filtert_status(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        id1 = detection_repo.upsert(_make_detection(catalog_entry_id=1, source=DetectionSource.INSTALLED_APP))
        id2 = detection_repo.upsert(_make_detection(catalog_entry_id=2, source=DetectionSource.MX_LOOKUP, raw_match="b"))
        id3 = detection_repo.upsert(_make_detection(catalog_entry_id=3, source=DetectionSource.CERT_ISSUER, raw_match="c"))

        detection_repo.set_status(id2, DetectionStatus.REJECTED)
        detection_repo.set_status(id3, DetectionStatus.DEFERRED)

        ids = {d.id for d in detection_repo.list_actionable()}
        assert ids == {id1, id3}  # PENDING + DEFERRED

    def test_list_for_catalog_entry(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        detection_repo.upsert(_make_detection(catalog_entry_id=1, source=DetectionSource.INSTALLED_APP, raw_match="a"))
        detection_repo.upsert(_make_detection(catalog_entry_id=1, source=DetectionSource.MX_LOOKUP, raw_match="b"))
        detection_repo.upsert(_make_detection(catalog_entry_id=2, source=DetectionSource.INSTALLED_APP, raw_match="c"))

        for_one = detection_repo.list_for_catalog_entry(1)
        assert len(for_one) == 2
        for_two = detection_repo.list_for_catalog_entry(2)
        assert len(for_two) == 1


class TestDetectionRepositoryStatus:
    def test_set_status_accepted_braucht_vendor_id(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        det_id = detection_repo.upsert(_make_detection())
        with pytest.raises(ValueError, match="vendor_id"):
            detection_repo.set_status(det_id, DetectionStatus.ACCEPTED)

    def test_set_status_accepted_setzt_vendor_id(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        det_id = detection_repo.upsert(_make_detection())
        detection_repo.set_status(det_id, DetectionStatus.ACCEPTED, vendor_id=42)
        fetched = detection_repo.get_by_id(det_id)
        assert fetched is not None
        assert fetched.status is DetectionStatus.ACCEPTED
        assert fetched.vendor_id == 42

    def test_set_status_unbekannte_id_wirft(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        with pytest.raises(ValueError, match="Kein Detection"):
            detection_repo.set_status(9999, DetectionStatus.REJECTED)


class TestDetectionRepositoryCascade:
    def test_delete_all_for_catalog_entry(
        self, detection_repo: VendorDetectionRepository
    ) -> None:
        detection_repo.upsert(_make_detection(catalog_entry_id=1, raw_match="a"))
        detection_repo.upsert(_make_detection(catalog_entry_id=1, raw_match="b"))
        detection_repo.upsert(_make_detection(catalog_entry_id=2, raw_match="c"))

        removed = detection_repo.delete_all_for_catalog_entry(1)
        assert removed == 2
        assert detection_repo.list_for_catalog_entry(1) == []
        assert len(detection_repo.list_for_catalog_entry(2)) == 1
