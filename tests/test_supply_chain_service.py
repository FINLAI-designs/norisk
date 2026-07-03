"""
test_supply_chain_service.

Tests fuer:class:`VendorService`. Der Service ist in Iter 2a ein duenner
UseCase-Layer ueber dem Repository — die wichtigsten Pfade pruefen wir
trotzdem, weil 2b/2c-UseCases hier andocken (Auto-Detection-Merge,
AVV-Validierung) und ein Regressionsnetz haben sollten.
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import VendorCategory


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
def service() -> VendorService:
    return VendorService(repository=VendorRepository(db=_InMemoryDB()))


def test_add_vendor_liefert_persistiertes_objekt_mit_id(service: VendorService) -> None:
    vendor = service.add_vendor(
        name="DATEV",
        category=VendorCategory.KANZLEISOFTWARE,
        criticality_score=5,
        notes="Mandanten-Buchhaltung",
    )
    assert vendor.id is not None
    assert vendor.id > 0
    assert vendor.name == "DATEV"
    assert vendor.notes == "Mandanten-Buchhaltung"


def test_add_vendor_ungueltige_daten_propagieren_value_error(
    service: VendorService,
) -> None:
    with pytest.raises(ValueError):
        service.add_vendor(
            name="",
            category=VendorCategory.CLOUD,
            criticality_score=3,
        )
    with pytest.raises(ValueError):
        service.add_vendor(
            name="X",
            category=VendorCategory.CLOUD,
            criticality_score=99,
        )


def test_list_vendors_zeigt_persistiete_eintraege(service: VendorService) -> None:
    service.add_vendor(name="A", category=VendorCategory.CLOUD, criticality_score=1)
    service.add_vendor(name="B", category=VendorCategory.MSP, criticality_score=5)

    vendors = service.list_vendors()

    assert {v.name for v in vendors} == {"A", "B"}


def test_update_vendor_uebernimmt_aenderungen(service: VendorService) -> None:
    created = service.add_vendor(
        name="OldName",
        category=VendorCategory.SPEZIAL,
        criticality_score=2,
    )
    assert created.id is not None

    # Vendor ist frozen — wir konstruieren ein neues Objekt mit derselben ID.
    from tools.supply_chain_monitor.domain.models import Vendor  # noqa: PLC0415

    updated = Vendor(
        id=created.id,
        name="NewName",
        category=VendorCategory.CLOUD,
        criticality_score=4,
        notes="hat Cloud-Migration durchgemacht",
        created_at=created.created_at,
        updated_at=created.updated_at,
    )
    service.update_vendor(updated)

    fetched = service.get_vendor(created.id)
    assert fetched is not None
    assert fetched.name == "NewName"
    assert fetched.category is VendorCategory.CLOUD
    assert fetched.criticality_score == 4


def test_delete_vendor_entfernt_eintrag(service: VendorService) -> None:
    created = service.add_vendor(
        name="ToDelete",
        category=VendorCategory.CLOUD,
        criticality_score=1,
    )
    assert created.id is not None

    assert service.delete_vendor(created.id) is True
    assert service.get_vendor(created.id) is None


def test_delete_unbekannter_vendor_liefert_false(service: VendorService) -> None:
    assert service.delete_vendor(99999) is False


def test_get_unbekannter_vendor_liefert_none(service: VendorService) -> None:
    assert service.get_vendor(99999) is None
