"""
test_partner_management_views — GUI-Tests fuer die Partner-Verwaltung (IA-Umbau).

Deckt VendorManagementView (Lieferanten) + CustomerManagementView (Kunden) ab:
Tabelle fuellt aus dem Service/Store, fail-soft ohne Store, Filter auf KUNDE.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.security_subject.models import Subject, SubjectKind
from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory
from tools.supply_chain_monitor.gui.customer_management_view import (
    CustomerManagementView,
)
from tools.supply_chain_monitor.gui.vendor_management_view import VendorManagementView

pytestmark = pytest.mark.gui


# --------------------------------------------------------------------------
# VendorManagementView
# --------------------------------------------------------------------------


class _FakeVendorService:
    def __init__(self, vendors: list[Vendor]) -> None:
        self._vendors = vendors

    def list_vendors(self) -> list[Vendor]:
        return list(self._vendors)


class _FakePatchLinker:
    def summarize_per_vendor(self) -> dict:
        return {}


class _FakeOffboarding:
    def progress_per_vendor(self) -> dict:
        return {}


def _vendor(name: str = "DATEV") -> Vendor:
    now = datetime.now(UTC)
    return Vendor(
        id=1,
        name=name,
        category=VendorCategory.KANZLEISOFTWARE,
        criticality_score=4,
        created_at=now,
        updated_at=now,
    )


def test_vendor_view_fuellt_tabelle(qtbot, app) -> None:
    view = VendorManagementView(
        vendor_service=_FakeVendorService([_vendor("DATEV"), _vendor("Microsoft")]),
        patch_linker=_FakePatchLinker(),
        offboarding_service=_FakeOffboarding(),
    )
    qtbot.addWidget(view)
    assert view._table.rowCount() == 2
    assert view._table.item(0, 0).text() == "DATEV"
    # Buttons ohne Auswahl deaktiviert.
    assert not view._edit_btn.isEnabled()
    assert not view._delete_btn.isEnabled()


def test_vendor_view_leerer_zustand(qtbot, app) -> None:
    view = VendorManagementView(
        vendor_service=_FakeVendorService([]),
        patch_linker=_FakePatchLinker(),
        offboarding_service=_FakeOffboarding(),
    )
    qtbot.addWidget(view)
    assert view._table.rowCount() == 0
    # Leer-Hinweis nicht explizit versteckt, Tabelle versteckt (isHidden statt
    # isVisible, da das Widget im Test nicht show-t).
    assert not view._empty_hint.isHidden()
    assert view._table.isHidden()


# --------------------------------------------------------------------------
# CustomerManagementView
# --------------------------------------------------------------------------


class _FakeStore:
    def __init__(self, subjects: list[Subject]) -> None:
        self._subjects = subjects

    def list_all(self) -> list[Subject]:
        return list(self._subjects)


def test_customer_view_filtert_kunde(qtbot, app) -> None:
    store = _FakeStore(
        [
            Subject(subject_id="k1", kind=SubjectKind.KUNDE, name="Mandant Mueller"),
            Subject(subject_id="self", kind=SubjectKind.EIGENES, name="Wir GmbH"),
        ]
    )
    view = CustomerManagementView(subject_store=store)
    qtbot.addWidget(view)
    # Nur das KUNDE-Subjekt erscheint (eigenes System raus).
    assert view._table.rowCount() == 1
    assert view._table.item(0, 0).text() == "Mandant Mueller"
    assert view._add_btn.isEnabled()


def test_customer_view_ohne_store_fail_soft(qtbot, app) -> None:
    view = CustomerManagementView(subject_store=_FakeStore([]))
    qtbot.addWidget(view)
    # Store-Ausfall simulieren (create_subject_store resolved im Test sonst real).
    view._store = None
    view.reload()
    assert view._table.rowCount() == 0
    assert not view._empty_hint.isHidden()
    # Ohne Store kann man keinen Kunden anlegen.
    assert not view._add_btn.isEnabled()
