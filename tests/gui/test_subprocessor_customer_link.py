"""
test_subprocessor_customer_link — H (Live-Test 2026-07-01).

GUI-Tests fuer die Kunden-Perspektive im Sub-Auftragnehmer-Verknuepfungs-
Dialog: Partner-Typ-Picker (Lieferant/Kunde), Partner-Auswahl je Perspektive
und die kombinierte Link-Verwaltung (beide Typen mit Typ-Spalte + korrektem
Unlink-Dispatch).

Author: Patrick Riederich
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt

from tools.supply_chain_monitor.domain.models import (
    CustomerSubprocessorLink,
    Subprocessor,
    VendorCategory,
    VendorSubprocessorLink,
)
from tools.supply_chain_monitor.gui.subprocessor_tab_view import (
    _AddLinkDialog,
    _LinkManagementDialog,
)

pytestmark = pytest.mark.gui


def _vendors() -> list:
    return [SimpleNamespace(id=1, name="DATEV"), SimpleNamespace(id=2, name="Microsoft")]


def test_add_link_dialog_perspektive_wechsel(qtbot, app) -> None:  # noqa: ARG001
    customers = [("subj-1", "Kunde Alpha"), ("subj-2", "Kunde Beta")]
    dlg = _AddLinkDialog(vendors=_vendors(), customers=customers)
    qtbot.add_widget(dlg)

    # Default: erste Perspektive = Lieferant -> Partner-Ref ist eine Vendor-ID (int).
    assert dlg.selected_perspective() == "vendor"
    assert isinstance(dlg.selected_party_ref(), int)

    # Auf Kunde umschalten -> Partner-Combo zeigt Kunden, Ref ist subject_id (str).
    idx = dlg._perspective_combo.findData("customer")  # noqa: SLF001
    dlg._perspective_combo.setCurrentIndex(idx)  # noqa: SLF001
    assert dlg.selected_perspective() == "customer"
    assert dlg.selected_party_ref() == "subj-1"


def test_add_link_dialog_nur_kunden(qtbot, app) -> None:  # noqa: ARG001
    # Ohne Vendoren bleibt nur die Kunden-Perspektive uebrig.
    dlg = _AddLinkDialog(vendors=[], customers=[("subj-1", "Kunde Alpha")])
    qtbot.add_widget(dlg)
    assert dlg.selected_perspective() == "customer"
    assert dlg.selected_party_ref() == "subj-1"


def test_link_management_zeigt_beide_typen(qtbot, app) -> None:  # noqa: ARG001
    sub = Subprocessor(id=5, name="AWS", country="US", category=VendorCategory.CLOUD)
    fake_service = SimpleNamespace(
        links_for_subprocessor=lambda _sid: [
            VendorSubprocessorLink(
                id=10, vendor_id=1, subprocessor_id=5, role="Storage"
            )
        ],
        customer_links_for_subprocessor=lambda _sid: [
            CustomerSubprocessorLink(
                id=20, subject_id="subj-1", subprocessor_id=5, role="CDN"
            )
        ],
    )
    dlg = _LinkManagementDialog(
        subprocessor=sub,
        vendors=_vendors(),
        customers=[("subj-1", "Kunde Alpha")],
        service=fake_service,
    )
    qtbot.add_widget(dlg)

    assert dlg._table.rowCount() == 2  # noqa: SLF001
    typen = {dlg._table.item(r, 0).text() for r in range(2)}  # noqa: SLF001
    assert typen == {"Lieferant", "Kunde"}
    partner = {dlg._table.item(r, 1).text() for r in range(2)}  # noqa: SLF001
    assert partner == {"DATEV", "Kunde Alpha"}
    # UserRole traegt (kind, link_id) — steuert das richtige Unlink.
    metas = {
        dlg._table.item(r, 0).data(Qt.ItemDataRole.UserRole)  # noqa: SLF001
        for r in range(2)
    }
    assert ("vendor", 10) in metas
    assert ("customer", 20) in metas


def test_link_management_remove_customer_dispatch(qtbot, app) -> None:  # noqa: ARG001
    sub = Subprocessor(id=5, name="AWS", country="US", category=VendorCategory.CLOUD)
    unlinked: dict[str, int] = {}
    fake_service = SimpleNamespace(
        links_for_subprocessor=lambda _sid: [],
        customer_links_for_subprocessor=lambda _sid: [
            CustomerSubprocessorLink(
                id=20, subject_id="subj-1", subprocessor_id=5, role="CDN"
            )
        ],
        unlink=lambda lid: unlinked.__setitem__("vendor", lid),
        unlink_customer=lambda lid: unlinked.__setitem__("customer", lid),
    )
    dlg = _LinkManagementDialog(
        subprocessor=sub,
        vendors=[],
        customers=[("subj-1", "Kunde Alpha")],
        service=fake_service,
    )
    qtbot.add_widget(dlg)

    dlg._table.selectRow(0)  # noqa: SLF001
    dlg._on_remove_link()  # noqa: SLF001
    # Kunden-Link -> unlink_customer, NICHT unlink.
    assert unlinked == {"customer": 20}
