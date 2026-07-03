"""
test_customer_avv_tab_view — GUI-Tests fuer die Kunden-Perspektive.

Prueft: Namensaufloesung (Batch, kein N+1), genau ein list_all pro Reload (Perf),
lazy Aufbau der Kunden-Sicht im Perspektiven-Container und die subject_id-Logik
des Upload-Dialogs (Bestandskunde vs. Neuanlage).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.security_subject.models import Subject, SubjectKind
from tools.supply_chain_monitor.domain.models import (
    AvvDocumentStatus,
    CustomerAvvDocument,
)
from tools.supply_chain_monitor.gui.avv_perspective_tabs import AvvPerspectiveTabs
from tools.supply_chain_monitor.gui.customer_avv_tab_view import CustomerAvvTabView
from tools.supply_chain_monitor.gui.customer_avv_upload_dialog import (
    CustomerAvvUploadDialog,
)

pytestmark = pytest.mark.gui

_SUBJ_ID = "subj-1"


def _doc(subject_id: str = _SUBJ_ID, days_until: int = 365) -> CustomerAvvDocument:
    now = datetime.now(UTC)
    return CustomerAvvDocument(
        id=1,
        subject_id=subject_id,
        file_path="/irrelevant/avv.pdf.enc",
        sha256="a" * 64,
        size_bytes=1024,
        original_filename="kunden_avv.pdf",
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=days_until),
        status=AvvDocumentStatus.ACTIVE,
    )


class _FakeStore:
    def __init__(self, subjects: list[Subject]) -> None:
        self._subjects = subjects
        self.created: list[str] = []

    def list_all(self) -> list[Subject]:
        return list(self._subjects)

    def get(self, subject_id: str) -> Subject | None:
        return next((s for s in self._subjects if s.subject_id == subject_id), None)

    def find_or_create_client(self, name: str) -> Subject:
        self.created.append(name)
        subject = Subject(subject_id="new-id", kind=SubjectKind.KUNDE, name=name)
        self._subjects.append(subject)
        return subject


class _FakeCustomerService:
    def __init__(self, docs: list[CustomerAvvDocument]) -> None:
        self._docs = docs
        self.list_all_calls = 0
        self.emit_calls: list[dict] = []

    def list_all(self) -> list[CustomerAvvDocument]:
        self.list_all_calls += 1
        return list(self._docs)

    def list_expiring(self, *, within_days=90, include_overdue=True, docs=None):
        # Muss die vorgeladenen docs nutzen (kein erneuter list_all-DB-Read).
        assert docs is not None
        return []

    def emit_renewal_findings(self, *, subject_name_lookup=None, expiring=None) -> int:
        self.emit_calls.append(
            {"subject_name_lookup": subject_name_lookup, "expiring": expiring}
        )
        return 0

    def purge_open_temp(self) -> None:
        pass


class _FakeVendorService:
    def list_vendors(self) -> list:
        return []


class _FakeVendorAvvService:
    def __init__(self, docs: list) -> None:
        self._docs = docs

    def list_all(self) -> list:
        return list(self._docs)

    def list_expiring(self, *, within_days=90, include_overdue=True):
        return []

    def emit_renewal_findings(self, *, vendor_name_lookup=None, within_days=90) -> int:
        return 0

    def purge_open_temp(self) -> None:
        pass


def _subjects() -> list[Subject]:
    return [
        Subject(subject_id=_SUBJ_ID, kind=SubjectKind.KUNDE, name="Mandant Mueller"),
        Subject(subject_id="eigenes", kind=SubjectKind.EIGENES, name="Wir GmbH"),
    ]


def test_reload_resolves_customer_name_batch(qtbot, app) -> None:
    service = _FakeCustomerService([_doc()])
    store = _FakeStore(_subjects())
    widget = CustomerAvvTabView(customer_avv_service=service, subject_store=store)
    qtbot.addWidget(widget)

    # Tabelle gefuellt, Kundenname aus dem Batch-Map (nicht "?").
    assert widget._table.rowCount() == 1
    assert widget._table.item(0, 0).text() == "Mandant Mueller"
    # Perf: genau EIN list_all pro Reload (Banner + Emit bekamen vorgeladene docs).
    assert service.list_all_calls == 1
    # Emit bekam den Namens-Lookup + vorberechnete expiring-Liste.
    assert len(service.emit_calls) == 1
    assert service.emit_calls[0]["subject_name_lookup"] == {_SUBJ_ID: "Mandant Mueller"}
    assert service.emit_calls[0]["expiring"] is not None


def test_unknown_subject_falls_back_to_placeholder(qtbot, app) -> None:
    service = _FakeCustomerService([_doc(subject_id="weg")])
    store = _FakeStore(_subjects())
    widget = CustomerAvvTabView(customer_avv_service=service, subject_store=store)
    qtbot.addWidget(widget)
    assert widget._table.item(0, 0).text() == "?"


def test_perspective_container_builds_customer_lazily(qtbot, app) -> None:
    vendor_docs: list = []
    customer_service = _FakeCustomerService([_doc()])
    store = _FakeStore(_subjects())
    container = AvvPerspectiveTabs(
        vendor_service=_FakeVendorService(),
        avv_service=_FakeVendorAvvService(vendor_docs),
        customer_avv_service=customer_service,
        subject_store=store,
    )
    qtbot.addWidget(container)

    # Kunden-Bereich ist anfangs NICHT gebaut (lazy).
    assert container._customer_built is False
    # Wechsel auf Tab 1 -> Kunden-Bereich (Verwaltung + AVVs) wird gebaut.
    container._tabs.setCurrentIndex(1)
    assert container._customer_built is True
    assert container._customer_avv is not None
    assert customer_service.list_all_calls == 1


# ---------------------------------------------------------------------------
# Upload-Dialog: subject_id-Logik (Bestandskunde vs. Neuanlage)
# ---------------------------------------------------------------------------


def test_upload_dialog_existing_customer(qtbot, app) -> None:
    dialog = CustomerAvvUploadDialog(customers=[(_SUBJ_ID, "Mandant Mueller")])
    qtbot.addWidget(dialog)
    dialog._customer_combo.setCurrentIndex(0)  # Bestandskunde
    assert dialog.selected_subject_id() == _SUBJ_ID
    assert dialog.new_customer_name() == ""


def test_upload_dialog_new_customer(qtbot, app) -> None:
    dialog = CustomerAvvUploadDialog(customers=[(_SUBJ_ID, "Mandant Mueller")])
    qtbot.addWidget(dialog)
    # Letzter Eintrag = "Neuen Kunden anlegen..."
    dialog._customer_combo.setCurrentIndex(dialog._customer_combo.count() - 1)
    assert dialog._new_name_input.isEnabled()
    dialog._new_name_input.setText("Neue Firma KG")
    assert dialog.selected_subject_id() is None
    assert dialog.new_customer_name() == "Neue Firma KG"


def test_upload_dialog_empty_customers_starts_in_new_mode(qtbot, app) -> None:
    dialog = CustomerAvvUploadDialog(customers=[])
    qtbot.addWidget(dialog)
    # Ohne Bestandskunden steht der Combo direkt auf Neuanlage.
    assert dialog.selected_subject_id() is None
    assert dialog._new_name_input.isEnabled()
