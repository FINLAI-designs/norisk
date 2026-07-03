"""
test_customer_audit_delete_wiring — I (Live-Test 2026-07-01).

GUI-Wiring der dualen Loeschung im Audit-Listen-Widget: pro Karte "Loeschen"
(Einzelversion) plus — nur bei Ketten mit mehreren Versionen — "Ganze Historie"
(DSGVO Art. 17). Prueft chain_size-Gating der Buttons und dass die Slots die
richtige Use-Case-Methode aufrufen (delete_version vs. delete).

Author: Patrick Riederich
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QDialog, QPushButton

from tools.customer_audit.gui import customer_list_widget as mod
from tools.customer_audit.gui.customer_list_widget import CustomerListWidget

pytestmark = pytest.mark.gui


def _summary(audit_id: str, version: int, root: str) -> dict:
    return {
        "audit_id": audit_id,
        "firmenname": "Acme GmbH",
        "created_at": "2026-06-01T10:00:00+00:00",
        "overall_score": 70.0,
        "risk_level": "Mittel",
        "version": version,
        "root_audit_id": root,
    }


def _widget(qtbot, summaries: list[dict]):
    services = MagicMock()
    services.load.get_all_summaries.return_value = summaries
    widget = CustomerListWidget(services)
    qtbot.add_widget(widget)
    return widget, services


def test_einzelversion_ohne_historie_button(qtbot, app) -> None:  # noqa: ARG001
    widget, _ = _widget(qtbot, [_summary("a1", 1, "a1")])
    texts = {b.text() for b in widget.findChildren(QPushButton)}
    assert "Löschen" in texts
    assert "Ganze Historie" not in texts  # Einzel-Audit -> keine Ketten-Aktion


def test_mehrere_versionen_zeigen_historie_button(qtbot, app) -> None:  # noqa: ARG001
    widget, _ = _widget(
        qtbot, [_summary("v2", 2, "root"), _summary("root", 1, "root")]
    )
    texts = [b.text() for b in widget.findChildren(QPushButton)]
    assert "Löschen" in texts
    assert "Ganze Historie" in texts


def test_delete_version_slot_ruft_delete_version(qtbot, app, monkeypatch) -> None:  # noqa: ARG001
    widget, services = _widget(qtbot, [_summary("v2", 2, "root")])
    services.load.get_by_id.return_value = SimpleNamespace(
        customer_data=SimpleNamespace(firmenname="Acme GmbH"), version=2
    )
    services.load.delete_version.return_value = True
    monkeypatch.setattr(
        mod,
        "FinlaiConfirmDialog",
        lambda **_kw: SimpleNamespace(exec=lambda: QDialog.DialogCode.Accepted),
    )
    widget._delete_version("v2")  # noqa: SLF001
    services.load.delete_version.assert_called_once_with("v2")
    services.load.delete.assert_not_called()  # NICHT der Ketten-Loeschpfad


def test_delete_chain_slot_ruft_delete(qtbot, app, monkeypatch) -> None:  # noqa: ARG001
    widget, services = _widget(qtbot, [_summary("v2", 2, "root")])
    services.load.get_by_id.return_value = SimpleNamespace(
        customer_data=SimpleNamespace(firmenname="Acme GmbH"), version=2
    )
    services.load.delete.return_value = True
    monkeypatch.setattr(
        mod,
        "FinlaiConfirmDialog",
        lambda **_kw: SimpleNamespace(exec=lambda: QDialog.DialogCode.Accepted),
    )
    widget._delete_chain("v2")  # noqa: SLF001
    services.load.delete.assert_called_once_with("v2")
    services.load.delete_version.assert_not_called()
