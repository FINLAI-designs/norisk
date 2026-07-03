"""
test_document_scanner_async.

Pruft den ScanWorker-Pfad: Drop → PendingCard sofort sichtbar →
ScanWorker laeuft → finished-Signal ersetzt Pending durch ResultCard.

Wir nutzen ``qtbot.waitSignal`` damit der Test waertet bis der Worker
fertig ist — kein hartes Sleep.
"""

from __future__ import annotations

import pytest

from tools.document_scanner.application.quarantine_manager import QuarantineManager
from tools.document_scanner.application.scanner_service import DocumentScannerService

pytestmark = pytest.mark.gui


def test_drop_zeigt_pending_und_dann_result(qapp, qtbot, tmp_path) -> None:  # noqa: ARG001
    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )
    from tools.document_scanner.gui.pending_card import PendingCard
    from tools.document_scanner.gui.result_card import ResultCard

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    src = tmp_path / "harmlos.txt"
    src.write_text("hi", encoding="utf-8")

    widget._on_file_dropped(src)  # noqa: SLF001

    # Direkt nach dem Drop: eine PendingCard im Layout
    pendings = [
        widget._cards_layout.itemAt(i).widget()  # noqa: SLF001
        for i in range(widget._cards_layout.count())  # noqa: SLF001
    ]
    assert any(isinstance(w, PendingCard) for w in pendings), (
        "Direkt nach Drop muss eine PendingCard sichtbar sein"
    )

    # Auf den Worker warten
    worker = widget._workers[-1]  # noqa: SLF001
    with qtbot.waitSignal(worker.finished, timeout=10_000):
        pass

    # Nach finished: keine PendingCard mehr, eine ResultCard
    final = [
        widget._cards_layout.itemAt(i).widget()  # noqa: SLF001
        for i in range(widget._cards_layout.count())  # noqa: SLF001
    ]
    assert not any(isinstance(w, PendingCard) for w in final)
    assert any(isinstance(w, ResultCard) for w in final)


def test_on_scan_failed_zeigt_messagebox_und_entfernt_pending(
    qapp, qtbot, tmp_path, monkeypatch  # noqa: ARG001
) -> None:
    """Direkter Slot-Test: ``_on_scan_failed`` zeigt einen Fehler-Dialog
    (FinlaiInfoDialog) und entfernt die uebergebene PendingCard.

    Dialog-Migration: Der native ``QMessageBox.critical``-Aufruf
    wurde durch den FINLAI-konformen ``FinlaiInfoDialog.exec`` ersetzt.
    Wir patchen die Dialog-Klasse als MagicMock und pruefen, dass sie mit dem
    Fehlertext instanziiert und ``.exec`` aufgerufen wird — das ersetzt das
    fruehere ``QMessageBox.critical wurde aufgerufen``.
    """
    from unittest.mock import MagicMock

    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )
    from tools.document_scanner.gui.pending_card import PendingCard

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    dialog_cls = MagicMock(name="FinlaiInfoDialog")
    monkeypatch.setattr(
        "tools.document_scanner.gui.document_scanner_widget.FinlaiInfoDialog",
        dialog_cls,
    )

    # Pending-Card kuenstlich einsetzen ohne Worker zu starten
    pending = widget._add_pending_card(tmp_path / "fake.bin")  # noqa: SLF001
    widget._on_scan_failed(pending, "Synthetischer Fehler")  # noqa: SLF001

    assert dialog_cls.called, "FinlaiInfoDialog sollte instanziiert werden"
    # Der Fehlertext muss als message in den Dialog wandern
    _, kwargs = dialog_cls.call_args
    assert kwargs.get("message") == "Synthetischer Fehler"
    # Der Dialog muss tatsaechlich angezeigt werden (.exec)
    dialog_cls.return_value.exec.assert_called_once()

    items = [
        widget._cards_layout.itemAt(i).widget()  # noqa: SLF001
        for i in range(widget._cards_layout.count())  # noqa: SLF001
    ]
    assert not any(isinstance(w, PendingCard) for w in items)
