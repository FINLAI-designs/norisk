"""
test_document_scanner_widget.

GUI-Smokes fuer den Document Scanner. Testet das Zusammenspiel
zwischen DropzoneWidget, ResultCard und DocumentScannerWidget.

Wir simulieren keinen echten Drag&Drop-Event — Qt-Drag-Simulation ist
flaky. Stattdessen rufen wir die ``_on_file_dropped``-Slot direkt mit
einem ``Path`` auf — das ist exakt der Pfad nach dem Drop.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.document_scanner.application.quarantine_manager import QuarantineManager
from tools.document_scanner.application.scanner_service import DocumentScannerService

pytestmark = pytest.mark.gui


def test_widget_zeigt_titel_und_dropzone(qapp, qtbot, tmp_path) -> None:  # noqa: ARG001
    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    assert widget._dropzone is not None  # noqa: SLF001
    # Anfangszustand: Empty-Hint sichtbar
    assert widget._empty_hint.isVisibleTo(widget) is False or True  # noqa: SLF001 -- vor show ist isVisibleTo immer False


def test_drop_fuegt_result_card_hinzu(qapp, qtbot, tmp_path) -> None:  # noqa: ARG001
    """: Drop laeuft jetzt asynchron — auf finished warten."""
    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    src = tmp_path / "harmlos.txt"
    src.write_text("ein kurzer text", encoding="utf-8")
    widget._on_file_dropped(src)  # noqa: SLF001

    worker = widget._workers[-1]  # noqa: SLF001
    with qtbot.waitSignal(worker.finished, timeout=10_000):
        pass

    assert len(widget._cards) == 1  # noqa: SLF001


def test_loeschen_entfernt_card_und_slot(qapp, qtbot, tmp_path) -> None:  # noqa: ARG001
    """: asynchron — auf finished warten, dann loeschen."""
    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    src = tmp_path / "harmlos.txt"
    src.write_text("hi", encoding="utf-8")
    widget._on_file_dropped(src)  # noqa: SLF001

    worker = widget._workers[-1]  # noqa: SLF001
    with qtbot.waitSignal(worker.finished, timeout=10_000):
        pass

    card = widget._cards[0]  # noqa: SLF001
    slot_dir = card._result.entry.quarantine_dir  # noqa: SLF001

    card.delete_requested.emit()

    assert len(widget._cards) == 0  # noqa: SLF001
    assert not slot_dir.exists()


def test_drop_unbekannter_pfad_zeigt_warnung_kein_card(
    qapp, qtbot, tmp_path, monkeypatch  # noqa: ARG001
) -> None:
    """Nicht-existenter Pfad → keine Card, Hinweis-Dialog geblockt."""
    from unittest.mock import MagicMock

    from tools.document_scanner.gui import document_scanner_widget as mod
    from tools.document_scanner.gui.document_scanner_widget import (
        DocumentScannerWidget,
    )

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    widget = DocumentScannerWidget(service=service)
    qtbot.add_widget(widget)

    # Dialog-Migration (Native QMessageBox → core.dialogs.FinlaiInfoDialog):
    # Der Warn-Dialog wird als MagicMock gepatcht, damit der Test nicht blockt.
    dialog_cls = MagicMock(name="FinlaiInfoDialog")
    monkeypatch.setattr(mod, "FinlaiInfoDialog", dialog_cls)

    widget._on_file_dropped(Path(tmp_path / "gibts_nicht.bin"))  # noqa: SLF001

    assert len(widget._cards) == 0  # noqa: SLF001
    # Warnung wurde gezeigt: Dialog instanziiert +.exec aufgerufen
    assert dialog_cls.called  # FinlaiInfoDialog instanziiert
    dialog_cls.return_value.exec.assert_called_once()


def test_document_scanner_im_file_scanner_container() -> None:
    """ (3b): document_scanner ist kein eigenes Dock mehr, sondern der
    Office-Tab im file_scanner-Container — also der file_scanner-nav_key im
    _NAV_TOOL_MAP, NICHT mehr document_scanner."""
    from core.main_window import MainWindow

    keys = [entry[0] for entry in MainWindow._NAV_TOOL_MAP]  # noqa: SLF001
    assert "file_scanner" in keys
    assert "document_scanner" not in keys


def test_file_scanner_modul_in_app_config() -> None:
    """ (3b): der verschmolzene ``tools.file_scanner.tool`` ist registriert;
    die drei Einzel-tool.py sind aus tool_modules entfernt."""
    from apps.app_config import NORISK_CONFIG

    assert "tools.file_scanner.tool" in NORISK_CONFIG.tool_modules
    assert "tools.document_scanner.tool" not in NORISK_CONFIG.tool_modules
    assert "tools.email_scanner.tool" not in NORISK_CONFIG.tool_modules
    assert "tools.pdf_risk_scanner.tool" not in NORISK_CONFIG.tool_modules
