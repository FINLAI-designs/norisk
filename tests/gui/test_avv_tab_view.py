"""
test_avv_tab_view — GUI-Test fuer den AVV-Oeffnen-Button (D10 /).

Prueft, dass der "AVV oeffnen"-Button die PDF ueber den Service entschluesselt
(Temp-Decrypt) und im System-Viewer oeffnet, und dass Fehler (Datei weg, altes
Klartext-Format) als Warnung erscheinen statt still zu scheitern (coding-rules R3).

Author: Patrick Riederich
Version: 2.0 — Temp-Decrypt statt Klartext-Open)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools.supply_chain_monitor.application.avv_service import AvvPdfDecryptError
from tools.supply_chain_monitor.domain.models import AvvDocument, AvvDocumentStatus
from tools.supply_chain_monitor.gui import avv_tab_view as avv_mod
from tools.supply_chain_monitor.gui.avv_tab_view import AvvTabView

pytestmark = pytest.mark.gui


class _FakeVendorService:
    def list_vendors(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(id=1, name="ACME GmbH")]


class _FakeAvvService:
    def __init__(
        self,
        docs: list[AvvDocument],
        *,
        open_result: Path | None = None,
        open_error: Exception | None = None,
    ) -> None:
        self._docs = docs
        self._open_result = open_result
        self._open_error = open_error
        self.purged = 0

    def list_all(self) -> list[AvvDocument]:
        return list(self._docs)

    def list_expiring(self, *, within_days: int = 90, include_overdue: bool = True):
        return []

    def emit_renewal_findings(self, *, vendor_name_lookup=None, within_days: int = 90) -> int:
        return 0

    def open_decrypted(self, avv_id: int) -> Path:
        if self._open_error is not None:
            raise self._open_error
        assert self._open_result is not None
        return self._open_result

    def purge_open_temp(self) -> None:
        self.purged += 1


def _doc() -> AvvDocument:
    now = datetime.now(UTC)
    return AvvDocument(
        id=1,
        vendor_id=1,
        file_path="/irrelevant/avv.pdf.enc",
        sha256="a" * 64,
        size_bytes=1024,
        original_filename="avv_acme.pdf",
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=365),
        status=AvvDocumentStatus.ACTIVE,
    )


def _widget(qtbot, avv_service: _FakeAvvService) -> AvvTabView:
    widget = AvvTabView(
        vendor_service=_FakeVendorService(),
        avv_service=avv_service,
    )
    qtbot.addWidget(widget)
    return widget


def test_open_button_opens_decrypted_pdf(
    qtbot, app, tmp_path: Path, monkeypatch
) -> None:
    decrypted = tmp_path / "avv_acme.pdf"
    decrypted.write_bytes(b"%PDF-1.4 plain")
    widget = _widget(qtbot, _FakeAvvService([_doc()], open_result=decrypted))

    opened: list = []
    monkeypatch.setattr(
        avv_mod.QDesktopServices, "openUrl", lambda url: opened.append(url) or True
    )
    widget._table.selectRow(0)
    assert widget._open_btn.isEnabled()
    widget._on_open()

    assert len(opened) == 1
    # QUrl normalisiert auf Forward-Slashes -> ueber Path vergleichen.
    assert Path(opened[0].toLocalFile()) == decrypted


def test_open_button_warns_on_decrypt_error(
    qtbot, app, monkeypatch
) -> None:
    widget = _widget(
        qtbot,
        _FakeAvvService([_doc()], open_error=AvvPdfDecryptError("alt")),
    )

    info_dialog = MagicMock(name="FinlaiInfoDialog")
    monkeypatch.setattr(avv_mod, "FinlaiInfoDialog", info_dialog)
    opened: list = []
    monkeypatch.setattr(
        avv_mod.QDesktopServices, "openUrl", lambda url: opened.append(url) or True
    )
    widget._table.selectRow(0)
    widget._on_open()

    # Hinweis "aelteres Format" erscheint: Dialog instanziiert + angezeigt.
    assert info_dialog.call_count == 1
    info_dialog.return_value.exec.assert_called_once()
    assert opened == []  # nichts geoeffnet


def test_open_button_warns_when_missing(qtbot, app, monkeypatch) -> None:
    widget = _widget(
        qtbot,
        _FakeAvvService([_doc()], open_error=FileNotFoundError("weg")),
    )

    info_dialog = MagicMock(name="FinlaiInfoDialog")
    monkeypatch.setattr(avv_mod, "FinlaiInfoDialog", info_dialog)
    widget._table.selectRow(0)
    widget._on_open()

    # Hinweis "Datei nicht gefunden" erscheint: Dialog instanziiert + angezeigt.
    assert info_dialog.call_count == 1
    info_dialog.return_value.exec.assert_called_once()


def test_open_button_disabled_without_selection(qtbot, app) -> None:
    widget = _widget(qtbot, _FakeAvvService([_doc()]))
    # Nach Reload ohne Auswahl ist der Oeffnen-Button deaktiviert.
    assert not widget._open_btn.isEnabled()
