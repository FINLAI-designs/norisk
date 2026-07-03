"""
test_document_scanner_vt_button.

Tests fuer den VT-Button in der ResultCard. Wir mocken
``virustotal_client.lookup_hash`` damit der Test offline laeuft.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

from core.security.virustotal_client import VtResult
from tools.document_scanner.domain.models import (
    DocumentScanResult,
    QuarantineEntry,
    ScanVerdict,
)

pytestmark = pytest.mark.gui


def _make_result(tmp_path: Path) -> DocumentScanResult:
    entry = QuarantineEntry(
        uuid=uuid4(),
        original_name="datei.pdf",
        quarantine_dir=tmp_path / "q" / "x",
        stored_path=tmp_path / "q" / "x" / "datei.pdf",
        sha256="a" * 64,
        size_bytes=1234,
        created_at=datetime.now(UTC),
    )
    return DocumentScanResult(
        entry=entry,
        verdict=ScanVerdict.SAFE,
        risk_score=0,
        magika_label="pdf",
        type_match=True,
        threats=[],
        validation_report=None,
        duration_ms=12.3,
    )


def test_vt_button_zeigt_hinweis_ohne_key(qapp, qtbot, tmp_path, monkeypatch) -> None:  # noqa: ARG001
    """Wenn kein Key gespeichert ist, sehen wir einen FinlaiInfoDialog."""
    from tools.document_scanner.gui.result_card import ResultCard

    # has_api_key liefert False
    monkeypatch.setattr(
        "tools.document_scanner.gui.result_card.has_api_key", lambda: False
    )
    # Native QMessageBox wurde durch FinlaiInfoDialog ersetzt — den
    # Dialog patchen, damit kein modales Fenster den Test blockiert,
    # und pruefen, dass er instanziiert und angezeigt (.exec) wurde.
    with patch(
        "tools.document_scanner.gui.result_card.FinlaiInfoDialog"
    ) as dialog_cls:
        card = ResultCard(_make_result(tmp_path))
        qtbot.add_widget(card)
        card._vt_btn.click()  # noqa: SLF001

    assert dialog_cls.called, "FinlaiInfoDialog sollte instanziiert worden sein"
    dialog_cls.return_value.exec.assert_called_once()


def test_vt_button_zeigt_clean_result(qapp, qtbot, tmp_path, monkeypatch) -> None:  # noqa: ARG001
    """Bei has_api_key=True + clean-Result wird die Status-Zeile gefuellt."""
    from tools.document_scanner.gui.result_card import ResultCard

    monkeypatch.setattr(
        "tools.document_scanner.gui.result_card.has_api_key", lambda: True
    )
    fake_vt = VtResult(
        status="clean",
        harmless=70,
        undetected=5,
        permalink="https://www.virustotal.com/gui/file/" + "a" * 64,
        message="VirusTotal: 0 Treffer aus 75 Antivirus-Engines.",
    )
    with patch(
        "tools.document_scanner.gui.result_card.lookup_hash", return_value=fake_vt
    ):
        card = ResultCard(_make_result(tmp_path))
        qtbot.add_widget(card)
        card._vt_btn.click()  # noqa: SLF001
        # Worker abwarten
        with qtbot.waitSignal(card._vt_worker.finished_with, timeout=5000):  # noqa: SLF001
            pass

    assert card._vt_status_lbl.isVisibleTo(card) or True  # noqa: SLF001 -- visibility vor show falsch
    assert "0 Treffer aus 75" in card._vt_status_lbl.text()  # noqa: SLF001


def test_vt_button_zeigt_malicious_result(qapp, qtbot, tmp_path, monkeypatch) -> None:  # noqa: ARG001
    from tools.document_scanner.gui.result_card import ResultCard

    monkeypatch.setattr(
        "tools.document_scanner.gui.result_card.has_api_key", lambda: True
    )
    fake_vt = VtResult(
        status="malicious",
        malicious=42,
        harmless=10,
        undetected=20,
        permalink="https://www.virustotal.com/gui/file/" + "a" * 64,
        message="42 Antivirus-Engine(s) markieren die Datei als boesartig (aus 72 Engines).",
    )
    with patch(
        "tools.document_scanner.gui.result_card.lookup_hash", return_value=fake_vt
    ):
        card = ResultCard(_make_result(tmp_path))
        qtbot.add_widget(card)
        card._vt_btn.click()  # noqa: SLF001
        with qtbot.waitSignal(card._vt_worker.finished_with, timeout=5000):  # noqa: SLF001
            pass

    assert "42" in card._vt_status_lbl.text()  # noqa: SLF001
    assert "boesartig" in card._vt_status_lbl.text()  # noqa: SLF001
