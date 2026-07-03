"""
test_system_tuner_widget — GUI-Smoke fuer SystemTunerWidget (Phase 1c).

Konstruiert das Widget headless (offscreen) gegen den MockHardeningProbe und
prueft, dass der read-only Scan rendert (Banner + Tabelle), ohne zu crashen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.probes.mock_hardening_probe import MockHardeningProbe
from tools.system_tuner.application.catalog_loader import YamlTweakCatalog
from tools.system_tuner.application.tuner_scan_use_case import TunerScanUseCase
from tools.system_tuner.gui.tuner_widget import SystemTunerWidget

pytestmark = pytest.mark.gui


def _widget(qtbot) -> SystemTunerWidget:
    probe = MockHardeningProbe()
    # Emitter gemockt: der GUI-Smoke soll die reale mainpage-DB nicht beschreiben.
    use_case = TunerScanUseCase(
        probe=probe, catalog=YamlTweakCatalog(), ki_todo_emitter=MagicMock()
    )
    widget = SystemTunerWidget(scan_use_case=use_case)
    qtbot.addWidget(widget)
    return widget


def test_widget_builds_and_populates(qtbot, app) -> None:
    widget = _widget(qtbot)
    # Der gebuendelte Katalog hat >= 6 Tweaks -> ebenso viele Zeilen.
    assert widget._table.rowCount() >= 6
    # Edition-Banner ist gesetzt (hier 'nicht ermittelt' mangels Mock-Wert).
    assert widget._edition_lbl.text() != ""
    assert "Privacy-Score" in widget._score_lbl.text()


def test_refresh_is_idempotent(qtbot, app) -> None:
    widget = _widget(qtbot)
    rows_before = widget._table.rowCount()
    widget._refresh()
    assert widget._table.rowCount() == rows_before


@pytest.fixture
def home(tmp_path):
    from core.finlai_paths import set_finlai_home

    set_finlai_home(str(tmp_path))
    yield tmp_path
    set_finlai_home(None)


def test_apply_button_always_enabled(qtbot, app) -> None:
    # kein Pro-Gate mehr — Anwenden-Button ist immer aktiv
    # (Ed25519-Katalog-Signatur im Apply-Flow bleibt der Trust-Root).
    widget = _widget(qtbot)
    assert widget._apply_btn.isEnabled()


def test_open_recommendations_lists_not_applied(qtbot, app) -> None:
    widget = _widget(qtbot)
    recs = widget._open_recommendations()
    # Telemetrie-Registry-Tweaks sind gegen MockHardeningProbe NOT_APPLIED.
    assert recs
    assert all(isinstance(tid, str) and tid for tid, _t, _tr in recs)


def test_selected_recommendations_reflects_checkboxes(qtbot, app) -> None:
    # F (Live-Test 2026-07-01): Offene Empfehlungen sind einzeln an-/abwaehlbar;
    # nur die angehakten werden angewandt. Default: alle offenen angehakt.
    from PySide6.QtCore import Qt

    widget = _widget(qtbot)
    all_open = widget._open_recommendations()
    assert all_open
    # Default: jede offene Empfehlung ist angehakt -> Auswahl == alle offenen.
    assert len(widget._selected_recommendations()) == len(all_open)

    # Erste ankreuzbare Zeile abwaehlen -> genau eine weniger in der Auswahl.
    for row in range(widget._table.rowCount()):
        item = widget._table.item(row, 0)
        if item is not None and (item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
            item.setCheckState(Qt.CheckState.Unchecked)
            break
    assert len(widget._selected_recommendations()) == len(all_open) - 1


def test_ensure_consent_records_on_yes(qtbot, app, home, monkeypatch) -> None:
    from PySide6.QtWidgets import QDialog

    from tools.system_tuner.gui.consent_dialog import ConsentDialog

    monkeypatch.setattr(
        ConsentDialog, "exec", lambda self: QDialog.DialogCode.Accepted
    )
    widget = _widget(qtbot)
    assert widget._ensure_consent() is True
    assert widget._ensure_consent() is True  # bereits zugestimmt (kein Dialog mehr)


def test_ensure_consent_declined(qtbot, app, home, monkeypatch) -> None:
    from PySide6.QtWidgets import QDialog

    from tools.system_tuner.gui.consent_dialog import ConsentDialog

    monkeypatch.setattr(
        ConsentDialog, "exec", lambda self: QDialog.DialogCode.Rejected
    )
    widget = _widget(qtbot)
    assert widget._ensure_consent() is False


def test_export_button_writes_pdf(qtbot, app, monkeypatch, tmp_path) -> None:
    """Der Nachweis-Export-Button erzeugt aus dem aktuellen Scan ein PDF."""
    import tools.system_tuner.gui.tuner_widget as tw

    widget = _widget(qtbot)
    assert widget._export_btn is not None
    assert widget._report is not None  # Scan lief in __init__

    out = tmp_path / "nachweis.pdf"
    captured: dict[str, object] = {}

    class _FakeFileDialog:
        @staticmethod
        def getSaveFileName(*_a, **_k):
            return (str(out), "PDF-Dokument (*.pdf)")

    class _FakeExporter:
        def export_pdf(self, report, path) -> bool:
            from pathlib import Path

            captured["report"] = report
            captured["path"] = str(path)
            Path(path).write_bytes(b"%PDF-1.4 stub")
            return True

    class _FakeSuccess:
        def __init__(self, *_a, **_k) -> None:
            pass

        def exec(self) -> int:
            return 0

    monkeypatch.setattr(tw, "QFileDialog", _FakeFileDialog)
    monkeypatch.setattr(tw, "EvidenceExporter", _FakeExporter)
    monkeypatch.setattr(tw, "FinlaiSuccessDialog", _FakeSuccess)

    widget._on_export_clicked()

    assert captured["path"] == str(out)
    assert out.exists()


def test_export_without_scan_shows_info(qtbot, app, monkeypatch) -> None:
    """Ohne Scan zeigt der Export einen Hinweis und oeffnet KEINEN Datei-Dialog."""
    import tools.system_tuner.gui.tuner_widget as tw

    widget = _widget(qtbot)
    widget._report = None
    info_shown: list[bool] = []

    class _FakeInfo:
        def __init__(self, *_a, **_k) -> None:
            info_shown.append(True)

        def exec(self) -> int:
            return 0

    class _FailDialog:
        @staticmethod
        def getSaveFileName(*_a, **_k):
            raise AssertionError("Datei-Dialog darf ohne Scan nicht erscheinen")

    monkeypatch.setattr(tw, "FinlaiInfoDialog", _FakeInfo)
    monkeypatch.setattr(tw, "QFileDialog", _FailDialog)

    widget._on_export_clicked()
    assert info_shown == [True]


def test_apply_worker_emits_done(qtbot, app) -> None:
    from tools.system_tuner.gui.apply_worker import ApplyWorker

    captured: list = []
    worker = ApplyWorker(["TW-A"], apply_fn=lambda ids: ("RESULT", ids))
    worker.done.connect(captured.append)
    worker.run()
    assert captured == [("RESULT", ["TW-A"])]


def test_apply_reason_lines_surfaces_reject_detail(qtbot, app) -> None:
    # D6: der Elevation-Ausgang muss sichtbar werden — globale Reject-Marker
    # (tweak_id="*", z.B. "A3:..." im unsignierten Build) erscheinen mit Grund,
    # per-Tweak-Fehler mit ihrem Titel, erfolgreiche Tweaks gar nicht.
    from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
    from tools.system_tuner.domain.enums import TweakStatus

    widget = _widget(qtbot)
    real = widget._report.tweaks[0]
    result = BatchResult(
        (
            TweakResult(
                "*", TweakStatus.BLOCKED, "A3: Laufzeit-Image nicht vertrauenswuerdig"
            ),
            TweakResult(real.id, TweakStatus.FAILED, "Registry-Zugriff verweigert"),
            TweakResult(real.id, TweakStatus.SUCCESS, ""),
            TweakResult("ANOTHER", TweakStatus.BLOCKED, ""),  # leerer Grund -> raus
        )
    )
    lines = widget._apply_reason_lines(result)
    assert "A3: Laufzeit-Image nicht vertrauenswuerdig" in lines
    assert f"{real.title_de}: Registry-Zugriff verweigert" in lines
    assert len(lines) == 2  # SUCCESS + leerer Grund tauchen nicht auf


def test_apply_reason_lines_empty_on_all_success(qtbot, app) -> None:
    from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
    from tools.system_tuner.domain.enums import TweakStatus

    widget = _widget(qtbot)
    real = widget._report.tweaks[0]
    result = BatchResult((TweakResult(real.id, TweakStatus.SUCCESS, "ok"),))
    assert widget._apply_reason_lines(result) == []
