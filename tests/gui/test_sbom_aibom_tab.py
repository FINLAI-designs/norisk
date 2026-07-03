"""GUI-Tests fuer SbomAiBomTab.

Laufen offscreen via pytest-qt. Echte SBOM-/AI-BOM-Erzeugung wird gemockt —
es geht hier um den GUI-Pfad (Button → Service-Call → Status-Label /
File-Save), nicht um die Service-Korrektheit (separate Service-Tests).
"""

from __future__ import annotations

import pytest

import tools.einstellungen.gui.sbom_aibom_tab as mod
from tools.einstellungen.gui.sbom_aibom_tab import SbomAiBomTab


@pytest.fixture(autouse=True)
def _no_blocking_dialogs(monkeypatch):
    """FinlaiInfoDialog nicht modal blockieren."""
    monkeypatch.setattr(mod.FinlaiInfoDialog, "exec", lambda self: 0, raising=False)


def test_tab_baut_ohne_fehler(qtbot):
    """Smoke: Tab laesst sich offscreen instantiieren."""
    tab = SbomAiBomTab()
    qtbot.addWidget(tab)
    assert tab._sbom_button.text().startswith("SBOM erzeugen")
    assert tab._ai_bom_button.text().startswith("AI-BOM erzeugen")
    assert tab._sbom_status.text() == ""
    assert tab._ai_bom_status.text() == ""


def test_sbom_export_aktualisiert_status(qtbot, monkeypatch, tmp_path):
    """Erfolgreicher SBOM-Export setzt das Status-Label mit Komponenten-Anzahl."""
    target = tmp_path / "bom.cdx.json"
    monkeypatch.setattr(
        SbomAiBomTab,
        "_ask_save_path",
        lambda self, *, title, default_name, file_filter: target,
    )
    fake_bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "x"}, {"name": "y"}],
    }
    monkeypatch.setattr(mod.SbomService, "generate", lambda self: fake_bom)
    monkeypatch.setattr(
        mod.SbomService,
        "export_json",
        lambda self, bom, path: path,
    )

    tab = SbomAiBomTab()
    qtbot.addWidget(tab)
    tab._on_export_sbom_clicked()

    assert "2 Komponenten" in tab._sbom_status.text()
    assert str(target) in tab._sbom_status.text()


def test_sbom_export_ohne_zielpfad_kein_call(qtbot, monkeypatch):
    """Bricht der Nutzer den Save-Dialog ab, wird kein Service aufgerufen."""
    monkeypatch.setattr(
        SbomAiBomTab,
        "_ask_save_path",
        lambda self, *, title, default_name, file_filter: None,
    )
    called = {"generate": False}

    def _generate(self):
        called["generate"] = True
        return {}

    monkeypatch.setattr(mod.SbomService, "generate", _generate)
    tab = SbomAiBomTab()
    qtbot.addWidget(tab)
    tab._on_export_sbom_clicked()

    assert called["generate"] is False
    assert tab._sbom_status.text() == ""


def test_ai_bom_export_zeigt_lokal_und_cloud_zahlen(qtbot, monkeypatch, tmp_path):
    """Der AI-BOM-Status nennt die Anzahl lokaler Modelle und Cloud-Dienste."""
    target = tmp_path / "ai.json"
    monkeypatch.setattr(
        SbomAiBomTab,
        "_ask_save_path",
        lambda self, *, title, default_name, file_filter: target,
    )
    fake_document = {
        "aibomFormat": "FINLAI-AIBOM",
        "components": [
            {"name": "qwen", "location": "local"},
            {"name": "gemma", "location": "local"},
            {"name": "DeepL Translate", "location": "cloud"},
        ],
    }
    monkeypatch.setattr(mod.AiBomService, "generate", lambda self: fake_document)
    monkeypatch.setattr(
        mod.AiBomService,
        "export_json",
        lambda self, doc, path: path,
    )

    tab = SbomAiBomTab()
    qtbot.addWidget(tab)
    tab._on_export_ai_bom_clicked()

    assert "2 lokalen Modellen" in tab._ai_bom_status.text()
    assert "1 Cloud-Diensten" in tab._ai_bom_status.text()


def test_sbom_export_fehler_zeigt_fehler_status(qtbot, monkeypatch, tmp_path):
    """Ein Fehler beim Service-Aufruf wird im Status-Label gemeldet."""
    target = tmp_path / "bom.cdx.json"
    monkeypatch.setattr(
        SbomAiBomTab,
        "_ask_save_path",
        lambda self, *, title, default_name, file_filter: target,
    )

    def _raise(self):
        msg = "kaputt"
        raise RuntimeError(msg)

    monkeypatch.setattr(mod.SbomService, "generate", _raise)
    tab = SbomAiBomTab()
    qtbot.addWidget(tab)
    tab._on_export_sbom_clicked()

    assert "Fehler" in tab._sbom_status.text()
    assert "RuntimeError" in tab._sbom_status.text()
