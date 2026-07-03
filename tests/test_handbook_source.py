"""
test_handbook_source — Parser des In-App-Handbuchs (.md → navigierbare Abschnitte).

Prüft, dass der HelpDialog seine Navigation korrekt aus der echten
Anwenderhandbuch-Datei ableitet: Kapitel + Unterkapitel, stabile Nummern,
Inhaltsverzeichnis übersprungen, überschneidungsfreie Abschnittskörper.

Author: Patrick Riederich
"""

from __future__ import annotations

from core.help import handbook_source as hs


class TestLoadSectionsSynthetic:
    def _write(self, tmp_path, text):
        import core.help.handbook_source as mod

        f = tmp_path / "ANWENDERHANDBUCH_NORISK.md"
        f.write_text(text, encoding="utf-8")
        # docs-Verzeichnis auf tmp umbiegen
        orig = mod._docs_dir
        mod._docs_dir = lambda: tmp_path  # type: ignore[assignment]
        return orig

    def test_parses_chapters_and_subsections(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hs, "_docs_dir", lambda: tmp_path)
        (tmp_path / "ANWENDERHANDBUCH_NORISK.md").write_text(
            "# Titel\n\n## Inhaltsverzeichnis\n\n- [x](#x)\n\n"
            "## 7. Das Cockpit\n\nIntro-Text.\n\n"
            "### 7.1 Überblick\n\nUnterkapitel-Text.\n\n"
            "### 7.4 Workflow\n\n![alt](images/cockpit_workflow.png)\n\nMehr Text.\n\n"
            "## 8. Lage\n\nLetztes Kapitel.\n",
            encoding="utf-8",
        )
        secs = hs.load_sections("norisk")
        titles = [s.title for s in secs]
        # Inhaltsverzeichnis übersprungen; H1 (#) ignoriert
        assert "Inhaltsverzeichnis" not in titles
        assert "Titel" not in titles
        assert titles == ["7. Das Cockpit", "7.1 Überblick", "7.4 Workflow", "8. Lage"]

    def test_numbers_and_levels(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hs, "_docs_dir", lambda: tmp_path)
        (tmp_path / "ANWENDERHANDBUCH_NORISK.md").write_text(
            "## 7. Das Cockpit\n\nx\n\n### 7.4 Workflow\n\ny\n", encoding="utf-8"
        )
        secs = hs.load_sections("norisk")
        assert secs[0].level == 2 and secs[0].number == "7"
        assert secs[1].level == 3 and secs[1].number == "7.4"

    def test_bodies_non_overlapping(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hs, "_docs_dir", lambda: tmp_path)
        (tmp_path / "ANWENDERHANDBUCH_NORISK.md").write_text(
            "## 7. Cockpit\n\nINTRO\n\n### 7.1 Sub\n\nSUBTEXT\n", encoding="utf-8"
        )
        secs = hs.load_sections("norisk")
        # Kapitel-Intro enthält NICHT den Unterkapitel-Text (überschneidungsfrei)
        assert "INTRO" in secs[0].body and "SUBTEXT" not in secs[0].body
        assert "SUBTEXT" in secs[1].body

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hs, "_docs_dir", lambda: tmp_path)  # leeres Verzeichnis
        assert hs.load_sections("norisk") == []


class TestRealHandbook:
    def test_real_handbook_has_workflow_section_with_image(self):
        # Gegen die ECHTE ausgelieferte Datei (verifiziert die Pfad-Auflösung).
        secs = hs.load_sections("norisk")
        assert secs, "Anwenderhandbuch muss ladbar sein"
        by_num = {s.number: s for s in secs}
        assert "7.4" in by_num  # Workflow-Reiter
        assert "images/cockpit_workflow.png" in by_num["7.4"].body
        # Tiefen-Blöcke sind enthalten
        assert any("Alle Funktionen im Detail" in s.body for s in secs)

    def test_images_base_uri_is_file_url(self):
        uri = hs.images_base_uri("norisk")
        assert uri.startswith("file:")


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
