"""
test_ki_verzeichnis — Tests fuer KiVerzeichnisService (EU KI-VO Art. 4).

Pflicht-Tests, weil das KI-Verzeichnis Compliance-Beweis-Dokument ist —
ein Schema-Defekt waere eine harte Audit-Findung. Coverage:

* generiere_verzeichnis liefert die NoRisk-Eintraege FINLAI-Assistent +
  Cyber-Lagebild (Ollama); Buchpruefung (FINLAI-Tool) und DeepL sind in NoRisk
  nicht gelistet.: Security Chat + Handbuch-Assistent verschmolzen.
* Jeder Builder produziert die EU-KI-VO-Pflichtfelder mit korrekten
  Werten (lokal vs Cloud, human_review_required, kategorie).
* _speichern schreibt valides JSON mit Schema {generiert_am,
  finlai_version, eintraege} und legt das Verzeichnis bei Bedarf an.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.ki_verzeichnis.ki_verzeichnis_service import (
    KiEintrag,
    KiVerzeichnisService,
)


class TestGeneriereVerzeichnis:
    """Tests fuer den Top-Level-Use-Case."""

    @pytest.fixture(autouse=True)
    def _isolate_path(self, tmp_path, monkeypatch):
        # Schreibe das KI-Verzeichnis in tmp_path statt nach ~/.finlai/.
        target = tmp_path / "ki_verzeichnis.json"
        monkeypatch.setattr(KiVerzeichnisService, "VERZEICHNIS_PATH", target)
        self.target = target

    def test_norisk_ki_einsaetze(self):
        # NoRisk (Cybersecurity) erfasst zwei lokale Ollama-KI-Einsätze:
        # den vereinten FINLAI-Assistenten: Security Chat + Handbuch-
        # Assistent verschmolzen) und das Cyber-Lagebild (Briefing).
        # Buchprüfung ist ein FINLAI-Tool und in NoRisk nicht vorhanden;
        # customer_audit/security_scoring nutzen kein LLM.
        eintraege = KiVerzeichnisService().generiere_verzeichnis()
        namen = {e.name for e in eintraege}
        assert namen == {
            "FINLAI-Assistent",
            "Cyber-Lagebild (Briefing)",
        }
        assert all(e.lokal for e in eintraege)  # NoRisk ist 100% lokal

    def test_alle_eintraege_sind_kieintrag_instanzen(self):
        for e in KiVerzeichnisService().generiere_verzeichnis():
            assert isinstance(e, KiEintrag)

    def test_pflichtfelder_nicht_leer(self):
        for e in KiVerzeichnisService().generiere_verzeichnis():
            assert e.name
            assert e.kategorie
            assert e.zweck
            assert e.modell
            assert e.verantwortlich
            assert e.erstellt_am  # ISO-Zeitstempel
            assert e.datenarten  # mind. 1 Eintrag
            assert e.human_review is True  # EU KI-VO Art. 4

    def test_speichert_json_datei(self):
        KiVerzeichnisService().generiere_verzeichnis()
        assert self.target.exists()

    def test_legt_eltern_verzeichnis_an(self, tmp_path, monkeypatch):
        # Wenn das Eltern-Verzeichnis noch nicht existiert, muss
        # _speichern es per mkdir(parents=True) anlegen.
        nested = tmp_path / "nicht_existent" / "noch_tiefer" / "ki.json"
        monkeypatch.setattr(KiVerzeichnisService, "VERZEICHNIS_PATH", nested)
        KiVerzeichnisService().generiere_verzeichnis()
        assert nested.exists()
        assert nested.parent.is_dir()


class TestEinzelneEintraege:
    """Tests fuer die Builder-Methoden (Ollama)."""

    def test_assistent_eintrag_lokal(self):
        e = KiVerzeichnisService()._assistent_eintrag()
        assert e.name == "FINLAI-Assistent"
        assert e.kategorie == "Chat"
        assert e.lokal is True
        assert "Ollama" in e.modell
        assert e.human_review is True
        # Vereint: deckt Bedienung UND IT-Sicherheit ab.
        assert "Nutzerfragen (Bedienung + IT-Sicherheit)" in e.datenarten
        assert "Sicherheits-Korpus (lokal indiziert)" in e.datenarten

    def test_briefing_eintrag_lokal(self):
        e = KiVerzeichnisService()._briefing_eintrag()
        assert e.name == "Cyber-Lagebild (Briefing)"
        assert e.kategorie == "Analyse"
        assert e.lokal is True
        assert "Ollama" in e.modell
        assert e.human_review is True
        assert e.datenarten  # mind. 1 Datenart

class TestSpeichernJsonSchema:
    """Tests fuer das Datei-Schema der ki_verzeichnis.json."""

    @pytest.fixture(autouse=True)
    def _isolate_path(self, tmp_path, monkeypatch):
        self.target = tmp_path / "ki_verzeichnis.json"
        monkeypatch.setattr(KiVerzeichnisService, "VERZEICHNIS_PATH", self.target)

    def _read(self) -> dict:
        return json.loads(self.target.read_text(encoding="utf-8"))

    def test_top_level_keys(self):
        KiVerzeichnisService().generiere_verzeichnis()
        data = self._read()
        assert set(data.keys()) >= {"generiert_am", "finlai_version", "eintraege"}

    def test_eintraege_enthaelt_alle_pflichtfelder(self):
        KiVerzeichnisService().generiere_verzeichnis()
        for e in self._read()["eintraege"]:
            for feld in (
                "name", "kategorie", "zweck", "datenarten", "modell",
                "lokal", "verantwortlich", "erstellt_am", "human_review",
            ):
                assert feld in e

    def test_utf8_und_kein_ascii_escape(self):
        # Umlaute müssen als echtes UTF-8 erscheinen (nicht ASCII-escaped),
        # damit die Datei direkt fuer Audits lesbar ist. Der FINLAI-Assistent-
        # Zweck enthält "erklärt" (ä) als Prüf-Umlaut.
        KiVerzeichnisService().generiere_verzeichnis()
        raw = self.target.read_text(encoding="utf-8")
        assert "erklärt" in raw
        assert "\\u00" not in raw

    def test_speichern_ueberschreibt_bestehende_datei(self):
        # Zwei Aufrufe duerfen nicht akkumulieren — der zweite Lauf
        # ersetzt den Inhalt vollstaendig.
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text("STUB", encoding="utf-8")
        KiVerzeichnisService().generiere_verzeichnis()
        data = self._read()
        assert "eintraege" in data
        # NoRisk-Kontext: FINLAI-Assistent + Cyber-Lagebild (Briefing).
        assert len(data["eintraege"]) == 2

    def test_isoformat_zeitstempel(self):
        # erstellt_am pro Eintrag und generiert_am Top-Level muessen ISO-8601
        # parsbar sein.
        from datetime import datetime
        KiVerzeichnisService().generiere_verzeichnis()
        data = self._read()
        # Top-Level — wirft sonst ValueError
        datetime.fromisoformat(data["generiert_am"])
        for e in data["eintraege"]:
            datetime.fromisoformat(e["erstellt_am"])


# Hilfs-Re-Import fuer den Pfad-Test oben (nutzt explizit Path)
_ = Path
