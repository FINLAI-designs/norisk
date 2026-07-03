"""
test_login_attempts — Tests fuer den persistenten Login-Lockout.

Schutz gegen Brute-Force gegen lokal lesbare bcrypt-Hashes
(`users.json`). Coverage:

- is_locked_out: vor Limit nicht gesperrt, ab Limit gesperrt,
  nach Lockout-Window wieder frei.
- record_failed_attempt: Persistenz, Window-Abschneidung, Cap.
- clear_attempts: leert Historie eines Users.
- File-Format: JSON-Korruption, Schreibfehler werden tolerant gehandhabt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.auth import login_attempts as la


@pytest.fixture(autouse=True)
def _isolate_attempts_file(tmp_path, monkeypatch):
    target = tmp_path / "login_attempts.json"
    monkeypatch.setattr(la, "_FINLAI_DIR", tmp_path)
    monkeypatch.setattr(la, "_ATTEMPTS_FILE", target)
    yield target


class TestIsLockedOut:
    def test_kein_user_kein_lockout(self):
        assert la.is_locked_out("") == (False, 0)

    def test_user_ohne_history_nicht_gesperrt(self):
        assert la.is_locked_out("alice") == (False, 0)

    def test_unter_limit_nicht_gesperrt(self):
        for _ in range(la.MAX_ATTEMPTS_PER_WINDOW - 1):
            la.record_failed_attempt("alice")
        locked, remaining = la.is_locked_out("alice")
        assert locked is False
        assert remaining == 0

    def test_ab_limit_gesperrt(self):
        for _ in range(la.MAX_ATTEMPTS_PER_WINDOW):
            la.record_failed_attempt("alice")
        locked, remaining = la.is_locked_out("alice")
        assert locked is True
        # remaining liegt zwischen 0 und LOCKOUT_MINUTES * 60
        assert 0 < remaining <= la.LOCKOUT_MINUTES * 60

    def test_lockout_endet_nach_lockout_minutes(
        self, tmp_path, monkeypatch
    ):
        # Manuell altes Lockout-Szenario in die Datei schreiben:
        # MAX_ATTEMPTS-Versuche, alle laenger her als LOCKOUT_MINUTES.
        target: Path = tmp_path / "login_attempts.json"
        old = datetime.now() - timedelta(minutes=la.LOCKOUT_MINUTES + 1)
        timestamps = [old.isoformat()] * la.MAX_ATTEMPTS_PER_WINDOW
        target.write_text(json.dumps({"alice": timestamps}), encoding="utf-8")
        monkeypatch.setattr(la, "_ATTEMPTS_FILE", target)
        # Window-Filter wirft alle alten Eintraege raus → nicht gesperrt
        locked, remaining = la.is_locked_out("alice")
        assert locked is False
        assert remaining == 0

    def test_eintrag_ausserhalb_window_zaehlt_nicht(
        self, tmp_path, monkeypatch
    ):
        target: Path = tmp_path / "login_attempts.json"
        # Mische: 3 alte (ausserhalb Window) + 2 neue
        old_ts = (
            datetime.now() - timedelta(minutes=la.WINDOW_MINUTES + 5)
        ).isoformat()
        new_ts = datetime.now().isoformat()
        target.write_text(
            json.dumps({"alice": [old_ts, old_ts, old_ts, new_ts, new_ts]}),
            encoding="utf-8",
        )
        monkeypatch.setattr(la, "_ATTEMPTS_FILE", target)
        # Nur 2 valid → nicht gesperrt (Limit ist 5)
        assert la.is_locked_out("alice")[0] is False


class TestRecordFailedAttempt:
    def test_legt_datei_an(self, _isolate_attempts_file):
        la.record_failed_attempt("alice")
        assert _isolate_attempts_file.exists()

    def test_eintrag_persistiert(self, _isolate_attempts_file):
        la.record_failed_attempt("alice")
        data = json.loads(_isolate_attempts_file.read_text(encoding="utf-8"))
        assert "alice" in data
        assert len(data["alice"]) == 1

    def test_mehrere_user_isoliert(self, _isolate_attempts_file):
        la.record_failed_attempt("alice")
        la.record_failed_attempt("bob")
        la.record_failed_attempt("alice")
        data = json.loads(_isolate_attempts_file.read_text(encoding="utf-8"))
        assert len(data["alice"]) == 2
        assert len(data["bob"]) == 1

    def test_leerer_username_wird_ignoriert(self, _isolate_attempts_file):
        la.record_failed_attempt("")
        # Datei darf gar nicht erst angelegt werden
        assert not _isolate_attempts_file.exists()

    def test_cap_verhindert_unbegrenztes_wachstum(
        self, _isolate_attempts_file
    ):
        # 100 schnell hintereinander geschriebene Versuche duerfen die
        # Datei nicht auf 100 Eintraege wachsen lassen.
        for _ in range(100):
            la.record_failed_attempt("alice")
        data = json.loads(_isolate_attempts_file.read_text(encoding="utf-8"))
        assert len(data["alice"]) <= la.MAX_ATTEMPTS_PER_WINDOW * 2


class TestClearAttempts:
    def test_loescht_nur_diesen_user(self, _isolate_attempts_file):
        la.record_failed_attempt("alice")
        la.record_failed_attempt("bob")
        la.clear_attempts("alice")
        data = json.loads(_isolate_attempts_file.read_text(encoding="utf-8"))
        assert "alice" not in data
        assert "bob" in data

    def test_leerer_username_kein_crash(self):
        la.clear_attempts("")  # darf nicht crashen

    def test_unbekannter_user_kein_crash(self, _isolate_attempts_file):
        la.record_failed_attempt("alice")
        la.clear_attempts("nicht_existent")
        # Alice-Eintrag muss erhalten bleiben
        data = json.loads(_isolate_attempts_file.read_text(encoding="utf-8"))
        assert "alice" in data

    def test_clear_setzt_lockout_zurueck(self):
        for _ in range(la.MAX_ATTEMPTS_PER_WINDOW):
            la.record_failed_attempt("alice")
        assert la.is_locked_out("alice")[0] is True
        la.clear_attempts("alice")
        assert la.is_locked_out("alice") == (False, 0)


class TestFileResilience:
    def test_korrupte_json_liefert_leere_history(
        self, _isolate_attempts_file
    ):
        _isolate_attempts_file.write_text("{ kein gueltiges json", encoding="utf-8")
        # is_locked_out muss gracefully False zurueckgeben
        assert la.is_locked_out("alice") == (False, 0)

    def test_falsches_json_top_level_typ(self, _isolate_attempts_file):
        # JSON ist gueltig, aber kein dict → wir behandeln als leer
        _isolate_attempts_file.write_text("[1, 2, 3]", encoding="utf-8")
        assert la.is_locked_out("alice") == (False, 0)

    def test_invaliderzeitstempel_wird_uebersprungen(
        self, _isolate_attempts_file
    ):
        _isolate_attempts_file.write_text(
            json.dumps(
                {"alice": ["nicht-iso", None, datetime.now().isoformat()]}
            ),
            encoding="utf-8",
        )
        # Nur 1 valider Eintrag, kein Lockout
        assert la.is_locked_out("alice")[0] is False
