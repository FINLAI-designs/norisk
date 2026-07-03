"""tests/test_dek_mismatch_hardening.py — Regression fuer den DEK-Mismatch-
Incident und die strukturelle Haertung.

Abgedeckt:
  * C1 — zentrale Datenwurzel ``finlai_dir`` + ``FINLAI_HOME``-Isolation,
          plus Grep-Guard gegen neue ``Path.home/'.finlai'``-Hardcodes.
  * C2 — app-scoped ``migration-state``: completed_at der einen App darf die
          andere nicht als "fertig" markieren (verhindert blockierte Selbst-
          heilung).
  * C4 — ``_classify_db_error`` meldet Wrong-Key (DEK-Mismatch) auf einer
          existierenden Datei als ``DatabaseEncryptionError``, nicht als
          irrefuehrenden ``DatabaseCorruptError``.
"""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# C1 — zentrale Datenwurzel + Isolation
# ---------------------------------------------------------------------------


class TestFinlaiDir:
    def test_default_is_home_finlai(self, monkeypatch):
        """Ohne Override/Env liefert finlai_dir ``~/.finlai`` (Produktion)."""
        from core import finlai_paths

        monkeypatch.delenv("FINLAI_HOME", raising=False)
        finlai_paths.set_finlai_home(None)
        assert finlai_paths.finlai_dir() == Path.home() / ".finlai"

    def test_env_var_override(self, monkeypatch, tmp_path):
        """``FINLAI_HOME`` biegt die Datenwurzel auf ein Wegwerf-Verzeichnis."""
        from core import finlai_paths

        finlai_paths.set_finlai_home(None)
        monkeypatch.setenv("FINLAI_HOME", str(tmp_path))
        assert finlai_paths.finlai_dir() == tmp_path

    def test_runtime_override_wins_over_env(self, monkeypatch, tmp_path):
        """Laufzeit-Override hat Vorrang vor ``FINLAI_HOME``."""
        from core import finlai_paths

        monkeypatch.setenv("FINLAI_HOME", str(tmp_path / "env"))
        try:
            finlai_paths.set_finlai_home(tmp_path / "override")
            assert finlai_paths.finlai_dir() == tmp_path / "override"
        finally:
            finlai_paths.set_finlai_home(None)

    def test_no_direct_hardcode_in_app_runtime(self):
        """C1-Grep-Guard: kein App-Runtime-Modul (``core/``, ``tools/``,
        ``apps/``, ``main.py``) ausser ``finlai_paths`` leitet die Datenwurzel
        selbst via ``Path.home/'.finlai'`` ab — sonst greift die
        FINLAI_HOME-Isolation nicht und destruktive Tests/Release treffen das
        echte Profil (Incident 2026-06-02). Build-Tooling ausserhalb der App-Schichten ist bewusst ausgenommen."""
        repo = Path(__file__).resolve().parent.parent
        pattern = re.compile(r"Path\.home\(\)\s*/\s*[\"']\.finlai")
        files: list[Path] = [
            p
            for root in (repo / "core", repo / "tools", repo / "apps")
            if root.is_dir()
            for p in root.rglob("*.py")
        ]
        if (repo / "main.py").is_file():
            files.append(repo / "main.py")
        offenders: list[str] = []
        for py in files:
            if py.name == "finlai_paths.py":
                continue
            for lineno, line in enumerate(
                py.read_text(encoding="utf-8").splitlines(), 1
            ):
                if pattern.search(line):
                    offenders.append(f"{py.relative_to(repo)}:{lineno}")
        assert not offenders, (
            "Direkte ~/.finlai-Hardcodes gefunden (nutze finlai_dir()): "
            + ", ".join(offenders)
        )


# ---------------------------------------------------------------------------
# C2 — app-scoped migration-state
# ---------------------------------------------------------------------------


class TestAppScopedMigrationState:
    def test_no_cross_app_clobber(self, tmp_path, monkeypatch):
        """Fremd-App 'completed' darf norisk NICHT als fertig markieren —
        sonst ueberspringt norisk seine Migration und heilt sich nie."""
        from core.database import migration_state as ms

        monkeypatch.setattr(
            ms, "_MIGRATION_STATE_FILE", tmp_path / "migration-state.json"
        )
        sibling_state = {
            "schema_version": 1,
            "started_at": "2026-05-28T00:00:00+00:00",
            "completed_at": "2026-05-28T00:00:01+00:00",
            "backup_path": None,
            "dbs": {},
            "secure_store": {"status": "absent"},
        }
        ms.set_state(sibling_state, "sibling_app")

        # norisk hat keinen eigenen State → None (laeuft frisch / Selbstheilung).
        assert ms.get_state("norisk") is None
        assert ms.get_state("sibling_app") == sibling_state
        assert (tmp_path / "migration-state-sibling_app.json").exists()
        assert not (tmp_path / "migration-state-norisk.json").exists()

    def test_clear_is_app_scoped(self, tmp_path, monkeypatch):
        """clear_state(app) entfernt nur die Datei dieser App."""
        from core.database import migration_state as ms

        monkeypatch.setattr(
            ms, "_MIGRATION_STATE_FILE", tmp_path / "migration-state.json"
        )
        base = {
            "schema_version": 1,
            "started_at": "x",
            "completed_at": None,
            "dbs": {},
            "secure_store": {},
        }
        ms.set_state(base, "norisk")
        ms.set_state(base, "sibling_app")
        ms.clear_state("norisk")
        assert ms.get_state("norisk") is None
        assert ms.get_state("sibling_app") is not None


# ---------------------------------------------------------------------------
# C4 — Wrong-Key vs. Korruption
# ---------------------------------------------------------------------------


class TestClassifyWrongKey:
    def test_existing_file_wrong_key_is_encryption_error(self, tmp_path):
        """'file is not a database' auf existierender, nicht-leerer Datei +
        db_path → DatabaseEncryptionError (Schluessel-Mismatch)."""
        from core.database.encrypted_db import (
            DatabaseEncryptionError,
            _classify_db_error,
        )

        db = tmp_path / "x.db"
        db.write_bytes(b"\x01" * 4096)
        result = _classify_db_error(
            "x", Exception("file is not a database"), db
        )
        assert isinstance(result, DatabaseEncryptionError)

    def test_without_path_stays_corrupt(self):
        """Ohne db_path bleibt 'file is not a database' → DatabaseCorruptError
        (Rueckwaertskompatibilitaet fuer den 2-Argument-Aufruf)."""
        from core.database.encrypted_db import (
            DatabaseCorruptError,
            _classify_db_error,
        )

        result = _classify_db_error("x", Exception("file is not a database"))
        assert isinstance(result, DatabaseCorruptError)

    def test_malformed_stays_corrupt_even_with_path(self, tmp_path):
        """'malformed' ist echte Korruption — bleibt DatabaseCorruptError
        auch mit db_path."""
        from core.database.encrypted_db import (
            DatabaseCorruptError,
            _classify_db_error,
        )

        db = tmp_path / "x.db"
        db.write_bytes(b"\x01" * 4096)
        result = _classify_db_error(
            "x", Exception("database disk image is malformed"), db
        )
        assert isinstance(result, DatabaseCorruptError)

    def test_missing_file_stays_corrupt(self, tmp_path):
        """Nicht existierende/leere Datei → DatabaseCorruptError (keine
        Wrong-Key-Annahme ohne reale Datei)."""
        from core.database.encrypted_db import (
            DatabaseCorruptError,
            _classify_db_error,
        )

        result = _classify_db_error(
            "x", Exception("file is not a database"), tmp_path / "missing.db"
        )
        assert isinstance(result, DatabaseCorruptError)

    def test_real_sqlcipher_message_with_path_gives_recovery_hint(self, tmp_path):
        """Die ECHTE SQLCipher-Wrong-Key-Meldung ist 'file is encrypted or is
        not a database'. Mit existierender Datei MUSS sie die reiche
        DatabaseEncryptionError-Variante MIT Recovery-Hinweis liefern (sonst
        feuert das C4-Feature im haeufigsten Realfall nicht)."""
        from core.database.encrypted_db import (
            DatabaseEncryptionError,
            _classify_db_error,
        )

        db = tmp_path / "x.db"
        db.write_bytes(b"\x01" * 4096)
        result = _classify_db_error(
            "x", Exception("file is encrypted or is not a database"), db
        )
        assert isinstance(result, DatabaseEncryptionError)
        assert ".unrecoverable" in str(result)

    def test_file_encrypted_without_path_stays_encryption(self):
        """'file is encrypted or is not a database' ohne db_path → weiterhin
        DatabaseEncryptionError (generisch, Rueckwaerts-Kompat)."""
        from core.database.encrypted_db import (
            DatabaseEncryptionError,
            _classify_db_error,
        )

        result = _classify_db_error(
            "x", Exception("file is encrypted or is not a database")
        )
        assert isinstance(result, DatabaseEncryptionError)
