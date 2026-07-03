"""
test_encrypted_db — Tests fuer EncryptedDatabase.

Prueft:
- DB-Datei wird verschluesselt erstellt
- Daten bleiben nach Reconnect erhalten
- DB ohne Schluessel ist nicht lesbar (Verschluesselung aktiv)
- Jede DB hat einen eigenen Schluessel
- init_schema ist idempotent
- migrate_from_plaintext migriert Daten korrekt

Test-Bootstrap: KeyManager-Bootstrap kommt aus dem globalen
``tests/conftest.py``-Autouse-Fixture (Subtask 2).

Author: Patrick Riederich
"""

import sqlite3
from unittest.mock import patch

import pytest


class TestEncryptedDatabase:
    """Tests fuer EncryptedDatabase."""

    @pytest.fixture
    def db(self, tmp_path):
        """Test-DB in tmp-Verzeichnis."""
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            db = EncryptedDatabase("test")
            return db

    def test_db_erstellt(self, db):
        """DB-Datei wird nach erstem Schreiben erstellt."""
        with db.connection() as conn:
            conn.execute("CREATE TABLE t (id INTEGER)")
        assert db._db_path.exists()

    def test_daten_persistent(self, db):
        """Daten bleiben nach Trennung und Reconnect erhalten."""
        with db.connection() as conn:
            conn.execute("CREATE TABLE t (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO t VALUES (1, 'Test')")

        # Neue Verbindung — Daten muessen noch da sein
        with db.connection() as conn:
            row = conn.execute("SELECT * FROM t").fetchone()
            assert row[0] == 1
            assert row[1] == "Test"

    def test_ohne_key_nicht_lesbar(self, db, tmp_path):
        """DB ohne Schluessel kann nicht gelesen werden."""
        with db.connection() as conn:
            conn.execute("CREATE TABLE t (id INTEGER)")
            conn.execute("INSERT INTO t VALUES (1)")

        # Standard sqlite3 ohne Key muss fehlschlagen
        raw = sqlite3.connect(str(db._db_path))
        with pytest.raises(Exception):
            raw.execute("SELECT * FROM t").fetchall()

    def test_verschiedene_db_verschiedene_keys(self, tmp_path):
        """Jede Datenbank hat einen eigenen Schluessel."""
        from core.database.encrypted_db import _derive_db_key

        key_a = _derive_db_key("accounts")
        key_b = _derive_db_key("maps")
        key_c = _derive_db_key("dokumentenanalyse")

        assert key_a != key_b
        assert key_b != key_c
        assert key_a != key_c

    def test_schema_idempotent(self, db):
        """init_schema kann mehrfach aufgerufen werden."""
        schema = "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY);"
        db.init_schema(schema)
        db.init_schema(schema)  # Kein Fehler beim zweiten Aufruf

    def test_migration_plaintext(self, db, tmp_path):
        """Migration von sqlite3 zu SQLCipher kopiert alle Daten."""
        # Alte unverschluesselte DB erstellen
        old_path = tmp_path / "old.db"
        old_conn = sqlite3.connect(str(old_path))
        old_conn.execute("CREATE TABLE t (id INTEGER, name TEXT)")
        old_conn.execute("INSERT INTO t VALUES (1, 'Mueller GmbH')")
        old_conn.commit()
        old_conn.close()

        # Schema in neuer verschluesselter DB anlegen
        db.init_schema("CREATE TABLE IF NOT EXISTS t (id INTEGER, name TEXT)")

        # Migration durchfuehren
        db.migrate_from_plaintext(old_path)

        # Backup der alten DB muss existieren
        backup = old_path.with_suffix(".db.plaintext_backup")
        assert backup.exists()

        # Daten muessen in verschluesselter DB vorhanden sein
        with db.connection() as conn:
            row = conn.execute("SELECT * FROM t").fetchone()
            assert row[1] == "Mueller GmbH"

    def test_migration_nicht_vorhanden(self, db, tmp_path):
        """migrate_from_plaintext ist No-op wenn Quelldatei fehlt."""
        db.migrate_from_plaintext(tmp_path / "does_not_exist.db")
        # Kein Fehler, DB-Datei nicht erstellt
        assert not db._db_path.exists()

    def test_rollback_bei_exception(self, db):
        """Transaktion wird bei Exception zurueckgerollt."""
        with db.connection() as conn:
            conn.execute("CREATE TABLE t (id INTEGER)")

        try:
            with db.connection() as conn:
                conn.execute("INSERT INTO t VALUES (99)")
                raise RuntimeError("Absichtlicher Fehler")
        except RuntimeError:
            pass

        with db.connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]

        assert count == 0

    def test_key_ist_hex_string(self):
        """Abgeleiteter DB-Schluessel ist ein 64-stelliger Hex-String."""
        from core.database.encrypted_db import _derive_db_key

        key = _derive_db_key("test")
        assert isinstance(key, str)
        assert len(key) == 64
        int(key, 16)  # Wirft ValueError wenn kein gueltiger Hex


class TestDatabaseTimeout:
    """Prueft dass der Timeout-Wert korrekt konfiguriert ist."""

    def test_timeout_konstante(self):
        """_DB_LOCK_TIMEOUT_SECONDS ist auf 30 gesetzt."""
        from core.database.encrypted_db import _DB_LOCK_TIMEOUT_SECONDS

        assert _DB_LOCK_TIMEOUT_SECONDS == 30

    def test_connect_mit_timeout(self, tmp_path):
        """sqlcipher3.connect wird mit timeout aufgerufen."""
        from unittest.mock import MagicMock, patch

        from core.database.encrypted_db import (
            _DB_LOCK_TIMEOUT_SECONDS,
            EncryptedDatabase,
        )

        mock_conn = MagicMock()
        mock_conn.execute.return_value = MagicMock()

        with (
            patch("core.database.encrypted_db.DB_DIR", tmp_path),
            patch("sqlcipher3.connect", return_value=mock_conn) as mock_connect,
        ):
            db = EncryptedDatabase("timeout_test")
            with db.connection():
                pass
            mock_connect.assert_called_once_with(
                str(db._db_path),
                timeout=_DB_LOCK_TIMEOUT_SECONDS,
            )


class TestDatabaseExceptions:
    """Prueft die spezifischen DB-Exception-Typen."""

    def test_exception_hierarchie(self):
        """Alle spezifischen Exceptions erben von FinLaiDatabaseError."""
        from core.database.encrypted_db import (
            DatabaseCorruptError,
            DatabaseEncryptionError,
            DatabaseLockedError,
            FinLaiDatabaseError,
        )

        assert issubclass(DatabaseLockedError, FinLaiDatabaseError)
        assert issubclass(DatabaseCorruptError, FinLaiDatabaseError)
        assert issubclass(DatabaseEncryptionError, FinLaiDatabaseError)

    def test_classify_locked(self):
        """'database is locked' → DatabaseLockedError."""
        from core.database.encrypted_db import DatabaseLockedError, _classify_db_error

        exc = Exception("database is locked")
        result = _classify_db_error("test", exc)
        assert isinstance(result, DatabaseLockedError)

    def test_classify_busy(self):
        """'database is busy' → DatabaseLockedError."""
        from core.database.encrypted_db import DatabaseLockedError, _classify_db_error

        exc = Exception("database is busy")
        result = _classify_db_error("test", exc)
        assert isinstance(result, DatabaseLockedError)

    def test_classify_corrupt(self):
        """'file is not a database' → DatabaseCorruptError."""
        from core.database.encrypted_db import DatabaseCorruptError, _classify_db_error

        exc = Exception("file is not a database")
        result = _classify_db_error("test", exc)
        assert isinstance(result, DatabaseCorruptError)

    def test_classify_malformed(self):
        """'malformed' → DatabaseCorruptError."""
        from core.database.encrypted_db import DatabaseCorruptError, _classify_db_error

        exc = Exception("database disk image is malformed")
        result = _classify_db_error("test", exc)
        assert isinstance(result, DatabaseCorruptError)

    def test_classify_encrypted(self):
        """'file is encrypted' → DatabaseEncryptionError."""
        from core.database.encrypted_db import (
            DatabaseEncryptionError,
            _classify_db_error,
        )

        exc = Exception("file is encrypted or is not a database")
        result = _classify_db_error("test", exc)
        assert isinstance(result, DatabaseEncryptionError)

    def test_classify_generic(self):
        """Unbekannte Exception → generische FinLaiDatabaseError."""
        from core.database.encrypted_db import FinLaiDatabaseError, _classify_db_error

        exc = Exception("some unexpected db error")
        result = _classify_db_error("test", exc)
        assert type(result) is FinLaiDatabaseError

    def test_connection_wirft_spezifische_exception(self, tmp_path):
        """connection hebt FinLaiDatabaseError statt RuntimeError."""
        from unittest.mock import MagicMock, patch

        import sqlcipher3

        from core.database.encrypted_db import EncryptedDatabase, FinLaiDatabaseError

        mock_conn = MagicMock()
        mock_conn.execute.side_effect = sqlcipher3.DatabaseError(
            "file is not a database"
        )

        with (
            patch("core.database.encrypted_db.DB_DIR", tmp_path),
            patch("sqlcipher3.connect", return_value=mock_conn),
        ):
            db = EncryptedDatabase("exc_test")
            with pytest.raises(FinLaiDatabaseError), db.connection():
                pass


class TestWithDbRetry:
    """Prueft den with_db_retry-Decorator."""

    def test_retry_bei_locked(self, tmp_path):
        """Bei DatabaseLockedError wird bis zu _MAX_RETRIES Mal wiederholt."""
        from unittest.mock import patch

        from core.database.encrypted_db import (
            _MAX_RETRIES,
            DatabaseLockedError,
            with_db_retry,
        )

        call_count = 0

        class FakeRepo:
            @with_db_retry
            def do_work(self):
                nonlocal call_count
                call_count += 1
                raise DatabaseLockedError("locked")

        with (
            patch("core.database.encrypted_db.time.sleep"),
            pytest.raises(DatabaseLockedError),
        ):
            FakeRepo().do_work()

        assert call_count == _MAX_RETRIES

    def test_kein_retry_bei_anderem_fehler(self):
        """Bei anderen Exceptions wird nicht wiederholt."""
        from core.database.encrypted_db import with_db_retry

        call_count = 0

        class FakeRepo:
            @with_db_retry
            def do_work(self):
                nonlocal call_count
                call_count += 1
                raise ValueError("nicht DB-Lock")

        with pytest.raises(ValueError):
            FakeRepo().do_work()

        assert call_count == 1

    def test_erfolg_beim_zweiten_versuch(self):
        """Retry greift wenn erster Versuch gesperrt, zweiter erfolgreich."""
        from unittest.mock import patch

        from core.database.encrypted_db import DatabaseLockedError, with_db_retry

        call_count = 0

        class FakeRepo:
            @with_db_retry
            def do_work(self):
                nonlocal call_count
                call_count += 1
                if call_count < 2:
                    raise DatabaseLockedError("locked")
                return "ok"

        with patch("core.database.encrypted_db.time.sleep"):
            result = FakeRepo().do_work()

        assert result == "ok"
        assert call_count == 2


class TestConsolidatedRemap:
    """: DB-Konsolidierung (Remap nur im App-Kontext) + Alt-DB-Wipe."""

    @pytest.fixture
    def app_context(self):
        """Setzt den Produktions-App-Kontext (aktiviert den Remap)."""
        from core.database.db_context import clear_db_app_id, set_db_app_id

        set_db_app_id("norisk")
        yield
        clear_db_app_id()

    def test_no_remap_without_app_context(self, tmp_path):
        """Ohne App-Boot: kein Remap -> jeder Name eigene Datei (Isolation)."""
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            a = EncryptedDatabase("system_scanner")
            b = EncryptedDatabase("network_scanner")
        assert a._db_path.name == "system_scanner.db"
        assert b._db_path.name == "network_scanner.db"
        assert a._db_path != b._db_path

    def test_remap_consolidates_in_app_context(self, app_context, tmp_path):
        """Mit App-Kontext: konsolidierte Tools -> EINE norisk.db, EIN Key."""
        from core.database.encrypted_db import EncryptedDatabase, _derive_db_key

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            a = EncryptedDatabase("system_scanner")
            b = EncryptedDatabase("api_security")
        assert a._db_path == b._db_path
        assert a._db_path.name == "norisk.db"
        assert a._db_key == b._db_key == _derive_db_key("norisk")

    def test_separate_dbs_not_remapped(self, app_context, tmp_path):
        """network_monitor bleibt trotz App-Kontext seine eigene DB."""
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            nm = EncryptedDatabase("network_monitor")
        assert nm._db_path.name == "network_monitor.db"

    def test_coexistence_no_collision(self, app_context, tmp_path):
        """system_scanner.scans + network_scanner.port_scans koexistieren."""
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            sysdb = EncryptedDatabase("system_scanner")
            with sysdb.connection() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER)")
                conn.execute("INSERT INTO scans VALUES (1)")
            netdb = EncryptedDatabase("network_scanner")  # -> selbe norisk.db
            with netdb.connection() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS port_scans (id INTEGER)")
                conn.execute("INSERT INTO port_scans VALUES (2)")
            with sysdb.connection() as conn:
                tables = {
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
        assert {"scans", "port_scans"} <= tables
        assert sysdb._db_path == netdb._db_path

    def test_purge_keeps_consolidated_and_separate(self, app_context, tmp_path):
        """Wipe behaelt norisk + separate, loescht Alt-Per-Tool-DBs, idempotent."""
        from core.database.encrypted_db import purge_consolidated_legacy_dbs

        appdir = tmp_path / "norisk"
        appdir.mkdir()
        for name in ("norisk", "network_monitor", "system_scanner", "api_security"):
            (appdir / f"{name}.db").write_bytes(b"x")

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            removed = purge_consolidated_legacy_dbs()
            second = purge_consolidated_legacy_dbs()  # idempotent (Sentinel)

        assert removed == 2  # system_scanner + api_security
        assert second == 0
        assert (appdir / "norisk.db").exists()
        assert (appdir / "network_monitor.db").exists()
        assert not (appdir / "system_scanner.db").exists()
        assert not (appdir / "api_security.db").exists()
        assert (appdir / ".db_consolidation_v1").exists()

    def test_busy_timeout_is_set(self, tmp_path):
        """: busy_timeout aktiv (Multi-Writer-Contention-Mitigation)."""
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            db = EncryptedDatabase("test")
            with db.connection() as conn:
                timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 5000

    def test_concurrent_writer_reader_no_lock(self, app_context, tmp_path):
        """ §6 Nebenlaeufigkeits-Smoke: parallele Writer + Reader auf der
        EINEN konsolidierten norisk-DB laufen ohne ``database is locked`` durch.

        Belegt die Mitigation der akzeptierten Konsequenz (hoehere
        Writer-Contention auf der Haupt-DB): WAL entkoppelt Reader von Writern,
        ``busy_timeout`` serialisiert konkurrierende Writer intern. Alle
        konsolidierten Tools teilen sich physisch ``norisk.db`` (gleicher Key).
        """
        import threading

        from core.database.encrypted_db import EncryptedDatabase

        writers, readers, per = 4, 4, 20
        errors: list[Exception] = []

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            with EncryptedDatabase("norisk").connection() as conn:
                conn.execute(
                    "CREATE TABLE events ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, val INTEGER)"
                )

            def write_loop() -> None:
                try:
                    db = EncryptedDatabase("norisk")
                    for i in range(per):
                        with db.connection() as conn:
                            conn.execute(
                                "INSERT INTO events (val) VALUES (?)", (i,)
                            )
                except Exception as exc:  # noqa: BLE001 -- Thread-Fehler sammeln
                    errors.append(exc)

            def read_loop() -> None:
                try:
                    db = EncryptedDatabase("norisk")
                    for _ in range(per):
                        with db.connection() as conn:
                            conn.execute(
                                "SELECT count(*) FROM events"
                            ).fetchone()
                except Exception as exc:  # noqa: BLE001 -- Thread-Fehler sammeln
                    errors.append(exc)

            threads = [
                threading.Thread(target=write_loop) for _ in range(writers)
            ]
            threads += [
                threading.Thread(target=read_loop) for _ in range(readers)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            with EncryptedDatabase("norisk").connection() as conn:
                total = conn.execute("SELECT count(*) FROM events").fetchone()[0]

        assert not errors, f"Nebenlaeufigkeit warf Fehler: {errors!r}"
        assert total == writers * per

    def test_purge_deletes_genuine_sqlcipher_db(self, app_context, tmp_path):
        """Wipe entfernt eine ECHTE SQLCipher-Alt-DB (inkl. WAL/SHM) und laesst
        die konsolidierte norisk-DB intakt + weiter benutzbar.

        Haertet ``test_purge_keeps_consolidated_and_separate`` (Fake-Bytes): der
        Full-Wipe ist dateibasiert, aber der Survivor darf dabei nicht
        beschaedigt werden. ``db_path`` legt die Alt-DB als eigene Datei an
        (umgeht den Remap), sodass eine genuine Per-Tool-Datei entsteht.
        """
        from core.database.encrypted_db import (
            EncryptedDatabase,
            purge_consolidated_legacy_dbs,
        )

        appdir = tmp_path / "norisk"

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            with EncryptedDatabase("norisk").connection() as conn:
                conn.execute("CREATE TABLE keep (id INTEGER)")
                conn.execute("INSERT INTO keep VALUES (1)")

            legacy_path = appdir / "system_scanner.db"
            legacy = EncryptedDatabase("system_scanner", db_path=legacy_path)
            with legacy.connection() as conn:
                conn.execute("CREATE TABLE old (id INTEGER)")
                conn.execute("INSERT INTO old VALUES (1)")
            assert legacy_path.exists()

            removed = purge_consolidated_legacy_dbs()

            with EncryptedDatabase("norisk").connection() as conn:
                kept = conn.execute("SELECT count(*) FROM keep").fetchone()[0]

        assert removed == 1
        assert not legacy_path.exists()
        assert not legacy_path.with_name("system_scanner.db-wal").exists()
        assert not legacy_path.with_name("system_scanner.db-shm").exists()
        assert (appdir / "norisk.db").exists()
        assert kept == 1

    def test_purge_removes_pii_backup_artifacts(self, app_context, tmp_path):
        """Wipe entfernt PII-Backup-Artefakte (*.bak/*.plaintext_backup), die
        nicht auf.db enden und den *.db-Wipe sonst ueberleben — und
        laesst verwaltete Backup-Verzeichnisse (eigene Retention) unangetastet.
        """
        from core.database.encrypted_db import purge_consolidated_legacy_dbs

        appdir = tmp_path / "norisk"
        appdir.mkdir()
        (appdir / "norisk.db").write_bytes(b"x")
        (appdir / "network_monitor.db").write_bytes(b"x")
        # PII-Backup-Artefakte (muessen weg)
        pii_artifacts = (
            appdir / "customer_assessment.db.migrated_to_audit.bak",
            appdir / "norisk.db.nis2_tamper_v1.bak",
            appdir / "customer_assessment.db.plaintext_backup",
        )
        for art in pii_artifacts:
            art.write_bytes(b"pii")
        # Verwaltetes pre_migration_backup-Verzeichnis (muss bleiben) — auch ein
        #.bak-FILE darin darf der non-rekursive Wipe NICHT anfassen.
        managed = appdir / ".migration-backup-2026-06-28"
        managed.mkdir()
        (managed / "inner.db.bak").write_bytes(b"recovery")

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            purge_consolidated_legacy_dbs()

        assert (appdir / "norisk.db").exists()
        assert (appdir / "network_monitor.db").exists()
        for art in pii_artifacts:
            assert not art.exists(), f"{art.name} haette geloescht werden muessen"
        assert managed.is_dir()
        assert (managed / "inner.db.bak").exists()  # non-rekursiv geschont
