"""tests/database/test_migrate_to_envelope.py — Pre-Migration-Backup Tests (Subtask 3 §3.2).

Test-IDs B-1 bis B-4 aus MIGRATION_TEST_PLAN §3.5 plus Edge-Cases:
``compute_backup_dir_path``-Verhalten (Erst-Lauf vs. Mehrfach-Lauf am
selben Tag), Sub-Verzeichnis-Filterung, Fehler-Pfade.

Spaetere Schritte (3.3/3.4) erweitern diese Datei um Migrations-
Algorithmus- und SecureStorage-Migrations-Tests.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
import sqlcipher3

from core.database import migrate_to_envelope as mte
from core.database.key_manager import KeyManager, MigrationStatus
from core.database.key_manager_platform import InMemoryDPAPIBackend
from core.database.migrate_to_envelope import SecureStoreMigrationStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_dir(tmp_path):
    """Erzeugt ein App-DB-Verzeichnis mit drei DB-Dateien verschiedener Groesse."""
    d = tmp_path / "db" / "norisk"
    d.mkdir(parents=True)
    (d / "cyber_dashboard.db").write_bytes(b"\x00" * 1024)
    (d / "network_monitor.db").write_bytes(b"\x01" * 2048)
    (d / "cert_monitor.db").write_bytes(b"\x02" * 512)
    return d


@pytest.fixture
def secure_store(tmp_path):
    """Erzeugt eine secure_store.enc-Datei."""
    f = tmp_path / "secure_store.enc"
    f.write_bytes(b"\x99" * 256)
    return f


# ---------------------------------------------------------------------------
# compute_backup_dir_path
# ---------------------------------------------------------------------------


class TestComputeBackupDirPath:
    def test_first_run_uses_date_only(self, db_dir):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        path = mte.compute_backup_dir_path(db_dir, now=anchor)
        assert path.name == ".pre-envelope-backup-2026-05-06"
        assert path.parent == db_dir

    def test_second_run_same_day_eskaliert_zu_hhmmss(self, db_dir):
        # Tagesverzeichnis existiert bereits → Fallback auf HHMMSS-Suffix.
        (db_dir / ".pre-envelope-backup-2026-05-06").mkdir()
        anchor = datetime(2026, 5, 6, 14, 30, 45, tzinfo=UTC)
        path = mte.compute_backup_dir_path(db_dir, now=anchor)
        assert path.name == ".pre-envelope-backup-2026-05-06-143045"

    def test_default_now_yields_a_date_path(self, db_dir):
        # Smoke-Test: ohne now-Argument crasht es nicht und liefert
        # einen Pfad mit Backup-Praefix.
        path = mte.compute_backup_dir_path(db_dir)
        assert path.name.startswith(".pre-envelope-backup-")
        assert path.parent == db_dir


# ---------------------------------------------------------------------------
# B-1: Backup-Verzeichnis wird vor erster DB-Manipulation angelegt
# ---------------------------------------------------------------------------


class TestB1BackupDirCreated:
    def test_B1_backup_dir_created_with_all_dbs(self, db_dir):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)

        assert result.backup_dir.is_dir()
        assert result.backup_dir.name == ".pre-envelope-backup-2026-05-06"
        assert (result.backup_dir / "cyber_dashboard.db").is_file()
        assert (result.backup_dir / "network_monitor.db").is_file()
        assert (result.backup_dir / "cert_monitor.db").is_file()
        assert result.db_count == 3

    def test_B1_originals_unchanged_after_backup(self, db_dir):
        original = {
            p.name: p.stat().st_size for p in db_dir.glob("*.db")
        }
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.pre_migration_backup(db_dir, now=anchor)
        # Drei DB-Files sind unveraendert; das Backup-Verzeichnis ist
        # ein Geschwister-Eintrag, nicht in *.db enthalten.
        new = {
            p.name: p.stat().st_size
            for p in db_dir.glob("*.db")
            if p.is_file()
        }
        assert new == original

    def test_B1_subdirectories_not_copied(self, db_dir):
        #.archive- und.unrecoverable-Sub-Verzeichnisse mit Inhalt —
        # duerfen NICHT ins Backup wandern (Filter ist *.db, kein recurse).
        archive = db_dir / ".archive"
        archive.mkdir()
        (archive / "old.db").write_bytes(b"\x77" * 100)
        (db_dir / ".unrecoverable").mkdir()

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)

        assert result.db_count == 3
        assert not (result.backup_dir / ".archive").exists()
        assert not (result.backup_dir / ".unrecoverable").exists()

    def test_B1_other_backup_dirs_not_recursively_copied(self, db_dir):
        # Verbliebenes Backup-Verzeichnis vom Vortag — soll nicht ins
        # neue Backup wandern (sonst rekursiver Backup-Zyklus).
        prev = db_dir / ".pre-envelope-backup-2026-05-05"
        prev.mkdir()
        (prev / "stale.db").write_bytes(b"\x66" * 50)

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)

        assert result.db_count == 3
        assert not (
            result.backup_dir / ".pre-envelope-backup-2026-05-05"
        ).exists()


# ---------------------------------------------------------------------------
# B-2: Backup-Datei-Groessen identisch zu Original
# ---------------------------------------------------------------------------


class TestB2SizeMatch:
    def test_B2_sizes_match_originals(self, db_dir):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)
        for src in db_dir.glob("*.db"):
            if not src.is_file():
                continue
            dst = result.backup_dir / src.name
            assert dst.stat().st_size == src.stat().st_size

    def test_B2_total_bytes_matches_sum_of_db_sizes(self, db_dir):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)
        expected = sum(
            p.stat().st_size for p in db_dir.glob("*.db") if p.is_file()
        )
        # secure_store war None; alle Bytes stammen aus DB-Files.
        assert result.total_bytes == expected

    def test_B2_size_mismatch_raises_runtimeerror(self, db_dir):
        # shutil.copy2 mocken: schreibt nur 1 Byte ins Ziel — Verify-
        # Schritt muss FileSystemError werfen Phase 2: ehemals
        # nackter RuntimeError, jetzt domain-spezifisch).
        def truncated_copy(src, dst):
            Path(dst).write_bytes(b"x")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        with (
            patch.object(mte.shutil, "copy2", side_effect=truncated_copy),
            pytest.raises(OSError, match="Groessen-Mismatch"),
        ):
            mte.pre_migration_backup(db_dir, now=anchor)


# ---------------------------------------------------------------------------
# B-3: Bei Backup-Fail: Migration startet nicht (Originale unangetastet)
# ---------------------------------------------------------------------------


class TestB3CopyFailure:
    def test_B3_copy_fail_propagates_oserror(self, db_dir):
        def boom(src, dst):
            raise OSError("simulated copy failure")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        with (
            patch.object(mte.shutil, "copy2", side_effect=boom),
            pytest.raises(OSError, match="simulated copy failure"),
        ):
            mte.pre_migration_backup(db_dir, now=anchor)

    def test_B3_copy_fail_originals_unchanged(self, db_dir):
        original = {
            p.name: p.stat().st_size for p in db_dir.glob("*.db")
        }

        def boom(src, dst):
            raise OSError("simulated copy failure")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        with (
            patch.object(mte.shutil, "copy2", side_effect=boom),
            pytest.raises(OSError),
        ):
            mte.pre_migration_backup(db_dir, now=anchor)

        new = {
            p.name: p.stat().st_size
            for p in db_dir.glob("*.db")
            if p.is_file()
        }
        assert new == original


# ---------------------------------------------------------------------------
# B-4: secure_store.enc.pre-envelope-{date} wird angelegt
# ---------------------------------------------------------------------------


class TestB4SecureStoreBackup:
    def test_B4_secure_store_backup_created(self, db_dir, secure_store):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(
            db_dir, secure_store_path=secure_store, now=anchor
        )
        expected = secure_store.with_name(
            "secure_store.enc.pre-envelope-backup-2026-05-06"
        )
        assert expected.is_file()
        assert result.secure_store_backup == expected
        assert expected.stat().st_size == secure_store.stat().st_size

    def test_B4_secure_store_missing_yields_none(self, db_dir, tmp_path):
        ghost = tmp_path / "no_such_secure_store.enc"
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(
            db_dir, secure_store_path=ghost, now=anchor
        )
        assert result.secure_store_backup is None

    def test_B4_secure_store_backup_uses_same_suffix_as_db_dir(
        self, db_dir, secure_store
    ):
        # Tagesverzeichnis existiert → HHMMSS-Suffix → secure_store
        # bekommt denselben Suffix.
        (db_dir / ".pre-envelope-backup-2026-05-06").mkdir()
        anchor = datetime(2026, 5, 6, 14, 30, 45, tzinfo=UTC)
        result = mte.pre_migration_backup(
            db_dir, secure_store_path=secure_store, now=anchor
        )
        assert (
            result.backup_dir.name
            == ".pre-envelope-backup-2026-05-06-143045"
        )
        assert result.secure_store_backup is not None
        assert result.secure_store_backup.name == (
            "secure_store.enc.pre-envelope-backup-2026-05-06-143045"
        )

    def test_B4_no_secure_store_arg_means_none(self, db_dir):
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(db_dir, now=anchor)
        assert result.secure_store_backup is None


# ---------------------------------------------------------------------------
# Edge-Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_db_dir_returns_zero_count_but_creates_backup_dir(
        self, tmp_path
    ):
        empty = tmp_path / "empty"
        empty.mkdir()
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        result = mte.pre_migration_backup(empty, now=anchor)
        assert result.db_count == 0
        assert result.total_bytes == 0
        # Auch bei leerem Quell-Dir wird das Backup-Verzeichnis angelegt
        # — Konvention "Backup-Lauf hat stattgefunden".
        assert result.backup_dir.is_dir()

    def test_nonexistent_db_dir_raises_oserror(self, tmp_path):
        ghost = tmp_path / "no_such_dir"
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        with pytest.raises(OSError, match="db_dir existiert nicht"):
            mte.pre_migration_backup(ghost, now=anchor)

    def test_db_dir_is_a_file_raises_oserror(self, tmp_path):
        f = tmp_path / "not_a_dir"
        f.write_bytes(b"x")
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        with pytest.raises(OSError, match="db_dir existiert nicht"):
            mte.pre_migration_backup(f, now=anchor)


# ===========================================================================
# Schritt 3.3 — Migrations-Algorithmus pro DB
# ===========================================================================


@pytest.fixture
def isolated_key_manager(tmp_path, monkeypatch):
    """Frischer KeyManager mit InMemory-Backend in tmp_path-Scope.

    Unabhaengig von der globalen ``_ensure_global_key_manager``-Fixture —
    Migrations-Tests wollen einen neuen, deterministischen DEK pro Test,
    damit ``derive_secondary_key("db:foo")`` reproduzierbar ist.
    """
    from core.database import key_manager as km_mod

    monkeypatch.setattr(
        km_mod, "_MASTER_KEY_FILE", tmp_path / "isolated.master.wrapped"
    )
    km = KeyManager(backend=InMemoryDPAPIBackend())
    km.initialize()
    return km


# ---------------------------------------------------------------------------
# KeyManager.migrate_legacy_db — Per-DB-Worker
# ---------------------------------------------------------------------------


class TestMigrateLegacyDb:
    def test_already_migrated_returns_already(
        self, isolated_key_manager, tmp_path
    ):
        # DB direkt mit DEK-Schluessel verschluesseln.
        from core.database.encrypted_db import _configure_connection

        db_path = tmp_path / "already.db"
        new_key = isolated_key_manager.derive_secondary_key(
            "db:already"
        ).hex()
        conn = sqlcipher3.connect(str(db_path))
        try:
            _configure_connection(conn, new_key)
            conn.execute("CREATE TABLE t (x INTEGER)")
            conn.commit()
        finally:
            conn.close()

        status = isolated_key_manager.migrate_legacy_db(
            db_path, lambda: "deadbeef" * 8
        )
        assert status == MigrationStatus.ALREADY_MIGRATED

    def test_M1_legacy_v2_migrated(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v2_factory,
    ):
        # DB mit synthetischem v2-Schluessel anlegen.
        db_path = make_legacy_db(
            "network_monitor", synthetic_legacy_v2_factory
        )
        # Migration durchfuehren.
        status = isolated_key_manager.migrate_legacy_db(
            db_path,
            lambda: synthetic_legacy_v2_factory("network_monitor"),
        )
        assert status == MigrationStatus.MIGRATED
        # Nach Migration: DB mit DEK-Schluessel lesbar.
        new_key = isolated_key_manager.derive_secondary_key(
            "db:network_monitor"
        ).hex()
        assert mte._can_open_with_key(db_path, new_key)

    def test_M2_legacy_v1_migrated(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v1_factory,
    ):
        # Symmetrischer Test mit v1-Synthese — gleicher Pfad,
        # anderer Fingerprint-Identifier.
        db_path = make_legacy_db(
            "cyber_dashboard", synthetic_legacy_v1_factory
        )
        status = isolated_key_manager.migrate_legacy_db(
            db_path,
            lambda: synthetic_legacy_v1_factory("cyber_dashboard"),
        )
        assert status == MigrationStatus.MIGRATED

    def test_failed_when_old_key_func_raises(
        self, isolated_key_manager, make_legacy_db, synthetic_legacy_v2_factory
    ):
        db_path = make_legacy_db("foo", synthetic_legacy_v2_factory)

        def boom():
            raise RuntimeError("legacy key not derivable")

        status = isolated_key_manager.migrate_legacy_db(db_path, boom)
        assert status == MigrationStatus.FAILED

    def test_failed_when_neither_key_works(
        self, isolated_key_manager, make_legacy_db, synthetic_legacy_v2_factory
    ):
        db_path = make_legacy_db("foo", synthetic_legacy_v2_factory)
        # Wrong-key-func liefert deterministisch falschen Key.
        status = isolated_key_manager.migrate_legacy_db(
            db_path, lambda: "00" * 32
        )
        assert status == MigrationStatus.FAILED

    def test_data_preserved_after_migration(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v2_factory,
    ):
        db_path = make_legacy_db(
            "preserved", synthetic_legacy_v2_factory
        )
        isolated_key_manager.migrate_legacy_db(
            db_path,
            lambda: synthetic_legacy_v2_factory("preserved"),
        )
        # Daten sind nach Migration unter NEW-Key noch da.
        from core.database.encrypted_db import _configure_connection

        new_key = isolated_key_manager.derive_secondary_key(
            "db:preserved"
        ).hex()
        conn = sqlcipher3.connect(str(db_path))
        try:
            # Die Legacy→DEK-Migration erzeugt eine DEK-String-Key-DB
            # (PRAGMA rekey ohne x'...') Raw-Key ist erst der spaetere
            # Discard-/Neuanlage-Schritt. Daher hier String-Key lesen.
            _configure_connection(conn, new_key, raw_key=False)
            rows = conn.execute(
                "SELECT value FROM sample ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        assert [r[0] for r in rows] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# handle_unrecoverable
# ---------------------------------------------------------------------------


class TestHandleUnrecoverable:
    def test_M3_corrupt_moved_to_unrecoverable_with_context(
        self, make_corrupt_db, tmp_path
    ):
        # db_dir muss das Parent vom DB-Path sein, damit
        #.unrecoverable/ als Sibling erzeugt wird.
        db_path = make_corrupt_db("network_scanner")
        db_dir = db_path.parent
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)

        target = mte.handle_unrecoverable(
            db_path,
            db_dir,
            tried_algorithms=["dek_new", "v2_legacy"],
            last_error_class="DatabaseEncryptionError",
            last_error_message="file is encrypted or is not a database",
            backend_type="in_memory",
            now=anchor,
        )
        assert target.is_file()
        assert target.parent.name == ".unrecoverable"
        assert not db_path.exists()

        context_path = target.with_suffix(".context.json")
        assert context_path.is_file()
        ctx = json.loads(context_path.read_text(encoding="utf-8"))
        assert ctx["schema_version"] == 1
        assert ctx["db_name"] == "network_scanner"
        assert ctx["tried_algorithms"] == ["dek_new", "v2_legacy"]
        assert ctx["last_error_class"] == "DatabaseEncryptionError"
        assert "last_error_hash_sha256" in ctx
        # Hash hat 64 Hex-Zeichen.
        assert len(ctx["last_error_hash_sha256"]) == 64
        # Kein Crypto-Material exponiert §3.3 — verbotene
        # Top-Level- und nested-Field-Namen).
        forbidden = {"key_material", "dek", "hw_components", "secret"}
        assert forbidden.isdisjoint(ctx.keys())
        assert forbidden.isdisjoint(ctx["key_manager_metadata"].keys())
        assert ctx["key_manager_metadata"]["backend_type"] == "in_memory"

    def test_unrecoverable_target_collision_eskaliert_zu_suffix(
        self, make_corrupt_db
    ):
        db_path = make_corrupt_db("collision")
        db_dir = db_path.parent
        # Ein Kollisions-Ziel vorhanden machen.
        unrec = db_dir / ".unrecoverable"
        unrec.mkdir()
        (unrec / "collision.db").write_bytes(b"already-here")

        anchor = datetime(2026, 5, 6, 14, 30, 45, tzinfo=UTC)
        target = mte.handle_unrecoverable(
            db_path,
            db_dir,
            tried_algorithms=["dek_new"],
            last_error_class="X",
            last_error_message="msg",
            now=anchor,
        )
        assert target.name == "collision-20260506-143045.db"
        # Erste Datei unangetastet.
        assert (unrec / "collision.db").read_bytes() == b"already-here"


# ---------------------------------------------------------------------------
# migrate_all_databases — Orchestrator (M-4 + I-1..I-3)
# ---------------------------------------------------------------------------


class TestMigrateAllDatabases:
    def test_M4_multi_db_mixed(
        self,
        isolated_key_manager,
        make_legacy_db,
        make_corrupt_db,
        synthetic_legacy_v1_factory,
        synthetic_legacy_v2_factory,
        tmp_path,
    ):
        # Layout: ein db_dir, das v1-, v2- und corrupt-DBs enthaelt.
        db_dir = tmp_path / "db" / "norisk"
        db_dir.mkdir(parents=True)

        # v1-DBs
        for name in ("v1_a", "v1_b"):
            src = make_legacy_db(name, synthetic_legacy_v1_factory)
            shutil.move(str(src), str(db_dir / src.name))
        # v2-DB
        src = make_legacy_db("v2_a", synthetic_legacy_v2_factory)
        shutil.move(str(src), str(db_dir / src.name))
        # corrupt-DBs
        for name in ("corrupt_a", "corrupt_b"):
            src = make_corrupt_db(name)
            shutil.move(str(src), str(db_dir / src.name))

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        report = mte.migrate_all_databases(
            db_dir,
            isolated_key_manager,
            legacy_key_factories={
                "v2_legacy": synthetic_legacy_v2_factory,
                "v1_legacy": synthetic_legacy_v1_factory,
            },
            now=anchor,
        )

        assert sorted(report.migrated) == ["v1_a", "v1_b", "v2_a"]
        assert sorted(report.unrecoverable) == ["corrupt_a", "corrupt_b"]
        # Im State sind die korrupten als failed_v1_v2 markiert.
        assert (
            report.state["dbs"]["corrupt_a"]["status"] == "failed_v1_v2"
        )
        # Reihenfolge der Algos im old_key_algo: v2_legacy zuerst, also
        # eine v1-DB hat als old_key_algo "v1_legacy" (zweiter Versuch).
        assert (
            report.state["dbs"]["v1_a"]["old_key_algo"] == "v1_legacy"
        )
        assert (
            report.state["dbs"]["v2_a"]["old_key_algo"] == "v2_legacy"
        )
        # Korrupte sind in.unrecoverable/.
        unrec = db_dir / ".unrecoverable"
        assert (unrec / "corrupt_a.db").is_file()
        assert (unrec / "corrupt_a.context.json").is_file()
        assert (unrec / "corrupt_b.db").is_file()

    def test_I1_idempotent_second_run_is_noop(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        tmp_path,
    ):
        db_dir = tmp_path / "db" / "norisk"
        db_dir.mkdir(parents=True)
        src = make_legacy_db("foo", synthetic_legacy_v2_factory)
        shutil.move(str(src), str(db_dir / "foo.db"))

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        first = mte.migrate_all_databases(
            db_dir,
            isolated_key_manager,
            legacy_key_factories={"v2_legacy": synthetic_legacy_v2_factory},
            now=anchor,
        )
        assert first.migrated == ["foo"]

        # Zweiter Lauf ohne State: ALREADY_MIGRATED-Pfad — DB ist mit
        # DEK verschluesselt.
        second = mte.migrate_all_databases(
            db_dir,
            isolated_key_manager,
            legacy_key_factories={"v2_legacy": synthetic_legacy_v2_factory},
            now=datetime(2026, 5, 6, 12, 5, 0, tzinfo=UTC),
        )
        assert second.already_migrated == ["foo"]
        assert second.migrated == []
        # State zeigt old_key_algo=None (already-Pfad).
        assert second.state["dbs"]["foo"]["old_key_algo"] is None

    def test_I2_resume_skips_already_migrated_in_state(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        tmp_path,
    ):
        db_dir = tmp_path / "db" / "norisk"
        db_dir.mkdir(parents=True)
        src1 = make_legacy_db("done", synthetic_legacy_v2_factory)
        src2 = make_legacy_db("pending", synthetic_legacy_v2_factory)
        shutil.move(str(src1), str(db_dir / "done.db"))
        shutil.move(str(src2), str(db_dir / "pending.db"))

        # State, der "done" schon als migrated markiert (auch wenn die
        # DB selber noch im legacy-Format auf Disk ist — Resume soll
        # blind den State respektieren).
        prior_state = {
            "schema_version": 1,
            "started_at": "2026-05-06T11:00:00+00:00",
            "completed_at": None,
            "backup_path": None,
            "dbs": {
                "done": {
                    "status": "migrated",
                    "old_key_algo": "v2_legacy",
                    "migrated_at": "2026-05-06T11:01:00+00:00",
                    "error": None,
                },
            },
            "secure_store": {"status": "pending"},
        }

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        report = mte.migrate_all_databases(
            db_dir,
            isolated_key_manager,
            legacy_key_factories={"v2_legacy": synthetic_legacy_v2_factory},
            state=prior_state,
            now=anchor,
        )
        # "done" wurde als already_migrated behandelt (Resume),
        # "pending" frisch migriert.
        assert report.already_migrated == ["done"]
        assert report.migrated == ["pending"]

    def test_I3_stale_state_resumes_after_warning(
        self,
        isolated_key_manager,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        tmp_path,
        caplog,
    ):
        # Stale-Detection ist eine Funktion in migration_state.py.
        # Hier: Verifizieren, dass ein State mit started_at > 24h
        # weiter funktioniert (kein Reset).
        from core.database import migration_state as ms

        old = (
            datetime.now(tz=UTC) - timedelta(hours=25)
        ).isoformat()
        state = {
            "schema_version": 1,
            "started_at": old,
            "completed_at": None,
            "backup_path": None,
            "dbs": {},
            "secure_store": {"status": "pending"},
        }
        assert ms.is_state_stale(state) is True

        db_dir = tmp_path / "db" / "norisk"
        db_dir.mkdir(parents=True)
        src = make_legacy_db("foo", synthetic_legacy_v2_factory)
        shutil.move(str(src), str(db_dir / "foo.db"))

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        report = mte.migrate_all_databases(
            db_dir,
            isolated_key_manager,
            legacy_key_factories={"v2_legacy": synthetic_legacy_v2_factory},
            state=state,
            now=anchor,
        )
        # Migration laeuft trotzdem durch.
        assert report.migrated == ["foo"]


# ===========================================================================
# Schritt 3.4 — SecureStorage-Migration (SM-1..SM-4)
# ===========================================================================


@pytest.fixture
def patch_legacy_salt(monkeypatch):
    """Patcht den Legacy-Salt von _get_or_create_salt auf statisch \\x42*32."""
    monkeypatch.setattr(
        "core.security.encryption._get_or_create_salt",
        lambda: b"\x42" * 32,
    )


@pytest.fixture
def make_legacy_secure_store(tmp_path, patch_legacy_salt):  # noqa: ARG001
    """Factory: erzeugt eine secure_store.enc mit Legacy-Pfad-Verschluesselung.

    Nutzt:func:`core.security.encryption._derive_key` mit synthetischem
    Password — realistisch, weil die Production-Migration genau diesen
    Code-Pfad zur Entschluesselung nutzt.
    """

    def _make(payload: dict[str, str], password: str = "test-fp") -> Path:
        from cryptography.fernet import Fernet

        from core.database.migrate_to_envelope import (
            _derive_legacy_fernet_key,
        )

        legacy_key = _derive_legacy_fernet_key(password)
        encrypted = Fernet(legacy_key).encrypt(
            json.dumps(payload).encode("utf-8")
        )
        path = tmp_path / "secure_store.enc"
        path.write_bytes(encrypted)
        return path

    return _make


class TestMigrateSecureStore:
    def test_absent_returns_absent(
        self, isolated_key_manager, tmp_path
    ):
        ghost = tmp_path / "no_such_secure_store.enc"
        status = mte.migrate_secure_store(ghost, isolated_key_manager)
        assert status == SecureStoreMigrationStatus.ABSENT

    def test_SM1_legacy_data_preserved_after_migration(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        # Alte Datei mit synthetischem Password verschluesseln.
        path = make_legacy_secure_store(
            {"deepl_api_key": "sk-deepl", "openai_api_key": "sk-openai"},
            password="test-fp",
        )
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        status = mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=anchor,
        )
        assert status == SecureStoreMigrationStatus.MIGRATED

    def test_SM2_new_file_readable_with_dek_fernet_key(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        path = make_legacy_secure_store(
            {"deepl_api_key": "sk-deepl"}, password="test-fp"
        )
        mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC),
        )
        # Mit DEK-Fernet-Key lesbar?
        import base64

        from cryptography.fernet import Fernet

        new_key = base64.urlsafe_b64encode(
            isolated_key_manager.derive_secondary_key("secure_storage")
        )
        decrypted = Fernet(new_key).decrypt(path.read_bytes())
        assert json.loads(decrypted.decode("utf-8")) == {
            "deepl_api_key": "sk-deepl"
        }

    def test_SM3_backup_file_created(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        path = make_legacy_secure_store(
            {"foo": "bar"}, password="test-fp"
        )
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=anchor,
        )
        expected_backup = path.with_name(
            "secure_store.enc.pre-envelope-backup-2026-05-06"
        )
        assert expected_backup.is_file()

    def test_SM4_legacy_unreadable_yields_empty_store(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        # Datei mit Legacy verschluesseln, aber Migration mit FALSCHEM
        # Password aufrufen → Legacy-Decryption fail → leerer neuer Store.
        path = make_legacy_secure_store(
            {"foo": "bar"}, password="real-fp"
        )
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        status = mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "wrong-fp",
            now=anchor,
        )
        assert status == SecureStoreMigrationStatus.MIGRATED_EMPTY
        # Backup haelt das Original.
        backup = path.with_name(
            "secure_store.enc.pre-envelope-backup-2026-05-06"
        )
        assert backup.is_file()
        # Neue Datei ist mit DEK lesbar und enthaelt {}.
        import base64

        from cryptography.fernet import Fernet

        new_key = base64.urlsafe_b64encode(
            isolated_key_manager.derive_secondary_key("secure_storage")
        )
        decrypted = Fernet(new_key).decrypt(path.read_bytes())
        assert json.loads(decrypted.decode("utf-8")) == {}

    def test_already_migrated_idempotent(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        path = make_legacy_secure_store({"foo": "bar"}, password="test-fp")
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        # Erster Lauf: MIGRATED.
        status_first = mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=anchor,
        )
        assert status_first == SecureStoreMigrationStatus.MIGRATED
        # Zweiter Lauf: ALREADY_MIGRATED.
        status_second = mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=datetime(2026, 5, 6, 12, 5, 0, tzinfo=UTC),
        )
        assert (
            status_second == SecureStoreMigrationStatus.ALREADY_MIGRATED
        )

    def test_existing_backup_not_overwritten(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        # Wenn Backup-Pfad bereits existiert (z. B. von Schritt 3.2-
        # pre_migration_backup), wird er NICHT ueberschrieben.
        path = make_legacy_secure_store({"foo": "bar"}, password="test-fp")
        existing_backup = path.with_name(
            "secure_store.enc.pre-envelope-backup-2026-05-06"
        )
        existing_backup.write_bytes(b"OLDER-BACKUP-FROM-3.2")
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=lambda: "test-fp",
            now=anchor,
        )
        # Backup-Inhalt ist unveraendert (3.2 hatte vorher schon Recovery
        # gesichert).
        assert existing_backup.read_bytes() == b"OLDER-BACKUP-FROM-3.2"

    def test_legacy_password_func_raises_yields_empty_store(
        self, isolated_key_manager, make_legacy_secure_store
    ):
        path = make_legacy_secure_store({"foo": "bar"}, password="test-fp")

        def boom():
            raise RuntimeError("legacy password not derivable")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        status = mte.migrate_secure_store(
            path,
            isolated_key_manager,
            legacy_password_func=boom,
            now=anchor,
        )
        # Legacy-Read fail → leerer neuer Store, Backup vorhanden.
        assert status == SecureStoreMigrationStatus.MIGRATED_EMPTY


# ===========================================================================
# Schritt 3.5 — Bootstrap-Trigger (run_bootstrap_migration)
# ===========================================================================


@pytest.fixture
def bootstrap_env(tmp_path, monkeypatch, patch_legacy_salt):  # noqa: ARG001
    """Komplette Test-Isolation fuer Bootstrap-Migrations-Tests."""
    finlai_dir = tmp_path / "finlai"
    finlai_dir.mkdir()
    db_root = finlai_dir / "db"
    db_root.mkdir()

    from core.database import migration_state

    monkeypatch.setattr(
        migration_state,
        "_MIGRATION_STATE_FILE",
        finlai_dir / "migration-state.json",
    )

    return {
        "finlai_dir": finlai_dir,
        "db_root": db_root,
        "state_path": finlai_dir / "migration-state-norisk.json",
    }


class TestBootstrapMigration:
    def test_fresh_install_no_dbs_marks_completed(
        self, isolated_key_manager, bootstrap_env
    ):
        """Frische Installation: kein <db_root>/<app_id>/, kein Backup,
        State wird mit ``completed_at`` gesetzt."""
        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.run_bootstrap_migration(
            isolated_key_manager,
            "norisk",
            db_root=bootstrap_env["db_root"],
            secure_store_path=bootstrap_env["finlai_dir"]
            / "secure_store.enc",
            finlai_dir=bootstrap_env["finlai_dir"],
            now=anchor,
        )
        # State ist gesetzt + completed_at gefuellt.
        from core.database import migration_state

        state = migration_state.get_state("norisk")
        assert state is not None
        assert state["completed_at"] is not None
        assert state["dbs"] == {}
        assert state["secure_store"]["status"] == "absent"

    def test_first_run_with_legacy_dbs_migrates(
        self,
        isolated_key_manager,
        bootstrap_env,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        monkeypatch,
    ):
        """Erst-Migration mit bestehenden Legacy-DBs: Backup +
        DB-Migration + State persistiert + Migration-Log angelegt."""
        # Default Legacy-Factory: hier setzen wir _legacy_db_key auf
        # den synthetischen Pfad, weil run_bootstrap_migration intern
        # migrate_all_databases mit Default-Factories aufruft.
        monkeypatch.setattr(
            mte, "legacy_db_key", synthetic_legacy_v2_factory
        )

        # DBs anlegen
        app_dir = bootstrap_env["db_root"] / "norisk"
        app_dir.mkdir()
        for name in ("alpha", "beta"):
            src = make_legacy_db(name, synthetic_legacy_v2_factory)
            shutil.move(str(src), str(app_dir / src.name))

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.run_bootstrap_migration(
            isolated_key_manager,
            "norisk",
            db_root=bootstrap_env["db_root"],
            secure_store_path=bootstrap_env["finlai_dir"]
            / "secure_store.enc",
            finlai_dir=bootstrap_env["finlai_dir"],
            now=anchor,
        )

        # Backup-Verzeichnis liegt im app_dir.
        backup_dir = app_dir / ".pre-envelope-backup-2026-05-06"
        assert backup_dir.is_dir()
        assert (backup_dir / "alpha.db").is_file()
        assert (backup_dir / "beta.db").is_file()

        # State ist persistiert + completed_at gesetzt.
        from core.database import migration_state

        state = migration_state.get_state("norisk")
        assert state is not None
        assert state["completed_at"] is not None
        assert state["dbs"]["alpha"]["status"] == "migrated"
        assert state["dbs"]["beta"]["status"] == "migrated"

        # Migration-Log angelegt.
        mig_log = (
            bootstrap_env["finlai_dir"] / "migration-2026-05-06.log"
        )
        assert mig_log.is_file()
        log_content = mig_log.read_text(encoding="utf-8")
        assert "Pre-Migration-Backup" in log_content
        assert "Migration abgeschlossen" in log_content

    def test_already_completed_state_is_noop(
        self,
        isolated_key_manager,
        bootstrap_env,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        monkeypatch,
    ):
        """State.completed_at gesetzt → run_bootstrap_migration is no-op,
        macht KEIN neues Backup, fasst keine DB an."""
        monkeypatch.setattr(
            mte, "legacy_db_key", synthetic_legacy_v2_factory
        )

        # DB anlegen, aber State sagt "schon migriert".
        app_dir = bootstrap_env["db_root"] / "norisk"
        app_dir.mkdir()
        src = make_legacy_db("foo", synthetic_legacy_v2_factory)
        shutil.move(str(src), str(app_dir / src.name))

        from core.database import migration_state

        completed_state = {
            "schema_version": 1,
            "started_at": "2026-05-05T10:00:00+00:00",
            "completed_at": "2026-05-05T10:01:00+00:00",
            "backup_path": "/some/old/backup",
            "dbs": {
                "foo": {
                    "status": "migrated",
                    "old_key_algo": "v2_legacy",
                    "migrated_at": "2026-05-05T10:01:00+00:00",
                    "error": None,
                }
            },
            "secure_store": {"status": "absent"},
        }
        migration_state.set_state(completed_state, "norisk")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.run_bootstrap_migration(
            isolated_key_manager,
            "norisk",
            db_root=bootstrap_env["db_root"],
            secure_store_path=bootstrap_env["finlai_dir"]
            / "secure_store.enc",
            finlai_dir=bootstrap_env["finlai_dir"],
            now=anchor,
        )

        # Kein neues Backup-Verzeichnis fuer 2026-05-06.
        new_backup = app_dir / ".pre-envelope-backup-2026-05-06"
        assert not new_backup.exists()

        # State unveraendert.
        state_after = migration_state.get_state("norisk")
        assert state_after == completed_state

    def test_resume_from_partial_state_skips_migrated(
        self,
        isolated_key_manager,
        bootstrap_env,
        make_legacy_db,
        synthetic_legacy_v2_factory,
        monkeypatch,
    ):
        """Resume: State mit pending DBs → laeuft, fasst migrated nicht an."""
        monkeypatch.setattr(
            mte, "legacy_db_key", synthetic_legacy_v2_factory
        )

        app_dir = bootstrap_env["db_root"] / "norisk"
        app_dir.mkdir()
        # Zwei DBs: "done" + "todo". State markiert "done" als migrated.
        src1 = make_legacy_db("done", synthetic_legacy_v2_factory)
        src2 = make_legacy_db("todo", synthetic_legacy_v2_factory)
        shutil.move(str(src1), str(app_dir / "done.db"))
        shutil.move(str(src2), str(app_dir / "todo.db"))

        from core.database import migration_state

        partial_state = {
            "schema_version": 1,
            "started_at": "2026-05-06T11:00:00+00:00",
            "completed_at": None,
            "backup_path": str(
                app_dir / ".pre-envelope-backup-2026-05-06"
            ),
            "dbs": {
                "done": {
                    "status": "migrated",
                    "old_key_algo": "v2_legacy",
                    "migrated_at": "2026-05-06T11:01:00+00:00",
                    "error": None,
                }
            },
            "secure_store": {"status": "pending"},
        }
        migration_state.set_state(partial_state, "norisk")

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.run_bootstrap_migration(
            isolated_key_manager,
            "norisk",
            db_root=bootstrap_env["db_root"],
            secure_store_path=bootstrap_env["finlai_dir"]
            / "secure_store.enc",
            finlai_dir=bootstrap_env["finlai_dir"],
            now=anchor,
        )

        state_after = migration_state.get_state("norisk")
        # Beide jetzt migriert.
        assert state_after["dbs"]["done"]["status"] == "migrated"
        assert state_after["dbs"]["todo"]["status"] == "migrated"
        # done bleibt mit ursprünglichem migrated_at → wir wurden NICHT
        # erneut auf done getriggert.
        assert (
            state_after["dbs"]["done"]["migrated_at"]
            == "2026-05-06T11:01:00+00:00"
        )
        # todo wurde im aktuellen Lauf migriert.
        assert state_after["dbs"]["todo"]["migrated_at"] == anchor.isoformat()
        # completed_at ist jetzt gesetzt.
        assert state_after["completed_at"] == anchor.isoformat()

    def test_secure_store_path_migrated_when_present(
        self,
        isolated_key_manager,
        bootstrap_env,
        make_legacy_secure_store,
        monkeypatch,
    ):
        """SecureStore-Pfad existiert → Migration laeuft + Status wird
        in state.secure_store eingetragen."""
        # Default Legacy-Password fuer secure_store-Migration auf den
        # gleichen synthetischen Wert setzen, mit dem wir die Fixture
        # verschluesseln.
        monkeypatch.setattr(
            mte,
            "_legacy_secure_store_password",
            lambda: "test-fp",
        )

        # SecureStore an die erwartete Stelle verschieben.
        path = make_legacy_secure_store({"k": "v"}, password="test-fp")
        target = bootstrap_env["finlai_dir"] / "secure_store.enc"
        shutil.move(str(path), str(target))

        # App-Dir anlegen (auch leer), damit run_bootstrap_migration den
        # vollen Migrations-Pfad geht (sonst fresh-install-No-Op).
        app_dir = bootstrap_env["db_root"] / "norisk"
        app_dir.mkdir()

        anchor = datetime(2026, 5, 6, 12, 0, 0, tzinfo=UTC)
        mte.run_bootstrap_migration(
            isolated_key_manager,
            "norisk",
            db_root=bootstrap_env["db_root"],
            secure_store_path=target,
            finlai_dir=bootstrap_env["finlai_dir"],
            now=anchor,
        )

        from core.database import migration_state

        state = migration_state.get_state("norisk")
        assert state is not None
        assert state["secure_store"]["status"] == "migrated"
        # Backup angelegt.
        assert (
            bootstrap_env["finlai_dir"]
            / "secure_store.enc.pre-envelope-backup-2026-05-06"
        ).is_file()
