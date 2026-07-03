"""tests/database/test_migration_state.py — State-File Tests §3.6).

Test-IDs S-1, S-2, S-3 aus MIGRATION_TEST_PLAN §3.6 plus
Schema-Version-Roundtrip, Permissions-skipif-POSIX und I-3
Stale-Detection.

Die globale conftest-Fixture ``_ensure_global_key_manager`` ist autouse
und wirkt auch hier — fuer die migration_state-Tests irrelevant
(unabhaengiges Modul), aber verhindert Test-Pollution falls eine kuenftige
Erweiterung den KeyManager beruehrt.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from core.database import migration_state as ms


@pytest.fixture
def state_path(tmp_path, monkeypatch):
    """Isoliert ``_MIGRATION_STATE_FILE`` auf ``tmp_path/migration-state.json``."""
    p = tmp_path / "migration-state.json"
    monkeypatch.setattr(ms, "_MIGRATION_STATE_FILE", p)
    return p


# ---------------------------------------------------------------------------
# Roundtrip basics
# ---------------------------------------------------------------------------


class TestSetGetClearRoundtrip:
    def test_set_then_get_returns_same(self, state_path):
        state = {
            "schema_version": 1,
            "started_at": "2026-05-06T08:00:00+00:00",
            "completed_at": None,
            "backup_path": "/tmp/backup",
            "dbs": {"network_monitor": {"status": "pending"}},
        }
        ms.set_state(state)
        assert ms.get_state() == state

    def test_get_state_without_file_returns_none(self, state_path):
        assert not state_path.exists()
        assert ms.get_state() is None

    def test_clear_state_removes_file(self, state_path):
        ms.set_state({"schema_version": 1})
        assert state_path.exists()
        ms.clear_state()
        assert not state_path.exists()

    def test_clear_state_is_idempotent(self, state_path):
        ms.clear_state()
        ms.clear_state()
        assert not state_path.exists()


# ---------------------------------------------------------------------------
# S-3 Schema-Version + Robustness
# ---------------------------------------------------------------------------


class TestSchemaVersion:
    def test_S3_unexpected_schema_version_returns_none(
        self, state_path, caplog
    ):
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps({"schema_version": 99, "dbs": {}}),
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            assert ms.get_state() is None
        assert any(
            "schema_version" in record.getMessage()
            for record in caplog.records
        )

    def test_missing_schema_version_returns_none(self, state_path, caplog):
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps({"dbs": {}}),
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            assert ms.get_state() is None

    def test_set_state_persists_schema_version(self, state_path):
        ms.set_state({"schema_version": 1, "dbs": {}})
        on_disk = json.loads(state_path.read_text(encoding="utf-8"))
        assert on_disk["schema_version"] == 1

    def test_invalid_json_returns_none(self, state_path, caplog):
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text("{not-json}", encoding="utf-8")
        with caplog.at_level("WARNING"):
            assert ms.get_state() is None

    def test_top_level_list_returns_none(self, state_path, caplog):
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps([{"schema_version": 1}]),
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            assert ms.get_state() is None


# ---------------------------------------------------------------------------
# S-1 Atomic-Write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_S1_uses_tmp_then_replace(self, state_path):
        # Verifiziert die Atomar-Schreib-Sequenz: os.replace wird genau
        # einmal mit (.tmp, target) aufgerufen, vor dem Replace enthaelt
        # die.tmp-Datei bereits den finalen Inhalt.
        original_replace = os.replace
        replace_calls: list[tuple[Path, Path]] = []

        def spy_replace(src, dst):
            src_path = Path(src)
            replace_calls.append((src_path, Path(dst)))
            content = src_path.read_bytes()
            assert b'"schema_version"' in content
            original_replace(src, dst)

        with patch.object(os, "replace", side_effect=spy_replace):
            ms.set_state({"schema_version": 1, "dbs": {}})

        assert len(replace_calls) == 1
        src, dst = replace_calls[0]
        assert src.name.endswith(".tmp")
        assert dst == state_path

    def test_S1_failed_replace_cleans_tmp(self, state_path):
        # Crash zwischen.tmp-Schreibvorgang und os.replace simulieren:
        # State-File darf nicht halb-geschrieben sein,.tmp aufgeraeumt.
        def boom(src, dst):
            raise OSError("simulated replace failure")

        with (
            patch.object(os, "replace", side_effect=boom),
            pytest.raises(OSError, match="simulated replace failure"),
        ):
            ms.set_state({"schema_version": 1})

        tmp_path = state_path.with_name(state_path.name + ".tmp")
        assert not tmp_path.exists(), ".tmp wurde nicht aufgeraeumt"
        assert not state_path.exists(), "Final-File darf nicht existieren"

    def test_S1_overwrite_keeps_only_final_file(self, state_path):
        # Zweiter set_state-Aufruf ueberschreibt sauber,.tmp bleibt nicht.
        ms.set_state({"schema_version": 1, "dbs": {"a": {}}})
        ms.set_state({"schema_version": 1, "dbs": {"a": {}, "b": {}}})
        on_disk = json.loads(state_path.read_text(encoding="utf-8"))
        assert "b" in on_disk["dbs"]
        tmp_path = state_path.with_name(state_path.name + ".tmp")
        assert not tmp_path.exists()


# ---------------------------------------------------------------------------
# S-2 Permissions 0600 (POSIX)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only chmod")
class TestPermissionsPosix:
    def test_S2_state_file_is_0600(self, state_path):
        ms.set_state({"schema_version": 1})
        mode = state_path.stat().st_mode & 0o777
        assert mode == 0o600


# ---------------------------------------------------------------------------
# I-3 Stale-State-Detection
# ---------------------------------------------------------------------------


class TestStaleDetection:
    def test_fresh_state_is_not_stale(self):
        now = datetime.now(tz=UTC).isoformat()
        state = {
            "schema_version": 1,
            "started_at": now,
            "completed_at": None,
        }
        assert ms.is_state_stale(state) is False

    def test_state_older_than_24h_is_stale(self):
        old = (datetime.now(tz=UTC) - timedelta(hours=25)).isoformat()
        state = {
            "schema_version": 1,
            "started_at": old,
            "completed_at": None,
        }
        assert ms.is_state_stale(state) is True

    def test_completed_state_is_not_stale_even_if_old(self):
        old = (datetime.now(tz=UTC) - timedelta(hours=48)).isoformat()
        state = {
            "schema_version": 1,
            "started_at": old,
            "completed_at": datetime.now(tz=UTC).isoformat(),
        }
        assert ms.is_state_stale(state) is False

    def test_state_without_started_at_is_not_stale(self):
        state = {
            "schema_version": 1,
            "started_at": None,
            "completed_at": None,
        }
        assert ms.is_state_stale(state) is False

    def test_unparsable_started_at_is_not_stale(self):
        state = {
            "schema_version": 1,
            "started_at": "garbage",
            "completed_at": None,
        }
        assert ms.is_state_stale(state) is False

    def test_naive_started_at_does_not_crash(self):
        # Naive datetime ohne tz wird als UTC interpretiert (defensiver
        # Default). Test verifiziert nur, dass der Code nicht raised.
        state = {
            "schema_version": 1,
            "started_at": "2026-05-06T08:00:00",
            "completed_at": None,
        }
        result = ms.is_state_stale(state)
        assert isinstance(result, bool)

    def test_just_under_24h_is_not_stale(self):
        old = (
            datetime.now(tz=UTC) - timedelta(hours=23, minutes=59)
        ).isoformat()
        state = {
            "schema_version": 1,
            "started_at": old,
            "completed_at": None,
        }
        assert ms.is_state_stale(state) is False
