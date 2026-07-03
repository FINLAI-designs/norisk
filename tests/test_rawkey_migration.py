"""Tests fuer — SQLCipher Raw-Key + Pre-Prod-Discard der Alt-Format-DBs.

Deckt ab:
  - _configure_connection: Raw-Key vs String-Key round-trip + Format-Trennung.
  - EncryptedDatabase legt frische DBs im Raw-Key-Format an.
  - discard_pre_rawkey_databases: Alt-Format-DB wird verschoben, Raw-DB bleibt,
    Idempotenz via Marker, frische Installation setzt nur den Marker.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

import sqlcipher3

from core.database.encrypted_db import EncryptedDatabase, _configure_connection
from core.database.key_manager_context import get_active_key_manager
from core.database.migration_dbs import _can_open_with_key
from core.database.migration_rawkey import (
    _RAWKEY_MARKER,
    discard_pre_rawkey_databases,
)


def _make_string_key_db(db_path: Path, key_hex: str) -> None:
    """Legt eine DB im ALTEN String-Key/PBKDF2-Format an (Test-Helfer)."""
    conn = sqlcipher3.connect(str(db_path))
    _configure_connection(conn, key_hex, raw_key=False)
    conn.execute("CREATE TABLE t(v TEXT)")
    conn.execute("INSERT INTO t(v) VALUES('alt')")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# _configure_connection — Raw-Key vs String-Key
# ---------------------------------------------------------------------------


def test_rawkey_roundtrip(tmp_path: Path) -> None:
    km = get_active_key_manager()
    key = km.derive_secondary_key("db:rk").hex()
    p = tmp_path / "rk.db"
    conn = sqlcipher3.connect(str(p))
    _configure_connection(conn, key, raw_key=True)
    conn.execute("CREATE TABLE t(v TEXT)")
    conn.execute("INSERT INTO t(v) VALUES('raw')")
    conn.commit()
    conn.close()
    # Raw-Key oeffnet die Raw-DB; String-Key (PBKDF2) nicht.
    assert _can_open_with_key(p, key, raw_key=True) is True
    assert _can_open_with_key(p, key, raw_key=False) is False


def test_string_key_db_not_raw_openable(tmp_path: Path) -> None:
    km = get_active_key_manager()
    key = km.derive_secondary_key("db:sk").hex()
    p = tmp_path / "sk.db"
    _make_string_key_db(p, key)
    assert _can_open_with_key(p, key, raw_key=False) is True
    assert _can_open_with_key(p, key, raw_key=True) is False


def test_encrypted_database_creates_rawkey() -> None:
    # Frische EncryptedDatabase ist jetzt Raw-Key (DB_DIR via conftest-Fixture).
    db = EncryptedDatabase("fresh_rawkey")
    with db.connection() as c:
        c.execute("CREATE TABLE t(v TEXT)")
        c.execute("INSERT INTO t(v) VALUES('x')")
    km = get_active_key_manager()
    key = km.derive_secondary_key("db:fresh_rawkey").hex()
    assert _can_open_with_key(db.db_path, key, raw_key=True) is True
    assert _can_open_with_key(db.db_path, key, raw_key=False) is False
    with db.connection() as c:
        assert c.execute("SELECT v FROM t").fetchone()[0] == "x"


# ---------------------------------------------------------------------------
# discard_pre_rawkey_databases
# ---------------------------------------------------------------------------


def test_discard_moves_string_key_db(tmp_path: Path) -> None:
    km = get_active_key_manager()
    app = "norisk"
    db_dir = tmp_path / app
    db_dir.mkdir(parents=True)
    key = km.derive_secondary_key("db:old").hex()
    _make_string_key_db(db_dir / "old.db", key)

    discarded = discard_pre_rawkey_databases(km, app, db_root=tmp_path)

    assert discarded == ["old"]
    assert not (db_dir / "old.db").exists()  # verschoben
    assert (db_dir / _RAWKEY_MARKER).exists()  # Marker gesetzt
    moved = list(db_dir.glob(".pre-rawkey-discarded-*/old.db"))
    assert len(moved) == 1  # Backup, nicht geloescht


def test_discard_keeps_rawkey_db(tmp_path: Path) -> None:
    km = get_active_key_manager()
    app = "norisk"
    db_dir = tmp_path / app
    db_dir.mkdir(parents=True)
    key = km.derive_secondary_key("db:newraw").hex()
    conn = sqlcipher3.connect(str(db_dir / "newraw.db"))
    _configure_connection(conn, key, raw_key=True)
    conn.execute("CREATE TABLE t(v TEXT)")
    conn.commit()
    conn.close()

    discarded = discard_pre_rawkey_databases(km, app, db_root=tmp_path)

    assert discarded == []
    assert (db_dir / "newraw.db").exists()  # unangetastet


def test_discard_idempotent_via_marker(tmp_path: Path) -> None:
    km = get_active_key_manager()
    app = "norisk"
    db_dir = tmp_path / app
    db_dir.mkdir(parents=True)
    key = km.derive_secondary_key("db:old").hex()
    _make_string_key_db(db_dir / "old.db", key)
    discard_pre_rawkey_databases(km, app, db_root=tmp_path)

    # Zweiter Lauf: Marker gesetzt -> no-op, auch wenn eine neue Alt-DB liegt.
    _make_string_key_db(db_dir / "old2.db", key)
    second = discard_pre_rawkey_databases(km, app, db_root=tmp_path)
    assert second == []
    assert (db_dir / "old2.db").exists()


def test_discard_fresh_install_sets_marker(tmp_path: Path) -> None:
    km = get_active_key_manager()
    app = "norisk"
    discarded = discard_pre_rawkey_databases(km, app, db_root=tmp_path)
    assert discarded == []
    assert (tmp_path / app / _RAWKEY_MARKER).exists()
