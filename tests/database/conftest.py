"""tests/database/conftest.py — Crypto-Fixtures fuer Migrations-Tests (Subtask 3).

Stellt synthetische Legacy-DB-Erzeuger fuer M-1/M-2/M-3/M-4-Tests
bereit. Synthetische statt echte Hardware-Fingerprints aus
:doc:`MIGRATION_TEST_PLAN` §2.1 — reale v1-/v2-Aggregate sind
hardware-identifizierende Information und werden NICHT eingecheckt.

Die globale ``_ensure_global_key_manager``-Fixture aus
``tests/conftest.py`` ist autouse=True und wirkt auch hier — sie
stellt einen test-isolierten KeyManager mit ``InMemoryDPAPIBackend``
bereit. Migrations-Tests nutzen diesen KeyManager als Ziel des
``PRAGMA rekey``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
import sqlcipher3


def _synthetic_legacy_key(fingerprint_id: str, db_name: str) -> str:
    """Deterministischer 64-Hex-Test-Schluessel aus zwei Strings.

    Nicht real, nur Fixture. SHA-256(``"<fp>::<db>"``).hexdigest.

    Args:
        fingerprint_id: Synthetischer Fingerprint-Identifier
            (z. B. ``"v1"`` oder ``"v2"``).
        db_name: DB-Stem-Name.

    Returns:
        64-stelliger Hex-String fuer ``PRAGMA key``.
    """
    return hashlib.sha256(
        f"{fingerprint_id}::{db_name}".encode()
    ).hexdigest()


@pytest.fixture
def synthetic_legacy_v1_factory() -> Callable[[str], str]:
    """Liefert eine Factory ``db_name → hex_key`` fuer v1-Schluessel."""
    return lambda db_name: _synthetic_legacy_key("v1_synthetic", db_name)


@pytest.fixture
def synthetic_legacy_v2_factory() -> Callable[[str], str]:
    """Liefert eine Factory ``db_name → hex_key`` fuer v2-Schluessel."""
    return lambda db_name: _synthetic_legacy_key("v2_synthetic", db_name)


def _create_db_with_key(db_path: Path, key_hex: str) -> None:
    """Erzeugt eine SQLCipher-DB im ALTEN String-Key/PBKDF2-Format + Sample-Daten.

    Die Legacy→DEK-Migrationstests brauchen DBs im Pre--Format
    (String-Key, PBKDF2) — daher explizit ``raw_key=False`` (seit ist
    der Default Raw-Key). Cipher-Konfiguration sonst wie Production.
    """
    from core.database.encrypted_db import _configure_connection

    conn = sqlcipher3.connect(str(db_path))
    try:
        _configure_connection(conn, key_hex, raw_key=False)
        conn.execute(
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)"
        )
        conn.executemany(
            "INSERT INTO sample (value) VALUES (?)",
            [("a",), ("b",), ("c",)],
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def make_legacy_db(tmp_path):
    """Factory: legt eine SQLCipher-DB mit (db_name, factory) im tmp_path an.

    Beispiel::

        path = make_legacy_db("network_monitor", synthetic_legacy_v2_factory)
        # path zeigt auf network_monitor.db, verschluesselt mit dem
        # synthetischen v2-Schluessel.
    """

    def _make(db_name: str, factory: Callable[[str], str]) -> Path:
        db_path = tmp_path / f"{db_name}.db"
        key_hex = factory(db_name)
        _create_db_with_key(db_path, key_hex)
        return db_path

    return _make


@pytest.fixture
def make_corrupt_db(tmp_path):
    """Factory: legt eine DB mit zerstoertem Header an (M-3 Fixture)."""

    def _make(db_name: str = "corrupt") -> Path:
        # Erzeuge eine valide DB mit beliebigem Schluessel...
        db_path = tmp_path / f"{db_name}.db"
        _create_db_with_key(db_path, _synthetic_legacy_key("any", db_name))
        #... und zerstoere die ersten 16 Bytes.
        with open(db_path, "r+b") as fp:
            fp.write(b"\x00" * 16)
        return db_path

    return _make
