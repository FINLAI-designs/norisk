"""
encrypted_snapshot_repo — Verschluesselte, persistente Snapshot-Ablage (R5/T6).

Loest die fruehere Klartext-JSON-Ablage (``file_snapshot_repo``) ab. Snapshots
tragen den Vorzustand jedes Writes und sind die Grundlage des Reverts — sie
gehoeren prozessuebergreifend in die **admin-only** ``secure_store``-Ablage
(``%ProgramData%\\NoRisk\\system_tuner``), damit ein Non-Admin sie nicht
manipulieren kann (Integritaet via DACL, T6).

Diese Iteration legt sie zusaetzlich in eine **SQLCipher-DB** (AES-256-CBC,
HMAC-SHA512-Seitenintegritaet) — Verschluesselung-at-Rest + Tamper-Evidenz als
Defense-in-Depth oben auf die DACL. Muster: ``upgrade_history_repository`` +
``core.database.encrypted_db`` (append-only, ``PRAGMA user_version``, uuid4).

**DB-Schluessel (T9):** Der Schluessel wird vom zentralen ``KeyManager`` aus dem
envelope-DEK abgeleitet (``derive_secondary_key("db:system_tuner_snapshots")``,
HKDF-Domain-Separation) — wie bei allen FINLAI-DBs. Der app-bootlose elevated
Apply-Prozess bootet den KeyManager selbst aus dem DPAPI-gewrappten DEK
(derselbe Windows-User wie die GUI -> derselbe DEK -> derselbe abgeleitete
Schluessel, prozessuebergreifend). Verdrahtet ueber den ``key_manager``-
Konstruktor-Parameter; die Snapshots tragen ohnehin nur Konfig-Vorwerte (keine
Credentials), die tragende Integritaets-Mitigation bleibt die admin-only DACL.

**Append-only:** ``save`` fuegt eine neue Zeile ein (kein UPDATE/DELETE). ``get``
und ``list_all`` liefern den **jeweils neuesten** Snapshot je ``tweak_id``
(latest-wins) — semantisch identisch zur frueheren dict-Ablage, aber mit
revisionssicherem Verlauf. Bewusst OHNE Retention/Purge (anders als das Muster
``upgrade_history_repository``): endlicher Tweak-Katalog + seltene elevated
Applies → vernachlaessigbares Wachstum, und latest-wins macht Altzeilen
funktional irrelevant. Eine ``purge_older_than`` kann beim Scharfschalten (T9)
nachgezogen werden.

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.system_tuner.domain.apply_entities import Snapshot
from tools.system_tuner.domain.enums import ServiceStartMode
from tools.system_tuner.domain.interfaces import ISnapshotRepo

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

log = get_logger(__name__)

_DB_NAME = "system_tuner_snapshots"
_DB_FILENAME = "snapshots.db"
_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id                   TEXT PRIMARY KEY,
    created_at           INTEGER NOT NULL,
    tweak_id             TEXT NOT NULL,
    target_key           TEXT NOT NULL,
    existed              INTEGER NOT NULL,
    prior_registry_value TEXT,
    prior_registry_type  TEXT,
    prior_start_mode     TEXT
);

-- Index auf den tatsaechlichen Zugriffspfad: get() filtert ``WHERE tweak_id``,
-- list_all() gruppiert ``GROUP BY tweak_id``. Die Latest-wins-Ordnung laeuft
-- ueber die intrinsische ``rowid`` (kein created_at-Schluessel noetig).
CREATE INDEX IF NOT EXISTS idx_snapshots_tweak
    ON snapshots(tweak_id);
"""


def _to_row(snapshot: Snapshot) -> tuple[object, ...]:
    return (
        uuid.uuid4().hex,
        int(time.time()),
        snapshot.tweak_id,
        snapshot.target_key,
        1 if snapshot.existed else 0,
        snapshot.prior_registry_value,
        snapshot.prior_registry_type,
        snapshot.prior_start_mode.value if snapshot.prior_start_mode else None,
    )


def _row_to_snapshot(row: Iterable) -> Snapshot:
    (
        tweak_id,
        target_key,
        existed,
        prior_registry_value,
        prior_registry_type,
        prior_start_mode,
    ) = row
    return Snapshot(
        tweak_id=str(tweak_id),
        target_key=str(target_key),
        existed=bool(existed),
        prior_registry_value=prior_registry_value,
        prior_registry_type=prior_registry_type,
        prior_start_mode=(
            ServiceStartMode(str(prior_start_mode)) if prior_start_mode else None
        ),
    )


class EncryptedSnapshotRepository(ISnapshotRepo):
    """Append-only SQLCipher-Snapshot-Ablage (latest-wins je ``tweak_id``)."""

    def __init__(self, store_dir: Path, key_manager: KeyManager) -> None:
        """Oeffnet/erzeugt die verschluesselte Snapshot-DB unter ``store_dir``.

        Args:
            store_dir: Admin-only Ablage (``secure_store.secure_dir``).
            key_manager: Zentraler KeyManager; leitet den DB-Schluessel aus dem
                envelope-DEK ab (Purpose ``db:system_tuner_snapshots``).
        """
        self._db = EncryptedDatabase(
            _DB_NAME,
            db_path=store_dir / _DB_FILENAME,
            key_manager=key_manager,
        )
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # ``PRAGMA user_version = N`` akzeptiert keine Parameter-Bindings —
            # sicher, weil _SCHEMA_VERSION eine Modul-Konstante ist.
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")  # noqa: S608

    def get_schema_version(self) -> int:
        """Liefert die aktuelle ``PRAGMA user_version`` der DB."""
        with self._db.connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    def save(self, snapshot: Snapshot) -> None:
        """Fuegt einen Snapshot append-only ein (neuester gewinnt je tweak_id)."""
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO snapshots(
                    id, created_at, tweak_id, target_key, existed,
                    prior_registry_value, prior_registry_type, prior_start_mode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _to_row(snapshot),
            )

    def get(self, tweak_id: str) -> Snapshot | None:
        """Liefert den neuesten Snapshot zu einem Tweak (oder ``None``).

        Latest-wins ueber die monotone ``rowid`` (append-only, keine Deletes →
        strikt steigend) — robust auch bei mehreren Saves in derselben Sekunde,
        die ``created_at`` (Sekunden-Granularitaet) nicht trennen koennte.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT tweak_id, target_key, existed,
                       prior_registry_value, prior_registry_type, prior_start_mode
                FROM snapshots
                WHERE tweak_id = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (tweak_id,),
            ).fetchone()
        return _row_to_snapshot(row) if row else None

    def list_all(self) -> list[Snapshot]:
        """Liefert den jeweils neuesten Snapshot je ``tweak_id`` (latest-wins).

        Der Join auf ``MAX(rowid)`` je ``tweak_id`` waehlt genau eine Zeile pro
        Tweak — eindeutig, da ``rowid`` ein Primaerschluessel ist.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT s.tweak_id, s.target_key, s.existed,
                       s.prior_registry_value, s.prior_registry_type,
                       s.prior_start_mode
                FROM snapshots s
                JOIN (
                    SELECT tweak_id, MAX(rowid) AS mx
                    FROM snapshots GROUP BY tweak_id
                ) latest
                  ON s.rowid = latest.mx
                ORDER BY s.tweak_id
                """
            ).fetchall()
        return [_row_to_snapshot(r) for r in rows]
