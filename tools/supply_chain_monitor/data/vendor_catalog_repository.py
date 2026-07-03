"""
vendor_catalog_repository — Bekannte Vendoren + Detection-Patterns.

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren, keine
application/gui-Importe.

Schema-Version 2: Tabelle ``vendor_catalog``. Patterns
werden als JSON-Arrays von normalisierten Substrings persistiert.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import (
    VendorCatalogEntry,
    VendorCategory,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_catalog (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_name             TEXT NOT NULL UNIQUE,
    default_category           TEXT NOT NULL,
    aliases_json               TEXT NOT NULL DEFAULT '[]',
    app_name_patterns_json     TEXT NOT NULL DEFAULT '[]',
    mx_hostname_patterns_json  TEXT NOT NULL DEFAULT '[]',
    cert_issuer_patterns_json  TEXT NOT NULL DEFAULT '[]',
    notes                      TEXT NOT NULL DEFAULT '',
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vendor_catalog_name
  ON vendor_catalog(canonical_name COLLATE NOCASE);
"""


class VendorCatalogRepository:
    """CRUD-Repository fuer:class:`VendorCatalogEntry`."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        # Default-DB-Name passt zu:class:`VendorRepository` — beide Tools
        # teilen sich die Datei ``supply_chain_monitor.db``.
        self._db = db or EncryptedDatabase("supply_chain_monitor")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    def add(self, entry: VendorCatalogEntry) -> int:
        """Fuegt einen neuen Catalog-Eintrag ein.

        Returns:
            Die neu vergebene ID.

        Raises:
            ValueError: Wenn ``canonical_name`` bereits existiert (UNIQUE-Verstoss).
        """
        with self._db.connection() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO vendor_catalog
                        (canonical_name, default_category, aliases_json,
                         app_name_patterns_json, mx_hostname_patterns_json,
                         cert_issuer_patterns_json, notes,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.canonical_name,
                        entry.default_category.value,
                        json.dumps(list(entry.aliases)),
                        json.dumps(list(entry.app_name_patterns)),
                        json.dumps(list(entry.mx_hostname_patterns)),
                        json.dumps(list(entry.cert_issuer_patterns)),
                        entry.notes,
                        entry.created_at.isoformat(),
                        entry.updated_at.isoformat(),
                    ),
                )
                conn.commit()
            except Exception as exc:  # noqa: BLE001 — sqlite3.IntegrityError als allg. Fehler
                msg = str(exc).lower()
                if "unique" in msg and "canonical_name" in msg:
                    raise ValueError(
                        f"Catalog-Eintrag '{entry.canonical_name}' existiert bereits."
                    ) from exc
                raise
            new_id = int(cur.lastrowid or 0)
        _log.info("catalog_entry_added id=%s name=%r", new_id, entry.canonical_name)
        return new_id

    def get_by_id(self, entry_id: int) -> VendorCatalogEntry | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM vendor_catalog WHERE id = ?",
                (int(entry_id),),
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def get_by_canonical_name(self, name: str) -> VendorCatalogEntry | None:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM vendor_catalog WHERE canonical_name = ? COLLATE NOCASE",
                (name.strip(),),
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def list_all(self) -> list[VendorCatalogEntry]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vendor_catalog ORDER BY canonical_name COLLATE NOCASE ASC"
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def update(self, entry: VendorCatalogEntry) -> None:
        if entry.id is None:
            raise ValueError("VendorCatalogEntry.update braucht eine gesetzte id.")
        now_iso = datetime.now(UTC).isoformat()
        with self._db.connection() as conn:
            try:
                cur = conn.execute(
                    """
                    UPDATE vendor_catalog
                    SET canonical_name = ?,
                        default_category = ?,
                        aliases_json = ?,
                        app_name_patterns_json = ?,
                        mx_hostname_patterns_json = ?,
                        cert_issuer_patterns_json = ?,
                        notes = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        entry.canonical_name,
                        entry.default_category.value,
                        json.dumps(list(entry.aliases)),
                        json.dumps(list(entry.app_name_patterns)),
                        json.dumps(list(entry.mx_hostname_patterns)),
                        json.dumps(list(entry.cert_issuer_patterns)),
                        entry.notes,
                        now_iso,
                        int(entry.id),
                    ),
                )
                conn.commit()
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "unique" in msg and "canonical_name" in msg:
                    raise ValueError(
                        f"Catalog-Eintrag '{entry.canonical_name}' existiert bereits."
                    ) from exc
                raise
            if cur.rowcount == 0:
                raise ValueError(f"Kein Catalog-Eintrag mit id={entry.id} gefunden.")
        _log.info("catalog_entry_updated id=%s", entry.id)

    def delete(self, entry_id: int) -> bool:
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM vendor_catalog WHERE id = ?",
                (int(entry_id),),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0

    def count(self) -> int:
        with self._db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM vendor_catalog").fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------------
    # Row-Mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_entry(row) -> VendorCatalogEntry:  # noqa: ANN001
        # Spalten-Indizes folgen der SELECT *-Reihenfolge (Schema oben).
        return VendorCatalogEntry(
            id=int(row[0]),
            canonical_name=row[1],
            default_category=VendorCategory.from_value(row[2]),
            aliases=_load_json_tuple(row[3]),
            app_name_patterns=_load_json_tuple(row[4]),
            mx_hostname_patterns=_load_json_tuple(row[5]),
            cert_issuer_patterns=_load_json_tuple(row[6]),
            notes=row[7] or "",
            created_at=_parse_iso_utc(row[8]),
            updated_at=_parse_iso_utc(row[9]),
        )


def _load_json_tuple(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    try:
        data = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return ()
    if not isinstance(data, list):
        return ()
    return tuple(str(item) for item in data)


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
