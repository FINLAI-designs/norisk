"""
manual_entry_repository — SQLCipher-Persistenz für manuell erfasste
Sicherheitskomponenten-Einträge.

Wiederverwendet die ``system_scanner``-DB, legt aber eine eigene Tabelle
``manual_scanner_entries`` an. Manuelle Einträge sind unabhängig von Scan-
Ergebnissen und überleben jeden Scan.

Sicherheitsdesign:
  - AES-256 Vollverschlüsselung via EncryptedDatabase
  - Kein sqlite3.connect direkt
  - Keine Logging-Ausgabe der Eintragsinhalte

Schichtzugehörigkeit: data/ — DB-Zugriff + Serialisierung erlaubt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.exceptions import ValidationError
from core.logger import get_logger
from tools.system_scanner.domain.entities import ManualScannerEntry
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType

log = get_logger(__name__)

_DB_NAME = "system_scanner"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS manual_scanner_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'unknown',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_manual_entries_category
    ON manual_scanner_entries(category);
"""

# Maximale Feldlängen — UI enforced zusätzlich
_MAX_NAME_LENGTH = 100
_MAX_VERSION_LENGTH = 50


class ManualScannerEntryRepository:
    """CRUD-Repository für manuelle Sicherheitskomponenten-Einträge."""

    def __init__(self) -> None:
        """Initialisiert die Datenbank und legt das Schema an."""
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    def get_all(self, category: ComponentType) -> list[ManualScannerEntry]:
        """Lädt alle manuellen Einträge einer Kategorie.

        Args:
            category: Kategorie-Filter (antivirus/firewall/encryption).

        Returns:
            Liste manueller Einträge, alphabetisch nach Name sortiert.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, category, name, version, status, created_at, updated_at
                FROM manual_scanner_entries
                WHERE category = ?
                ORDER BY name COLLATE NOCASE
                """,
                (category.value,),
            ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def add(self, entry: ManualScannerEntry) -> ManualScannerEntry:
        """Legt einen neuen manuellen Eintrag an.

        Setzt ``created_at`` und ``updated_at`` auf jetzt; ignoriert
        ``entry.entry_id`` (AUTOINCREMENT).

        Args:
            entry: Neuer Eintrag (``entry_id`` wird ignoriert).

        Returns:
            Dieselbe Entity mit gesetzter ``entry_id``.

        Raises:
            ValueError: Wenn Name leer ist oder Feldlängen überschritten.
        """
        self._validate(entry)
        now = int(time.time())
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO manual_scanner_entries
                    (category, name, version, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.category.value,
                    entry.name.strip(),
                    entry.version.strip(),
                    entry.status.value,
                    now,
                    now,
                ),
            )
            new_id = cur.lastrowid
        log.debug("Manueller Eintrag hinzugefügt: %s/%s", entry.category.value, new_id)
        entry.entry_id = int(new_id) if new_id is not None else None
        entry.created_at = datetime.fromtimestamp(now, tz=UTC)
        entry.updated_at = entry.created_at
        return entry

    def update(self, entry: ManualScannerEntry) -> ManualScannerEntry:
        """Aktualisiert einen bestehenden Eintrag.

        Args:
            entry: Zu aktualisierender Eintrag (``entry_id`` muss gesetzt sein).

        Returns:
            Aktualisierte Entity mit neuem ``updated_at``.

        Raises:
            ValueError: Wenn ``entry_id`` fehlt, Name leer oder Feldlängen
                überschritten.
        """
        if entry.entry_id is None:
            raise ValidationError("update() benötigt gesetzte entry_id")
        self._validate(entry)
        now = int(time.time())
        with self._db.connection() as conn:
            conn.execute(
                """
                UPDATE manual_scanner_entries
                   SET category = ?,
                       name = ?,
                       version = ?,
                       status = ?,
                       updated_at = ?
                 WHERE id = ?
                """,
                (
                    entry.category.value,
                    entry.name.strip(),
                    entry.version.strip(),
                    entry.status.value,
                    now,
                    entry.entry_id,
                ),
            )
        entry.updated_at = datetime.fromtimestamp(now, tz=UTC)
        log.debug("Manueller Eintrag aktualisiert: id=%s", entry.entry_id)
        return entry

    def delete(self, entry_id: int) -> bool:
        """Löscht einen Eintrag.

        Args:
            entry_id: DB-ID des zu löschenden Eintrags.

        Returns:
            True wenn ein Eintrag gelöscht wurde, sonst False.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM manual_scanner_entries WHERE id = ?",
                (entry_id,),
            )
            deleted = cur.rowcount > 0
        if deleted:
            log.debug("Manueller Eintrag gelöscht: id=%s", entry_id)
        return deleted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate(entry: ManualScannerEntry) -> None:
        """Prüft Pflichtfeld und Feldlängen."""
        if not entry.name or not entry.name.strip():
            raise ValidationError("Name ist ein Pflichtfeld")
        if len(entry.name) > _MAX_NAME_LENGTH:
            raise ValidationError(f"Name darf max. {_MAX_NAME_LENGTH} Zeichen haben")
        if len(entry.version) > _MAX_VERSION_LENGTH:
            raise ValidationError(f"Version darf max. {_MAX_VERSION_LENGTH} Zeichen haben")

    @staticmethod
    def _row_to_entry(row: tuple) -> ManualScannerEntry:
        """Baut eine Entity aus einer DB-Zeile."""
        entry_id, category, name, version, status, created_at, updated_at = row
        return ManualScannerEntry(
            entry_id=int(entry_id),
            category=ComponentType(category),
            name=name,
            version=version or "",
            status=ComponentStatus(status),
            created_at=datetime.fromtimestamp(int(created_at), tz=UTC),
            updated_at=datetime.fromtimestamp(int(updated_at), tz=UTC),
        )
