"""
scanner_repository — Persistenz für System-Scan-Ergebnisse.

Implementiert IScanRepository mit EncryptedDatabase (SQLCipher).
Speichert Scan-Ergebnisse als JSON-Blob.

Sicherheitsdesign:
  - AES-256 Vollverschlüsselung via EncryptedDatabase
  - Kein sqlite3.connect direkt — nur EncryptedDatabase
  - Software-Inhalte werden nicht geloggt

Schichtzugehörigkeit: data/ — darf DB-Zugriff und JSON-Serialisierung.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import uuid

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.system_scanner.domain.entities import ScanResult
from tools.system_scanner.domain.interfaces import IScanRepository

log = get_logger(__name__)

_DB_NAME = "system_scanner"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    platform     TEXT NOT NULL,
    result_json  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_timestamp
    ON scans(timestamp DESC);
"""


class ScanRepository(IScanRepository):
    """SQLCipher-Repository für System-Scan-Ergebnisse."""

    def __init__(self) -> None:
        """Initialisiert die Datenbank und erstellt das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        """Erstellt die Tabellen falls noch nicht vorhanden."""
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    def save(self, result: ScanResult) -> None:
        """Speichert ein Scan-Ergebnis.

        Generiert eine UUID als scan_id wenn noch keine vorhanden.

        Args:
            result: Zu speicherndes Scan-Ergebnis.
        """
        if not result.scan_id:
            result.scan_id = str(uuid.uuid4())

        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                    (scan_id, timestamp, platform, result_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.timestamp.isoformat(),
                    result.os_info.platform.value,
                    json.dumps(result.to_dict()),
                ),
            )
        log.debug("Scan %s gespeichert", result.scan_id[:8])

    def load_latest(self) -> ScanResult | None:
        """Lädt das zuletzt gespeicherte Scan-Ergebnis.

        Returns:
            Letztes Scan-Ergebnis oder None.
        """
        results = self.load_history(limit=1)
        return results[0] if results else None

    def load_history(self, limit: int = 10) -> list[ScanResult]:
        """Lädt die letzten N Scan-Ergebnisse.

        Args:
            limit: Maximale Anzahl.

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT result_json
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        results: list[ScanResult] = []
        for (result_json,) in rows:
            try:
                data = json.loads(result_json)
                results.append(ScanResult.from_dict(data))
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Scan-Ergebnis konnte nicht geladen werden: %s", exc)
        return results
