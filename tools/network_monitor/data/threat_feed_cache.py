"""network_monitor.data.threat_feed_cache — Verschlüsselter Threat-Feed-Cache F-D).

Persistiert die rohen Feed-Downloads in der verschlüsselten Tool-DB
``network_monitor`` (eigene Tabelle ``threat_feed_cache``, getrennt von
``connection_history``/``process_traffic``). Zweck:

  - **Offline-Resilienz:** Bei einem fehlgeschlagenen Refresh bleibt der letzte
    gute Stand erhalten (kein fail-open zu einer leeren Blocklist).
  - **Schonung:** Eine TTL verhindert, dass jeder App-Start die Quellen erneut
    abruft.

Der Cache speichert den Roh-Payload (nicht die geparsten Netze) — die Parse-
Logik bleibt Single-Source in
:func:`~tools.network_monitor.data.threat_feed_client.parse_feed_text` und kann
sich weiterentwickeln, ohne den Cache zu invalidieren.

Schichtzugehörigkeit: ``data/`` — SQLCipher über:class:`EncryptedDatabase`.

Author: Patrick Riederich
Version: 1.0 F-D)
"""

from __future__ import annotations

import time
from typing import Final

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.network_monitor.domain.models import CachedFeed

_DB_NAME: Final[str] = "network_monitor"

_CREATE_TABLE: Final[str] = """
CREATE TABLE IF NOT EXISTS threat_feed_cache (
    source_key  TEXT PRIMARY KEY,
    raw_payload TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0
)
"""

_UPSERT: Final[str] = """
INSERT INTO threat_feed_cache (source_key, raw_payload, fetched_at, entry_count)
VALUES (?, ?, ?, ?)
ON CONFLICT(source_key) DO UPDATE SET
    raw_payload = excluded.raw_payload,
    fetched_at  = excluded.fetched_at,
    entry_count = excluded.entry_count
"""


class ThreatFeedCacheRepository:
    """SQLCipher-Adapter für den Threat-Intel-Feed-Cache F-D)."""

    def __init__(self, db_name: str = _DB_NAME) -> None:
        """Initialisiert das Repository und legt die Tabelle an.

        Args:
            db_name: Optionaler DB-Name. Default ``"network_monitor"`` (geteilt
                mit den übrigen Monitor-Tabellen). Tests übergeben einen eigenen.

        Raises:
            RuntimeError: Wenn kein aktiver ``KeyManager`` vorliegt
                (``EncryptedDatabase`` ist fail-closed) — der Aufrufer behandelt
                das fail-soft (z. B. Nicht-Windows ohne Collector).
        """
        self._log = get_logger(__name__)
        self._db = EncryptedDatabase(db_name)
        with self._db.connection() as conn:
            conn.execute(_CREATE_TABLE)

    def save(self, source_key: str, raw_payload: str, entry_count: int) -> None:
        """Speichert/aktualisiert den Roh-Payload einer Quelle (jetzt = ``fetched_at``).

        Args:
            source_key: Stabiler Quell-Schlüssel.
            raw_payload: Roher, bereits größen-geprüfter Feed-Text.
            entry_count: Anzahl der beim Download geparsten gültigen Einträge.
        """
        with self._db.connection() as conn:
            conn.execute(_UPSERT, (source_key, raw_payload, time.time(), entry_count))

    def save_many(self, items: list[tuple[str, str, int]]) -> None:
        """Speichert mehrere Quellen in EINER Verbindung (Perf, ADR-Triage P0a).

        Jeder ``EncryptedDatabase.connection`` zahlt die SQLCipher-PBKDF2-
        Schluesselableitung (kdf_iter) — mehrere Einzel-``save`` waren der
        Haupttreiber des Feed-Refresh-Freezes. ``save_many`` buendelt alle
        Upserts in eine Transaktion (= eine Verbindung).

        Args:
            items: Liste von ``(source_key, raw_payload, entry_count)``.
        """
        if not items:
            return
        now = time.time()
        rows = [(key, payload, now, count) for key, payload, count in items]
        with self._db.connection() as conn:
            conn.executemany(_UPSERT, rows)

    def load(self, source_key: str) -> CachedFeed | None:
        """Lädt den gecachten Stand einer Quelle.

        Args:
            source_key: Stabiler Quell-Schlüssel.

        Returns:
:class:`CachedFeed` oder ``None`` wenn die Quelle nicht gecacht ist.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT source_key, raw_payload, fetched_at, entry_count "
                "FROM threat_feed_cache WHERE source_key = ?",
                (source_key,),
            ).fetchone()
        if row is None:
            return None
        return CachedFeed(
            key=row[0],
            raw_payload=row[1],
            fetched_at=float(row[2]),
            entry_count=int(row[3] or 0),
        )

    def load_all(self) -> list[CachedFeed]:
        """Lädt alle gecachten Feeds.

        Returns:
            Liste aller:class:`CachedFeed` (kann leer sein).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT source_key, raw_payload, fetched_at, entry_count "
                "FROM threat_feed_cache ORDER BY source_key"
            ).fetchall()
        return [
            CachedFeed(
                key=row[0],
                raw_payload=row[1],
                fetched_at=float(row[2]),
                entry_count=int(row[3] or 0),
            )
            for row in rows
        ]

    def age_seconds(self, source_key: str) -> float | None:
        """Alter des Cache-Eintrags in Sekunden (``None`` wenn nicht gecacht).

        Args:
            source_key: Stabiler Quell-Schlüssel.

        Returns:
            Vergangene Sekunden seit dem letzten Download oder ``None``.
        """
        cached = self.load(source_key)
        if cached is None:
            return None
        return max(0.0, time.time() - cached.fetched_at)
