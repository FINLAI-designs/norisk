"""
nvd_cache_repository — SQLCipher-Cache für NVD CVE API 2.0 Responses.

Isoliert vom allgemeinen ``cache_repository`` (cyber_dashboard.db), damit
NVD-Ausfälle und TTL-Strategien unabhängig vom RSS-Cache gehandhabt
werden können.

Designziele:
  - TTL: 6 Stunden (frische Reads hitten Cache, alte werden re-fetched)
  - Stale-Reads erlaubt: bei NVD-Timeout gibt der Service abgelaufene
    Cache-Einträge zurück — User sieht Offline-Banner statt leerem Panel
  - Cache-Key = deterministischer Hash der Request-Parameter

Erweiterung Sprint S0b: Zusätzliche Tabelle ``cve_products`` als normalisierte
Lookup-Struktur (cve_id, product_name) für Cross-Tool-Synergien
(TechStack ↔ NVD-CVE-Match). Wird vom NvdService bei jedem Online-Sync
gefüllt; Backfill-Pfad iteriert über vorhandene ``nvd_cache``-Rohdaten.

Schichtzugehörigkeit: data/ (Repository-Adapter für NvdService).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger

log = get_logger(__name__)

_DB_NAME = "nvd_cache"
CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 Stunden

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nvd_cache (
    cache_key   TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    fetched_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nvd_cache_fetched
    ON nvd_cache(fetched_at DESC);

CREATE TABLE IF NOT EXISTS cve_products (
    cve_id        TEXT NOT NULL,
    product_name  TEXT NOT NULL,
    PRIMARY KEY (cve_id, product_name)
);

CREATE INDEX IF NOT EXISTS idx_cve_products_product
    ON cve_products(product_name);
"""


@dataclass(frozen=True)
class NvdCacheEntry:
    """Gecachte NVD-Antwort mit Metadaten.

    Attributes:
        data: Die geparste NVD-Antwort als JSON-serialisierbare Liste.
        fetched_at: Zeitpunkt des erfolgreichen Fetch (UTC).
        is_stale: True wenn die TTL überschritten wurde.
    """

    data: list[dict[str, Any]]
    fetched_at: datetime
    is_stale: bool


def compute_cache_key(params: dict[str, Any]) -> str:
    """Deterministischer Cache-Key aus Request-Parametern.

    Args:
        params: NVD-API Query-Parameter.

    Returns:
        SHA-256 Hex-Digest (64 Zeichen) der normalisierten Params.
    """
    normalized = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class NvdCacheRepository:
    """Persistiert NVD-Responses in einer eigenen SQLCipher-Datenbank.

    Nutzung:
        repo = NvdCacheRepository
        entry = repo.get(cache_key)
        if entry and not entry.is_stale:
            return entry.data
        # sonst neu fetchen...
        repo.set(cache_key, fresh_data)
    """

    def __init__(self, ttl_seconds: int = CACHE_TTL_SECONDS) -> None:
        """Initialisiert die Datenbank und legt das Schema an.

        Args:
            ttl_seconds: TTL in Sekunden. Default 6h.
        """
        self._ttl = ttl_seconds
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    def get(self, cache_key: str) -> NvdCacheEntry | None:
        """Liest einen Cache-Eintrag. Gibt auch abgelaufene Einträge zurück.

        Der Aufrufer entscheidet anhand von ``is_stale`` ob er den Eintrag
        verwendet (Offline-Fallback) oder neu lädt.

        Args:
            cache_key: Hash-Key aus:func:`compute_cache_key`.

        Returns:
:class:`NvdCacheEntry` oder ``None`` wenn nichts gecacht ist.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data, fetched_at FROM nvd_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if row is None:
            return None

        try:
            data = json.loads(row[0])
        except json.JSONDecodeError:
            log.warning("Cache-Eintrag '%s' ist kaputtes JSON — ignoriere", cache_key)
            return None

        fetched_ts = int(row[1])
        fetched_at = datetime.fromtimestamp(fetched_ts, tz=UTC)
        age = int(time.time()) - fetched_ts
        return NvdCacheEntry(
            data=data,
            fetched_at=fetched_at,
            is_stale=age > self._ttl,
        )

    def set(self, cache_key: str, data: list[dict[str, Any]]) -> None:
        """Schreibt einen frischen Cache-Eintrag.

        Args:
            cache_key: Hash-Key aus:func:`compute_cache_key`.
            data: Zu speichernde Payload (JSON-serialisierbar).
        """
        payload = json.dumps(data, default=str)
        now = int(time.time())
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO nvd_cache(cache_key, data, fetched_at)"
                " VALUES (?, ?, ?)",
                (cache_key, payload, now),
            )

    def purge_older_than(self, seconds: int) -> int:
        """Löscht alle Einträge die älter als ``seconds`` sind.

        Args:
            seconds: Maximales Alter in Sekunden.

        Returns:
            Anzahl gelöschter Einträge.
        """
        threshold = int(time.time()) - seconds
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM nvd_cache WHERE fetched_at < ?", (threshold,)
            )
            return cur.rowcount

    # ------------------------------------------------------------------
    # cve_products — normalisierter (cve_id, product_name)-Index
    # ------------------------------------------------------------------

    def upsert_products(
        self, cve_id: str, product_names: list[str]
    ) -> int:
        """Schreibt (cve_id, product_name)-Paare idempotent.

        ``INSERT OR IGNORE`` über den zusammengesetzten Primary Key —
        wiederholte Aufrufe mit identischen Werten sind no-ops, ohne
        ``IntegrityError`` auszulösen.

        Args:
            cve_id: CVE-Bezeichner (z. B. ``"CVE-2024-1234"``).
            product_names: Bereits aus dem CPE-URI extrahierte Anzeigenamen
                (z. B. ``["microsoft windows", "openssl openssl"]``). Leere
                Strings und Dubletten werden ignoriert. Leere Liste = no-op.

        Returns:
            Anzahl tatsächlich neu eingefügter Zeilen.
        """
        unique = {p.strip() for p in product_names if p and p.strip()}
        if not cve_id or not unique:
            return 0
        with self._db.connection() as conn:
            cur = conn.executemany(
                "INSERT OR IGNORE INTO cve_products(cve_id, product_name)"
                " VALUES (?, ?)",
                [(cve_id, name) for name in unique],
            )
            return cur.rowcount

    def find_cves_by_product(self, product_name: str) -> list[str]:
        """Findet alle CVE-IDs zu einem Produkt-Namen (case-insensitive).

        Args:
            product_name: Produkt-Anzeigename (Whitespace wird getrimmt).

        Returns:
            Sortierte, deduplizierte Liste von CVE-IDs. Leer wenn der
            Name nicht bekannt ist oder die Tabelle leer ist.
        """
        needle = product_name.strip().lower()
        if not needle:
            return []
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT cve_id FROM cve_products"
                " WHERE LOWER(product_name) = ?"
                " ORDER BY cve_id ASC",
                (needle,),
            ).fetchall()
        return [row[0] for row in rows]

    def count_products(self) -> int:
        """Anzahl Zeilen in ``cve_products`` (für Backfill-Telemetrie)."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM cve_products"
            ).fetchone()
        return int(row[0]) if row else 0

    def iter_cache_payloads(self) -> Iterator[list[dict[str, Any]]]:
        """Yieldet die geparsten JSON-Payloads aller ``nvd_cache``-Zeilen.

        Wird vom Backfill-Pfad in:class:`NvdService` konsumiert: der
        Service kennt das Item-Schema (``[{"cve":...},...]``) und kann
        je Item ``CveEintrag.betroffene_produkte`` rekonstruieren, ohne
        dass die Repository-Schicht das Item-Format kennen muss.

        Yields:
            Eine Liste von ``vulnerabilities``-Items pro Cache-Eintrag
            (analog zu:meth:`get`-Returns ohne TTL-Bewertung).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT cache_key, data FROM nvd_cache"
            ).fetchall()
        for cache_key, data_json in rows:
            try:
                yield json.loads(data_json)
            except json.JSONDecodeError:
                log.warning(
                    "Backfill: Cache-Eintrag '%s' ist kaputtes JSON — überspringe",
                    cache_key,
                )
                continue
