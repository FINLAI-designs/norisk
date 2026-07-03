"""
patch_eol_cache — SQLCipher-Cache fuer endoflife.date-Antworten.

Pattern analog:class:`tools.cyber_dashboard.data.nvd_cache_repository.NvdCacheRepository`:
EncryptedDatabase mit eigener DB ``eol_cache``, Single-Tabelle mit
TTL-Konvention. Cache-Key ist der endoflife.date-Produkt-Slug
(z. B. ``"office"``, ``"windows-server"``).

Schicht: ``core/`` — Daten-Persistenz analog ``nvd_cache``. Wird vom
:class:`core.patch_eol_resolver.EndoflifeApiResolver` benutzt.

Author: Patrick Riederich
Version: 1.0 Stop-Step A, 2026-05-13)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger

log = get_logger(__name__)

_DB_NAME: Final[str] = "eol_cache"
_SCHEMA_VERSION: Final[int] = 1

#: Default-TTL: 24 h. endoflife.date-Daten aendern sich rare (Vendor-EOL-
#: Daten sind stabil ueber Wochen), 24 h ist konservativ.
DEFAULT_TTL_SECONDS: Final[int] = 24 * 60 * 60

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS eol_cache (
    product_slug TEXT PRIMARY KEY,
    cycles_json  TEXT NOT NULL,
    fetched_at   INTEGER NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class EolCacheEntry:
    """Ein Cache-Eintrag pro Produkt-Slug.

    Attributes:
        cycles: Liste von Cycle-Dicts wie von endoflife.date geliefert
                    (Felder ``cycle``, ``releaseDate``, ``eol``, ``latest``,
                    etc. — Schema ist Vendor-spezifisch flexibel).
        fetched_at: UTC-Zeitpunkt des Fetches.
        is_stale: True wenn aelter als die TTL beim ``get``-Aufruf.
    """

    cycles: list[dict[str, Any]]
    fetched_at: datetime
    is_stale: bool


class EolCacheRepository:
    """SQLCipher-Cache fuer endoflife.date-Antworten."""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        """Initialisiert die DB. ``ttl_seconds`` wird im ``get`` ausgewertet."""
        self._ttl = ttl_seconds
        self._db = EncryptedDatabase(_DB_NAME)
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            # PRAGMA user_version akzeptiert keine Parameter-Bindings.
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")  # noqa: S608

    def get_schema_version(self) -> int:
        with self._db.connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
            return int(row[0]) if row else 0

    def get(self, product_slug: str) -> EolCacheEntry | None:
        """Liest einen Cache-Eintrag (auch wenn stale).

        Der Aufrufer entscheidet anhand von ``is_stale`` ob er den
        Eintrag verwendet (Offline-Fallback) oder neu laedt.
        """
        if not product_slug:
            return None
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT cycles_json, fetched_at FROM eol_cache "
                "WHERE product_slug = ?",
                (product_slug,),
            ).fetchone()
        if row is None:
            return None
        try:
            cycles = json.loads(row[0])
            if not isinstance(cycles, list):
                cycles = []
        except json.JSONDecodeError:
            log.warning(
                "EolCacheEntry '%s' ist kaputtes JSON — ignoriere.",
                product_slug,
            )
            return None

        fetched_ts = int(row[1])
        fetched_at = datetime.fromtimestamp(fetched_ts, tz=UTC)
        age = int(time.time()) - fetched_ts
        return EolCacheEntry(
            cycles=cycles,
            fetched_at=fetched_at,
            is_stale=age > self._ttl,
        )

    def set(self, product_slug: str, cycles: list[dict[str, Any]]) -> None:
        """Schreibt einen frischen Cache-Eintrag (upsert)."""
        if not product_slug:
            return
        payload = json.dumps(cycles, default=str, ensure_ascii=False)
        now = int(time.time())
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO eol_cache "
                "(product_slug, cycles_json, fetched_at) VALUES (?, ?, ?)",
                (product_slug, payload, now),
            )

    def purge_stale(self, max_age_seconds: int | None = None) -> int:
        """Loescht Eintraege aelter als ``max_age_seconds`` (Default 7 Tage).

        Returns: Anzahl geloeschter Zeilen.
        """
        max_age = max_age_seconds if max_age_seconds is not None else 7 * 24 * 3600
        cutoff = int(time.time()) - max_age
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM eol_cache WHERE fetched_at < ?",
                (cutoff,),
            )
            return cur.rowcount


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "EolCacheEntry",
    "EolCacheRepository",
]
