"""network_monitor.data.dns_query_repository — DNS-Query-History Regel 5).

Persistiert die vom DNS-Aggregator gesammelten
:class:`~tools.network_monitor.domain.models.DnsQuerySample` in der
verschluesselten Tool-DB ``network_monitor`` (eigene Tabelle ``dns_queries``).
48h-Retention (DSGVO; Query-Namen sind potenziell personenbezogen). Die
Peak-Rate-Aggregation liefert die Datenbasis fuer den DNS-Tunneling-Alert.

Author: Patrick Riederich
Version: 1.0 Regel 5)
"""

from __future__ import annotations

import time
from typing import Final

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IDnsQueryRepository
from tools.network_monitor.domain.models import DnsQuerySample, DnsRateAggregate

_DB_NAME: Final[str] = "network_monitor"
_DEFAULT_RETENTION_HOURS: Final[int] = 48
_SECONDS_PER_HOUR: Final[int] = 3_600

_CREATE_TABLE: Final[str] = """
CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    query_count INTEGER NOT NULL,
    distinct_names INTEGER NOT NULL,
    max_label_len INTEGER NOT NULL,
    max_label_entropy REAL NOT NULL,
    sample_query TEXT NOT NULL DEFAULT '',
    game_cdn TEXT NOT NULL DEFAULT ''
)
"""
_CREATE_INDEX_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp "
    "ON dns_queries(timestamp)"
)
_CREATE_INDEX_PID_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_dns_queries_pid_ts "
    "ON dns_queries(pid, timestamp)"
)
_INSERT: Final[str] = (
    "INSERT INTO dns_queries "
    "(timestamp, pid, process_name, query_count, distinct_names, "
    "max_label_len, max_label_entropy, sample_query, game_cdn) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class DnsQueryRepository(IDnsQueryRepository):
    """SQLCipher-Adapter fuer die DNS-Query-History Regel 5)."""

    def __init__(self, db_name: str = _DB_NAME) -> None:
        self._log = get_logger(__name__)
        self._db = EncryptedDatabase(db_name)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._db.connection() as conn:
            cols = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(dns_queries)"
                ).fetchall()
            }
            if cols and "game_cdn" not in cols:
                self._log.info(
                    "dns_queries: altes Schema ohne game_cdn — DROP/CREATE "
                    "(Daten ephemer)."
                )
                conn.execute("DROP TABLE dns_queries")
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX_TS)
            conn.execute(_CREATE_INDEX_PID_TS)

    def save_samples(
        self,
        samples: list[DnsQuerySample],
        *,
        retention_hours: int = _DEFAULT_RETENTION_HOURS,
    ) -> int:
        """Persistiert ein Sampling-Intervall und purged alte Eintraege.

        Returns:
            Anzahl gespeicherter Zeilen.
        """
        now = time.time()
        rows = [
            (
                now,
                s.pid,
                s.process_name,
                s.query_count,
                s.distinct_names,
                s.max_label_len,
                s.max_label_entropy,
                s.sample_query,
                s.game_cdn,
            )
            for s in samples
        ]
        cutoff = now - retention_hours * _SECONDS_PER_HOUR
        with self._db.connection() as conn:
            if rows:
                conn.executemany(_INSERT, rows)
            conn.execute("DELETE FROM dns_queries WHERE timestamp < ?", (cutoff,))
        return len(rows)

    def peak_rate_per_process(self, cutoff_ts: float) -> list[DnsRateAggregate]:
        """Pro Prozess die hoechste Query-Rate (pro Intervall) ab ``cutoff_ts``.

        Returns:
            Aggregate, absteigend nach Peak-Query-Anzahl.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT pid, process_name, MAX(query_count), "
                "MAX(max_label_len), MAX(max_label_entropy), MAX(sample_query), "
                "MAX(game_cdn) "
                "FROM dns_queries WHERE timestamp >= ? "
                "GROUP BY pid, process_name "
                "ORDER BY MAX(query_count) DESC",
                (cutoff_ts,),
            ).fetchall()
        return [
            DnsRateAggregate(
                pid=row[0],
                process_name=row[1],
                peak_query_count=int(row[2] or 0),
                max_label_len=int(row[3] or 0),
                max_label_entropy=float(row[4] or 0.0),
                sample_query=row[5] or "",
                game_cdn=row[6] or "",
            )
            for row in rows
        ]

    def purge_older_than(self, hours: int = _DEFAULT_RETENTION_HOURS) -> int:
        """Loescht Eintraege aelter als (oder genau bei) ``hours`` Stunden.

        ``<=`` statt ``<``: ``time.time`` hat auf Windows ~15 ms Granularitaet
        — bei ``hours=0`` (alles bis jetzt loeschen) koennen ein gerade
        gespeicherter Eintrag und der Purge-Cutoff in denselben Tick fallen
        (``timestamp == cutoff``). Ein striktes ``<`` loescht ihn dann NICHT ->
        flaky (test_purge). Die Boundary-Mikrosekunde ist fuer die Retention
        irrelevant, ``<=`` ist also unbedenklich + deterministisch.
        """
        cutoff = time.time() - hours * _SECONDS_PER_HOUR
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM dns_queries WHERE timestamp <= ?", (cutoff,)
            )
            return cur.rowcount or 0
