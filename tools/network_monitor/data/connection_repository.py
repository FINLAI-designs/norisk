"""network_monitor.data.connection_repository — SQLCipher-History (Pro-Feature).

Persistiert Verbindungs-Snapshots in der verschlüsselten Tool-Datenbank
``network_monitor``. Rollierende 24h-Retention. Wird nur aufgerufen wenn
der Nutzer das Pro-Feature lizenziert hat — das Gating selbst findet im
Widget statt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IConnectionRepository
from tools.network_monitor.domain.models import ConnectionInfo, Conversation

_DB_NAME = "network_monitor"
_DEFAULT_RETENTION_HOURS = 24
_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    local_port INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    status TEXT NOT NULL,
    suspicious INTEGER NOT NULL,
    suspicious_reason TEXT NOT NULL
)
"""
_CREATE_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_history_timestamp "
    "ON connection_history(timestamp)"
)


def _parse_int_csv(value: str | None) -> tuple[int, ...]:
    """Parst eine ``GROUP_CONCAT``-Ganzzahl-Liste zu einem sortierten Int-Tupel.

    Nicht-parsebare Tokens werden übersprungen (resilient gegen unerwartete Werte).
    """
    if not value:
        return ()
    out: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if token.isdigit():
            out.add(int(token))
    return tuple(sorted(out))


def _parse_str_csv(value: str | None) -> tuple[str, ...]:
    """Parst eine ``GROUP_CONCAT``-String-Liste zu einem sortierten String-Tupel."""
    if not value:
        return ()
    return tuple(sorted({t.strip() for t in value.split(",") if t.strip()}))


class ConnectionHistoryRepository(IConnectionRepository):
    """SQLCipher-Adapter für die Verbindungs-Historie."""

    def __init__(self, db_name: str = _DB_NAME) -> None:
        """Initialisiert das Repository und erstellt Tabelle + Index.

        Args:
            db_name: Optionaler DB-Name. Default ``"network_monitor"``. Tests
                können einen eigenen Namen übergeben.
        """
        self._log = get_logger(__name__)
        self._db = EncryptedDatabase(db_name)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._db.connection() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)

    def save_snapshot(self, connections: list[ConnectionInfo]) -> None:
        """Speichert einen Snapshot + räumt alte Einträge auf.

        Args:
            connections: Aktuelle aktive Verbindungen.
        """
        if not connections:
            self.purge_older_than(_DEFAULT_RETENTION_HOURS)
            return

        now = time.time()
        rows = [
            (
                now,
                c.remote_ip,
                c.remote_port,
                c.local_port,
                c.pid,
                c.process_name,
                c.status,
                1 if c.suspicious else 0,
                c.suspicious_reason,
            )
            for c in connections
        ]
        with self._db.connection() as conn:
            conn.executemany(
                "INSERT INTO connection_history "
                "(timestamp, remote_ip, remote_port, local_port, pid, "
                "process_name, status, suspicious, suspicious_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            cutoff = now - (_DEFAULT_RETENTION_HOURS * 3600)
            conn.execute(
                "DELETE FROM connection_history WHERE timestamp < ?",
                (cutoff,),
            )

    def load_recent(
        self, hours: int = _DEFAULT_RETENTION_HOURS
    ) -> list[tuple[float, ConnectionInfo]]:
        """Lädt Verbindungen der letzten ``hours`` Stunden (absteigend sortiert)."""
        cutoff = time.time() - (hours * 3600)
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT timestamp, remote_ip, remote_port, local_port, pid, "
                "process_name, status, suspicious, suspicious_reason "
                "FROM connection_history WHERE timestamp >= ? "
                "ORDER BY timestamp DESC",
                (cutoff,),
            ).fetchall()
        return [
            (
                row[0],
                ConnectionInfo(
                    remote_ip=row[1],
                    remote_port=row[2],
                    local_port=row[3],
                    pid=row[4],
                    process_name=row[5],
                    status=row[6],
                    suspicious=bool(row[7]),
                    suspicious_reason=row[8],
                ),
            )
            for row in rows
        ]

    def aggregate_conversations(
        self, hours: int = _DEFAULT_RETENTION_HOURS
    ) -> list[Conversation]:
        """Verdichtet die Historie per SQL zu (Prozess, Ziel-IP)-Konversationen (Phase 5).

        Eine ``GROUP BY (process_name, remote_ip)``-Aggregation über das Zeitfenster:
        Anzahl Snapshots, distinkte Ports/Status (``GROUP_CONCAT DISTINCT``), ob je
        verdächtig (``MAX(suspicious)``) inkl. repräsentativem Grund, erster/letzter
        Zeitstempel. Häufigste Konversation zuerst.

        Args:
            hours: Zeitfenster in Stunden (Default 24).

        Returns:
            Liste aggregierter:class:`Conversation`-Objekte.
        """
        cutoff = time.time() - (hours * 3600)
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT process_name, remote_ip, COUNT(*) AS cnt, "
                "GROUP_CONCAT(DISTINCT remote_port) AS ports, "
                "GROUP_CONCAT(DISTINCT status) AS statuses, "
                "MAX(suspicious) AS susp, "
                "MAX(CASE WHEN suspicious = 1 THEN suspicious_reason ELSE '' END) "
                "AS reason, "
                "MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts "
                "FROM connection_history WHERE timestamp >= ? "
                "GROUP BY process_name, remote_ip ORDER BY cnt DESC",
                (cutoff,),
            ).fetchall()
        return [
            Conversation(
                process_name=row[0],
                remote_ip=row[1],
                connection_count=row[2],
                ports=_parse_int_csv(row[3]),
                statuses=_parse_str_csv(row[4]),
                suspicious=bool(row[5]),
                suspicious_reason=row[6] or "",
                first_seen=row[7] or 0.0,
                last_seen=row[8] or 0.0,
            )
            for row in rows
        ]

    def purge_older_than(self, hours: int = _DEFAULT_RETENTION_HOURS) -> int:
        """Löscht Einträge älter als ``hours`` Stunden.

        Returns:
            Anzahl gelöschter Zeilen.
        """
        cutoff = time.time() - (hours * 3600)
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM connection_history WHERE timestamp < ?", (cutoff,)
            )
            return cur.rowcount or 0
