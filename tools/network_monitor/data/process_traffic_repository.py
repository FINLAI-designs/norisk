"""network_monitor.data.process_traffic_repository — Per-Flow-Byte-History.

Persistiert die vom ETW-Subscriber (Stop-Step B) gesammelten
:class:`~tools.network_monitor.domain.models.ProcessTrafficSample` in der
verschluesselten Tool-DB ``network_monitor`` (eigene Tabelle ``process_traffic``,
getrennt von ``connection_history``).

Grain = ``(pid, remote_ip, remote_port, protocol)`` pro Intervall (Flow-artig,
vgl. NetLimiter/Sysmon). Die 24h-Aggregation liefert per-Prozess die Datenbasis
fuer die Live-View (Stop-Step C); die feinere per-IP-Granularitaet traegt die
Threshold-Alerts „High-Volume-Single-IP" und „Game-CDN" (Stop-Step D).

Retention: **48h** (DSGVO-Datenminimierung — IP-Adressen sind potenziell
personenbezogen; konsistent mit ``connection_history`` (24h) + THREAT_MODEL.md,
Marge ueber das 24h-Alert-Fenster). Eine spaetere Phase-3-Baseline (7 Tage) laeuft
auf einem separaten, privacy-sicheren Aggregat (per-Prozess, ohne IP/Pfad), NICHT
auf diesen Roh-Daten.

Pro-Feature + Admin-pflichtig (ETW-Kernel-Network) — das Gating findet im Widget
statt, die Persistenz selbst ist neutral.

Author: Patrick Riederich
Version: 2.0 Stop-Step B2 — per-(pid, remote_ip)-Grain)
"""

from __future__ import annotations

import time
from typing import Final

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IProcessTrafficRepository
from tools.network_monitor.domain.models import (
    ProcessOutbound,
    ProcessTrafficAggregate,
    ProcessTrafficSample,
    RemoteIpTraffic,
)

_DB_NAME: Final[str] = "network_monitor"
_DEFAULT_RETENTION_HOURS: Final[int] = 48
_AGGREGATE_WINDOW_HOURS: Final[int] = 24
_SECONDS_PER_HOUR: Final[int] = 3_600

_CREATE_TABLE: Final[str] = """
CREATE TABLE IF NOT EXISTS process_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    bytes_sent INTEGER NOT NULL,
    bytes_recv INTEGER NOT NULL,
    image_path TEXT NOT NULL DEFAULT ''
)
"""
# image_path: reserviert fuer Alert „Unbekannter Pfad" (D) — Population via
# Microsoft-Windows-Kernel-Process zur Erfassungszeit; bis dahin Default ''.
_CREATE_INDEX_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_process_traffic_timestamp "
    "ON process_traffic(timestamp)"
)
_CREATE_INDEX_PID_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_process_traffic_pid_ts "
    "ON process_traffic(pid, timestamp)"
)

_INSERT: Final[str] = (
    "INSERT INTO process_traffic "
    "(timestamp, pid, process_name, remote_ip, remote_port, protocol, "
    "bytes_sent, bytes_recv, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class ProcessTrafficRepository(IProcessTrafficRepository):
    """SQLCipher-Adapter fuer die Per-Flow-Byte-History."""

    def __init__(self, db_name: str = _DB_NAME) -> None:
        """Initialisiert das Repository und legt Tabelle + Indizes an.

        Args:
            db_name: Optionaler DB-Name. Default ``"network_monitor"``
                (geteilt mit der Verbindungs-History, eigene Tabelle). Tests
                koennen einen eigenen Namen uebergeben.
        """
        self._log = get_logger(__name__)
        self._db = EncryptedDatabase(db_name)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Legt das v2-Schema an; verwirft eine alte v1-Tabelle (per-PID-Grain).

        Repo-Konvention: kein ALTER-Helfer. Da die Daten ephemer sind (<=48h,
        kontinuierlich neu), wird bei Grain-Wechsel die alte Tabelle verworfen
        (DROP/CREATE) statt migriert — selbst-enthalten via ``table_info``
        (kein gemeinsames ``user_version`` der geteilten DB).
        """
        with self._db.connection() as conn:
            cols = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(process_traffic)"
                ).fetchall()
            }
            if cols and "remote_ip" not in cols:
                self._log.info(
                    "process_traffic: altes v1-Schema (per-PID) erkannt — "
                    "DROP/CREATE auf v2 (per-IP-Grain), Daten ephemer."
                )
                conn.execute("DROP TABLE process_traffic")
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX_TS)
            conn.execute(_CREATE_INDEX_PID_TS)

    def save_samples(
        self,
        samples: list[ProcessTrafficSample],
        *,
        retention_hours: int = _DEFAULT_RETENTION_HOURS,
    ) -> int:
        """Persistiert ein Sampling-Intervall und purged alte Eintraege.

        Alle Samples eines Intervalls bekommen denselben ``timestamp`` (jetzt).
        Leere Intervalle triggern nur das Retention-Purge.

        Args:
            samples: Per-Flow-Byte-Samples des aktuellen Intervalls.
            retention_hours: Aufbewahrungsdauer in Stunden.

        Returns:
            Anzahl gespeicherter Zeilen.
        """
        now = time.time()
        rows = [
            (
                now,
                s.pid,
                s.process_name,
                s.remote_ip,
                s.remote_port,
                s.protocol,
                s.bytes_sent,
                s.bytes_recv,
                s.image_path,
            )
            for s in samples
        ]
        cutoff = now - retention_hours * _SECONDS_PER_HOUR
        with self._db.connection() as conn:
            if rows:
                conn.executemany(_INSERT, rows)
            conn.execute(
                "DELETE FROM process_traffic WHERE timestamp < ?", (cutoff,)
            )
        return len(rows)

    def aggregate_last_24h(self) -> list[ProcessTrafficAggregate]:
        """Per-Prozess kumulierte Bytes der letzten 24h (ueber alle IPs).

        Returns:
            Liste der Aggregate, absteigend nach Gesamt-Bytes (sent+recv) —
            die groessten Verbraucher zuerst (Live-View-Reihenfolge).
        """
        cutoff = time.time() - _AGGREGATE_WINDOW_HOURS * _SECONDS_PER_HOUR
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT pid, process_name, "
                "SUM(bytes_sent) AS sent, SUM(bytes_recv) AS recv "
                "FROM process_traffic WHERE timestamp >= ? "
                "GROUP BY pid, process_name "
                "ORDER BY (SUM(bytes_sent) + SUM(bytes_recv)) DESC",
                (cutoff,),
            ).fetchall()
        return [
            ProcessTrafficAggregate(
                pid=row[0],
                process_name=row[1],
                total_bytes_sent=int(row[2] or 0),
                total_bytes_recv=int(row[3] or 0),
            )
            for row in rows
        ]

    def outbound_per_process_since(self, cutoff_ts: float) -> list[ProcessOutbound]:
        """Per-Prozess gesendete Bytes ab ``cutoff_ts`` (Volume-Spike/Path)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT pid, process_name, image_path, SUM(bytes_sent) "
                "FROM process_traffic WHERE timestamp >= ? "
                "GROUP BY pid, process_name, image_path "
                "ORDER BY SUM(bytes_sent) DESC",
                (cutoff_ts,),
            ).fetchall()
        return [
            ProcessOutbound(
                pid=row[0],
                process_name=row[1],
                image_path=row[2] or "",
                bytes_sent=int(row[3] or 0),
            )
            for row in rows
        ]

    def offhours_outbound_per_process(
        self, cutoff_ts: float
    ) -> list[ProcessOutbound]:
        """Per-Prozess gesendete Bytes ab ``cutoff_ts``, nur Nacht-Stunden.

        Nacht = lokale Stunde >= 22 oder < 7 (Off-Hours-Regel). ``localtime``
        nutzt die Zeitzone des laufenden Prozesses.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT pid, process_name, image_path, SUM(bytes_sent) "
                "FROM process_traffic WHERE timestamp >= ? AND ("
                "CAST(strftime('%H', timestamp, 'unixepoch', 'localtime') "
                "AS INTEGER) >= 22 OR "
                "CAST(strftime('%H', timestamp, 'unixepoch', 'localtime') "
                "AS INTEGER) < 7) "
                "GROUP BY pid, process_name, image_path "
                "ORDER BY SUM(bytes_sent) DESC",
                (cutoff_ts,),
            ).fetchall()
        return [
            ProcessOutbound(
                pid=row[0],
                process_name=row[1],
                image_path=row[2] or "",
                bytes_sent=int(row[3] or 0),
            )
            for row in rows
        ]

    def traffic_per_remote_ip_since(
        self, cutoff_ts: float
    ) -> list[RemoteIpTraffic]:
        """Per-(Prozess, Remote-IP) Bytes ab ``cutoff_ts`` (Single-IP/Game-CDN)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT pid, process_name, remote_ip, "
                "SUM(bytes_sent), SUM(bytes_recv) "
                "FROM process_traffic WHERE timestamp >= ? "
                "GROUP BY pid, process_name, remote_ip "
                "ORDER BY (SUM(bytes_sent) + SUM(bytes_recv)) DESC",
                (cutoff_ts,),
            ).fetchall()
        return [
            RemoteIpTraffic(
                pid=row[0],
                process_name=row[1],
                remote_ip=row[2],
                bytes_sent=int(row[3] or 0),
                bytes_recv=int(row[4] or 0),
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
        irrelevant, ``<=`` ist also unbedenklich + deterministisch (
        dns_query_repository, Commit 15cdbc2).

        Returns:
            Anzahl geloeschter Zeilen.
        """
        cutoff = time.time() - hours * _SECONDS_PER_HOUR
        with self._db.connection() as conn:
            cur = conn.execute(
                "DELETE FROM process_traffic WHERE timestamp <= ?", (cutoff,)
            )
            return cur.rowcount or 0
