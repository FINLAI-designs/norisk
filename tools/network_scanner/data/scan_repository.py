"""
scan_repository — Persistenz für Netzwerk-Scan-Ergebnisse.

Implementiert IScanRepository mit EncryptedDatabase (SQLCipher).
Speichert Scan-Ergebnisse als JSON-Blob für einfaches Lesen/Schreiben.

Sicherheitsdesign:
  - AES-256-CBC Vollverschlüsselung via EncryptedDatabase
  - Kein sqlite3.connect direkt — nur EncryptedDatabase
  - Scan-Inhalte (Hosts, Ports) werden nicht einzeln geloggt

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.network_scanner.domain.interfaces import IScanRepository
from tools.network_scanner.domain.models import (
    HostInfo,
    NetworkScanResult,
    PortInfo,
    PortRisk,
    PortState,
)

log = get_logger(__name__)

_DB_NAME = "network_scanner"

# Tabelle heisst ``port_scans`` (nicht ``scans``) — in der
# konsolidierten ``norisk``-DB kollidierte ``scans`` sonst mit der
# gleichnamigen Tabelle des system_scanner. Der DB-Name bleibt
# "network_scanner" (EncryptedDatabase lenkt ihn in Produktion auf "norisk").
_SCHEMA = """
CREATE TABLE IF NOT EXISTS port_scans (
    scan_id       TEXT PRIMARY KEY,
    ziel          TEXT NOT NULL,
    scanner_typ   TEXT NOT NULL,
    gestartet_am  TEXT NOT NULL,
    beendet_am    TEXT NOT NULL,
    ergebnis_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_port_scans_datum
    ON port_scans(gestartet_am DESC);
"""


def _host_zu_dict(host: HostInfo) -> dict:
    """Serialisiert einen HostInfo in ein JSON-serialisierbares Dict.

    Args:
        host: Zu serialisierender Host.

    Returns:
        Dict-Repräsentation.
    """
    return {
        "host": host.host,
        "erreichbar": host.erreichbar,
        "betriebssystem": host.betriebssystem,
        "scan_dauer_s": host.scan_dauer_s,
        "offene_ports": [
            {
                "port": p.port,
                "state": p.state.value,
                "service": p.service,
                "banner": p.banner,
                "risk": p.risk.value,
                "hinweis": p.hinweis,
            }
            for p in host.offene_ports
        ],
    }


def _dict_zu_host(d: dict) -> HostInfo:
    """Deserialisiert ein Dict in einen HostInfo.

    Args:
        d: Dict-Repräsentation.

    Returns:
        HostInfo-Objekt.
    """
    ports = [
        PortInfo(
            port=p["port"],
            state=PortState(p.get("state", "unknown")),
            service=p.get("service", ""),
            banner=p.get("banner", ""),
            risk=PortRisk(p.get("risk", "info")),
            hinweis=p.get("hinweis", ""),
        )
        for p in d.get("offene_ports", [])
    ]
    return HostInfo(
        host=d["host"],
        erreichbar=d.get("erreichbar", False),
        offene_ports=ports,
        betriebssystem=d.get("betriebssystem", ""),
        scan_dauer_s=d.get("scan_dauer_s", 0.0),
    )


class ScanRepository(IScanRepository):
    """SQLCipher-Repository für Netzwerk-Scan-Ergebnisse."""

    def __init__(self) -> None:
        """Initialisiert die Datenbank und erstellt das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._init_schema()

    def _init_schema(self) -> None:
        """Erstellt die Tabellen falls sie noch nicht existieren."""
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    def speichere_scan(self, result: NetworkScanResult) -> None:
        """Speichert ein Scan-Ergebnis.

        Generiert eine UUID als scan_id wenn noch keine vorhanden.

        Args:
            result: Zu speicherndes Scan-Ergebnis.
        """
        if not result.scan_id:
            result.scan_id = str(uuid.uuid4())

        ergebnis = {
            "hosts": [_host_zu_dict(h) for h in result.hosts],
        }

        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO port_scans
                    (scan_id, ziel, scanner_typ, gestartet_am,
                     beendet_am, ergebnis_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.ziel,
                    result.scanner_typ,
                    result.gestartet_am.isoformat(),
                    result.beendet_am.isoformat(),
                    json.dumps(ergebnis),
                ),
            )
        log.debug("Scan %s gespeichert: %s", result.scan_id[:8], result.ziel)

    def lade_letzte_scans(self, limit: int = 10) -> list[NetworkScanResult]:
        """Lädt die zuletzt gespeicherten Scans.

        Args:
            limit: Maximale Anzahl zurückgegebener Scans.

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, ziel, scanner_typ,
                       gestartet_am, beendet_am, ergebnis_json
                FROM port_scans
                ORDER BY gestartet_am DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        result: list[NetworkScanResult] = []
        for row in rows:
            try:
                ergebnis = json.loads(row[5])
                hosts = [_dict_zu_host(h) for h in ergebnis.get("hosts", [])]
                result.append(
                    NetworkScanResult(
                        scan_id=row[0],
                        ziel=row[1],
                        scanner_typ=row[2],
                        gestartet_am=datetime.fromisoformat(row[3]).replace(tzinfo=UTC),
                        beendet_am=datetime.fromisoformat(row[4]).replace(tzinfo=UTC),
                        hosts=hosts,
                    )
                )
            except (ValueError, KeyError, TypeError, AttributeError, IndexError):
                pass
        return result

    def delete_scan(self, scan_id: str) -> bool:
        """Löscht einen einzelnen Scan anhand seiner ID.

        Args:
            scan_id: Eindeutiger Scan-Bezeichner.

        Returns:
            True wenn ein Eintrag gelöscht wurde, False wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM port_scans WHERE scan_id = ?", (scan_id,)
            )
            deleted = cursor.rowcount > 0
        if deleted:
            log.info("Scan gelöscht: %s", scan_id[:8])
        return deleted

    def delete_all_scans(self) -> int:
        """Löscht alle gespeicherten Scans.

        Returns:
            Anzahl gelöschter Einträge.
        """
        with self._db.connection() as conn:
            cursor = conn.execute("DELETE FROM port_scans")
            count = cursor.rowcount
        log.info("Gesamter Scan-Verlauf gelöscht: %d Einträge", count)
        return count

    def lade_scan(self, scan_id: str) -> NetworkScanResult | None:
        """Lädt einen Scan anhand seiner ID.

        Args:
            scan_id: Eindeutiger Scan-Bezeichner.

        Returns:
            Scan-Ergebnis oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT scan_id, ziel, scanner_typ,
                       gestartet_am, beendet_am, ergebnis_json
                FROM port_scans WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchone()

        if not row:
            return None
        try:
            ergebnis = json.loads(row[5])
            hosts = [_dict_zu_host(h) for h in ergebnis.get("hosts", [])]
            return NetworkScanResult(
                scan_id=row[0],
                ziel=row[1],
                scanner_typ=row[2],
                gestartet_am=datetime.fromisoformat(row[3]).replace(tzinfo=UTC),
                beendet_am=datetime.fromisoformat(row[4]).replace(tzinfo=UTC),
                hosts=hosts,
            )
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            return None
