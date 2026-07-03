"""cert_repository — Persistenz für überwachte Domains und Scan-Ergebnisse.

Speichert die Liste der überwachten Domains und Scan-Historien
in der EncryptedDatabase 'cert_monitor'.

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.cert_monitor.domain.models import CertInfo, CertStatus

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cert_domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
    port        INTEGER NOT NULL DEFAULT 443,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(domain, port)
);

CREATE TABLE IF NOT EXISTS cert_scan_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT    NOT NULL,
    port                INTEGER NOT NULL DEFAULT 443,
    letzte_pruefung     TEXT,
    gueltig_bis         TEXT,
    tage_verbleibend    INTEGER,
    tls_version         TEXT,
    cipher_name         TEXT,
    cipher_bits         INTEGER,
    ist_self_signed     INTEGER DEFAULT 0,
    aussteller          TEXT,
    san_domains_json    TEXT,
    serial_number       TEXT,
    status              TEXT,
    findings_json       TEXT,
    fehler_meldung      TEXT,
    UNIQUE(domain, port)
);
"""


class CertRepository:
    """Verwaltet überwachte Domains und Scan-Historien.

    Nutzt EncryptedDatabase 'cert_monitor' (SQLCipher AES-256).
    """

    def __init__(self) -> None:
        self._db = EncryptedDatabase("cert_monitor")
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Domain-Liste
    # ------------------------------------------------------------------

    def lade_domains(self) -> list[tuple[str, int]]:
        """Lädt alle überwachten Domains.

        Returns:
            Geordnete Liste von (domain, port)-Tupeln.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT domain, port FROM cert_domains ORDER BY sort_order, id"
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def fuge_domain_hinzu(self, domain: str, port: int = 443) -> None:
        """Fügt eine Domain zur Überwachungsliste hinzu.

        Args:
            domain: Hostname.
            port: TLS-Port.
        """
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO cert_domains (domain, port, sort_order) "
                "VALUES (?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM cert_domains))",
                (domain, port),
            )

    def entferne_domain(self, domain: str, port: int = 443) -> None:
        """Entfernt eine Domain aus der Überwachungsliste.

        Args:
            domain: Hostname.
            port: TLS-Port.
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM cert_domains WHERE domain = ? AND port = ?",
                (domain, port),
            )
            conn.execute(
                "DELETE FROM cert_scan_results WHERE domain = ? AND port = ?",
                (domain, port),
            )

    # ------------------------------------------------------------------
    # Scan-Ergebnisse
    # ------------------------------------------------------------------

    def speichere_ergebnis(self, cert: CertInfo) -> None:
        """Speichert oder aktualisiert ein Scan-Ergebnis.

        Args:
            cert: CertInfo mit den Scan-Ergebnissen.
        """
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cert_scan_results "
                "(domain, port, letzte_pruefung, gueltig_bis, tage_verbleibend, "
                "tls_version, cipher_name, cipher_bits, ist_self_signed, aussteller, "
                "san_domains_json, serial_number, status, findings_json, fehler_meldung) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cert.domain,
                    cert.port,
                    cert.letzte_pruefung,
                    cert.gueltig_bis,
                    cert.tage_verbleibend,
                    cert.tls_version,
                    cert.cipher_name,
                    cert.cipher_bits,
                    int(cert.ist_self_signed),
                    cert.aussteller,
                    json.dumps(cert.san_domains),
                    cert.serial_number,
                    cert.status.value,
                    json.dumps(cert.findings),
                    cert.fehler_meldung,
                ),
            )

    def lade_ergebnisse(self) -> list[CertInfo]:
        """Lädt alle gespeicherten Scan-Ergebnisse.

        Returns:
            Liste der CertInfo-Objekte (leer wenn keine Daten).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT domain, port, letzte_pruefung, gueltig_bis, tage_verbleibend, "
                "tls_version, cipher_name, cipher_bits, ist_self_signed, aussteller, "
                "san_domains_json, serial_number, status, findings_json, fehler_meldung "
                "FROM cert_scan_results ORDER BY domain"
            ).fetchall()

        result = []
        for r in rows:
            try:
                status = CertStatus(r[12]) if r[12] else CertStatus.UNBEKANNT
            except ValueError:
                status = CertStatus.UNBEKANNT
            result.append(
                CertInfo(
                    domain=r[0],
                    port=r[1],
                    letzte_pruefung=r[2] or "",
                    gueltig_bis=r[3] or "",
                    tage_verbleibend=r[4] or 0,
                    tls_version=r[5] or "",
                    cipher_name=r[6] or "",
                    cipher_bits=r[7] or 0,
                    ist_self_signed=bool(r[8]),
                    aussteller=r[9] or "",
                    san_domains=json.loads(r[10] or "[]"),
                    serial_number=r[11] or "",
                    status=status,
                    findings=json.loads(r[13] or "[]"),
                    fehler_meldung=r[14] or "",
                )
            )
        return result
