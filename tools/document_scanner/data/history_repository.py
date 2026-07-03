"""
history_repository — Scan-History fuer den Document Scanner.

Pro Scan wird ein History-Eintrag geschrieben. Damit kann der User
auch nach App-Neustart sehen, was er bisher gescannt hat — Pfad zur
Original-Datei haben wir nicht (Datei lag im Drag&Drop). Wir speichern
deshalb nur Meta-Daten:

- timestamp, original_name, magika_label
- sha256, size_bytes, verdict, risk_score
- threat_count plus optional: ein JSON-Snapshot der wichtigsten
  Threat-Codes (nicht die Messages, die koennen sensible Pfade
  enthalten).

Die Datei selbst landet NICHT in der History — sie ist nach
``shutdown`` ohnehin weg (Quarantaene-Cleanup).

Schichtzugehoerigkeit: data/ — darf domain/ + core/ importieren,
keine application/gui-Imports.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.document_scanner.domain.models import DocumentScanResult, ScanVerdict

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS document_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at    TEXT NOT NULL,
    original_name TEXT NOT NULL,
    magika_label  TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    verdict       TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    threat_count  INTEGER NOT NULL,
    threat_codes  TEXT NOT NULL,
    duration_ms   REAL NOT NULL,
    type_match    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_document_scans_at
  ON document_scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_document_scans_sha256
  ON document_scans(sha256);
"""


@dataclass(frozen=True)
class HistoryEntry:
    """Eine Zeile aus der Document-Scan-History."""

    id: int
    scanned_at: datetime
    original_name: str
    magika_label: str
    sha256: str
    size_bytes: int
    verdict: ScanVerdict
    risk_score: int
    threat_count: int
    threat_codes: list[str]
    duration_ms: float
    type_match: bool


class HistoryRepository:
    """EncryptedDatabase-gestuetztes Scan-History-Repository."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        self._db = db or EncryptedDatabase("document_scanner")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._db.connection() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()

    def add(self, result: DocumentScanResult) -> int:
        """Schreibt einen Scan-Eintrag aus einem DocumentScanResult.

        Args:
            result: DocumentScanResult aus dem ScannerService.

        Returns:
            Die neu vergebene ``id`` des History-Eintrags.
        """
        return self.add_scan_record(
            scanned_at=result.scanned_at,
            original_name=result.entry.original_name,
            magika_label=result.magika_label,
            sha256=result.entry.sha256,
            size_bytes=result.entry.size_bytes,
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            threat_codes=[getattr(t, "code", "") for t in result.threats],
            duration_ms=result.duration_ms,
            type_match=result.type_match,
        )

    def add_scan_record(
        self,
        *,
        scanned_at: datetime,
        original_name: str,
        magika_label: str,
        sha256: str,
        size_bytes: int,
        verdict: str,
        risk_score: int,
        threat_codes: list[str],
        duration_ms: float,
        type_match: bool,
    ) -> int:
        """Schreibt einen Scan-Eintrag aus rohen Feldern.

        Fuer Fremd-Scanner (z. B. den PDF-Risk-Scanner-B), die dieselbe
        Datei-Scan-History speisen, aber kein:class:`DocumentScanResult` bauen.
        Es werden NUR ``threat_codes`` gespeichert — NIE Threat-Messages (die
        koennen sensible Pfade enthalten) und KEIN Original-Pfad.

        Args:
            scanned_at: Zeitpunkt des Scans (UTC).
            original_name: Datei-Name (NICHT der volle Pfad).
            magika_label: Erkannter Typ (z. B. ``"pdf"``).
            sha256: Hash der gescannten Datei.
            size_bytes: Dateigroesse.
            verdict: User-orientierter Status-String.
            risk_score: 0-100.
            threat_codes: Threat-Code-Liste (ohne Messages).
            duration_ms: Scan-Dauer.
            type_match: Magika-Typ vs. Endung konsistent?

        Returns:
            Die neu vergebene ``id`` des History-Eintrags.
        """
        codes = json.dumps(threat_codes[:50], ensure_ascii=False)
        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO document_scans
                  (scanned_at, original_name, magika_label, sha256, size_bytes,
                   verdict, risk_score, threat_count, threat_codes, duration_ms,
                   type_match)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scanned_at.isoformat(),
                    original_name,
                    magika_label,
                    sha256,
                    size_bytes,
                    verdict,
                    risk_score,
                    len(threat_codes),
                    codes,
                    duration_ms,
                    1 if type_match else 0,
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def list_recent(self, limit: int = 50) -> list[HistoryEntry]:
        """Gibt die letzten N Eintraege zurueck (neuste zuerst)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, scanned_at, original_name, magika_label, sha256,
                       size_bytes, verdict, risk_score, threat_count,
                       threat_codes, duration_ms, type_match
                FROM document_scans
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()

        result: list[HistoryEntry] = []
        for row in rows:
            try:
                codes = json.loads(row[9]) if row[9] else []
            except (TypeError, json.JSONDecodeError):
                codes = []
            try:
                verdict = ScanVerdict(row[6])
            except ValueError:
                verdict = ScanVerdict.SUSPICIOUS
            try:
                scanned_at = datetime.fromisoformat(row[1])
            except (TypeError, ValueError):
                scanned_at = datetime.now(UTC)
            result.append(
                HistoryEntry(
                    id=int(row[0]),
                    scanned_at=scanned_at,
                    original_name=row[2],
                    magika_label=row[3],
                    sha256=row[4],
                    size_bytes=int(row[5]),
                    verdict=verdict,
                    risk_score=int(row[7]),
                    threat_count=int(row[8]),
                    threat_codes=list(codes),
                    duration_ms=float(row[10]),
                    type_match=bool(row[11]),
                )
            )
        return result

    def delete(self, entry_id: int) -> None:
        """Loescht einen History-Eintrag."""
        with self._db.connection() as conn:
            conn.execute("DELETE FROM document_scans WHERE id = ?", (int(entry_id),))
            conn.commit()

    def clear(self) -> int:
        """Loescht die gesamte History. Gibt Anzahl entfernter Zeilen zurueck."""
        with self._db.connection() as conn:
            cur = conn.execute("DELETE FROM document_scans")
            conn.commit()
            return int(cur.rowcount or 0)
