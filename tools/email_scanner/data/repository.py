"""
repository — SQLCipher-Persistenz für Mail-Reports + Attachment-Quarantäne.

Zwei Tabellen:

- ``mail_reports``: Meta-Zeile pro gescannter Mail (Pfad, Betreff,
  Absender, Status, Score, Scan-Zeitpunkt).
- ``attachment_quarantine``: Read-only-Blobs für später abgerufene
  Anhänge. Jeder Eintrag ist über seinen SHA-256-Hash adressierbar,
  Duplikate werden automatisch dedupliziert.

Es gibt **kein** Update-API für Quarantäne-Einträge — read-only,
wie im Spec gefordert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.email_scanner.domain.models import (
    Attachment,
    AttachmentReport,
    MailReport,
    MailScanStatus,
)

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mail_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path     TEXT    NOT NULL,
    subject         TEXT,
    from_addr       TEXT,
    to_addrs_json   TEXT,
    scan_ts         TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    fehler          TEXT,
    attachments_summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_mail_reports_scan_ts ON mail_reports(scan_ts);
CREATE INDEX IF NOT EXISTS idx_mail_reports_status  ON mail_reports(status);

CREATE TABLE IF NOT EXISTS attachment_quarantine (
    sha256          TEXT    PRIMARY KEY,
    filename        TEXT    NOT NULL,
    content_type    TEXT    NOT NULL,
    size            INTEGER NOT NULL,
    quarantined_ts  TEXT    NOT NULL,
    data            BLOB    NOT NULL
);
"""


class EmailScannerRepository:
    """Speichert Mail-Reports und Attachment-Quarantäne verschlüsselt."""

    def __init__(self, db: EncryptedDatabase | None = None) -> None:
        """Initialisiert die Datenbank.

        Args:
            db: Optional eine vorbereitete EncryptedDatabase (für Tests
                mit einem isolierten Schema-Namen). Standard: DB
                ``email_scanner``.
        """
        self._db = db or EncryptedDatabase("email_scanner")
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Mail-Reports
    # ------------------------------------------------------------------

    def speichere_report(self, report: MailReport) -> int:
        """Legt eine Zeile in ``mail_reports`` an.

        Args:
            report: Der zu speichernde Mail-Report.

        Returns:
            Die neu vergebene DB-ID.
        """
        subject = report.mail.subject if report.mail else ""
        from_addr = report.mail.from_addr if report.mail else ""
        to_addrs = report.mail.to_addrs if report.mail else []
        summary = [
            {
                "filename": r.attachment.filename,
                "sha256": r.attachment.sha256,
                "size": r.attachment.size,
                "status": r.status.value,
                "score": r.validation.risk_score,
                "threats": [
                    {"code": t.code, "severity": t.severity.value, "message": t.message}
                    for t in r.validation.threats
                ],
            }
            for r in report.attachment_reports
        ]

        with self._db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO mail_reports(
                    source_path, subject, from_addr, to_addrs_json,
                    scan_ts, status, risk_score, fehler,
                    attachments_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.source_path,
                    subject,
                    from_addr,
                    json.dumps(to_addrs, ensure_ascii=False),
                    datetime.now().isoformat(timespec="seconds"),
                    report.status.value,
                    report.risk_score,
                    report.fehler,
                    json.dumps(summary, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid or 0)

    def lade_reports(self, *, limit: int = 500) -> list[dict]:
        """Listet gespeicherte Reports (neueste zuerst).

        Args:
            limit: Maximalzahl an Zeilen.

        Returns:
            Liste von Dicts mit den wichtigsten Spalten.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, source_path, subject, from_addr, scan_ts, status,
                       risk_score, fehler, attachments_summary_json
                FROM mail_reports
                ORDER BY scan_ts DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        ergebnisse: list[dict] = []
        for row in rows:
            summary_raw = row[8] or "[]"
            try:
                summary = json.loads(summary_raw)
            except json.JSONDecodeError:
                summary = []
            ergebnisse.append(
                {
                    "id": row[0],
                    "source_path": row[1],
                    "subject": row[2] or "",
                    "from_addr": row[3] or "",
                    "scan_ts": row[4],
                    "status": MailScanStatus(row[5]),
                    "risk_score": int(row[6] or 0),
                    "fehler": row[7] or "",
                    "attachments_summary": summary,
                }
            )
        return ergebnisse

    def loesche_report(self, report_id: int) -> None:
        """Löscht einen einzelnen Mail-Report (Quarantäne bleibt erhalten)."""
        with self._db.connection() as conn:
            conn.execute("DELETE FROM mail_reports WHERE id = ?", (report_id,))

    # ------------------------------------------------------------------
    # Attachment-Quarantäne
    # ------------------------------------------------------------------

    def quarantaene_speichern(self, report: AttachmentReport) -> str:
        """Legt ein Attachment in die Read-only-Quarantäne.

        Existiert bereits ein Eintrag mit demselben SHA-256, wird er
        nicht überschrieben — die Quarantäne ist append-only.

        Args:
            report: ``AttachmentReport`` mit den zu sichernden Bytes.

        Returns:
            SHA-256 des quarantierten Attachments.
        """
        att: Attachment = report.attachment
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO attachment_quarantine(
                    sha256, filename, content_type, size,
                    quarantined_ts, data
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    att.sha256,
                    att.filename,
                    att.content_type,
                    att.size,
                    datetime.now().isoformat(timespec="seconds"),
                    att.data,
                ),
            )
        return att.sha256

    def lade_quarantaene(self) -> list[dict]:
        """Listet Quarantäne-Metadaten (ohne Blobs)."""
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT sha256, filename, content_type, size, quarantined_ts
                FROM attachment_quarantine
                ORDER BY quarantined_ts DESC
                """
            ).fetchall()
        return [
            {
                "sha256": r[0],
                "filename": r[1],
                "content_type": r[2],
                "size": r[3],
                "quarantined_ts": r[4],
            }
            for r in rows
        ]

    def lade_blob(self, sha256: str) -> bytes | None:
        """Liefert den Blob eines quarantierten Attachments."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data FROM attachment_quarantine WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
        return bytes(row[0]) if row else None
