"""
scan_repository — Persistenz fuer API-Security-Scan-Laeufe (SQLCipher).

Implementiert IScanRepository aus domain/interfaces.py.

Datenbankstrategie:
    - Zentrale DB: api_security.db (alle URLs in einer DB)
    - Tabellen: api_scan_laeufe, api_scan_findings
    - Findings werden mit ON DELETE CASCADE geloescht

Sicherheit:
    - Ausschliesslich parametrisierte Queries — kein String-Building
    - JSON-Felder ueber json.dumps/json.loads mit try/except (JSON-Safety)
    - Alle DBs ueber EncryptedDatabase (SQLCipher AES-256)
    - URL-Bereinigung vor Speicherung: Query-Parameter entfernt

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from urllib.parse import urlparse, urlunparse

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.api_security.domain.interfaces import IScanRepository
from tools.api_security.domain.models import Finding, OWASPCategory, ScanLauf, Severity

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# DB-Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_scan_laeufe (
    id                   TEXT PRIMARY KEY,
    target_url           TEXT NOT NULL,
    api_type             TEXT NOT NULL,
    scan_start           TEXT NOT NULL,
    scan_end             TEXT,
    total_checks         INTEGER,
    findings_count       INTEGER,
    severity_summary_json TEXT,
    erstellt_am          TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_scan_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    lauf_id        TEXT NOT NULL,
    code           TEXT NOT NULL DEFAULT '',
    category       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT,
    description    TEXT,
    evidence       TEXT,
    recommendation TEXT,
    FOREIGN KEY (lauf_id) REFERENCES api_scan_laeufe(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_laeufe_url
    ON api_scan_laeufe(target_url, scan_start DESC);

CREATE INDEX IF NOT EXISTS idx_scan_findings_lauf
    ON api_scan_findings(lauf_id);
"""

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _sanitize_url(url: str) -> str:
    """Entfernt Query-Parameter und Fragment — koennen API-Keys enthalten.

    Args:
        url: Vollstaendige URL.

    Returns:
        URL ohne Query-String und Fragment.
    """
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def _lauf_to_insert_params(lauf: ScanLauf) -> tuple:
    """Parameter fuer INSERT in api_scan_laeufe."""
    return (
        lauf.id,
        lauf.target_url,
        lauf.api_type,
        lauf.scan_start,
        lauf.scan_end,
        lauf.total_checks,
        lauf.findings_count,
        json.dumps(lauf.severity_summary),
    )


def _finding_to_insert_params(lauf_id: str, f: Finding) -> tuple:
    """Parameter fuer INSERT in api_scan_findings."""
    return (
        lauf_id,
        f.code,
        f.owasp.value,
        f.severity.value,
        f.title,
        f.description,
        f.detail,
        f.remediation,
    )


def _row_to_finding(row: tuple) -> Finding:
    """Wandelt eine DB-Zeile (api_scan_findings) in ein Finding-Objekt um."""
    (
        _id,
        _lauf_id,
        code,
        category,
        severity,
        title,
        description,
        evidence,
        recommendation,
    ) = row
    try:
        sev = Severity(severity)
    except ValueError:
        sev = Severity.INFO
    try:
        owasp = OWASPCategory(category)
    except ValueError:
        owasp = OWASPCategory.API8
    return Finding(
        code=code or "",
        title=title or "",
        description=description or "",
        severity=sev,
        owasp=owasp,
        detail=evidence or "",
        remediation=recommendation or "",
    )


def _row_to_lauf(row: tuple, findings: list[Finding]) -> ScanLauf:
    """Wandelt eine DB-Zeile (api_scan_laeufe) + Findings in ScanLauf um."""
    (
        id_,
        target_url,
        api_type,
        scan_start,
        scan_end,
        total_checks,
        findings_count,
        severity_summary_json,
        _erstellt_am,
    ) = row
    try:
        severity_summary = (
            json.loads(severity_summary_json) if severity_summary_json else {}
        )
    except (json.JSONDecodeError, TypeError):
        _log.warning(
            "scan_repository: korruptes severity_summary JSON fuer Lauf %r", id_
        )
        severity_summary = {}
    return ScanLauf(
        id=id_,
        target_url=target_url,
        api_type=api_type or "",
        scan_start=scan_start,
        scan_end=scan_end or "",
        total_checks=total_checks or 0,
        findings_count=findings_count or 0,
        severity_summary=severity_summary,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# ScanRepository
# ---------------------------------------------------------------------------

_SQL_SELECT_LAEUFE = (
    "SELECT id, target_url, api_type, scan_start, scan_end,"
    " total_checks, findings_count, severity_summary_json, erstellt_am"
    " FROM api_scan_laeufe"
)
_SQL_SELECT_FINDINGS = (
    "SELECT id, lauf_id, code, category, severity,"
    " title, description, evidence, recommendation"
    " FROM api_scan_findings"
)


class ScanRepository(IScanRepository):
    """Persistenz fuer API-Security-Scan-Laeufe in der zentralen api_security.db.

    Alle Scan-Laeufe aller URLs werden in einer gemeinsamen verschluesselten
    Datenbank gespeichert.

    Raises:
        FinLaiDatabaseError: Bei Datenbankfehler (aus EncryptedDatabase).
    """

    def __init__(self) -> None:
        """Initialisiert das Repository und erstellt das Schema."""
        self._db = EncryptedDatabase("api_security")
        self._db.init_schema(_SCHEMA)
        _log.debug("ScanRepository bereit.")

    # ------------------------------------------------------------------
    # IScanRepository — Schreib-Operationen
    # ------------------------------------------------------------------

    def speichere_lauf(self, lauf: ScanLauf) -> None:
        """Persistiert einen abgeschlossenen Scan-Lauf mit allen Findings.

        URL wird vor Speicherung bereinigt (Query-Parameter entfernt).
        Bereits gespeicherte Laeufe werden nicht ueberschrieben (PRIMARY KEY).

        Args:
            lauf: Abgeschlossener ScanLauf.
        """
        # Sichere URL — keine Query-Parameter
        sicherer_lauf = ScanLauf(
            id=lauf.id,
            target_url=_sanitize_url(lauf.target_url),
            api_type=lauf.api_type,
            scan_start=lauf.scan_start,
            scan_end=lauf.scan_end,
            total_checks=lauf.total_checks,
            findings_count=lauf.findings_count,
            severity_summary=lauf.severity_summary,
            findings=lauf.findings,
        )

        with self._db.connection() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO api_scan_laeufe
                   (id, target_url, api_type, scan_start, scan_end,
                    total_checks, findings_count, severity_summary_json)
                   VALUES (?,?,?,?,?,?,?,?)""",  # noqa: S608
                _lauf_to_insert_params(sicherer_lauf),
            )
            if sicherer_lauf.findings:
                conn.executemany(
                    """INSERT INTO api_scan_findings
                       (lauf_id, code, category, severity, title,
                        description, evidence, recommendation)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    [
                        _finding_to_insert_params(sicherer_lauf.id, f)
                        for f in sicherer_lauf.findings
                    ],
                )

        _log.debug(
            "Scan-Lauf %r gespeichert: url=%s findings=%d",
            sicherer_lauf.id,
            sicherer_lauf.target_url,
            sicherer_lauf.findings_count,
        )

    def loesche_lauf(self, lauf_id: str) -> None:
        """Loescht einen Scan-Lauf inkl. aller Findings (CASCADE).

        Args:
            lauf_id: UUID des zu loeschenden Laufs.
        """
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM api_scan_laeufe WHERE id = ?",
                (lauf_id,),
            )
        _log.debug("Scan-Lauf %r geloescht.", lauf_id)

    # ------------------------------------------------------------------
    # IScanRepository — Lese-Operationen
    # ------------------------------------------------------------------

    def lade_verlauf(
        self,
        target_url: str | None = None,
        limit: int = 20,
    ) -> list[ScanLauf]:
        """Laedt die letzten N Scan-Laeufe ohne Findings (nur Metadaten).

        Args:
            target_url: Optionaler URL-Filter. None = alle URLs.
            limit: Maximale Anzahl Eintraege (Standard: 20).

        Returns:
            Liste der ScanLauf-Objekte (findings=[]), neueste zuerst.
        """
        if target_url:
            sql = (
                _SQL_SELECT_LAEUFE
                + " WHERE target_url = ? ORDER BY scan_start DESC LIMIT ?"
            )
            params: tuple = (_sanitize_url(target_url), limit)
        else:
            sql = _SQL_SELECT_LAEUFE + " ORDER BY scan_start DESC LIMIT ?"
            params = (limit,)

        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()  # noqa: S608

        return [_row_to_lauf(r, []) for r in rows]

    def lade_lauf(self, lauf_id: str) -> ScanLauf | None:
        """Laedt einen einzelnen Scan-Lauf vollstaendig (inkl. Findings).

        Args:
            lauf_id: UUID des Laufs.

        Returns:
            ScanLauf mit Findings oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            lauf_row = conn.execute(
                _SQL_SELECT_LAEUFE + " WHERE id = ?",  # noqa: S608
                (lauf_id,),
            ).fetchone()

            if lauf_row is None:
                return None

            finding_rows = conn.execute(
                _SQL_SELECT_FINDINGS + " WHERE lauf_id = ? ORDER BY id",  # noqa: S608
                (lauf_id,),
            ).fetchall()

        findings = [_row_to_finding(r) for r in finding_rows]
        return _row_to_lauf(lauf_row, findings)

    def lade_alle_urls(self) -> list[str]:
        """Gibt alle distinct gescannten URLs zurueck (alphabetisch).

        Returns:
            Sortierte Liste aller URLs ohne Duplikate.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_url FROM api_scan_laeufe ORDER BY target_url"
            ).fetchall()
        return [r[0] for r in rows]
