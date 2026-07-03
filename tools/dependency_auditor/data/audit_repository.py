"""audit_repository — Persistenz der Dependency-Audit-Ergebnisse.

Speichert abgeschlossene:class:`DependencyAuditResult`-Objekte in der
EncryptedDatabase ``dependency_auditor`` (SQLCipher). Erfuellt den Port
:class:`~tools.dependency_auditor.domain.interfaces.IAuditRepository`.

Schichtzugehoerigkeit: data/ — kein GUI-Import.
"""

from __future__ import annotations

import json

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.dependency_auditor.domain.interfaces import IAuditRepository
from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    DependencyInfo,
    VulnerabilityInfo,
    VulnSeverity,
)

_log = get_logger(__name__)

#: Maximale Anzahl behaltener Audit-Laeufe (Wachstum begrenzen).
_MAX_HISTORY = 50

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_history (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp        TEXT    NOT NULL,
    source_file           TEXT    NOT NULL,
    total_dependencies    INTEGER NOT NULL,
    total_vulnerabilities INTEGER NOT NULL,
    severity_summary_json TEXT    NOT NULL,
    data_json             TEXT    NOT NULL
);
"""


class DbAuditRepository(IAuditRepository):
    """Persistiert Audit-Ergebnisse in der EncryptedDatabase 'dependency_auditor'."""

    def __init__(self) -> None:
        self._db = EncryptedDatabase("dependency_auditor")
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)

    def speichere_audit(self, result: DependencyAuditResult) -> None:
        """Persistiert ein Audit-Ergebnis (vollstaendig als JSON-Blob).

        Begrenzt die Historie anschliessend auf die juengsten ``_MAX_HISTORY``
        Eintraege.

        Args:
            result: Abgeschlossenes Audit-Ergebnis.
        """
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO audit_history "
                "(scan_timestamp, source_file, total_dependencies, "
                "total_vulnerabilities, severity_summary_json, data_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.scan_timestamp,
                    result.source_file,
                    result.total_dependencies,
                    result.total_vulnerabilities,
                    json.dumps(result.severity_summary),
                    json.dumps(_result_to_dict(result)),
                ),
            )
            conn.execute(
                "DELETE FROM audit_history WHERE id NOT IN "
                "(SELECT id FROM audit_history ORDER BY id DESC LIMIT ?)",
                (_MAX_HISTORY,),
            )

    def lade_verlauf(self, limit: int = 10) -> list[DependencyAuditResult]:
        """Laedt die letzten N Audit-Ergebnisse OHNE Vulnerabilities (neueste zuerst).

        Args:
            limit: Maximale Anzahl Eintraege.

        Returns:
            Ergebnisse mit ``vulnerabilities=[]`` (nur Aggregate + Severity-Summe).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT scan_timestamp, source_file, total_dependencies, "
                "total_vulnerabilities, severity_summary_json "
                "FROM audit_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            DependencyAuditResult(
                source_file=row[1],
                scan_timestamp=row[0],
                total_dependencies=row[2],
                total_vulnerabilities=row[3],
                severity_summary=json.loads(row[4] or "{}"),
            )
            for row in rows
        ]

    def lade_letztes_ergebnis(self) -> DependencyAuditResult | None:
        """Laedt das juengste Audit-Ergebnis VOLLSTAENDIG (inkl. Vulnerabilities).

        Returns:
            Das zuletzt gespeicherte Ergebnis, oder ``None`` wenn keines existiert.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM audit_history ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return _result_from_dict(json.loads(row[0]))


# ---------------------------------------------------------------- Serialisierung


def _dep_to_dict(dep: DependencyInfo) -> dict[str, object]:
    return {
        "name": dep.name,
        "version_pinned": dep.version_pinned,
        "version_spec": dep.version_spec,
        "line_number": dep.line_number,
        "version_installed": dep.version_installed,
    }


def _dep_from_dict(data: dict[str, object]) -> DependencyInfo:
    return DependencyInfo(
        name=data["name"],  # type: ignore[arg-type]
        version_pinned=data["version_pinned"],  # type: ignore[arg-type]
        version_spec=data["version_spec"],  # type: ignore[arg-type]
        line_number=data["line_number"],  # type: ignore[arg-type]
        version_installed=data.get("version_installed"),  # type: ignore[arg-type]
    )


def _vuln_to_dict(vuln: VulnerabilityInfo) -> dict[str, object]:
    return {
        "vuln_id": vuln.vuln_id,
        "package_name": vuln.package_name,
        "affected_versions": vuln.affected_versions,
        "fixed_version": vuln.fixed_version,
        "severity": vuln.severity.value,
        "summary": vuln.summary,
        "url": vuln.url,
    }


def _vuln_from_dict(data: dict[str, object]) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        vuln_id=data["vuln_id"],  # type: ignore[arg-type]
        package_name=data["package_name"],  # type: ignore[arg-type]
        affected_versions=data["affected_versions"],  # type: ignore[arg-type]
        fixed_version=data["fixed_version"],  # type: ignore[arg-type]
        severity=VulnSeverity(data["severity"]),
        summary=data["summary"],  # type: ignore[arg-type]
        url=data["url"],  # type: ignore[arg-type]
    )


def _result_to_dict(result: DependencyAuditResult) -> dict[str, object]:
    return {
        "source_file": result.source_file,
        "scan_timestamp": result.scan_timestamp,
        "total_dependencies": result.total_dependencies,
        "total_vulnerabilities": result.total_vulnerabilities,
        "dependencies": [_dep_to_dict(d) for d in result.dependencies],
        "vulnerabilities": [_vuln_to_dict(v) for v in result.vulnerabilities],
        "unpinned_dependencies": [_dep_to_dict(d) for d in result.unpinned_dependencies],
        "unverified_vulnerabilities": [
            _vuln_to_dict(v) for v in result.unverified_vulnerabilities
        ],
        "unverified_dependencies": [
            _dep_to_dict(d) for d in result.unverified_dependencies
        ],
        "severity_summary": result.severity_summary,
        "error": result.error,
    }


def _result_from_dict(data: dict[str, object]) -> DependencyAuditResult:
    deps = data.get("dependencies", [])
    vulns = data.get("vulnerabilities", [])
    unpinned = data.get("unpinned_dependencies", [])
    unverified_v = data.get("unverified_vulnerabilities", [])
    unverified_d = data.get("unverified_dependencies", [])
    return DependencyAuditResult(
        source_file=data["source_file"],  # type: ignore[arg-type]
        scan_timestamp=data["scan_timestamp"],  # type: ignore[arg-type]
        total_dependencies=data["total_dependencies"],  # type: ignore[arg-type]
        total_vulnerabilities=data["total_vulnerabilities"],  # type: ignore[arg-type]
        dependencies=[_dep_from_dict(d) for d in deps],  # type: ignore[arg-type]
        vulnerabilities=[_vuln_from_dict(v) for v in vulns],  # type: ignore[arg-type]
        unpinned_dependencies=[_dep_from_dict(d) for d in unpinned],  # type: ignore[arg-type]
        unverified_vulnerabilities=[
            _vuln_from_dict(v) for v in unverified_v  # type: ignore[arg-type]
        ],
        unverified_dependencies=[
            _dep_from_dict(d) for d in unverified_d  # type: ignore[arg-type]
        ],
        severity_summary=data.get("severity_summary", {}),  # type: ignore[arg-type]
        error=data.get("error"),  # type: ignore[arg-type]
    )
