"""
pdf_export_service — Fassade für den Dashboard-PDF-Export.

Bündelt Dateiname-Generierung, Aggregator-Aufruf (optional), PDF-Bau und
Audit-Log-Eintrag in einer einzigen Schnittstelle, damit die GUI nur eine
Methode zu kennen braucht.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from core.audit_log import AuditLogger
from core.logger import get_logger
from tools.norisk_dashboard.application.dashboard_pdf_builder import (
    DashboardPdfBuilder,
)
from tools.norisk_dashboard.domain.models import DashboardData

log = get_logger(__name__)

_DEFAULT_DIR = Path.home() / "Documents" / "NoRisk-Reports"
_AUDIT_ACTION = "DASHBOARD_PDF_EXPORTED"


def default_output_dir() -> Path:
    """Gibt das Standard-Zielverzeichnis zurück.

    Wird beim ersten Zugriff angelegt — damit Speichern-Dialoge einen
    existierenden Pfad vorschlagen können.
    """
    _DEFAULT_DIR.mkdir(parents=True, exist_ok=True)
    return _DEFAULT_DIR


def default_filename(generated_at: datetime | None = None) -> str:
    """Erzeugt den Standard-Dateinamen: ``NoRisk-Dashboard-Report_YYYY-MM-DD_HHMM.pdf``."""
    ts = generated_at or datetime.now()
    return f"NoRisk-Dashboard-Report_{ts:%Y-%m-%d_%H%M}.pdf"


class PdfExportService:
    """Bindet DashboardData → PDF → Audit-Log zusammen.

    Attributes:
        _audit: Audit-Logger-Instanz (injizierbar für Tests).
    """

    def __init__(self, audit: AuditLogger | None = None) -> None:
        self._audit = audit or AuditLogger()

    # ------------------------------------------------------------------

    def export(
        self,
        data: DashboardData,
        output_path: str | Path,
        target_name: str = "Allgemein",
        compliance_rows: list | None = None,
    ) -> Path:
        """Schreibt den Dashboard-Report als PDF und loggt den Export.

        Args:
            data: Aggregierter Dashboard-Snapshot.
            output_path: Zielpfad (Datei). Eltern-Verzeichnis wird angelegt.
            target_name: Scope-Name (z.B. Kundenname), erscheint im Header.
            compliance_rows: Optionale ``ComplianceRow``-Liste W3b). Ist sie
                gesetzt, haengt der Report eine indikative Regulatorik-Sektion an.

        Returns:
            Geschriebener Pfad.

        Raises:
            OSError: Bei Schreibfehlern.
        """
        path = Path(output_path)
        generated_at = data.generated or datetime.now()
        builder = DashboardPdfBuilder(
            output_path=path,
            data=data,
            target_name=target_name,
            generated_at=generated_at,
            compliance_rows=compliance_rows,
        )
        result = builder.build()
        self._audit_export(result, data, target_name, generated_at)
        return result

    # ------------------------------------------------------------------

    def _audit_export(
        self,
        path: Path,
        data: DashboardData,
        target_name: str,
        generated_at: datetime,
    ) -> None:
        """Schreibt einen Audit-Eintrag mit anonymisiertem Dateinamen."""
        try:
            file_size = path.stat().st_size
        except OSError:
            file_size = 0
        try:
            self._audit.log_action(
                _AUDIT_ACTION,
                {
                    "time_range": data.time_range.value,
                    "target_scope_hash": _short_hash(target_name),
                    "filename_hash": _short_hash(path.name),
                    "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%S"),
                    "file_size_bytes": file_size,
                    "section_counts": {
                        "changes": len(data.changes),
                        "cves": len(data.cves),
                        "scans": len(data.scans),
                        "breakdown": len(data.breakdown),
                        "trend_points": len(data.trend),
                        "org_tiles": len(data.org.tiles) if data.org else 0,
                    },
                },
                tool="norisk_dashboard",
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Audit-Log für PDF-Export fehlgeschlagen: %s", exc)


def _short_hash(value: str) -> str:
    """SHA-256-Kurzform für Audit-Pseudonymisierung (12 Zeichen)."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:12]
