"""
scan_service — Orchestriert den PDF-Deep-Scan für das GUI-Tool.

Der Service ist ein dünner Wrapper um ``validate_import(..., deep_scan=True)``
und liefert ein ``PdfScanResult`` zurück. Er ist getrennt vom GUI-Widget,
damit er in Tests ohne Qt-Stack ausführbar ist.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.security import ImportType, validate_import
from tools.pdf_risk_scanner.domain.models import PdfScanResult, status_from_report

if TYPE_CHECKING:
    from tools.document_scanner.data.history_repository import HistoryRepository

_log = get_logger(__name__)

_HASH_CHUNK = 65536


class PdfScanService:
    """Führt Deep-Scans auf PDFs aus und kapselt das Ergebnis."""

    def __init__(self, history_repo: HistoryRepository | None = None) -> None:
        """Initialisiert den Service.

        Args:
            history_repo: Optionales Datei-Scan-History-Repository-B).
                Default: lazy beim ersten Scan gebaut. Persistiert den PDF-Scan
                in die gemeinsame ``document_scanner``-DB, damit das Cockpit den
                PDF-Scan in der Datei-Scanner-Frische sieht.
        """
        self._history_repo = history_repo

    def scan(self, path: str | Path) -> PdfScanResult:
        """Prüft eine PDF-Datei und gibt ein ``PdfScanResult`` zurück.

        Args:
            path: Pfad zu einer PDF-Datei.

        Returns:
            ``PdfScanResult`` mit ``ValidationReport`` und aggregiertem
            ``ScanStatus``.

        Raises:
            FileNotFoundError: Wenn die Datei nicht existiert.
            ValueError: Bei Path-Traversal-Indikatoren.
        """
        report = validate_import(path, ImportType.PDF, deep_scan=True)
        status = status_from_report(report)
        _log.info(
            "PDF-Scan %s: status=%s, score=%d, threats=%d",
            Path(path).name,
            status.value,
            report.risk_score,
            len(report.threats),
        )
        result = PdfScanResult(
            path=report.path,
            report=report,
            status=status,
            duration_ms=report.duration_ms,
        )
        self._persistiere(path, report, status)
        return result

    def _persistiere(self, path: str | Path, report: object, status: object) -> None:
        """Schreibt den Scan fail-soft in die gemeinsame Datei-Scan-History.

        B: damit der Cockpit-Datei-Scanner auch PDF-Scans als Frische
        sieht. Ein Persistenz-Fehler darf den Scan NIE scheitern lassen. DSGVO:
        nur Datei-NAME (kein Pfad) + threat_codes (keine Messages).
        """
        try:
            repo = self._history_repo
            if repo is None:
                from tools.document_scanner.data.history_repository import (  # noqa: PLC0415
                    HistoryRepository,
                )

                repo = HistoryRepository()
            p = Path(path)
            sha = hashlib.sha256()
            size = 0
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
                    sha.update(chunk)
                    size += len(chunk)
            repo.add_scan_record(
                scanned_at=datetime.now(UTC),
                original_name=p.name,
                magika_label="pdf",
                sha256=sha.hexdigest(),
                size_bytes=size,
                verdict=status.value,  # type: ignore[attr-defined]
                risk_score=report.risk_score,  # type: ignore[attr-defined]
                threat_codes=[getattr(t, "code", "") for t in report.threats],  # type: ignore[attr-defined]
                duration_ms=report.duration_ms,  # type: ignore[attr-defined]
                type_match=True,
            )
        except Exception as exc:  # noqa: BLE001 -- Persistenz nie blockierend
            _log.debug("PDF-Scan-Persistenz uebersprungen (%s)", type(exc).__name__)
