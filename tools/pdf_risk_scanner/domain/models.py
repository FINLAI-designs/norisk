"""
models — Domain-Modelle für den PDF-Risk-Scanner.

Die eigentliche Scan-Logik lebt in ``core.security.import_validator``
und ``core.security.pdf_deep_scanner``. Dieses Modul definiert nur die
Anzeige-Tupel, mit denen das GUI-Widget arbeitet.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from core.security.validation_report import Severity, ValidationReport


class ScanStatus(Enum):
    """Gesamt-Status eines PDF-Scans in der Tabelle."""

    SAFE = "safe"  # kein Threat >= HIGH
    WARN = "warn"  # mindestens HIGH, aber nicht CRITICAL
    BLOCK = "block"  # CRITICAL — safe_to_parse=False


@dataclass(frozen=True)
class PdfScanResult:
    """Ergebnis eines einzelnen PDF-Scans.

    Attributes:
        path: Absoluter Pfad der untersuchten Datei.
        report: Vollständiger ``ValidationReport`` aus dem Deep-Scan.
        status: Zusammengefasster Status für die Tabellen-Ansicht.
        duration_ms: Gesamt-Dauer des Scans (entspricht
            ``report.duration_ms``, als Convenience-Feld).
    """

    path: Path
    report: ValidationReport
    status: ScanStatus
    duration_ms: float


def status_from_report(report: ValidationReport) -> ScanStatus:
    """Leitet den Tabellen-Status aus dem Report ab.

    Args:
        report: Abgeschlossener ValidationReport.

    Returns:
        ``ScanStatus.BLOCK`` bei nicht-parsebaren (CRITICAL) Reports,
        ``ScanStatus.WARN`` bei HIGH-Threats ODER unvollständiger Inspektion
        (Fail-Closed), sonst ``ScanStatus.SAFE``.
    """
    if not report.safe_to_parse:
        return ScanStatus.BLOCK
    if report.has_severity(Severity.HIGH):
        return ScanStatus.WARN
    # Fail-Closed: konnte das PDF nicht (vollständig) geprüft werden
    # (z.B. pypdf-Parse-Abbruch, Verschlüsselung), nie „sicher" melden.
    if report.scan_incomplete():
        return ScanStatus.WARN
    return ScanStatus.SAFE
