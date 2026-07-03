"""
pdf_validator — Strukturelle PDF-Prüfung (Layer 0 des PDF-Risk-Scanners).

Bewusst nur strukturelle Checks; tiefe Objekt-Analyse (JavaScript,
OpenAction, Launch, EmbeddedFile) gehört in das separate
``tools.pdf_risk_scanner``-Tool (Prompt 2). Dies hier ist das schnelle
Core-Gate vor jedem PDF-Parser.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.security.magika_adapter import identify
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

# PDFs dürfen bis 500 MB — große gescannte Steuerakten sind normal
MAX_PDF_SIZE_BYTES: int = 500 * 1024 * 1024

# PDF-Dateien beginnen mit "%PDF-" (4 Bytes + Version)
PDF_MAGIC_HEADER: bytes = b"%PDF-"

# PDF-EOF-Marker — muss innerhalb der letzten 1024 Bytes stehen
PDF_EOF_MARKER: bytes = b"%%EOF"
PDF_EOF_SEARCH_WINDOW: int = 1024


class PdfValidator(SubValidator):
    """Strukturelle Prüfung: Magika, Magic-Header, Größe, EOF-Marker.

    Bei ``deep_scan=True`` wird nach der Strukturprüfung zusätzlich die
    Objekt-Grafik via ``core.security.pdf_deep_scanner`` gescannt
    (JavaScript, OpenAction, Launch, EmbeddedFile, …).
    """

    def validate(
        self,
        path: Path,
        report: ValidationReport,
        *,
        deep_scan: bool = False,
    ) -> None:
        """Prüft PDF-Grundstruktur; setzt HIGH-Threat bei Strukturfehlern.

        Args:
            path: Zu prüfender PDF-Pfad.
            report: Report zum Anhängen.
            deep_scan: Wenn True, wird nach erfolgreicher Strukturprüfung
                ``deep_scan_pdf`` aufgerufen.
        """
        size = path.stat().st_size

        if size > MAX_PDF_SIZE_BYTES:
            report.add(
                Threat(
                    code="PDF_FILE_TOO_LARGE",
                    severity=Severity.HIGH,
                    message=(
                        f"PDF zu groß ({size // (1024 * 1024)} MB). "
                        f"Limit: {MAX_PDF_SIZE_BYTES // (1024 * 1024)} MB."
                    ),
                    context={"size_bytes": size, "limit_bytes": MAX_PDF_SIZE_BYTES},
                )
            )
            return  # Kein weiterer Check bei übergroßer Datei

        # Magika-Check: Label muss "pdf" sein
        ident = identify(path)
        if ident.label != "pdf":
            report.add(
                Threat(
                    code="PDF_CONTENT_MISMATCH",
                    severity=Severity.CRITICAL,
                    message=(
                        "Inhalt ist kein PDF — Magika erkannte "
                        f"'{ident.label}' ({ident.description})."
                    ),
                    context={
                        "detected_label": ident.label,
                        "mime_type": ident.mime_type,
                    },
                )
            )
            return  # Bei CRITICAL-Mismatch keine weiteren Strukturchecks

        # Header + EOF in einem Lesevorgang prüfen
        try:
            with path.open("rb") as f:
                head = f.read(len(PDF_MAGIC_HEADER) + 3)  # "%PDF-1.7" o.ä.
                if size > PDF_EOF_SEARCH_WINDOW:
                    f.seek(-PDF_EOF_SEARCH_WINDOW, 2)
                    tail = f.read(PDF_EOF_SEARCH_WINDOW)
                else:
                    f.seek(0)
                    tail = f.read()
        except OSError as exc:
            report.add(
                Threat(
                    code="PDF_SCAN_ERROR",
                    severity=Severity.MEDIUM,
                    message=f"PDF-Datei konnte nicht gelesen werden: {exc}",
                )
            )
            return

        if not head.startswith(PDF_MAGIC_HEADER):
            report.add(
                Threat(
                    code="PDF_MISSING_MAGIC_HEADER",
                    severity=Severity.HIGH,
                    message=(
                        "PDF-Header '%PDF-' fehlt — Datei ist beschädigt "
                        "oder kein echtes PDF."
                    ),
                )
            )

        if PDF_EOF_MARKER not in tail:
            report.add(
                Threat(
                    code="PDF_MISSING_EOF_MARKER",
                    severity=Severity.MEDIUM,
                    message=(
                        "PDF-EOF-Marker '%%EOF' fehlt im letzten Kilobyte — "
                        "möglicherweise abgeschnitten."
                    ),
                )
            )

        if deep_scan:
            from core.security.pdf_deep_scanner import deep_scan_pdf  # noqa: PLC0415

            deep_scan_pdf(path, report)
