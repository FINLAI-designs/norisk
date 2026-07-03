"""
attachment_router — Routing-Logik für extrahierte E-Mail-Anhänge.

Nimmt ein ``Attachment`` aus dem Parser entgegen, bestimmt den
``ImportType`` anhand von Dateiname + MIME-Type, schreibt die Bytes
in eine temporäre Datei und ruft ``core.security.validate_import`` auf.
Für PDFs wird zusätzlich der Tiefen-Scan aus
``tools.pdf_risk_scanner.application.scan_service`` ausgeführt.

Die temporäre Datei wird nach dem Scan sofort gelöscht — es gibt
keine Auto-Öffnen-Funktion.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from core.logger import get_logger
from core.security import ImportType, validate_import
from core.security.validation_report import ValidationReport
from tools.email_scanner.domain.models import (
    Attachment,
    AttachmentReport,
    status_from_validation,
)
from tools.pdf_risk_scanner.application.scan_service import PdfScanService
from tools.pdf_risk_scanner.domain.models import PdfScanResult

_log = get_logger(__name__)

# MIME-Type-Mapping auf ``ImportType``. Wir akzeptieren gängige
# Varianten (Office-Legacy-Types mit ``vnd.ms-…``) und fallen am Ende
# auf die Datei-Endung zurück.
_MIME_TO_TYPE: dict[str, ImportType] = {
    "application/pdf": ImportType.PDF,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (
        ImportType.XLSX
    ),
    "application/vnd.ms-excel.sheet.macroenabled.12": ImportType.XLSM,
    "application/json": ImportType.JSON,
    "application/x-ndjson": ImportType.JSONL,
    "text/csv": ImportType.CSV,
    "text/plain": ImportType.TXT,
    "message/rfc822": ImportType.EML,
}

# Datei-Endung → ``ImportType``. Wird bei unbekanntem MIME verwendet.
_SUFFIX_TO_TYPE: dict[str, ImportType] = {
    ".pdf": ImportType.PDF,
    ".xlsx": ImportType.XLSX,
    ".xlsm": ImportType.XLSM,
    ".json": ImportType.JSON,
    ".jsonl": ImportType.JSONL,
    ".csv": ImportType.CSV,
    ".txt": ImportType.TXT,
    ".eml": ImportType.EML,
    ".msg": ImportType.MSG,
}


class AttachmentRouter:
    """Routet Anhänge durch Secure-Import-Validator und PDF-Scanner."""

    def __init__(self, pdf_service: PdfScanService | None = None) -> None:
        """Initialisiert den Router.

        Args:
            pdf_service: Optional vorbereiteter PDF-Scanner. Wenn ``None``,
                wird eine Default-Instanz erzeugt.
        """
        self._pdf_service = pdf_service or PdfScanService()

    def route(self, attachment: Attachment) -> AttachmentReport:
        """Analysiert ein einzelnes Attachment.

        Args:
            attachment: Aus dem Parser extrahierter Anhang.

        Returns:
            ``AttachmentReport`` mit Validation-Report, optionalem
            PDF-Scan und Status.
        """
        expected = _guess_import_type(attachment)
        with _temp_file(attachment) as path:
            validation = validate_import(path, expected)
            pdf_scan = self._maybe_pdf_scan(path, expected, validation)

        status = status_from_validation(validation, pdf_scan)
        _log.info(
            "Attachment %s | %s | status=%s, score=%d",
            attachment.filename,
            expected.value,
            status.value,
            validation.risk_score,
        )
        return AttachmentReport(
            attachment=attachment,
            validation=validation,
            pdf_scan=pdf_scan,
            status=status,
        )

    def _maybe_pdf_scan(
        self,
        path: Path,
        expected: ImportType,
        validation: ValidationReport,
    ) -> PdfScanResult | None:
        """Führt den Tiefen-Scan nur aus, wenn das Attachment wirklich PDF ist.

        Args:
            path: Temp-Pfad des Attachments.
            expected: Angekündigter Import-Typ.
            validation: Report des Secure-Import-Validators.

        Returns:
            ``PdfScanResult`` oder ``None``, wenn kein Deep-Scan sinnvoll ist.
        """
        if expected is not ImportType.PDF:
            return None
        if not validation.safe_to_parse:
            # Bereits CRITICAL — kein zweiter Durchlauf nötig.
            return None
        try:
            return self._pdf_service.scan(path)
        except (FileNotFoundError, ValueError) as exc:
            _log.debug("PDF-Deep-Scan fehlgeschlagen: %s", exc)
            return None


def _guess_import_type(attachment: Attachment) -> ImportType:
    """Bestimmt den ``ImportType`` aus MIME oder Datei-Endung.

    Args:
        attachment: Zu klassifizierendes Attachment.

    Returns:
        Passender ``ImportType`` oder ``ImportType.UNKNOWN``.
    """
    mime = attachment.content_type.split(";")[0].strip().lower()
    if mime in _MIME_TO_TYPE:
        return _MIME_TO_TYPE[mime]
    suffix = Path(attachment.filename).suffix.lower()
    return _SUFFIX_TO_TYPE.get(suffix, ImportType.UNKNOWN)


class _temp_file:  # noqa: N801 — contextmanager-Klasse, Kleinschreibung bewusst
    """Context-Manager: schreibt Attachment-Bytes in eine temporäre Datei.

    Die Datei wird sofort nach Verlassen des ``with``-Blocks gelöscht,
    unabhängig vom Validations-Ergebnis.
    """

    def __init__(self, attachment: Attachment) -> None:
        self._attachment = attachment
        self._path: Path | None = None

    def __enter__(self) -> Path:
        suffix = Path(self._attachment.filename).suffix or ".bin"
        fd, name = tempfile.mkstemp(suffix=suffix, prefix="finlai_mail_")
        path = Path(name)
        try:
            with open(fd, "wb") as fh:
                fh.write(self._attachment.data)
        except OSError:
            path.unlink(missing_ok=True)
            raise
        self._path = path
        return path

    def __exit__(self, *exc: object) -> None:
        if self._path is not None:
            self._path.unlink(missing_ok=True)
            self._path = None
