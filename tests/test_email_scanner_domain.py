"""test_email_scanner_domain — Domain-Modelle des E-Mail-Anhang-Scanners.

Prüft Hash-Berechnung, Status-Ableitung und Aggregation. Service- und
Parser-Tests liegen in separaten Modulen (``test_email_scanner.py``
nach Split 2 und 3).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
from pathlib import Path

# Vollen Deep-Scan aktivieren — Tests nutzen validate_import/pdf_deep_scan.
os.environ.setdefault("FINLAI_DEV", "1")

from core.security.validation_report import (
    ImportType,
    Severity,
    Threat,
    ValidationReport,
)
from tools.email_scanner.domain.models import (
    Attachment,
    AttachmentReport,
    MailScanStatus,
    aggregate_status,
    status_from_validation,
)
from tools.pdf_risk_scanner.domain.models import PdfScanResult
from tools.pdf_risk_scanner.domain.models import ScanStatus as PdfStatus


def _validation(
    *, threats: list[Threat] | None = None, safe_to_parse: bool = True
) -> ValidationReport:
    return ValidationReport(
        path=Path("dummy.bin"),
        declared_type=ImportType.UNKNOWN,
        threats=threats or [],
        safe_to_parse=safe_to_parse,
    )


class TestAttachment:
    """``Attachment.from_bytes`` berechnet stabile SHA-256-Hashes."""

    def test_hash_stimmt_ueberein(self) -> None:
        a = Attachment.from_bytes("a.pdf", "application/pdf", b"hello")
        # sha256("hello")
        assert a.sha256 == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert a.size == 5

    def test_leere_metadaten_werden_geerbt(self) -> None:
        a = Attachment.from_bytes("", "", b"\x00\x01")
        assert a.filename == "(ohne Namen)"
        assert a.content_type == "application/octet-stream"


class TestStatusFromValidation:
    """``status_from_validation`` reflektiert den schwersten Fund."""

    def test_safe_bei_leerem_report(self) -> None:
        assert status_from_validation(_validation(), None) is MailScanStatus.SAFE

    def test_warn_bei_high(self) -> None:
        v = _validation(threats=[Threat("X", Severity.HIGH, "m")])
        assert status_from_validation(v, None) is MailScanStatus.WARN

    def test_block_bei_critical_validation(self) -> None:
        v = _validation(
            threats=[Threat("X", Severity.CRITICAL, "m")], safe_to_parse=False
        )
        assert status_from_validation(v, None) is MailScanStatus.BLOCK

    def test_block_bei_pdf_block(self) -> None:
        v = _validation()
        pdf_report = ValidationReport(
            path=Path("a.pdf"),
            declared_type=ImportType.PDF,
            threats=[Threat("PDF_LAUNCH_ACTION", Severity.CRITICAL, "l")],
            safe_to_parse=False,
        )
        pdf = PdfScanResult(
            path=Path("a.pdf"),
            report=pdf_report,
            status=PdfStatus.BLOCK,
            duration_ms=1.0,
        )
        assert status_from_validation(v, pdf) is MailScanStatus.BLOCK

    def test_warn_bei_scan_incomplete_attachment(self) -> None:
        # ein nicht vollständig prüfbarer Anhang darf nie "safe" sein.
        v = _validation(threats=[Threat("OFFICE_SCAN_ERROR", Severity.MEDIUM, "x")])
        assert status_from_validation(v, None) is MailScanStatus.WARN

    def test_warn_bei_scan_incomplete_pdf(self) -> None:
        v = _validation()
        pdf_report = ValidationReport(
            path=Path("a.pdf"),
            declared_type=ImportType.PDF,
            threats=[Threat("PDF_DEEP_SCAN_ERROR", Severity.MEDIUM, "x")],
        )
        pdf = PdfScanResult(
            path=Path("a.pdf"),
            report=pdf_report,
            status=PdfStatus.WARN,
            duration_ms=1.0,
        )
        assert status_from_validation(v, pdf) is MailScanStatus.WARN


class TestAggregateStatus:
    """``aggregate_status`` liefert den schwersten Einzel-Status."""

    def _report(self, status: MailScanStatus) -> AttachmentReport:
        return AttachmentReport(
            attachment=Attachment.from_bytes("x", "application/octet-stream", b""),
            validation=_validation(safe_to_parse=status is not MailScanStatus.BLOCK),
            pdf_scan=None,
            status=status,
        )

    def test_leere_liste_ist_safe(self) -> None:
        assert aggregate_status([]) is MailScanStatus.SAFE

    def test_block_schlaegt_warn(self) -> None:
        reports = [
            self._report(MailScanStatus.WARN),
            self._report(MailScanStatus.BLOCK),
        ]
        assert aggregate_status(reports) is MailScanStatus.BLOCK

    def test_warn_schlaegt_safe(self) -> None:
        reports = [
            self._report(MailScanStatus.SAFE),
            self._report(MailScanStatus.WARN),
        ]
        assert aggregate_status(reports) is MailScanStatus.WARN
