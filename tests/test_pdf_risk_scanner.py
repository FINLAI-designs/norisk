"""test_pdf_risk_scanner — Unit-Tests für den PDF-Risk-Scanner (NoRisk).

Deckt Domain-Helper, Service-Orchestrierung und die Tool-Plugin-Definition
ab. Der eigentliche Deep-Scan-Engine liegt in
``core/security/pdf_deep_scanner.py`` und ist unter
``tests/security/test_pdf_deep_scanner.py`` separat abgedeckt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Dev-Override (genereller Schalter). Seit ist der
# Deep-Content-Scan im Import-Validator unbedingt — der frueher noetige
# „voller Modus statt LICENSE_DEGRADED_MODE" haengt nicht mehr daran.
os.environ.setdefault("FINLAI_DEV", "1")

from core.security.validation_report import (
    ImportType,
    Severity,
    Threat,
    ValidationReport,
)
from tools.pdf_risk_scanner.application.scan_service import PdfScanService
from tools.pdf_risk_scanner.domain.models import (
    PdfScanResult,
    ScanStatus,
    status_from_report,
)
from tools.pdf_risk_scanner.tool import PdfRiskScannerTool


def _build_pdf(
    tmp_path: Path,
    *,
    catalog_extra: str = "",
    extra_objects: str = "",
    name: str = "t.pdf",
) -> Path:
    """Erzeugt ein minimales, handgeschriebenes PDF 1.5."""
    header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
    catalog = (
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R"
        + catalog_extra.encode("latin-1")
        + b" >>\nendobj\n"
    )
    pages = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    page = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>\nendobj\n"
    extra = extra_objects.encode("latin-1")
    body = catalog + pages + page + extra

    offset = len(header)
    xref_entries = [b"0000000000 65535 f \n"]
    pos = offset
    for obj_bytes in (catalog, pages, page):
        xref_entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))
        pos += len(obj_bytes)
    for _ in range(extra_objects.count("endobj")):
        xref_entries.append(f"{pos:010d} 00000 n \n".encode("latin-1"))

    xref_offset = offset + len(body)
    total_objs = 4 + extra_objects.count("endobj")
    xref = f"xref\n0 {total_objs}\n".encode("latin-1") + b"".join(xref_entries)
    trailer = (
        f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n"
        f"{xref_offset}\n%%EOF\n"
    ).encode("latin-1")

    p = tmp_path / name
    p.write_bytes(header + body + xref + trailer)
    return p


def _report(
    *,
    threats: list[Threat] | None = None,
    safe_to_parse: bool = True,
) -> ValidationReport:
    return ValidationReport(
        path=Path("dummy.pdf"),
        declared_type=ImportType.PDF,
        detected_label="pdf",
        threats=threats or [],
        safe_to_parse=safe_to_parse,
    )


class TestStatusFromReport:
    """``status_from_report`` bildet Reports auf Tabellen-Status ab."""

    def test_safe_bei_leerem_report(self) -> None:
        assert status_from_report(_report()) is ScanStatus.SAFE

    def test_safe_bei_low_und_medium(self) -> None:
        r = _report(
            threats=[
                Threat("X_LOW", Severity.LOW, "low"),
                Threat("X_MED", Severity.MEDIUM, "medium"),
            ]
        )
        assert status_from_report(r) is ScanStatus.SAFE

    def test_warn_bei_high(self) -> None:
        r = _report(threats=[Threat("X_HIGH", Severity.HIGH, "high")])
        assert status_from_report(r) is ScanStatus.WARN

    def test_block_bei_critical(self) -> None:
        r = _report(
            threats=[Threat("X_CRIT", Severity.CRITICAL, "crit")],
            safe_to_parse=False,
        )
        assert status_from_report(r) is ScanStatus.BLOCK

    def test_warn_bei_deep_scan_error_kein_safe(self) -> None:
        # Regression: ein nicht-parsebares PDF (nur MEDIUM-Scan-Fehler)
        # darf NICHT als "safe" gemeldet werden (Fail-Closed).
        r = _report(
            threats=[
                Threat("PDF_DEEP_SCAN_ERROR", Severity.MEDIUM, "startxref not found")
            ]
        )
        assert status_from_report(r) is ScanStatus.WARN

    def test_warn_bei_encrypted_kein_safe(self) -> None:
        r = _report(threats=[Threat("PDF_ENCRYPTED", Severity.MEDIUM, "verschlüsselt")])
        assert status_from_report(r) is ScanStatus.WARN


class TestPdfScanService:
    """``PdfScanService.scan`` delegiert an validate_import mit Deep-Scan."""

    def test_scan_liefert_ergebnis_fuer_clean_pdf(self, tmp_path: Path) -> None:
        pfad = _build_pdf(tmp_path, name="clean.pdf")
        service = PdfScanService()

        result = service.scan(pfad)

        assert isinstance(result, PdfScanResult)
        assert result.path.name == "clean.pdf"
        assert not result.report.has_severity(Severity.HIGH)
        assert result.status is ScanStatus.SAFE

    def test_scan_markiert_launch_als_block(self, tmp_path: Path) -> None:
        launch_obj = "4 0 obj\n<< /Type /Action /S /Launch /F (calc.exe) >>\nendobj\n"
        pfad = _build_pdf(
            tmp_path,
            catalog_extra=" /OpenAction 4 0 R",
            extra_objects=launch_obj,
            name="launch.pdf",
        )
        service = PdfScanService()

        result = service.scan(pfad)

        assert result.status is ScanStatus.BLOCK
        assert not result.report.safe_to_parse

    def test_scan_raised_file_not_found(self, tmp_path: Path) -> None:
        service = PdfScanService()
        with pytest.raises(FileNotFoundError):
            service.scan(tmp_path / "fehlt.pdf")

    def test_scan_persistiert_in_datei_scan_history(self, tmp_path: Path) -> None:
        """-B: ein PDF-Scan schreibt einen Eintrag in die gemeinsame
        Datei-Scan-History (Cockpit-Datei-Scanner-Frische). DSGVO: nur Name."""
        pfad = _build_pdf(tmp_path, name="report.pdf")
        repo = MagicMock()
        service = PdfScanService(history_repo=repo)

        service.scan(pfad)

        repo.add_scan_record.assert_called_once()
        kwargs = repo.add_scan_record.call_args.kwargs
        assert kwargs["original_name"] == "report.pdf"  # Name, KEIN Pfad
        assert kwargs["magika_label"] == "pdf"
        assert len(kwargs["sha256"]) == 64
        assert kwargs["size_bytes"] > 0
        assert isinstance(kwargs["threat_codes"], list)  # Codes, keine Messages

    def test_scan_persistenz_fehler_bricht_scan_nicht(self, tmp_path: Path) -> None:
        """Persistenz ist fail-soft: ein Repo-Fehler darf den Scan nie scheitern."""
        pfad = _build_pdf(tmp_path, name="x.pdf")
        repo = MagicMock()
        repo.add_scan_record.side_effect = RuntimeError("db down")
        service = PdfScanService(history_repo=repo)

        result = service.scan(pfad)  # darf NICHT raisen

        assert isinstance(result, PdfScanResult)


class TestPdfRiskScannerTool:
    """Plugin-Metadaten des Tools."""

    def test_plugin_attribute(self) -> None:
        tool = PdfRiskScannerTool()
        assert tool.name == "PDF Risk Scanner"
        assert tool.feature_name == "pdf_risk_scanner"
        assert tool.icon == "picture_as_pdf"
