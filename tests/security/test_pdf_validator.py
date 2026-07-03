"""Tests für PdfValidator — Struktur, Magic-Header, EOF-Marker."""

from __future__ import annotations

from core.security import ImportType, validate_import


def _codes(report):
    return [t.code for t in report.threats]


class TestPdfValidator:
    def test_valid_pdf_is_safe(self, make_pdf):
        path = make_pdf()
        r = validate_import(path, ImportType.PDF)
        assert r.safe_to_parse is True
        assert r.risk_score == 0

    def test_missing_magic_header_high(self, make_headerless_pdf):
        path = make_headerless_pdf()
        r = validate_import(path, ImportType.PDF)
        # Entweder Type-Mismatch (Magika erkennt nicht-PDF) oder
        # PDF_MISSING_MAGIC_HEADER
        codes = _codes(r)
        assert any(
            c in codes
            for c in (
                "PDF_MISSING_MAGIC_HEADER",
                "TYPE_MISMATCH",
                "PDF_CONTENT_MISMATCH",
            )
        )

    def test_truncated_pdf_reports_missing_eof(self, make_truncated_pdf):
        path = make_truncated_pdf()
        r = validate_import(path, ImportType.PDF)
        # Truncation entfernt EOF — sollte gemeldet werden
        codes = _codes(r)
        assert "PDF_MISSING_EOF_MARKER" in codes or "PDF_CONTENT_MISMATCH" in codes

    def test_pe_as_pdf_critical(self, make_fake_binary):
        path = make_fake_binary(name="tarnung.pdf")
        r = validate_import(path, ImportType.PDF)
        assert "TYPE_SPOOFING_DANGEROUS" in _codes(r)
        assert r.safe_to_parse is False
