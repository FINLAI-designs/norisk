"""Tests für den PDF-Deep-Scanner (core.security.pdf_deep_scanner)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from core.security import ImportType, Severity, validate_import
from core.security.pdf_deep_scanner import _scan_catalog, _scan_objects, deep_scan_pdf
from core.security.validation_report import ValidationReport


def _codes(report):
    return [t.code for t in report.threats]


def _empty_report(path: Path) -> ValidationReport:
    return ValidationReport(path=path, declared_type=ImportType.PDF)


class TestPdfDeepScanner:
    def test_clean_pdf_no_threats(self, make_pdf):
        path = make_pdf()
        r = _empty_report(path)
        deep_scan_pdf(path, r)
        # Clean PDF darf höchstens URI-Actions melden (LOW), aber keine
        # HIGH/CRITICAL.
        assert all(t.severity.points < Severity.HIGH.points for t in r.threats)

    def test_open_action_detected(self, make_pdf_with_raw):
        path = make_pdf_with_raw(catalog_extra=" /OpenAction [3 0 R /Fit]")
        r = _empty_report(path)
        deep_scan_pdf(path, r)
        assert "PDF_AUTO_ACTION" in _codes(r)

    def test_javascript_detected(self, make_pdf_with_raw):
        js_obj = "4 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\);) >>\nendobj\n"
        path = make_pdf_with_raw(extra_objects=js_obj)
        r = _empty_report(path)
        deep_scan_pdf(path, r)
        codes = _codes(r)
        assert "PDF_JAVASCRIPT" in codes

    def test_launch_action_critical(self, make_pdf_with_raw):
        launch_obj = "4 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"
        path = make_pdf_with_raw(extra_objects=launch_obj)
        r = _empty_report(path)
        deep_scan_pdf(path, r)
        codes = _codes(r)
        assert "PDF_LAUNCH_ACTION" in codes

    def test_deep_scan_via_validate_import(self, make_pdf_with_raw):
        path = make_pdf_with_raw(catalog_extra=" /OpenAction [3 0 R /Fit]")
        # Ohne deep_scan: strukturell sauber, keine Auto-Action gemeldet
        r_fast = validate_import(path, ImportType.PDF)
        assert "PDF_AUTO_ACTION" not in _codes(r_fast)
        # Mit deep_scan: Auto-Action wird erkannt
        r_deep = validate_import(path, ImportType.PDF, deep_scan=True)
        assert "PDF_AUTO_ACTION" in _codes(r_deep)


class TestDeepScanIncompleteMarkers:
    """: Abbruch des Objektgraph-Walks muss als unvollständig markiert werden.

    Sonst meldet ein PDF, das pypdf öffnet, dessen Katalog/xref aber unlesbar
    ist (während tolerante Reader es ausführen), fälschlich „sicher".
    """

    def test_catalog_fehler_markiert_unvollstaendig(self) -> None:
        reader = MagicMock()
        root = MagicMock()
        root.get_object.side_effect = ValueError("self-referential /Root")
        reader.trailer.get.return_value = root
        r = _empty_report(Path("x.pdf"))
        _scan_catalog(reader, r)
        assert r.scan_incomplete() is True
        assert "PDF_DEEP_SCAN_ERROR" in _codes(r)

    def test_nicht_aufloesbarer_root_markiert_unvollstaendig(self) -> None:
        reader = MagicMock()
        root = MagicMock()
        root.get_object.return_value = 42  # kein dict -> Katalog-Checks liefen nicht
        reader.trailer.get.return_value = root
        r = _empty_report(Path("x.pdf"))
        _scan_catalog(reader, r)
        assert r.scan_incomplete() is True

    def test_xref_fehler_markiert_unvollstaendig(self) -> None:
        reader = MagicMock()
        reader.xref.items.side_effect = RuntimeError("xref-Tabelle kaputt")
        r = _empty_report(Path("x.pdf"))
        _scan_objects(reader, r)
        assert r.scan_incomplete() is True
        assert "PDF_DEEP_SCAN_ERROR" in _codes(r)
