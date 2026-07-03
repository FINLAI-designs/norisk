"""
test_document_scanner_service.

Pruft:class:`DocumentScannerService` mit echter
``core.security.validate_import``-Pipeline. Wir nutzen kein Mocking
des Magika-Adapters — die Lib ist installiert und Bestandteil der
NoRisk-Runtime.

Pruefungen:

1. Eine harmlose Text-Datei liefert:class:`ScanVerdict.SAFE`.
2. Eine Datei mit ``.pdf``-Endung deren Inhalt aber kein PDF ist
   (Magika erkennt z. B. ``txt``) erzeugt mindestens einen
   ``TYPE_MISMATCH``-Threat → SUSPICIOUS oder DANGEROUS.
3. ``scan`` ruft tatsaechlich den QuarantineManager auf — Slot
   existiert nach dem Scan.
4. ``delete(result)`` raeumt den Slot weg.
5. ``shutdown`` haengt am QuarantineManager.cleanup_all dran.
"""

from __future__ import annotations

from pathlib import Path

from core.security.validation_report import ImportType
from tools.document_scanner.application.quarantine_manager import QuarantineManager
from tools.document_scanner.application.scanner_service import (
    DocumentScannerService,
    _import_type_for,
)
from tools.document_scanner.domain.models import ScanVerdict


def test_import_type_mapping() -> None:
    assert _import_type_for(Path("file.pdf")) == ImportType.PDF
    assert _import_type_for(Path("file.PDF")) == ImportType.PDF
    assert _import_type_for(Path("file.xlsx")) == ImportType.XLSX
    assert _import_type_for(Path("file.eml")) == ImportType.EML
    # Office/Archive/Script-Erweiterungen
    assert _import_type_for(Path("file.docx")) == ImportType.DOCX
    assert _import_type_for(Path("file.zip")) == ImportType.ZIP
    assert _import_type_for(Path("file.ps1")) == ImportType.PS1
    assert _import_type_for(Path("file.svg")) == ImportType.SVG
    # Wirklich unbekannte Endung → UNKNOWN (generic_validator)
    assert _import_type_for(Path("file.xyz")) == ImportType.UNKNOWN


def test_classify_scan_incomplete_low_marker_ist_suspicious() -> None:
    """: ein LOW-Inkomplett-Marker (z.B. übersprungener Formula-Scan, weil
    openpyxl fehlt) darf im document_scanner nicht SAFE ergeben."""
    from core.security.validation_report import Severity, Threat, ValidationReport
    from tools.document_scanner.application.scanner_service import _classify

    report = ValidationReport(path=Path("x.xlsx"), declared_type=ImportType.XLSX)
    report.add(Threat("XLSX_FORMULA_SCAN_SKIPPED", Severity.LOW, "openpyxl fehlt"))
    assert _classify(report) is ScanVerdict.SUSPICIOUS


def test_scan_harmlose_text_datei(tmp_path: Path) -> None:
    """Eine 5-Byte-Textdatei wird als ``SAFE`` klassifiziert (keine
    CRITICAL/HIGH/MEDIUM-Threats)."""
    src = tmp_path / "notiz.txt"
    src.write_text("hallo", encoding="utf-8")

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    result = service.scan(src)

    assert result.verdict == ScanVerdict.SAFE
    assert result.entry.original_name == "notiz.txt"
    assert result.entry.stored_path.exists()
    assert result.magika_label != ""  # Magika hat eine Klassifizierung geliefert


def test_scan_typ_spoofing_erkannt(tmp_path: Path) -> None:
    """Text als ``.pdf`` getarnt → mindestens HIGH-Threat (TYPE_MISMATCH)."""
    src = tmp_path / "rechnung.pdf"
    src.write_text("nope, dies ist kein PDF", encoding="utf-8")

    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    result = service.scan(src)

    # Spoofing → mindestens HIGH-Threat → Verdict mindestens SUSPICIOUS
    assert result.verdict in (ScanVerdict.SUSPICIOUS, ScanVerdict.DANGEROUS)
    # Mindestens ein Threat mit TYPE_MISMATCH oder TYPE_SPOOFING_*
    codes = {t.code for t in result.threats}
    assert any("TYPE" in c for c in codes), (
        f"Erwarteter TYPE_*-Threat fehlt; gefunden: {codes}"
    )


def test_delete_raeumt_slot(tmp_path: Path) -> None:
    src = tmp_path / "datei.txt"
    src.write_text("x")
    service = DocumentScannerService(QuarantineManager(root=tmp_path / "q"))
    result = service.scan(src)

    assert result.entry.quarantine_dir.exists()
    service.delete(result)
    assert not result.entry.quarantine_dir.exists()


def test_shutdown_loescht_alle_slots(tmp_path: Path) -> None:
    qm = QuarantineManager(root=tmp_path / "q")
    service = DocumentScannerService(qm)
    for i in range(3):
        f = tmp_path / f"f_{i}.txt"
        f.write_text("x")
        service.scan(f)

    removed = service.shutdown()
    assert removed == 3
    assert not any(qm.root.iterdir())
