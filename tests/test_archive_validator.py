"""
test_archive_validator.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from core.security.sub_validators.archive_validator import ArchiveValidator
from core.security.validation_report import ImportType, Severity, ValidationReport


def _new_report(path: Path) -> ValidationReport:
    return ValidationReport(path=path, declared_type=ImportType.ZIP)


def test_harmlosen_zip_keine_kritischen_threats(tmp_path: Path) -> None:
    src = tmp_path / "ok.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("readme.txt", b"hallo")
        zf.writestr("bild.jpg", b"\x00" * 100)

    report = _new_report(src)
    ArchiveValidator().validate(src, report)

    assert not any(t.severity == Severity.CRITICAL for t in report.threats)


def test_exe_im_zip_wird_geflaggt(tmp_path: Path) -> None:
    """``.bat`` triggert die gleiche Flag wie ``.exe`` — und Defender
    quarantaeniert das Test-ZIP nicht."""
    src = tmp_path / "boese.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("setup.bat", b"echo hi\n")

    report = _new_report(src)
    ArchiveValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "ARCHIVE_DANGEROUS_CONTENT" in codes


def test_doppel_endung_pdf_exe_wird_geflaggt(tmp_path: Path) -> None:
    """Doppel-Endung: Wir testen via Magika+Endung, der Datei-Inhalt
    selbst ist irrelevant. Defender koennte ``.exe`` als Trigger
    halten — wir nutzen daher ``.docx.bat`` statt ``.pdf.exe``."""
    src = tmp_path / "anhang.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("rechnung.docx.bat", b"echo hi\n")

    report = _new_report(src)
    ArchiveValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "ARCHIVE_DOUBLE_EXTENSION" in codes


def test_path_traversal_wird_geflaggt(tmp_path: Path) -> None:
    src = tmp_path / "trav.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("../../etc/passwd", b"x")

    report = _new_report(src)
    ArchiveValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "ARCHIVE_PATH_TRAVERSAL" in codes


def test_kein_zip_wird_geflaggt(tmp_path: Path) -> None:
    src = tmp_path / "nope.zip"
    src.write_bytes(b"kein zip")

    report = _new_report(src)
    ArchiveValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "ARCHIVE_NOT_A_ZIP" in codes
