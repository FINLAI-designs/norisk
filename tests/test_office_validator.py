"""
test_office_validator.

Pruft:class:`OfficeValidator` mit selbstgebauten ZIP-Containern.
Wir machen kein echtes docx/pptx-Roundtrip — der Validator schaut nur
auf Container-Eigenschaften und bekannte Pfad-Praefixe.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from core.security.sub_validators.office_validator import OfficeValidator
from core.security.validation_report import ImportType, Severity, ValidationReport


def _new_report(path: Path) -> ValidationReport:
    return ValidationReport(path=path, declared_type=ImportType.DOCX)


def _write_min_docx(path: Path, extra: dict[str, bytes] | None = None) -> None:
    """Baut einen minimalen DOCX-aehnlichen ZIP-Container."""
    extra = extra or {}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("word/document.xml", b"<doc/>")
        for name, data in extra.items():
            zf.writestr(name, data)


def test_minimaler_docx_keine_threats(tmp_path: Path) -> None:
    src = tmp_path / "leer.docx"
    _write_min_docx(src)

    report = _new_report(src)
    OfficeValidator().validate(src, report)

    # Threats moeglich: keine. Auf jeden Fall nicht CRITICAL.
    assert not any(t.severity == Severity.CRITICAL for t in report.threats)


def test_ole_embedding_wird_geflaggt(tmp_path: Path) -> None:
    src = tmp_path / "mit_ole.docx"
    _write_min_docx(src, {"word/embeddings/object1.bin": b"\x00" * 100})

    report = _new_report(src)
    OfficeValidator().validate(src, report)

    codes = {t.code for t in report.threats}
    assert "OFFICE_EMBEDDED_OLE" in codes


def test_externes_template_wird_geflaggt(tmp_path: Path) -> None:
    src = tmp_path / "ext.docx"
    rels = (
        b'<?xml version="1.0"?><Relationships xmlns="...">'
        b'<Relationship Type="http://schemas.openxmlformats.org/officeDocument'
        b'/2006/relationships/attachedTemplate" '
        b'Target="http://evil.example/template.dotm" '
        b'TargetMode="External"/>'
        b"</Relationships>"
    )
    _write_min_docx(src, {"word/_rels/settings.xml.rels": rels})

    report = _new_report(src)
    OfficeValidator().validate(src, report)

    codes = {t.code for t in report.threats}
    assert "OFFICE_EXTERNAL_TEMPLATE" in codes


def test_kaputter_container_wirft_keine_exception(tmp_path: Path) -> None:
    src = tmp_path / "kaputt.docx"
    src.write_bytes(b"das ist kein ZIP")

    report = _new_report(src)
    OfficeValidator().validate(src, report)

    codes = {t.code for t in report.threats}
    assert "OFFICE_SCAN_ERROR" in codes
