"""Tests für import_validator — End-to-End über alle ImportTypes."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.security import (
    ImportType,
    Severity,
    ValidationReport,
    validate_import,
)


class TestValidateImportBasics:
    def test_returns_validation_report(self, make_txt):
        path = make_txt("hello")
        r = validate_import(path, ImportType.TXT)
        assert isinstance(r, ValidationReport)
        assert r.path == path.resolve()
        assert r.declared_type is ImportType.TXT
        assert r.duration_ms >= 0.0

    def test_file_not_found_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            validate_import(tmp_path / "nope.txt", ImportType.TXT)

    def test_path_traversal_raises(self, tmp_path: Path):
        # Path enthält ".." — muss sofort abgelehnt werden
        with pytest.raises(ValueError, match="Path-Traversal"):
            validate_import(Path("subdir") / ".." / "file.txt", ImportType.TXT)

    def test_directory_path_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            validate_import(tmp_path, ImportType.TXT)

    def test_unknown_type_uses_generic(self, make_pdf):
        path = make_pdf()
        r = validate_import(path, ImportType.UNKNOWN)
        # UNKNOWN akzeptiert alles — kein TYPE_MISMATCH
        codes = [t.code for t in r.threats]
        assert "TYPE_MISMATCH" not in codes


class TestValidateImportMagikaFields:
    def test_detected_fields_populated(self, make_txt):
        path = make_txt("hello enough text for magika to classify")
        r = validate_import(path, ImportType.TXT)
        assert r.detected_label != ""
        assert r.detected_mime != ""

    def test_type_match_true_for_valid(self, make_xlsx):
        path = make_xlsx({"A1": "x"})
        r = validate_import(path, ImportType.XLSX)
        assert r.type_match is True

    def test_type_match_false_for_spoof(self, make_fake_binary):
        path = make_fake_binary(name="fake.xlsx")
        r = validate_import(path, ImportType.XLSX)
        assert r.type_match is False


class TestValidateImportDuration:
    def test_duration_recorded(self, make_txt):
        path = make_txt("hallo welt")
        r = validate_import(path, ImportType.TXT)
        # Magika-Init ist der erste Call teuer, aber > 0 muss immer gelten.
        assert r.duration_ms > 0


class TestSafeToParseSemantics:
    def test_high_alone_stays_safe(self, make_txt):
        # HIGH (z.B. Bidi) soll safe_to_parse=True behalten — nur CRITICAL
        # flipt das Flag. Der Aufrufer entscheidet selbst, welche Schwelle
        # einen Abbruch auslöst.
        path = make_txt("x\u202ey")
        r = validate_import(path, ImportType.TXT)
        assert r.has_severity(Severity.HIGH)
        assert r.safe_to_parse is True

    def test_critical_makes_unsafe(self, make_fake_binary):
        path = make_fake_binary(name="fake.pdf")
        r = validate_import(path, ImportType.PDF)
        assert r.safe_to_parse is False
