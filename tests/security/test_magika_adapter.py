"""Tests für magika_adapter — Label-Mapping und Robustheit."""

from __future__ import annotations

from pathlib import Path

from core.security.magika_adapter import (
    DANGEROUS_LABELS,
    MagikaIdentification,
    identify,
    is_compatible,
)
from core.security.validation_report import ImportType


class TestIdentify:
    def test_text_file(self, make_txt):
        path = make_txt("hello world with enough text for magika")
        ident = identify(path)
        assert ident.is_text is True
        assert ident.label in ("txt", "csv", "markdown")

    def test_missing_file_returns_unknown(self, tmp_path: Path):
        ident = identify(tmp_path / "does_not_exist.txt")
        assert ident.label == "unknown"
        assert ident.score == 0.0
        assert isinstance(ident, MagikaIdentification)

    def test_binary_recognized_as_dangerous(self, make_fake_binary):
        path = make_fake_binary(name="x.bin")
        ident = identify(path)
        # Magika erkennt MZ-Header als pebin
        assert ident.is_dangerous is True
        assert ident.label in DANGEROUS_LABELS


class TestIsCompatible:
    def test_unknown_accepts_everything(self):
        assert is_compatible("pebin", ImportType.UNKNOWN) is True
        assert is_compatible("zip", ImportType.UNKNOWN) is True

    def test_xlsx_accepts_zip_and_xlsx(self):
        assert is_compatible("xlsx", ImportType.XLSX) is True
        assert is_compatible("zip", ImportType.XLSX) is True
        assert is_compatible("ooxml", ImportType.XLSX) is True

    def test_xlsx_rejects_pdf(self):
        assert is_compatible("pdf", ImportType.XLSX) is False

    def test_pdf_strict(self):
        assert is_compatible("pdf", ImportType.PDF) is True
        assert is_compatible("zip", ImportType.PDF) is False

    def test_txt_accepts_csv(self):
        assert is_compatible("csv", ImportType.TXT) is True
        assert is_compatible("txt", ImportType.CSV) is True
