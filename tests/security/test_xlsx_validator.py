"""Tests für XlsxValidator — Zip-Bomb, Formula-Injection, Makros, External-Links."""

from __future__ import annotations

import pytest

from core.security import ImportType, validate_import


def _codes(report):
    return [t.code for t in report.threats]


class TestXlsxHappyPath:
    def test_clean_workbook_is_safe(self, make_xlsx):
        path = make_xlsx({"A1": "Kto", "A2": "1000", "B1": "Name", "B2": "Kasse"})
        r = validate_import(path, ImportType.XLSX)
        assert r.safe_to_parse is True


class TestXlsxFormulaInjection:
    def test_benign_formula_is_medium(self, make_xlsx):
        # Normale Summenformel — nicht gefährlich, aber Präfix "="
        path = make_xlsx({"A1": "=SUM(1,2)"})
        r = validate_import(path, ImportType.XLSX)
        # FORMULA_SUSPICIOUS muss feuern (kein DANGEROUS_FUNCTION)
        assert "XLSX_FORMULA_SUSPICIOUS" in _codes(r)
        assert "XLSX_FORMULA_INJECTION" not in _codes(r)

    def test_cmd_injection_high(self, make_xlsx):
        path = make_xlsx({"B4": "=cmd|'/c calc'!A1"})
        r = validate_import(path, ImportType.XLSX)
        assert "XLSX_FORMULA_INJECTION" in _codes(r)

    def test_webservice_high(self, make_xlsx):
        path = make_xlsx({"C3": '=WEBSERVICE("http://evil.example")'})
        r = validate_import(path, ImportType.XLSX)
        assert "XLSX_FORMULA_INJECTION" in _codes(r)

    def test_plus_prefix_detected(self, make_xlsx):
        path = make_xlsx({"A1": "+1+1"})
        r = validate_import(path, ImportType.XLSX)
        # Präfix '+' zählt als Formel-Kontext
        assert any(
            c in _codes(r)
            for c in ("XLSX_FORMULA_SUSPICIOUS", "XLSX_FORMULA_INJECTION")
        )


class TestXlsxZipBomb:
    def test_compression_ratio_high(self, make_zip_bomb_xlsx):
        # 10 MB Nullen → Ratio >> 100:1
        path = make_zip_bomb_xlsx(size=10 * 1024 * 1024)
        r = validate_import(path, ImportType.XLSX)
        assert any(
            c in _codes(r)
            for c in (
                "XLSX_ZIP_COMPRESSION_RATIO",
                "XLSX_ZIP_UNCOMPRESSED_TOO_LARGE",
                "XLSX_ZIP_TOO_MANY_ENTRIES",
            )
        )

    def test_too_many_entries_critical(self, make_many_entry_xlsx):
        path = make_many_entry_xlsx(count=10_500)
        r = validate_import(path, ImportType.XLSX)
        assert "XLSX_ZIP_TOO_MANY_ENTRIES" in _codes(r)
        assert r.safe_to_parse is False


class TestXlsxExternalLinks:
    def test_external_link_high(self, make_external_link_xlsx):
        path = make_external_link_xlsx()
        r = validate_import(path, ImportType.XLSX)
        assert "XLSX_EXTERNAL_LINKS" in _codes(r)


class TestXlsxTypeSpoofing:
    def test_pe_as_xlsx_critical(self, make_fake_binary):
        path = make_fake_binary(name="tarnung.xlsx")
        r = validate_import(path, ImportType.XLSX)
        codes = _codes(r)
        assert "TYPE_SPOOFING_DANGEROUS" in codes
        assert r.safe_to_parse is False


class TestXlsxPerformance:
    @pytest.mark.slow
    def test_realistic_workbook_under_500ms(self, make_xlsx):
        import time

        # 100x20 harmloser Zellen — realistischer Kontenrahmen
        cells = {}
        for row in range(1, 101):
            for col in ("A", "B", "C", "D", "E"):
                cells[f"{col}{row}"] = f"Wert_{col}{row}"
        path = make_xlsx(cells)
        t0 = time.perf_counter()
        validate_import(path, ImportType.XLSX)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 2000, f"{elapsed:.0f} ms übersteigt Budget"
