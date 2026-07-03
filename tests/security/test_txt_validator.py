"""Tests für TxtValidator — Bidi, Homoglyph, ANSI, UTF-8."""

from __future__ import annotations

import pytest

from core.security import ImportType, Severity, validate_import


def _codes(report):
    return [t.code for t in report.threats]


class TestTxtValidator:
    def test_clean_text_is_safe(self, make_txt):
        path = make_txt("Hallo Welt, dies ist ein harmloser Text.")
        r = validate_import(path, ImportType.TXT)
        assert r.safe_to_parse is True
        assert r.risk_score == 0
        assert "TXT_BIDI_CONTROL_CHARS" not in _codes(r)

    def test_bidi_override_detected(self, make_txt):
        # U+202E flipt die Anzeigereihenfolge (Trojan-Source)
        content = "Ueberweisung\u202e an Empfaenger"
        path = make_txt(content)
        r = validate_import(path, ImportType.TXT)
        codes = _codes(r)
        assert "TXT_BIDI_CONTROL_CHARS" in codes
        # HIGH → score 50
        assert r.risk_score >= 50

    def test_rlo_lri_both_detected(self, make_txt):
        content = "\u2067malicious\u2069\u202dbenign\u202c"
        path = make_txt(content)
        r = validate_import(path, ImportType.TXT)
        assert "TXT_BIDI_CONTROL_CHARS" in _codes(r)

    def test_homoglyph_cyrillic_latin_mix(self, make_txt):
        # 'а' (U+0430, kyrillisch) statt 'a' (lateinisch) in "paypal"
        content = "Logge dich bei pа\u0443pal.com ein"
        path = make_txt(content)
        r = validate_import(path, ImportType.TXT)
        codes = _codes(r)
        assert "TXT_HOMOGLYPH_MIX" in codes

    def test_ansi_escape_detected(self, make_txt):
        content = "Normaler Text\x1b[31m rot markiert \x1b[0m Ende"
        path = make_txt(content)
        r = validate_import(path, ImportType.TXT)
        assert "TXT_ANSI_ESCAPE" in _codes(r)

    def test_invalid_utf8_reports_high(self, make_txt_bytes):
        # 0xFF ist nie gültig als UTF-8-Startbyte
        path = make_txt_bytes(b"hallo \xff welt")
        r = validate_import(path, ImportType.TXT)
        assert "TXT_INVALID_UTF8" in _codes(r)

    def test_utf8_bom_info(self, make_txt_bytes):
        path = make_txt_bytes(b"\xef\xbb\xbfhallo welt mit genug inhalt")
        r = validate_import(path, ImportType.TXT)
        assert "TXT_BOM_PRESENT" in _codes(r)

    def test_binary_content_mismatch(self, make_txt_bytes):
        path = make_txt_bytes(b"MZ\x90\x00\x03" + bytes(1024))
        r = validate_import(path, ImportType.TXT)
        codes = _codes(r)
        # Entweder TYPE_SPOOFING_* (aus Haupt-Validator) oder
        # TXT_CONTENT_NOT_TEXT (aus Sub-Validator) muss feuern.
        assert any(c.startswith("TYPE_") or c == "TXT_CONTENT_NOT_TEXT" for c in codes)
        assert r.safe_to_parse is False

    def test_oversized_text_reports_high(self, tmp_path, monkeypatch):
        from core.security.sub_validators import txt_validator

        # Limit temporär auf 1 KB senken
        monkeypatch.setattr(txt_validator, "MAX_TXT_SIZE_BYTES", 1024)
        p = tmp_path / "big.txt"
        p.write_text("x" * 5000, encoding="utf-8")
        r = validate_import(p, ImportType.TXT)
        assert "TXT_FILE_TOO_LARGE" in _codes(r)
        # Schweregrad HIGH
        assert any(
            t.severity == Severity.HIGH and t.code == "TXT_FILE_TOO_LARGE"
            for t in r.threats
        )


class TestTxtValidatorPerformance:
    @pytest.mark.slow
    def test_large_clean_txt_under_2s(self, tmp_path):
        import time

        p = tmp_path / "big.txt"
        p.write_text("Hallo Welt\n" * 500_000, encoding="utf-8")
        t0 = time.perf_counter()
        validate_import(p, ImportType.TXT)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"Dauer {elapsed:.2f}s überschreitet Budget"
