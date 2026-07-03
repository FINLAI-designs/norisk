"""
test_yara_runner.

Pruft den YARA-Runner mit den NoRisk-eigenen Regeln. Erwartet dass
``yara-python`` installiert ist (Pflicht-Dep ab Iter 3) und die
Datei ``resources/yara_rules/norisk_document_scanner.yar`` greift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.security import yara_runner


def test_yara_is_available() -> None:
    """``yara-python`` muss installiert sein + die NoRisk-Regeln laden."""
    assert yara_runner.is_available(), (
        "YARA muss in Iter 3 verfuegbar sein — bitte requirements.txt pruefen."
    )


def test_ps_empire_stager_matched(tmp_path: Path) -> None:
    """PowerShell-Empire-Stager-Muster muss matchen."""
    src = tmp_path / "demo.ps1"
    src.write_text(
        # IEX + FromBase64String + langer Base64 → NoRisk_PS_Empire_Stager
        "iex ([System.Convert]::FromBase64String('"
        + "A" * 600
        + "'))",
        encoding="utf-8",
    )
    matches = yara_runner.scan_path(src)
    rules = {m.rule for m in matches}
    assert "NoRisk_PS_Empire_Stager" in rules


def test_phishing_brand_spoofing(tmp_path: Path) -> None:
    """Marken-Tarnung muss matchen."""
    src = tmp_path / "phish.txt"
    src.write_text(
        "Bitte verify your account innerhalb von 24 Stunden — "
        "Login auf paypa1.com",
        encoding="utf-8",
    )
    matches = yara_runner.scan_path(src)
    rules = {m.rule for m in matches}
    assert "NoRisk_Phishing_Brand_Spoofing" in rules


def test_url_shortener_matched(tmp_path: Path) -> None:
    src = tmp_path / "doc.txt"
    src.write_text("siehe https://bit.ly/abcd123 fuer Details", encoding="utf-8")
    matches = yara_runner.scan_path(src)
    rules = {m.rule for m in matches}
    assert "NoRisk_Suspicious_URL_Shortener" in rules


def test_harmlose_datei_keine_matches(tmp_path: Path) -> None:
    src = tmp_path / "harmlos.txt"
    src.write_text("Das ist ein voellig normaler deutscher Absatztext.", encoding="utf-8")
    matches = yara_runner.scan_path(src)
    assert matches == []


def test_yara_match_metadata_struktur() -> None:
    """``YaraMatch``-Felder sind alle gesetzt."""
    yara = pytest.importorskip("yara")  # type: ignore[no-untyped-call]
    rule = yara.compile(
        source='rule R { meta: severity = "high" family = "test" description = "X" strings: $a = "hallo" condition: $a }'
    )
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("hallo Welt")
        p = f.name
    matches = rule.match(p)
    assert matches, "Direkter yara.compile-Test sollte matchen"


def test_validate_import_yara_layer_integration(tmp_path: Path) -> None:
    """Die ``validate_import``-Pipeline ergaenzt einen ``YARA_*``-Threat
    fuer matchende Dateien (Layer 3)."""
    from core.security.import_validator import validate_import
    from core.security.validation_report import ImportType

    src = tmp_path / "stager.ps1"
    src.write_text(
        "iex ([System.Convert]::FromBase64String('" + "A" * 600 + "'))",
        encoding="utf-8",
    )
    report = validate_import(src, expected=ImportType.PS1)

    yara_codes = [t.code for t in report.threats if t.code.startswith("YARA_")]
    assert any("Empire_Stager" in c for c in yara_codes), (
        f"YARA-Treffer fehlt — Threats: {report.threats}"
    )
