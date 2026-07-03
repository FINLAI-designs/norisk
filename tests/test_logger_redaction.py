""": Log-Sanitisierung — IBAN/Secrets/lange Nummern werden redigiert.

Prüft die Format-Rand-Redaction (Datei + Konsole), die die persistierte Log-Zeile
bereinigt. ``caplog``/Record bleiben bewusst roh.
"""

from __future__ import annotations

import logging

import pytest

from core.logger import _redact, _RedactingFormatter


def _fmt(msg: str, *args: object) -> str:
    record = logging.LogRecord(
        name="finlai.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )
    return _RedactingFormatter("%(message)s").format(record)


@pytest.mark.parametrize(
    ("roh", "verboten"),
    [
        ("Kunde IBAN DE89370400440532013000 angelegt", "DE89370400440532013000"),
        # Gruppen-Format (Anzeige/Kopie) — Review-Fix P1.
        ("IBAN DE89 3704 0044 0532 0130 00 fehlerhaft", "0532 0130"),
        ("password=hunter2 gesetzt", "hunter2"),
        ("api_key: sk-secret-XYZ123", "sk-secret-XYZ123"),
        # JSON/quoted Secret — Review-Fix P1.
        ('payload {"password": "hunter2", "user": "bob"}', "hunter2"),
        ("Authorization Bearer abc.def.ghi token", "abc.def.ghi"),
        ("Kartennummer 4111111111111111 erkannt", "4111111111111111"),
        ("token = 9f8e7d6c5b4a", "9f8e7d6c5b4a"),
    ],
)
def test_secret_wird_redigiert(roh: str, verboten: str) -> None:
    out = _redact(roh)
    assert verboten not in out
    assert "[redacted]" in out


def test_formatter_redigiert_die_zeile() -> None:
    out = _fmt("login password=%s ok", "geheim123")
    assert "geheim123" not in out
    assert "[redacted]" in out


def test_normale_zahlen_bleiben() -> None:
    # Kurze/normale Zahlen (Ports, Zähler, Datümer) werden NICHT redigiert.
    out = _redact("Scan 42 Geräte auf Port 8080 um 20260622")
    assert "42" in out and "8080" in out and "20260622" in out
    assert "[redacted]" not in out
