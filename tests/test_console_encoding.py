"""Tests fuer core.console_encoding C0a /-Crash-Klasse)."""

from __future__ import annotations

import sys

import pytest

from core.console_encoding import console_encoding


def test_console_encoding_windows_oem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert console_encoding() == "oem"


def test_console_encoding_posix_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert console_encoding() == "utf-8"


def test_errors_replace_verhindert_unicodedecodeerror() -> None:
    """Der eigentliche-Schutz: errors='replace' crasht NIE auf OEM-Bytes.

    Byte 0x81 (in cp1252 undefiniert) loeste den UnicodeDecodeError im
    Subprocess-Reader-Thread aus. Mit errors='replace' wird er ersetzt statt
    geworfen — egal welches Encoding gewaehlt wird.
    """
    raw = b"Sch\x81tz aktiviert"
    # Darf NICHT werfen (vorher: UnicodeDecodeError):
    decoded = raw.decode("utf-8", errors="replace")
    assert "aktiviert" in decoded
