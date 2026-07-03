"""Tests fuer core.finlai_paths — Datenwurzel-Aufloesung + Override-Erkennung.

Deckt:func:`finlai_home_override` (explizite Isolation erkennen, fuer die
Weitergabe an Subprozesse) und das unveraenderte:func:`finlai_dir`-Verhalten
ab (Laufzeit-Override > FINLAI_HOME > ~/.finlai).
"""

from __future__ import annotations

from pathlib import Path

from core import finlai_paths


class TestFinlaiHomeOverride:
    def test_kein_override_gibt_none(self, monkeypatch) -> None:
        monkeypatch.setattr(finlai_paths, "_override", None)
        monkeypatch.delenv("FINLAI_HOME", raising=False)
        assert finlai_paths.finlai_home_override() is None

    def test_env_override(self, monkeypatch) -> None:
        monkeypatch.setattr(finlai_paths, "_override", None)
        monkeypatch.setenv("FINLAI_HOME", r"C:\iso")
        assert finlai_paths.finlai_home_override() == Path(r"C:\iso")

    def test_laufzeit_override_schlaegt_env(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("FINLAI_HOME", r"C:\env")
        finlai_paths.set_finlai_home(tmp_path)
        try:
            assert finlai_paths.finlai_home_override() == tmp_path
        finally:
            finlai_paths.set_finlai_home(None)


class TestFinlaiDir:
    def test_default_wenn_kein_override(self, monkeypatch) -> None:
        monkeypatch.setattr(finlai_paths, "_override", None)
        monkeypatch.delenv("FINLAI_HOME", raising=False)
        assert finlai_paths.finlai_dir() == Path.home() / ".finlai"

    def test_env_wirkt(self, monkeypatch) -> None:
        monkeypatch.setattr(finlai_paths, "_override", None)
        monkeypatch.setenv("FINLAI_HOME", r"C:\iso")
        assert finlai_paths.finlai_dir() == Path(r"C:\iso")

    def test_laufzeit_override_wirkt(self, monkeypatch, tmp_path) -> None:
        finlai_paths.set_finlai_home(tmp_path)
        try:
            assert finlai_paths.finlai_dir() == tmp_path
        finally:
            finlai_paths.set_finlai_home(None)
