"""Tests fuer core.elevation Phase C) — UAC-Helfer.

Die ``ctypes.windll``-abhaengigen Faelle laufen nur unter Windows (skipif);
die plattform-unabhaengige Logik (Target-Aufloesung, Nicht-Windows-Pfade)
laeuft ueberall (Linux-CI inklusive).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from core import elevation

# ``ctypes.windll`` existiert nur unter Windows → entsprechende Faelle dort skippen.
_WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32", reason="ctypes.windll nur unter Windows verfuegbar"
)


@pytest.fixture
def shell32():
    """Liefert das (gecachte) shell32-WinDLL-Objekt fuer Monkeypatching."""
    import ctypes

    return ctypes.windll.shell32


class TestIsAdmin:
    def test_nicht_windows_ist_false(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert elevation.is_admin() is False

    @_WINDOWS_ONLY
    def test_elevated_true(self, monkeypatch, shell32):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(shell32, "IsUserAnAdmin", lambda: 1, raising=False)
        assert elevation.is_admin() is True

    @_WINDOWS_ONLY
    def test_nicht_elevated_false(self, monkeypatch, shell32):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(shell32, "IsUserAnAdmin", lambda: 0, raising=False)
        assert elevation.is_admin() is False


class TestElevationTarget:
    def test_frozen_nutzt_exe_ohne_basisargs(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", r"C:\app\norisk.exe")
        exe, base_args = elevation._elevation_target()
        assert exe == r"C:\app\norisk.exe"
        assert base_args == ""

    def test_dev_nutzt_interpreter_und_skript(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.setattr(sys, "argv", ["apps/norisk_app.py"])
        exe, base_args = elevation._elevation_target()
        # Interpreter (python/pythonw, plattform-unabhaengig) + gequotetes Skript
        assert "python" in Path(exe).name.lower()
        assert base_args.startswith('"') and base_args.endswith('"')
        assert "norisk_app.py" in base_args


class TestQuoteArg:
    def test_pfad_mit_space_wird_gequotet(self):
        assert elevation._quote_arg(r"C:\iso profil") == r'"C:\iso profil"'

    def test_flag_ohne_space_unveraendert(self):
        assert elevation._quote_arg("--finlai-home") == "--finlai-home"

    def test_bereits_gequotet_unveraendert(self):
        assert elevation._quote_arg('"x y"') == '"x y"'

    def test_leer_unveraendert(self):
        assert elevation._quote_arg("") == ""


class TestRelaunchElevated:
    def test_nicht_windows_raised(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with pytest.raises(RuntimeError):
            elevation.relaunch_elevated("--install-collector-task")

    @_WINDOWS_ONLY
    def test_erfolg_gibt_true_und_haengt_flag_an(self, monkeypatch, shell32):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", r"C:\app\norisk.exe")
        captured = {}

        def fake_exec(hwnd, op, file, params, directory, show):
            captured.update(op=op, file=file, params=params, show=show)
            return 42  # > 32 => Erfolg

        monkeypatch.setattr(shell32, "ShellExecuteW", fake_exec, raising=False)
        assert elevation.relaunch_elevated("--install-collector-task") is True
        assert captured["op"] == "runas"
        assert captured["file"] == r"C:\app\norisk.exe"
        assert "--install-collector-task" in captured["params"]

    @_WINDOWS_ONLY
    def test_abgelehnt_gibt_false(self, monkeypatch, shell32):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", r"C:\app\norisk.exe")
        # 5 (SE_ERR_ACCESSDENIED) <= 32 => Fehler/Abbruch
        monkeypatch.setattr(shell32, "ShellExecuteW", lambda *a: 5, raising=False)
        assert elevation.relaunch_elevated("--install-collector-task") is False

    @_WINDOWS_ONLY
    def test_extra_args_angehaengt_und_gequotet(self, monkeypatch, shell32):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", r"C:\app\norisk.exe")
        captured = {}

        def fake_exec(hwnd, op, file, params, directory, show):
            captured.update(params=params)
            return 42

        monkeypatch.setattr(shell32, "ShellExecuteW", fake_exec, raising=False)
        ok = elevation.relaunch_elevated(
            "--install-collector-task", "--finlai-home", r"C:\iso profil"
        )
        assert ok is True
        assert "--install-collector-task" in captured["params"]
        # Pfad mit Space wird gequotet, Flag bleibt roh.
        assert '--finlai-home "C:\\iso profil"' in captured["params"]
