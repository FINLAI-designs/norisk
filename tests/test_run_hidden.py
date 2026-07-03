"""
test_run_hidden — pytest-Tests fuer:func:`core.proc.run_hidden`.

Deckt die Security-Vorgaben ab:

* LIST-args erzwungen — String-Command wird abgelehnt.
* ``shell=True`` wird abgelehnt.
* Windows: ``CREATE_NO_WINDOW`` + ``STARTUPINFO`` mit ``SW_HIDE``.
* Nicht-Windows: keine Flags, reiner Passthrough.
* Ein umgestellter Probe-Aufruf (WindowsHardeningProbe) parst weiterhin
  korrekt, wenn ``run_hidden`` einen:class:`subprocess.CompletedProcess`
  liefert.

Pure Logik — kein echter Subprozess wird gestartet (``subprocess.run`` ist
gemockt).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.proc import run_hidden

# Hinweis: ``core.proc.__init__`` re-exportiert die FUNKTION ``run_hidden`` als
# Paket-Attribut und ueberschattet damit das gleichnamige Submodul. Wir holen
# das echte Modul-Objekt deshalb explizit aus ``sys.modules`` (dort liegt das
# Submodul ``core.proc.run_hidden`` unter seinem voll-qualifizierten Namen),
# um ``subprocess.run`` im Modul-Scope monkeypatchen zu koennen.
run_hidden_mod = sys.modules["core.proc.run_hidden"]


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Ersetzt ``subprocess.run`` im run_hidden-Modul durch einen Recorder.

    Returns:
        Ein Dict, das nach dem Aufruf ``args`` (positional) und ``kwargs``
        des abgefangenen ``subprocess.run``-Aufrufs enthaelt.
    """
    captured: dict = {}

    def _fake_run(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args=args[0] if args else None,
            returncode=0,
            stdout="OK",
            stderr="",
        )

    monkeypatch.setattr(run_hidden_mod.subprocess, "run", _fake_run)
    return captured


# ===========================================================================
# Windows: CREATE_NO_WINDOW + STARTUPINFO
# ===========================================================================


class TestWindowsHidesWindow:
    def test_sets_create_no_window_flag(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        # Plattform-Verzweigung deterministisch auf Windows zwingen.
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", True)
        # Fake-Konstanten, damit der Test auch auf Linux-CI laeuft (dort
        # existiert subprocess.CREATE_NO_WINDOW nicht).
        monkeypatch.setattr(run_hidden_mod, "_CREATE_NO_WINDOW", 0x08000000)

        run_hidden(["powershell", "-NoProfile", "-Command", "Get-Date"])

        flags = captured_run["kwargs"]["creationflags"]
        assert flags & 0x08000000, "CREATE_NO_WINDOW muss gesetzt sein"

    def test_passes_hidden_startupinfo(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", True)
        monkeypatch.setattr(run_hidden_mod, "_CREATE_NO_WINDOW", 0x08000000)

        # STARTUPINFO-Builder durch ein Sentinel ersetzen — der echte Builder
        # ruft Windows-only-Attribute auf, die auf Linux-CI fehlen.
        sentinel = SimpleNamespace(name="hidden-startupinfo")
        monkeypatch.setattr(
            run_hidden_mod, "_build_hidden_startupinfo", lambda: sentinel
        )

        run_hidden(["wmic", "cpu", "get", "Name"])

        assert captured_run["kwargs"]["startupinfo"] is sentinel

    def test_create_no_window_is_additive(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", True)
        monkeypatch.setattr(run_hidden_mod, "_CREATE_NO_WINDOW", 0x08000000)
        monkeypatch.setattr(
            run_hidden_mod, "_build_hidden_startupinfo", lambda: object()
        )

        run_hidden(["winget", "list"], creationflags=0x00000200)

        flags = captured_run["kwargs"]["creationflags"]
        # Beide Flags muessen erhalten bleiben (ODER-Verknuepfung).
        assert flags & 0x08000000
        assert flags & 0x00000200

    def test_caller_startupinfo_not_overwritten(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", True)
        monkeypatch.setattr(run_hidden_mod, "_CREATE_NO_WINDOW", 0x08000000)

        own = SimpleNamespace(name="caller-startupinfo")
        run_hidden(["cmd", "/c", "echo", "hi"], startupinfo=own)

        assert captured_run["kwargs"]["startupinfo"] is own


# ===========================================================================
# Nicht-Windows: kein Flag, reiner Passthrough
# ===========================================================================


class TestNonWindowsPassthrough:
    def test_no_creationflags_on_posix(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", False)

        run_hidden(["ls", "-la"])

        assert "creationflags" not in captured_run["kwargs"]
        assert "startupinfo" not in captured_run["kwargs"]

    def test_kwargs_passed_through(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", False)

        run_hidden(
            ["echo", "x"],
            capture_output=True,
            text=True,
            timeout=7,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

        kw = captured_run["kwargs"]
        assert kw["capture_output"] is True
        assert kw["text"] is True
        assert kw["timeout"] == 7
        assert kw["encoding"] == "utf-8"
        assert kw["errors"] == "replace"
        assert kw["check"] is False

    def test_cmd_passed_as_first_positional(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", False)

        cmd = ["winget", "--version"]
        run_hidden(cmd)

        assert captured_run["args"][0] == cmd
        # shell wird IMMER explizit auf False gesetzt.
        assert captured_run["kwargs"]["shell"] is False


# ===========================================================================
# Security: LIST-args erzwungen, kein shell=True
# ===========================================================================


class TestSecurityGuards:
    def test_rejects_str_command(self, captured_run: dict) -> None:
        with pytest.raises(TypeError, match="Argument-Liste"):
            run_hidden("powershell -Command Get-Date")  # type: ignore[arg-type]
        # subprocess.run darf gar nicht erreicht worden sein.
        assert captured_run == {}

    def test_rejects_bytes_command(self, captured_run: dict) -> None:
        with pytest.raises(TypeError):
            run_hidden(b"winget list")  # type: ignore[arg-type]
        assert captured_run == {}

    def test_rejects_shell_true(self, captured_run: dict) -> None:
        with pytest.raises(ValueError, match="shell=True"):
            run_hidden(["winget", "list"], shell=True)
        assert captured_run == {}

    def test_returns_completed_process(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict
    ) -> None:
        monkeypatch.setattr(run_hidden_mod, "_WINDOWS", False)

        result = run_hidden(["echo", "hi"])
        assert isinstance(result, subprocess.CompletedProcess)
        assert result.returncode == 0
        assert result.stdout == "OK"


# ===========================================================================
# Probe-Integration: umgestellter Aufruf parst weiterhin korrekt
# ===========================================================================


class TestProbeStillParses:
    """Ein umgestellter WindowsHardeningProbe-Aufruf liefert sauberes ProbeResult."""

    def test_run_powershell_parses_via_run_hidden(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import core.probes.windows_hardening_probe as whp

        # is_available-Guard auf Windows-Pfad zwingen, ohne echtes Windows.
        monkeypatch.setattr(whp, "_WINDOWS", True)

        # run_hidden (im Probe-Modul referenziert) durch einen Recorder ersetzen,
        # der eine erfolgreiche Konsolen-Ausgabe simuliert.
        captured: dict = {}

        def _fake_run_hidden(cmd, **kwargs):  # noqa: ANN001, ANN003, ANN202
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="EnableSMB1Protocol : False",
                stderr="",
            )

        monkeypatch.setattr(whp, "run_hidden", _fake_run_hidden)

        probe = whp.WindowsHardeningProbe()
        result = probe.run_powershell("Get-SmbServerConfiguration", timeout=5)

        # Parsing-Schnittstelle unveraendert: success + stdout korrekt gemappt.
        assert result.success is True
        assert result.returncode == 0
        assert "EnableSMB1Protocol : False" in result.stdout
        # run_hidden bekam eine args-LISTE (kein String) — kein Shell-Pfad.
        assert isinstance(captured["cmd"], list)
        assert captured["cmd"][0] == "powershell.exe"
        # encoding/errors wurden durchgereicht (cp1252/OEM-Verhalten erhalten).
        assert captured["kwargs"]["encoding"] == "utf-8"
        assert captured["kwargs"]["errors"] == "replace"

    def test_run_command_failure_maps_exit_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import core.probes.windows_hardening_probe as whp

        monkeypatch.setattr(whp, "_WINDOWS", True)

        def _fake_run_hidden(cmd, **kwargs):  # noqa: ANN001, ANN003, ANN202
            return subprocess.CompletedProcess(
                args=cmd, returncode=87, stdout="", stderr="Zugriff verweigert"
            )

        monkeypatch.setattr(whp, "run_hidden", _fake_run_hidden)

        probe = whp.WindowsHardeningProbe()
        result = probe.run_command("manage-bde", ["-status"], timeout=8)

        assert result.success is False
        assert result.returncode == 87
        assert "Zugriff verweigert" in result.stderr
