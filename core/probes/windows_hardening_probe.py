"""
windows_hardening_probe — Production-Adapter fuer IHardeningProbe.

Konkrete Windows-Implementation der:class:`IHardeningProbe`-Methoden.
Nutzt ``subprocess`` fuer Command-/PowerShell-Aufrufe und ``winreg``
fuer Registry-Reads. **Read-only** — dieser Adapter veraendert nie den
System-State (Apply/Write-Ops leben in ``tools/system_tuner``).

Geteiltes Utility (core/probes/): urspruenglich
``tools/system_scanner/data/windows_hardening_probe.py``.

**Windows-only.** Auf nicht-Windows-Plattformen liefert
:meth:`is_available` ``False``; alle anderen Methoden returnen ein
fail-safes:class:`ProbeResult` mit ``success=False``.

CI-Hinweis: Diese Datei wird auf dem Linux-Smoke-Runner zwar importiert,
``winreg`` ist aber lazy importiert (innerhalb der Methode, hinter dem
Platform-Check). Damit bricht der Modul-Import nicht.

Schichtzugehoerigkeit: core/probes/ — Adapter-Implementation.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Final

from core.logger import get_logger
from core.probes.hardening_probe import (
    HIVE_HKCU,
    HIVE_HKLM,
    IHardeningProbe,
    ProbeResult,
)
from core.proc import run_hidden

log = get_logger(__name__)

_WINDOWS: Final[bool] = sys.platform == "win32"

#: Default-Timeout fuer Probes (Sekunden). Tools wie ``manage-bde`` oder
#: ``Get-SmbServerConfiguration`` koennen bei langsamen Systemen kurz
#: brauchen — 30 s ist konservativ.
_DEFAULT_TIMEOUT: Final[int] = 30


class WindowsHardeningProbe(IHardeningProbe):
    """Production-Adapter — laeuft Probes auf der echten Windows-Maschine.

    Wirft niemals Exceptions weiter — alle Fehler landen in
    ``ProbeResult.error``. Caller (WindowsHardeningScanner) reagiert
    gracefuly mit ``passed=False`` + Probe-Fehler-Detail.
    """

    def is_available(self) -> bool:
        """``True`` nur auf ``sys.platform == "win32"``."""
        return _WINDOWS

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def read_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
    ) -> str | None:
        """Liest einen Registry-Wert via winreg.

        Args:
            hive: ``HIVE_HKLM`` oder ``HIVE_HKCU``.
            key_path: Schluessel-Pfad ohne Hive-Praefix.
            value_name: Name des Werts.

        Returns:
            String-Repraesentation des Werts (auch numerische Werte
            werden via ``str`` konvertiert), oder ``None`` bei
            jedem Fehler (Schluessel/Wert fehlt, Permission-Denied,
            nicht-Windows).
        """
        if not _WINDOWS:
            return None
        # Lazy-Import: winreg existiert nur auf Windows. Auf Linux-CI wird
        # diese Methode wegen is_available-Guard nicht erreicht — der
        # Modul-Import bleibt sauber.
        import winreg  # noqa: PLC0415

        hive_const = _resolve_hive(winreg, hive)
        if hive_const is None:
            log.warning("Unbekannter Hive: %r", hive)
            return None

        try:
            with winreg.OpenKey(  # type: ignore[attr-defined]
                hive_const, key_path, 0, winreg.KEY_READ
            ) as key:
                value, _type = winreg.QueryValueEx(key, value_name)  # type: ignore[attr-defined]
        except FileNotFoundError:
            return None
        except OSError as exc:
            log.warning(
                "Registry-Read fehlgeschlagen %s\\%s\\%s: %s",
                hive,
                key_path,
                value_name,
                exc,
            )
            return None

        return str(value)

    # ------------------------------------------------------------------
    # Command
    # ------------------------------------------------------------------

    def run_command(
        self,
        executable: str,
        args: list[str],
        *,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> ProbeResult:
        """Ruft einen externen Befehl via subprocess auf.

        Args:
            executable: Tool-Name (PATH-Lookup).
            args: Argumente-Liste.
            timeout: Sekunden bis Abbruch.

        Returns:
:class:`ProbeResult` mit ``success`` reflektiert den
            Exit-Code (0 = success, sonst False).
        """
        if not _WINDOWS:
            return ProbeResult(
                success=False,
                error="WindowsHardeningProbe: nicht-Windows-Plattform",
                returncode=-1,
            )
        cmd = [executable, *args]
        return _run_subprocess(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # PowerShell
    # ------------------------------------------------------------------

    def run_powershell(
        self,
        script: str,
        *,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> ProbeResult:
        """Ruft ein PowerShell-Skript via ``powershell -NoProfile -Command`` auf.

        Args:
            script: PowerShell-Skript / Cmdlet-Aufruf.
            timeout: Sekunden bis Abbruch.

        Returns:
:class:`ProbeResult`.
        """
        if not _WINDOWS:
            return ProbeResult(
                success=False,
                error="WindowsHardeningProbe: nicht-Windows-Plattform",
                returncode=-1,
            )
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
        return _run_subprocess(cmd, timeout=timeout)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _resolve_hive(winreg_module: Any, hive: str) -> int | None:
    """Mapped einen Hive-String auf die winreg-Konstante (HKEY_* ist int)."""
    if hive == HIVE_HKLM:
        return int(winreg_module.HKEY_LOCAL_MACHINE)
    if hive == HIVE_HKCU:
        return int(winreg_module.HKEY_CURRENT_USER)
    return None


def _run_subprocess(cmd: list[str], *, timeout: int) -> ProbeResult:
    """Synchroner subprocess-Aufruf mit Timeout + Error-Mapping."""
    try:
        # run_hidden: args-Liste (kein Shell) + CREATE_NO_WINDOW,
        # kein aufflackerndes Konsolenfenster auf Windows).
        completed = run_hidden(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return ProbeResult(
            success=False,
            error=f"Executable nicht gefunden: {cmd[0]}",
            returncode=-1,
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(
            success=False,
            error=f"Timeout nach {timeout}s bei {cmd[0]}",
            returncode=-1,
        )
    except OSError as exc:
        return ProbeResult(
            success=False,
            error=f"OSError: {exc}",
            returncode=-1,
        )

    return ProbeResult(
        success=completed.returncode == 0,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        returncode=completed.returncode,
        error="" if completed.returncode == 0 else f"Exit-Code {completed.returncode}",
    )
