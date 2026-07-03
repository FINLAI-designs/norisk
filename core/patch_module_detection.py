"""
patch_module_detection — Detection des ``Microsoft.WinGet.Client``-Moduls.

Bug-Fix-Sprint C-2 (urspruenglich in:mod:`core.patch_collector` integriert,
zu/C-6 ausgegliedert weil:mod:`core.patch_collector` ueber 1300 LoC
gewachsen war).

Stellt die drei Detection-Subprocess-Aufrufe + Caching bereit:

1. ``Get-Module -ListAvailable`` — Modul installiert?
2. ``Import-Module + Get-WinGetPackage | First 1`` — Probe-Aufruf (nur wenn
   Modul installiert)
3. ``Get-ExecutionPolicy -Scope CurrentUser`` — Differenziert NEEDS_INSTALL
   vs. BLOCKED

Privacy-Filter (Bug-Fix-Sprint C-5)::attr:`ModuleStatusDetail.reason` ist
klassen-basiert (:data:`MODULE_REASON_CLASSES`), niemals stderr-Excerpts
oder Pfad-/User-Daten. stderr-Excerpts gehen ausschliesslich in
:attr:`ModuleStatusDetail.reason_detail` und werden nur in der
Diagnose-Section (Opt-in) angezeigt.

Backwards-Compat::mod:`core.patch_collector` re-exportiert die public-API
dieses Moduls — bestehende Importe aus ``core.patch_collector`` bleiben
funktional.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from core.logger import get_logger
from core.proc import run_hidden

log = get_logger(__name__)


class ModuleStatus(StrEnum):
    """Stand des ``Microsoft.WinGet.Client``-PowerShell-Moduls.

    -:attr:`AVAILABLE`: Modul installiert + Probe-Aufruf erfolgreich.
      Patch-Monitor nutzt den primaeren PowerShell-Modul-Pfad.
    -:attr:`NEEDS_INSTALL`: Modul nicht installiert, Install vermutlich
      moeglich (Execution-Policy ist ``RemoteSigned``/``Unrestricted``,
      oder unklar). Wizard kann ``Install-Module`` versuchen.
    -:attr:`BLOCKED`: Modul nicht installiert UND Install vermutlich
      nicht moeglich (``Restricted``/``AllSigned``-Policy oder
      Subprocess-Fehler), ODER Modul installiert aber Probe-Aufruf
      schlaegt fehl. Patch-Monitor nutzt Fallback (Tabular +
      Registry + MSIX) und zeigt UI-Banner mit Hinweis.
    """

    AVAILABLE = "available"
    NEEDS_INSTALL = "needs_install"
    BLOCKED = "blocked"


#: Vokabular fuer:attr:`ModuleStatusDetail.reason` — klassen-basiert, niemals
#: stderr-Excerpts oder Pfad-/User-Daten (Bug-Fix-Sprint C-5 Privacy-Filter).
#: stderr-Excerpts gehen in:attr:`ModuleStatusDetail.reason_detail` und werden
#: nur in der Diagnose-Section (Opt-in) angezeigt.
MODULE_REASON_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "non-windows-platform",
        "powershell-subprocess-unavailable",
        "get-module-failed",
        "execution-policy-restricted",
        "execution-policy-allsigned",
        "module-not-found",
        "probe-failed",
        "probe-succeeded",
    }
)


@dataclass(frozen=True)
class ModuleStatusDetail:
    """Detail-Info zu:class:`ModuleStatus` fuer Wizard-/UI-Logik.

    Attributes:
        status: Hauptstatus (Detection-Ergebnis).
        reason: **Klassen-basierter** Code aus:data:`MODULE_REASON_CLASSES`
            (z.B. ``"module-not-found"``, ``"execution-policy-restricted"``,
            ``"probe-succeeded"``, ``"probe-failed"``). Privacy-safe — niemals
            stderr-Excerpts oder Pfad-/User-Daten. UI-Banner und
            Settings-Setup-Tab nutzen ausschliesslich diesen Wert.
        can_attempt_install: ``True`` wenn der Wizard
            ``Install-Module`` versuchen sollte. ``False`` bei
            ``AVAILABLE`` (schon installiert) und bei harten
            ``BLOCKED``-Pfaden (Execution-Policy verbietet Install).
        reason_detail: Optionaler Detail-Text (z.B. stderr-Excerpt aus
            fehlgeschlagenem Subprocess). **Nur fuer Admin-Diagnose-Opt-in
            anzeigen** — kann User-Profile-Pfade, Domain-Namen oder interne
            URLs enthalten. ``None`` bei reinen Klassen-Status ohne
            zusaetzlichen Kontext (``probe-succeeded``, ``module-not-found``,
            ``execution-policy-*``).
    """

    status: ModuleStatus
    reason: str
    can_attempt_install: bool
    reason_detail: str | None = None


_MODULE_DETECT_TIMEOUT_S: Final[int] = 10
_MODULE_PROBE_TIMEOUT_S: Final[int] = 15

#: One-Liner-PS: prueft ob das Modul auf der Maschine listed ist.
#:
#: ``Get-Module -ListAvailable`` listet installierte Module aus allen
#: PSModulePath-Verzeichnissen (User + AllUsers). Wir geben einen klar
#: parsbaren String zurueck statt die vollstaendige Modul-Liste —
#: Subprocess-Output bleibt klein und Locale-stabil.
_MODULE_LIST_CMD: Final[str] = (
    "if (Get-Module -ListAvailable Microsoft.WinGet.Client) "
    "{ 'INSTALLED' } else { 'NOT_INSTALLED' }"
)

#: Probe-Aufruf: Modul laden + ein Get-WinGetPackage-Aufruf simulieren.
#:
#: Bei Erfolg ``OK``, bei jedem Fehler nicht-Null returncode + stderr.
#: ``Select-Object -First 1`` haelt den Output minimal — wir interessieren
#: uns nur fuer "schlaegt der Aufruf fehl?", nicht fuer den Inhalt.
_MODULE_PROBE_CMD: Final[str] = (
    "Import-Module Microsoft.WinGet.Client -ErrorAction Stop; "
    "Get-WinGetPackage | Select-Object -First 1 | Out-Null; "
    "Write-Output 'OK'"
)

#: Execution-Policy-Check fuer NEEDS_INSTALL/BLOCKED-Differenzierung.
_EXECUTION_POLICY_CMD: Final[str] = (
    "Get-ExecutionPolicy -Scope CurrentUser"
)


def _ps_subprocess(
    cmd: str, timeout: int
) -> subprocess.CompletedProcess[str] | None:
    """Helper: powershell -NoProfile -Command <cmd> als CompletedProcess.

    Returns ``None`` bei Subprocess-Fehler (TimeoutExpired,
    FileNotFoundError, OSError) — Caller behandelt das wie returncode != 0.
    """
    try:
        return run_hidden(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def detect_winget_module() -> ModuleStatusDetail:
    """Prueft den Stand des ``Microsoft.WinGet.Client``-PowerShell-Moduls.

    Drei Subprocess-Aufrufe (alle fail-open):

    1. ``Get-Module -ListAvailable`` → ``INSTALLED``/``NOT_INSTALLED``
    2. Wenn ``INSTALLED``: Probe-Aufruf ``Get-WinGetPackage | First 1``
       → ``OK`` oder Fehler
    3. Wenn ``NOT_INSTALLED``: ``Get-ExecutionPolicy -Scope CurrentUser``
       → ``Restricted``/``AllSigned`` ⇒ BLOCKED, sonst NEEDS_INSTALL

    Auf non-Windows-Plattformen: BLOCKED ohne Subprocess-Aufruf.
    Bei Subprocess-Fehler (kein PowerShell, Timeout): BLOCKED.

    Wird intern via:func:`get_winget_module_status` gecacht, damit
    nicht jeder ``collect_all``-Aufruf die 3 Subprocess-Aufrufe macht.
    """
    if sys.platform != "win32":
        return ModuleStatusDetail(
            status=ModuleStatus.BLOCKED,
            reason="non-windows-platform",
            can_attempt_install=False,
        )

    # 1. Modul-Listing
    list_result = _ps_subprocess(_MODULE_LIST_CMD, _MODULE_DETECT_TIMEOUT_S)
    if list_result is None:
        return ModuleStatusDetail(
            status=ModuleStatus.BLOCKED,
            reason="powershell-subprocess-unavailable",
            can_attempt_install=False,
        )
    if list_result.returncode != 0:
        stderr_excerpt = (list_result.stderr or "")[:120]
        return ModuleStatusDetail(
            status=ModuleStatus.BLOCKED,
            reason="get-module-failed",
            can_attempt_install=False,
            reason_detail=stderr_excerpt or None,
        )

    listing = (list_result.stdout or "").strip().upper()
    # Strict equality — "INSTALLED" als Substring matcht sonst auch
    # "NOT_INSTALLED".
    if listing != "INSTALLED":
        # Modul nicht installiert. Execution-Policy pruefen.
        ep_result = _ps_subprocess(
            _EXECUTION_POLICY_CMD, _MODULE_DETECT_TIMEOUT_S
        )
        ep = (ep_result.stdout or "").strip().lower() if ep_result else ""
        # Restricted: kein Skript darf laufen. AllSigned: nur signierte
        # Skripte — Install-Module schlaegt typisch fehl. Wir mappen die
        # zwei Sub-Klassen explizit, damit das Vokabular endlich ist.
        if ep == "restricted":
            return ModuleStatusDetail(
                status=ModuleStatus.BLOCKED,
                reason="execution-policy-restricted",
                can_attempt_install=False,
            )
        if ep == "allsigned":
            return ModuleStatusDetail(
                status=ModuleStatus.BLOCKED,
                reason="execution-policy-allsigned",
                can_attempt_install=False,
            )
        # RemoteSigned, Unrestricted, Bypass, Default oder unbekannt:
        # Install lohnt sich zu versuchen.
        return ModuleStatusDetail(
            status=ModuleStatus.NEEDS_INSTALL,
            reason="module-not-found",
            can_attempt_install=True,
        )

    # 2. Modul installiert → Probe-Aufruf
    probe_result = _ps_subprocess(_MODULE_PROBE_CMD, _MODULE_PROBE_TIMEOUT_S)
    if probe_result is None or probe_result.returncode != 0:
        stderr_excerpt = (
            (probe_result.stderr or "")[:120]
            if probe_result
            else "subprocess-error"
        )
        return ModuleStatusDetail(
            status=ModuleStatus.BLOCKED,
            reason="probe-failed",
            can_attempt_install=False,
            reason_detail=stderr_excerpt or None,
        )

    return ModuleStatusDetail(
        status=ModuleStatus.AVAILABLE,
        reason="probe-succeeded",
        can_attempt_install=False,
    )


# Modul-Cache (1× detect_winget_module pro Prozess) — vermeidet 3
# Subprocess-Aufrufe pro collect_all-Call.
_module_status_cache: ModuleStatusDetail | None = None


def get_winget_module_status(
    *, force_refresh: bool = False
) -> ModuleStatusDetail:
    """Cached Detection-Ergebnis.

    Args:
        force_refresh: Wenn ``True``, verwirft den Cache und ruft
:func:`detect_winget_module` neu auf. Wird vom Wizard
            (C-3) nach erfolgreichem ``Install-Module`` aufgerufen.

    Returns:
:class:`ModuleStatusDetail` — gecacht beim ersten Call.
    """
    global _module_status_cache  # noqa: PLW0603 -- bewusst Modul-State
    if force_refresh or _module_status_cache is None:
        _module_status_cache = detect_winget_module()
    return _module_status_cache
