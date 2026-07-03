"""
patch_winget_module — Software-Inventar via PowerShell-Modul ``Microsoft.WinGet.Client``.

Bug-Fix-Sprint C-1 (urspruenglich in:mod:`core.patch_collector` integriert,
zu/C-6 ausgegliedert weil:mod:`core.patch_collector` ueber 1300 LoC
gewachsen war). Primaerer Inventar-Pfad seit 2026-05-06 (loest Bug 3 —
``winget list --output json`` ist von winget-CLI-Versionen mit
``INVALID_CL_ARGUMENTS`` betroffen).

Locale-stabil: das PowerShell-Cmdlet liefert englische Property-Namen
(``Name``/``Id``/``InstalledVersion``/``AvailableVersions``/``IsUpdateAvailable``/``Source``).
Erfordert das Modul ``Microsoft.WinGet.Client`` — Onboarding via
:mod:`tools.patch_monitor.onboarding_dialog` (Bug-Fix-Sprint C-3 Option D).

Detection-Status liegt in:mod:`core.patch_module_detection` und wird vom
Fallback-Wrapper:func:`core.patch_collector.collect_winget_inventory`
genutzt.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Final

from core.logger import get_logger
from core.patch_software_types import SoftwareItem, SoftwareSource
from core.proc import run_hidden

log = get_logger(__name__)

_PWSH_MODULE_TIMEOUT_S: Final[int] = 30
_PWSH_MODULE_NAME: Final[str] = "Microsoft.WinGet.Client"

#: PowerShell-Befehl: Modul laden, Get-WinGetPackage aufrufen, JSON ausgeben.
#:
#: Output-Settings:
#: - ``$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new``
#: erzwingt UTF-8 fuer Subprocess-stdout. Notwendig fuer Unicode in
#: Display-Names (z.B. ``"Microsoft 365 Apps for business - ar-sa"``).
#: - ``-Depth 5`` reicht fuer das ``PSInstalledCatalogPackage``-Schema
#: (max. Tiefe 2 in der Praxis: Top-Level → AvailableVersions[]).
#: - ``-Compress`` minimiert stdout-Bytes ohne Whitespace.
#: - Leere Liste -> ``"[]"``-stdout, JSON-Parse erfolgt im Caller.
_PWSH_GET_PACKAGES_CMD: Final[str] = (
    '$OutputEncoding = [System.Text.UTF8Encoding]::new(); '
    '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); '
    'Import-Module Microsoft.WinGet.Client -ErrorAction Stop; '
    'Get-WinGetPackage | ConvertTo-Json -Depth 5 -Compress'
)


def collect_winget_module() -> list[SoftwareItem]:
    """Liest installierte Software via ``Microsoft.WinGet.Client``-PowerShell-Modul.

    PRIMAERER Pfad fuer Patch-Monitor seit 2026-05-06 (Bug-3-Fix).
    Locale-stabil (PowerShell-Cmdlet liefert englische Property-Namen),
    deckt ARP-/Registry- und Microsoft-Store-Apps mit ab (PSInstalledCatalogPackage
    aggregiert intern). Erfordert Modul-Installation (:func:`core.patch_module_detection.detect_winget_module` in C-2 / Wizard
    in C-3).

    Auf non-Windows-Plattformen: leere Liste. Bei fehlendem Modul,
    Subprocess-Timeout, JSON-Parse-Fehler oder unerwartetem Format:
    leere Liste + Log-Warning, kein Crash — Caller faellt auf
:func:`core.patch_collector.collect_winget` (Tabular) bzw. die
    Registry-/AppX-Sammler zurueck.

    Source-Mapping (Get-WinGetPackage → SoftwareSource):
        - ``"winget"`` → ``"winget"``
        - ``"msstore"`` → ``"msix"`` (semantisch passend, Store-Apps sind MSIX)
        - ``null`` → ``"registry"`` (ARP-Eintraege ohne winget-Catalog-Match)

    ``winget_id`` wird nur gesetzt wenn ``Source == "winget"`` — bei
    ARP-Apps ist ``Id`` ein Backslash-Pfad (``"ARP\\Machine\\X64\\..."``)
    der fuer CPE-Konstruktion (PM-1.5) untauglich ist. msstore-Apps
    haben Store-Identifier (``"XP8K2L36VP0QMB"``); aktuell ebenfalls
    ``winget_id=None`` gesetzt (Subtask 6 koennte das pruefen).

    Returns:
        Liste der gefundenen:class:`SoftwareItem`. Eintraege ohne
        ``Name`` oder ``InstalledVersion`` werden uebersprungen.
    """
    if sys.platform != "win32":
        return []

    # Subprocess: powershell.exe mit -NoProfile (laedt User-Profile
    # nicht — schneller + reproduzierbar).
    try:
        completed = run_hidden(
            ["powershell", "-NoProfile", "-Command", _PWSH_GET_PACKAGES_CMD],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_PWSH_MODULE_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "%s Get-WinGetPackage: Timeout nach %ds — leere Liste.",
            _PWSH_MODULE_NAME, _PWSH_MODULE_TIMEOUT_S,
        )
        return []
    except FileNotFoundError:
        log.warning("powershell.exe nicht im PATH — leere Liste.")
        return []
    except OSError as e:
        log.warning(
            "powershell-Subprocess fehlgeschlagen: %s — leere Liste.", e
        )
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "%s Get-WinGetPackage exit=%d, stderr=%r — leere Liste.",
            _PWSH_MODULE_NAME, completed.returncode, stderr_excerpt,
        )
        return []

    return _parse_winget_module_json(completed.stdout)


def _parse_winget_module_json(stdout: str) -> list[SoftwareItem]:
    """Parst ``Get-WinGetPackage | ConvertTo-Json -Compress``-Output.

    Erwartetes Schema (verifiziert auf Patrick-Workstation 2026-05-06):

.. code-block:: json

        [
          {
            "Name": "Docker Desktop",
            "Id": "Docker.DockerDesktop",
            "InstalledVersion": "4.69.0",
            "AvailableVersions": ["4.71.0", "4.70.0",...],
            "IsUpdateAvailable": true,
            "Source": "winget"
          },
...
]

    Edge-Cases (alle aus C-0.2-Verifikation):
        - Source kann ``"winget"`` / ``"msstore"`` / ``null`` sein
        - InstalledVersion kann Timestamp-String sein (Mesh-Agent-Pattern)
        - AvailableVersions kann leer sein (ARP-Apps)
        - AvailableVersions kann **aeltere** Version enthalten — dann
          IsUpdateAvailable=false (Bitdefender-Pattern). Wir nutzen
          IsUpdateAvailable autoritativ, leiten NICHT aus AvailableVersions ab.
        - ConvertTo-Json bei einzelnem Element liefert ein Objekt statt Array.
          Wir tolerieren beides.

    Tolerant: Eintraege ohne ``Name`` oder ``InstalledVersion`` werden
    uebersprungen, JSON-Parse-Fehler triggert leere Liste + log.warning.
    """
    if not stdout.strip():
        # Leerer Output (z.B. keine Packages) → leere Liste.
        return []

    try:
        data: Any = json.loads(stdout)
    except json.JSONDecodeError as e:
        log.warning(
            "%s: JSON-Parse-Fehler %s — leere Liste.",
            _PWSH_MODULE_NAME, e,
        )
        return []

    # ConvertTo-Json bei single-Element → dict statt Liste.
    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        log.warning(
            "%s: erwartete JSON-Liste oder dict, bekam %s — leere Liste.",
            _PWSH_MODULE_NAME, type(data).__name__,
        )
        return []

    items: list[SoftwareItem] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("Name")
        installed_version = entry.get("InstalledVersion")
        if not name or not installed_version:
            continue

        source_raw = entry.get("Source")
        ps_source: SoftwareSource
        winget_id: str | None
        store_id: str | None = None
        if source_raw == "winget":
            ps_source = "winget"
            winget_id = str(entry.get("Id")) if entry.get("Id") else None
        elif source_raw == "msstore":
            # Store-Apps: semantisch zu "msix" mappen. Id ist Store-
            # Identifier (z.B. "XP8K2L36VP0QMB"), kein winget-Catalog-
            # Format → kein winget_id, dafuer store_id.
            ps_source = "msix"
            winget_id = None
            store_id = str(entry.get("Id")) if entry.get("Id") else None
        else:
            # Source=null oder unbekannt → ARP/Registry-Eintrag.
            # Id ist Backslash-Pfad ("ARP\Machine\X64\Git_is1") und
            # untauglich fuer CPE → kein winget_id.
            ps_source = "registry"
            winget_id = None

        # Update-Info aus PowerShell-Modul (autoritativ — siehe Doc-
        # String von SoftwareItem.is_update_available).
        is_update = bool(entry.get("IsUpdateAvailable", False))
        avail_list = entry.get("AvailableVersions") or []
        latest = (
            str(avail_list[0])
            if isinstance(avail_list, list) and avail_list
            else None
        )

        items.append(
            SoftwareItem(
                name=str(name),
                version=str(installed_version),
                winget_id=winget_id,
                source=ps_source,
                is_update_available=is_update,
                latest_available=latest,
                store_id=store_id,
            )
        )

    return items
