"""
patch_collector — Software-Inventar via winget + Registry + MSIX/AppX.

PM-1.1a. Reine, synchrone Sammelfunktionen — kein Qt, kein
Threading, keine I/O ueber subprocess + winreg hinaus. Wird vom
ScanWorker (PM-1.1b) in einem Hintergrund-Thread aufgerufen.

Quellen:
    1. ``winget list --output json`` — vollstaendigste Quelle, liefert
       ``Id`` (z.B. ``Mozilla.Firefox``) fuer spaetere CPE-Konstruktion
       in PM-1.5.
    2. ``Uninstall``-Registry-Pfade in HKLM **und HKCU** — Fallback fuer
       Programme, die winget nicht kennt (selbst gehostete,
       MSI-installierte, alte Setup.exe). HKCU faengt
       Per-User-Installationen ab (Slack, Discord, Teams, Zoom, Spotify
       installieren sich typisch per-User, nicht in HKLM).
    3. ``Get-AppxPackage`` (PowerShell) — MSIX/Store-Apps. Beispiele:
       Microsoft Photos, Snipping Tool, Windows Terminal (Store-Variante),
       Xbox App. Tauchen nicht in winget-list und nicht in Registry auf.
    4. Windows-Update-Agent (PowerShell-COM, OFFLINE/cached) — ausstehende
       Windows-Updates: OS-/KB-Patches,.NET-Updates, Treiber-Updates.
       Nicht winget-installierbar (synthetische ``wu:``-Id, gegated);
       erscheinen als "Update verfuegbar", Installation ueber die
       Windows-Einstellungen. Siehe:func:`collect_windows_update`.
    5..NET-Laufzeiten (Registry + ``dotnet --list-runtimes``) —
       installierte.NET-Framework- und.NET-Core/5+-Versionen. Reine
       Inventar-Sichtbarkeit ohne Update-Erkennung (synthetische
       ``dotnet:``-Id, gegated); erscheinen als "up_to_date".
.NET-Updates kommen ueber Windows-Update (Quelle 4). Siehe
:func:`collect_dotnet_runtimes`.

Deduplizierung in:func:`collect_all`: Eintraege mit case-insensitiv
identischem ``name`` werden zusammengefuehrt — Reihenfolge:
**winget > registry > msix > windows_update > dotnet**. winget gewinnt
strukturell, weil die ``Id`` mehr Information fuer downstream-Schritte
traegt; Registry vor MSIX, weil viele MSIX-Apps zusaetzlich
Registry-Eintraege erzeugen; Windows-Updates danach (eigener
Namensraum, kollidiert in der Praxis nie);.NET-Laufzeiten zuletzt
(eigener Namensraum).

Alle Sammler ausser:func:`collect_dotnet_runtimes` sind
**Windows-only** und geben auf anderen Plattformen sofort eine leere
Liste zurueck (relevant fuer Linux-CI und non-Windows-Entwickler).
:func:`collect_dotnet_runtimes` ist teil-plattformuebergreifend: der
.NET-Framework-Teil ist Windows-only (Registry), der.NET-Core/5+-Teil
laeuft ueber ``dotnet --list-runtimes`` auf jeder Plattform.
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import sys
from typing import Any

from core.console_encoding import console_encoding
from core.logger import get_logger
from core.patch_normalizer import normalize_name

#/: SoftwareItem/SoftwareSource leben jetzt im Leaf-Modul
# patch_software_types (bricht den Zyklus patch_collector <-> patch_winget_module).
# Re-Export hier, damit bestehende ``from core.patch_collector import SoftwareItem``
# unveraendert funktionieren (Namen stehen in __all__).
from core.patch_software_types import SoftwareItem, SoftwareSource
from core.proc import run_hidden

log = get_logger(__name__)

_WINGET_TIMEOUT_S = 30
_APPX_TIMEOUT_S = 20
# Windows-Update-Agent-Suche: grosszuegiges Timeout, weil die COM-Suche
# auch im OFFLINE-Modus (cached) je nach Update-Historie ein paar
# Sekunden braucht. Online wuerde sie am Netzwerk haengen — deshalb
# erzwingt ``_WU_PS`` ``$u.Online = $false`` (
#:func:`collect_windows_update`).
_WU_TIMEOUT_S = 90
# ``dotnet --list-runtimes`` antwortet lokal in <1 s; 15 s ist grosszuegig
# fuer langsame/aufgewachte Disks, ohne im Hintergrund spuerbar zu blocken.
_DOTNET_TIMEOUT_S = 15
# ``Get-PnpDevice`` + pro Geraet ein ``Get-PnpDeviceProperty`` antwortet
# lokal in wenigen Sekunden; 30 s ist grosszuegig fuer Systeme mit vielen
# Geraeten, ohne im Hintergrund spuerbar zu blocken.
_DRIVER_TIMEOUT_S = 30

# Parst eine Zeile aus ``dotnet --list-runtimes``, z.B.
# ``Microsoft.NETCore.App 8.0.11 [C:\Program Files\dotnet\shared\...]``.
# Gruppen: (1) Family-Id (``Microsoft.NETCore.App``), (2) Voll-Version
# (``8.0.11``). Der Pfad-Teil in eckigen Klammern wird verworfen.
_DOTNET_RUNTIME_RE: re.Pattern[str] = re.compile(
    r"^(\S+)\s+(\d+\.\d+(?:\.\d+)*)\s*\["
)

# Family-Id (aus ``dotnet --list-runtimes``) -> menschenlesbarer Anzeige-
# Stamm. Der MAJOR.MINOR wird angehaengt (:func:`_parse_dotnet_runtimes`),
# sodass verschiedene Familien/Majors distinkte Inventar-Eintraege werden.
_DOTNET_FAMILY_LABELS: dict[str, str] = {
    "Microsoft.NETCore.App": ".NET Runtime",
    "Microsoft.AspNetCore.App": ".NET ASP.NET Core",
    "Microsoft.WindowsDesktop.App": ".NET Desktop",
}

# Extrahiert die KB-Nummer aus einem Update-Titel (z.B.
# "2024-06 Cumulative Update... (KB5039212)"). Stabiler Identifier-Kern
# fuer die synthetische ``wu:``-Id —:func:`_with_synthetic_id`.
_KB_PATTERN: re.Pattern[str] = re.compile(r"KB\d+", re.IGNORECASE)

# PowerShell-Skript fuer die Windows-Update-Agent-COM-Suche. OFFLINE
# (``$u.Online = $false``) -> nutzt den lokalen Update-Cache, ist damit
# schnell und haengt NIE am Netzwerk. Liefert pro ausstehendem,
# nicht-versteckten Update Title/KB/Severity als JSON. ``catch`` gibt
# einen Leerstring zurueck (z.B. wenn der Windows-Update-Dienst
# deaktiviert ist) ->:func:`collect_windows_update` faellt fail-soft
# auf ``[]`` zurueck.
_WU_PS = (
    "$ErrorActionPreference='Stop'\n"
    "try {\n"
    "  $s = New-Object -ComObject Microsoft.Update.Session\n"
    "  $u = $s.CreateUpdateSearcher()\n"
    "  $u.Online = $false\n"
    "  $r = $u.Search(\"IsInstalled=0 and IsHidden=0\")\n"
    "  $r.Updates | ForEach-Object {\n"
    "    [pscustomobject]@{ Title=$_.Title; "
    "KB=(($_.KBArticleIDs) -join ','); Severity=$_.MsrcSeverity }\n"
    "  } | ConvertTo-Json\n"
    "} catch { '' }"
)

# PowerShell-Skript fuer das KURATIERTE Treiber-Inventar. Fragt NUR die
# sicherheitsrelevanten Geraeteklassen ab (Display=GPU, Net=Netzwerk,
# DiskDrive/SCSIAdapter=Storage) — NICHT alle Treiber, sonst entstuenden
# hunderte rauschige Zeilen. Liest pro vorhandenem, funktionierendem
# Geraet (``Status -eq 'OK'``) die installierte Treiber-Version
# (``DEVPKEY_Device_DriverVersion``). ``catch`` gibt einen Leerstring
# zurueck ->:func:`collect_drivers` faellt fail-soft auf ``[]`` zurueck.
_DRIVER_PS = (
    "$ErrorActionPreference='Stop'\n"
    "try {\n"
    "  Get-PnpDevice -PresentOnly -Class Display,Net,DiskDrive,SCSIAdapter "
    "-ErrorAction Stop |\n"
    "    Where-Object { $_.Status -eq 'OK' } |\n"
    "    ForEach-Object {\n"
    "      $v = ($_ | Get-PnpDeviceProperty -KeyName "
    "'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data\n"
    "      [pscustomobject]@{ Name=$_.FriendlyName; Class=$_.Class; Version=$v }\n"
    "    } | ConvertTo-Json\n"
    "} catch { '' }"
)

# Tupel-Eintraege: (Hive-Name, Pfad). Hive-Name wird in
#:func:`collect_registry` ueber ``winreg``-Konstanten aufgeloest.
_REGISTRY_PATHS: tuple[tuple[str, str], ...] = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
)

# MSIX-Pakete, die System-Komponenten / Frameworks / Spiele-Overlays sind
# und nicht als eigenstaendige Software in der Patch-UI auftauchen sollen.
# Match per ``name.startswith`` (case-insensitiv — 
#:func:`_is_msix_noise`). Quelle: typische Get-AppxPackage-Ausgabe auf
# Standard-Windows-11-Installation, plus Code-Review 2026-05-03.
_MSIX_IGNORE_PREFIXES: tuple[str, ...] = (
    #.NET / VC / WinUI Runtimes (keine User-Apps)
    "Microsoft.NET.Native",
    "Microsoft.VCLibs",
    "Microsoft.UI.Xaml",
    "Microsoft.WindowsAppRuntime",
    "Microsoft.WindowsAppSDK",
    # Microsoft Store / Edge System-Komponenten
    "Microsoft.Services.Store",
    "Microsoft.Windows.NativeHost",
    "Microsoft.MicrosoftEdgeDevToolsClient",
    # Windows-System-Apps
    "Microsoft.BioEnrollment",
    "Microsoft.ECApp",
    "Microsoft.LockApp",
    "Microsoft.Win32WebViewHost",
    "Microsoft.AccountsControl",
    "Microsoft.AsyncTextService",
    "Microsoft.capabilityaccessmanager",
    "Microsoft.Windows.CapturePicker",
    "Microsoft.Windows.CloudExperienceHost",
    "Microsoft.Windows.OOBENetworkCaptivePortal",
    "Microsoft.Windows.PeopleExperienceHost",
    "Microsoft.Windows.PrintQueueActionCenter",
    "Microsoft.CredDialogHost",
    "Microsoft.AAD.BrokerPlugin",
    "Windows.CBSPreview",
    "windows.immersivecontrolpanel",
    # Xbox-Overlays (system, nicht "Xbox-App")
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    # Legacy-Built-Ins
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
)

# UUID-benannte MSIX-Pakete (z.B. ``1527c705-839a-4832-9118-54d4bd6a0c89``)
# sind typisch Preview-/Internal-Installs ohne stabilen Anzeige-Namen —
# fuer die Patch-UI uninteressant.
_UUID_PATTERN: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.IGNORECASE
)


def collect_winget() -> list[SoftwareItem]:
    """Liest installierte Software via ``winget list``.

    Auf non-Windows-Plattformen: leere Liste.

    Erkennt automatisch die installierte winget-Version (:func:`_get_winget_args`):

    * winget >= 1.6 → ``--output json`` (strukturierte JSON-Antwort)
    * winget < 1.6 → Text-Tabelle mit Spalten Name/Id/Version/Available

    So funktioniert die Sammlung auch auf Maschinen mit aelterer
    winget-Installation (z.B. Windows 10 ohne Auto-Update). Bei
    Timeout, JSON-Parse-Fehler, nicht-Null-Returncode oder
    unerwartetem Format: leere Liste + Log-Warning, kein Crash —
    der Aufrufer faellt dann auf:func:`collect_registry` zurueck.

    Returns:
        Liste der gefundenen:class:`SoftwareItem` mit
        ``source="winget"``. Eintraege ohne ``Name`` oder ``Version``
        werden uebersprungen.
    """
    if sys.platform != "win32":
        return []

    args = _get_winget_args()
    if args is None:
        return []
    use_json = "json" in args

    try:
        completed = run_hidden(
            args,
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_WINGET_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "winget list: Timeout nach %ds — leere Liste.", _WINGET_TIMEOUT_S
        )
        return []
    except FileNotFoundError:
        log.warning("winget nicht installiert oder nicht im PATH — leere Liste.")
        return []
    except OSError as e:
        log.warning("winget list fehlgeschlagen: %s — leere Liste.", e)
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "winget list exit=%d, stderr=%r — leere Liste.",
            completed.returncode,
            stderr_excerpt,
        )
        return []

    if use_json:
        return _parse_winget_json(completed.stdout)
    return _parse_winget_text(completed.stdout)


def _get_winget_args() -> list[str] | None:
    """Liefert ein passendes ``winget list``-argv basierend auf Version.

    Ablauf:

    1. Probiert ``winget --version`` auf (Timeout 5 s).
    2. winget nicht installiert / nicht im PATH / Fehler → ``None``
       (Aufrufer faellt auf Registry/MSIX zurueck).
    3. Version >= 1.6 → ``--output json`` (strukturiert).
    4. Version < 1.6 oder Parse-Fehler → ohne ``--output``-Flag
       (Text-Tabelle, geparst von:func:`_parse_winget_text`).

    Returns:
        argv-Liste fuer ``subprocess.run`` oder ``None``.
    """
    try:
        version_completed = run_hidden(
            ["winget", "--version"],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.warning("winget --version nicht abrufbar — leere Liste.")
        return None
    except OSError as e:
        log.warning("winget --version fehlgeschlagen: %s — leere Liste.", e)
        return None

    if version_completed.returncode != 0:
        log.warning(
            "winget --version exit=%d — leere Liste.",
            version_completed.returncode,
        )
        return None

    raw = (version_completed.stdout or "").strip().lstrip("v")
    use_json = False
    try:
        major_str, minor_str, *_ = raw.split(".")
        if (int(major_str), int(minor_str)) >= (1, 6):
            use_json = True
    except (ValueError, IndexError):
        # Unparsbarer Version-String -> defensiv den Text-Pfad waehlen.
        log.debug(
            "winget Version %r nicht parsbar — Text-Fallback.", raw
        )
        use_json = False

    base = [
        "winget",
        "list",
        "--accept-source-agreements",
        "--disable-interactivity",
    ]
    if use_json:
        return [base[0], base[1], "--output", "json", *base[2:]]
    return base


def _parse_winget_json(stdout: str) -> list[SoftwareItem]:
    """Parst ``winget list --output json``-Output.

    Erwartet eine JSON-Liste von Objekten mit Feldern
    ``Id``/``Name``/``Version``/``Source``. Tolerant gegenueber
    fehlenden Feldern: Eintraege ohne ``Name`` oder ``Version``
    werden uebersprungen.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        log.warning("winget list: JSON-Parse-Fehler %s — leere Liste.", e)
        return []

    if not isinstance(data, list):
        log.warning(
            "winget list: erwartete JSON-Liste, bekam %s — leere Liste.",
            type(data).__name__,
        )
        return []

    items: list[SoftwareItem] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("Name")
        version = entry.get("Version")
        if not name or not version:
            continue
        winget_id = entry.get("Id") or None
        items.append(
            SoftwareItem(
                name=str(name),
                version=str(version),
                winget_id=str(winget_id) if winget_id else None,
                source="winget",
            )
        )
    return items


def _parse_winget_text(stdout: str) -> list[SoftwareItem]:
    """Parst ``winget list``-Text-Tabelle (winget < 1.6).

    Format-Beispiel::

        Name Id Version Available Source
        ----------------------------------------------------------------
        Mozilla Firefox Mozilla.Firefox 120.0 121.0 winget
        PowerToys Microsoft.PowerToys 0.75.1 winget

    Spalten sind durch >=2 Leerzeichen getrennt; Ausrichtung erfolgt
    ueber Whitespace-Padding. Bei Parse-Fehler (Header nicht gefunden,
    weniger als 3 Spalten pro Zeile) wird die Zeile uebersprungen —
    nie ein Crash.
    """
    lines = stdout.splitlines()

    header_idx = None
    for i, line in enumerate(lines):
        if "Name" in line and "Id" in line and "Version" in line:
            header_idx = i
            break

    if header_idx is None:
        log.warning("winget list (Text): Header nicht gefunden — leere Liste.")
        return []

    # Separator-Zeile ueberspringen, falls vorhanden.
    data_start = header_idx + 1
    if data_start < len(lines) and re.match(
        r"^[-=\s]+$", lines[data_start]
    ):
        data_start += 1

    items: list[SoftwareItem] = []
    for line in lines[data_start:]:
        if not line.strip():
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3:
            # zu wenige Spalten → vermutlich Footer/Trenner
            continue
        name, wid, version, *_rest = parts
        if not name or not version:
            continue
        items.append(
            SoftwareItem(
                name=name.strip(),
                version=version.strip(),
                winget_id=(wid.strip() or None) if wid else None,
                source="winget",
            )
        )
    return items


def collect_registry() -> list[SoftwareItem]:
    """Liest installierte Software aus HKLM- und HKCU-Uninstall-Pfaden.

    Auf non-Windows-Plattformen: leere Liste.

    Liest drei Pfade (:data:`_REGISTRY_PATHS`):

    * HKLM ``SOFTWARE\\...\\Uninstall`` — System-weite Installationen.
    * HKLM ``SOFTWARE\\WOW6432Node\\...\\Uninstall`` — 32-Bit auf 64-Bit.
    * HKCU ``Software\\...\\Uninstall`` — **Per-User-Installationen**
      (Slack, Discord, Teams, Zoom, Spotify etc. landen typisch nur
      hier, nicht in HKLM).

    Pro Sub-Key: ``DisplayName`` als Anzeigename, ``DisplayVersion``
    als Version. Eintraege ohne ``DisplayName`` werden uebersprungen —
    typisch fuer Kernel-Updates und Hilfs-Komponenten ohne UI.
    Eintraege ohne ``DisplayVersion`` bekommen ``version="unbekannt"``.

    Bei Registry-Fehlern (Permission, Korruption) wird der jeweilige
    Sub-Key uebersprungen + Log-Debug-Eintrag, kein Abbruch der
    gesamten Sammlung.

    Returns:
        Liste der gefundenen:class:`SoftwareItem` mit
        ``source="registry"``, ``winget_id=None``.
    """
    if sys.platform != "win32":
        return []

    try:
        import winreg  # type: ignore[import-not-found] # nur Windows
    except ImportError:
        log.warning("winreg-Modul nicht verfuegbar — leere Liste.")
        return []

    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }

    items: list[SoftwareItem] = []
    for hive_name, path in _REGISTRY_PATHS:
        hive = hive_map[hive_name]
        try:
            root = winreg.OpenKey(hive, path)
        except OSError as e:
            log.debug(
                "Registry-Pfad %s\\%s nicht oeffnenbar: %s",
                hive_name, path, e,
            )
            continue

        try:
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub_name) as sub:
                        display_name = _read_str(sub, "DisplayName")
                        if not display_name:
                            continue
                        display_version = (
                            _read_str(sub, "DisplayVersion") or "unbekannt"
                        )
                        items.append(
                            SoftwareItem(
                                name=display_name,
                                version=display_version,
                                winget_id=None,
                                source="registry",
                            )
                        )
                except OSError as e:
                    log.debug("Registry-Sub-Key %r nicht lesbar: %s", sub_name, e)
                    continue
        finally:
            winreg.CloseKey(root)

    return items


def collect_appx() -> list[SoftwareItem]:
    """Liest Windows-Store-Apps + MSIX-Pakete via Get-AppxPackage.

    Auf non-Windows-Plattformen: leere Liste.

    Erfasst Apps, die weder in winget-list noch in der Uninstall-
    Registry erscheinen — typisch Microsoft Photos, Snipping Tool,
    Windows Terminal (Store-Variante), Xbox App, Calculator, etc.

    Bei Timeout (>20 s), nicht installiertem PowerShell, JSON-Parse-
    Fehler oder unerwartetem Format: leere Liste + Log-Warning. Kein
    Crash.

    Versions-Property von ``Get-AppxPackage`` wird vom.NET-Type
    ``System.Version`` als Objekt mit ``Major/Minor/Build/Revision``
    serialisiert —:func:`_format_appx_version` faltet das in einen
    String. ``"unbekannt"`` wenn die Property gar nicht da ist.

    Returns:
        Liste der gefundenen:class:`SoftwareItem` mit
        ``source="msix"``, ``winget_id=None``.
    """
    if sys.platform != "win32":
        return []

    try:
        completed = run_hidden(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-AppxPackage | Select-Object Name,Version "
                "| ConvertTo-Json",
            ],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_APPX_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "Get-AppxPackage: Timeout nach %ds — leere Liste.",
            _APPX_TIMEOUT_S,
        )
        return []
    except FileNotFoundError:
        log.warning("PowerShell nicht im PATH — leere Liste.")
        return []
    except OSError as e:
        log.warning("Get-AppxPackage fehlgeschlagen: %s — leere Liste.", e)
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "Get-AppxPackage exit=%d, stderr=%r — leere Liste.",
            completed.returncode,
            stderr_excerpt,
        )
        return []

    raw = (completed.stdout or "").strip()
    if not raw:
        # Leerer Output ist kein Fehler — kann passieren wenn der User
        # bewusst alle MSIX-Pakete deinstalliert hat.
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Get-AppxPackage: JSON-Parse-Fehler %s — leere Liste.", e)
        return []

    # Eine einzelne Zeile aus ConvertTo-Json kommt als Objekt statt Liste.
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        log.warning(
            "Get-AppxPackage: erwartete Liste, bekam %s — leere Liste.",
            type(data).__name__,
        )
        return []

    items: list[SoftwareItem] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("Name")
        if not name:
            continue
        name_str = str(name)
        if _is_msix_noise(name_str):
            continue  # Framework/System-Komponente, kein User-Patch-Ziel
        version = _format_appx_version(entry.get("Version"))
        items.append(
            SoftwareItem(
                name=name_str,
                version=version,
                winget_id=None,
                source="msix",
            )
        )
    return items


def _is_msix_noise(name: str) -> bool:
    """True wenn ``name`` ein gefiltertes Framework/System-MSIX ist.

    Zwei Checks:

    1. UUID-Form (``^[0-9a-f]{8}-[0-9a-f]{4}-…``) — Preview/Internal-
       Installs ohne stabilen Namen.
    2. Prefix-Match gegen:data:`_MSIX_IGNORE_PREFIXES`,
       case-insensitiv — PowerShell liefert manche Paketnamen mit
       kleinem 'w' (``windows.immersivecontrolpanel``), andere mit
       grossem ``Windows.``. Beide muessen gleichbehandelt werden.
    """
    if _UUID_PATTERN.match(name):
        return True
    name_lower = name.lower()
    return any(name_lower.startswith(p.lower()) for p in _MSIX_IGNORE_PREFIXES)


def _format_appx_version(raw: Any) -> str:
    """Konvertiert AppX-Version-Property zu einem String.

    PowerShell ``ConvertTo-Json`` serialisiert ``System.Version`` als
    Objekt mit ``Major/Minor/Build/Revision``-Feldern. Wenn die Property
    bereits ein String ist, wird sie unveraendert zurueckgegeben.

    Args:
        raw: Wert der ``Version``-Property aus dem AppX-JSON. Kann
            String, Dict oder None sein.

    Returns:
        ``"a.b.c.d"`` aus dem Version-Objekt, der String selbst,
        oder ``"unbekannt"``.
    """
    if not raw:
        return "unbekannt"
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        parts = [
            str(raw.get(k, 0)) for k in ("Major", "Minor", "Build", "Revision")
        ]
        if any(p != "0" for p in parts):
            return ".".join(parts)
    return "unbekannt"


def collect_windows_update() -> list[SoftwareItem]:
    """Liest ausstehende Windows-Updates via Windows-Update-Agent (COM).

    Auf non-Windows-Plattformen: leere Liste.

    Erfasst **ausstehende** (noch nicht installierte, nicht versteckte)
    Windows-Updates — Betriebssystem-/KB-Patches,.NET-Updates und
    Treiber-Updates. Diese tauchen weder in ``winget list`` noch in der
    Uninstall-Registry noch bei ``Get-AppxPackage`` auf.

    Die Suche laeuft **OFFLINE/cached** (``$u.Online = $false`` in
:data:`_WU_PS`): sie nutzt nur den lokalen Update-Cache, ist damit
    schnell und haengt NIE am Netzwerk. Eine Online-Suche koennte
    minutenlang blockieren — fuer ein Inventar-Sammeln im Hintergrund
    unzumutbar.

    Diese Updates sind **NICHT winget-installierbar**: in
:func:`collect_all` bekommen sie eine synthetische ``wu:``-Id
    (:func:`_with_synthetic_id`) und sind damit aus allen
    winget-Command-Gates ausgeschlossen
    (:func:`core.patch_id_utils.is_synthetic_id`). In der Patch-UI
    erscheinen sie als ``"Update verfuegbar"`` (``is_update_available``),
    aber nicht selektierbar — installiert werden sie ueber die
    **Windows-Einstellungen**.

    Bei Timeout (>90 s), nicht installiertem PowerShell, deaktiviertem
    Windows-Update-Dienst (``catch`` -> Leerstring), nicht-Null-
    Returncode, leerem Output oder JSON-Parse-Fehler: leere Liste +
    Log-Warning. Kein Crash.

    Returns:
        Liste der gefundenen:class:`SoftwareItem` mit
        ``source="windows_update"``, ``winget_id=None``,
        ``is_update_available=True`` und ``version="ausstehend"``.
        ``latest_available`` ist die KB-Nummer (``"KB5039212"``) wenn das
        Update eine traegt, sonst der Update-Titel. Eintraege ohne Title
        werden uebersprungen.
    """
    if sys.platform != "win32":
        return []

    try:
        completed = run_hidden(
            ["powershell", "-NoProfile", "-Command", _WU_PS],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_WU_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "Windows-Update-Suche: Timeout nach %ds — leere Liste.",
            _WU_TIMEOUT_S,
        )
        return []
    except FileNotFoundError:
        log.warning("PowerShell nicht im PATH — leere Liste (Windows-Update).")
        return []
    except OSError as e:
        log.warning("Windows-Update-Suche fehlgeschlagen: %s — leere Liste.", e)
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "Windows-Update-Suche exit=%d, stderr=%r — leere Liste.",
            completed.returncode,
            stderr_excerpt,
        )
        return []

    raw = (completed.stdout or "").strip()
    if not raw:
        # Leerer Output: keine ausstehenden Updates ODER der ``catch``-Zweig
        # hat einen Leerstring zurueckgegeben (Dienst deaktiviert). Beides
        # ist kein Fehler -> leere Liste.
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning(
            "Windows-Update-Suche: JSON-Parse-Fehler %s — leere Liste.", e
        )
        return []

    # ConvertTo-Json liefert bei einem einzigen Update ein Objekt statt Liste.
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        log.warning(
            "Windows-Update-Suche: erwartete Liste, bekam %s — leere Liste.",
            type(data).__name__,
        )
        return []

    items: list[SoftwareItem] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        title = entry.get("Title")
        if not title:
            continue
        title_str = str(title)
        kb = str(entry.get("KB") or "").strip()
        latest = f"KB{kb}" if kb else title_str
        items.append(
            SoftwareItem(
                name=title_str,
                version="ausstehend",
                winget_id=None,
                source="windows_update",
                is_update_available=True,
                latest_available=latest,
            )
        )
    return items


def collect_dotnet_runtimes() -> list[SoftwareItem]:
    """Liest installierte.NET-Laufzeiten (Framework + Core/5+).

    Zwei voneinander unabhaengige Teil-Erkennungen, beide **fail-soft**
    (eine fehlschlagende Teil-Erkennung killt die andere nicht):

    a. **.NET Framework** (nur Windows): liest die Registry-Schluessel
       ``...\\NDP\\v4\\Full`` (``Version`` + ``Release``) und ``...\\NDP\\v3.5``
       (``Install=1``). Liefert je einen:class:`SoftwareItem`
       ``".NET Framework 4.x"`` bzw. ``".NET Framework 3.5"``.

    b. **.NET Core / 5+** (plattformuebergreifend): ``dotnet
       --list-runtimes``. Parst Zeilen wie
       ``Microsoft.NETCore.App 8.0.11 [C:\\...]`` zu einem
:class:`SoftwareItem` je Familie+MAJOR.MINOR (:func:`_parse_dotnet_runtimes`). ``dotnet`` nicht installiert
       (``FileNotFoundError``) -> Teil b wird einfach uebersprungen.

    Diese Laufzeiten sind **installierte Versionen** — es gibt KEINE
    Update-Erkennung (``is_update_available=False``)..NET-Updates kommen
    ueber Windows-Update (bereits via:func:`collect_windows_update`
    abgedeckt). In:func:`collect_all` bekommen die Items eine
    synthetische ``dotnet:``-Id (:func:`_with_synthetic_id`) und sind
    damit aus allen winget-Command-Gates ausgeschlossen
    (:func:`core.patch_id_utils.is_synthetic_id`). In der Patch-UI
    erscheinen sie als ``"up_to_date"`` (kein Update verfuegbar).

    Robust: fehlt die ``dotnet``-CLI UND ist die Registry leer, liefert
    die Funktion eine leere Liste — kein Crash.

    Returns:
        Kombinierte Liste der gefundenen:class:`SoftwareItem` mit
        ``source="dotnet"``, ``winget_id=None``,
        ``is_update_available=False``. Reihenfolge: Framework-Items
        zuerst, dann Core/5+-Items.
    """
    items: list[SoftwareItem] = []
    items.extend(_collect_dotnet_framework())
    items.extend(_collect_dotnet_core())
    return items


def _collect_dotnet_framework() -> list[SoftwareItem]:
    """Liest installierte.NET-Framework-Versionen aus der Registry.

    Nur Windows. Liest ``HKLM\\...\\NDP\\v4\\Full`` (``Version``) und
    ``HKLM\\...\\NDP\\v3.5`` (``Install``). Jeder Registry-Fehler
    (Schluessel fehlt, Permission) wird fail-soft uebersprungen — kein
    Crash, kein Abbruch der jeweils anderen Pruefung.

    Returns:
        Liste mit 0–2:class:`SoftwareItem` (Framework 4.x und/oder 3.5).
    """
    if sys.platform != "win32":
        return []

    try:
        import winreg  # type: ignore[import-not-found] # nur Windows
    except ImportError:
        log.warning("winreg-Modul nicht verfuegbar — keine .NET-Framework-Daten.")
        return []

    items: list[SoftwareItem] = []

    #.NET Framework 4.x — ein Schluessel, ``Version`` traegt die volle
    # Versionsnummer (z.B. "4.8.09037").
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
        ) as key:
            version = _read_str(key, "Version")
            if version:
                items.append(
                    SoftwareItem(
                        name=".NET Framework 4.x",
                        version=version,
                        winget_id=None,
                        source="dotnet",
                        is_update_available=False,
                    )
                )
    except OSError as e:
        log.debug(".NET Framework 4.x nicht in Registry: %s", e)

    #.NET Framework 3.5 — ``Install=1`` (REG_DWORD) signalisiert
    # installiert. ``Version`` ist hier oft vorhanden, aber nicht garantiert.
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5",
        ) as key:
            try:
                install, _type = winreg.QueryValueEx(key, "Install")
            except OSError:
                install = 0
            if install == 1:
                version = _read_str(key, "Version") or "3.5"
                items.append(
                    SoftwareItem(
                        name=".NET Framework 3.5",
                        version=version,
                        winget_id=None,
                        source="dotnet",
                        is_update_available=False,
                    )
                )
    except OSError as e:
        log.debug(".NET Framework 3.5 nicht in Registry: %s", e)

    return items


def _collect_dotnet_core() -> list[SoftwareItem]:
    """Liest.NET Core / 5+ Laufzeiten via ``dotnet --list-runtimes``.

    Plattformuebergreifend. Bei nicht installiertem ``dotnet``
    (``FileNotFoundError``), Timeout, nicht-Null-Returncode oder leerem
    Output: leere Liste + Log-Debug/Warning. Kein Crash.

    Returns:
        Liste der:class:`SoftwareItem` aus
:func:`_parse_dotnet_runtimes`.
    """
    try:
        completed = run_hidden(
            ["dotnet", "--list-runtimes"],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_DOTNET_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError:
        # ``dotnet``-CLI nicht installiert — voellig normal, kein Fehler.
        log.debug("dotnet-CLI nicht im PATH — keine .NET-Core-Laufzeiten.")
        return []
    except subprocess.TimeoutExpired:
        log.warning(
            "dotnet --list-runtimes: Timeout nach %ds — leere Liste.",
            _DOTNET_TIMEOUT_S,
        )
        return []
    except OSError as e:
        log.warning("dotnet --list-runtimes fehlgeschlagen: %s — leere Liste.", e)
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "dotnet --list-runtimes exit=%d, stderr=%r — leere Liste.",
            completed.returncode,
            stderr_excerpt,
        )
        return []

    return _parse_dotnet_runtimes(completed.stdout or "")


def _parse_dotnet_runtimes(stdout: str) -> list[SoftwareItem]:
    """Parst die Textausgabe von ``dotnet --list-runtimes``.

    Format-Beispiel::

        Microsoft.AspNetCore.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\...]
        Microsoft.NETCore.App 6.0.33 [C:\\Program Files\\dotnet\\shared\\...]
        Microsoft.NETCore.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\...]
        Microsoft.WindowsDesktop.App 8.0.11 [C:\\Program Files\\dotnet\\shared\\...]

    Pro Familie+``MAJOR.MINOR`` entsteht GENAU EIN Eintrag (Schluessel
    ``"<Family> <Major>.<Minor>"``), damit verschiedene Familien/Majors
    distinkte Inventar-Eintraege werden. Mehrere Patch-Versionen
    derselben Familie+Major.Minor (selten parallel installiert) fallen
    auf den zuletzt gesehenen Eintrag zusammen — die ``dotnet:``-Id
    bleibt damit ueber Patch-Updates stabil. ``name`` traegt das
    Familien-Label + MAJOR.MINOR (z.B. ``".NET Runtime 8.0"``),
    ``version`` die volle Version (z.B. ``"8.0.11"``).

    Unbekannte Family-Ids (nicht in:data:`_DOTNET_FAMILY_LABELS`) und
    nicht parsbare Zeilen werden uebersprungen — kein Crash.

    Args:
        stdout: Roh-Output von ``dotnet --list-runtimes``.

    Returns:
        Liste der:class:`SoftwareItem` mit ``source="dotnet"``.
    """
    # Dict statt Liste: der (Family, Major.Minor)-Schluessel IST die
    # Dedup-Struktur — kein zweiter Index noetig.
    by_key: dict[str, SoftwareItem] = {}
    for line in stdout.splitlines():
        match = _DOTNET_RUNTIME_RE.match(line.strip())
        if not match:
            continue
        family, version = match.group(1), match.group(2)
        label = _DOTNET_FAMILY_LABELS.get(family)
        if label is None:
            continue  # unbekannte/zukuenftige Family — konservativ ueberspringen
        major_minor = ".".join(version.split(".")[:2])
        name = f"{label} {major_minor}"
        by_key[name] = SoftwareItem(
            name=name,
            version=version,
            winget_id=None,
            source="dotnet",
            is_update_available=False,
        )
    return list(by_key.values())


def collect_drivers() -> list[SoftwareItem]:
    """Liest installierte Geraetetreiber der kuratierten Klassen.

    Auf non-Windows-Plattformen: leere Liste.

    Erfasst NUR die sicherheitsrelevanten Geraeteklassen — GPU
    (``Display``), Netzwerk (``Net``) und Storage (``DiskDrive`` +
    ``SCSIAdapter``). Bewusst KEIN Vollscan aller Treiber: das ergaebe
    hunderte rauschige Zeilen (USB-Hubs, virtuelle Geraete, HID etc.).
    Pro vorhandenem, funktionierendem Geraet (``Status -eq 'OK'``) wird
    die installierte Treiber-Version (``DEVPKEY_Device_DriverVersion``)
    gelesen —:data:`_DRIVER_PS`.

    Dies sind **installierte Versionen** — es gibt KEINE
    Update-Erkennung (``is_update_available=False``). Treiber-**Updates**
    kommen ueber Windows-Update (bereits via
:func:`collect_windows_update` abgedeckt). In:func:`collect_all`
    bekommen die Items eine synthetische ``drv:``-Id
    (:func:`_with_synthetic_id`) und sind damit aus allen
    winget-Command-Gates ausgeschlossen
    (:func:`core.patch_id_utils.is_synthetic_id`). In der Patch-UI
    erscheinen sie als ``"up_to_date"`` (kein Update verfuegbar) — reine
    Inventar-Sichtbarkeit.

    Bei Timeout (>30 s), nicht installiertem PowerShell, nicht-Null-
    Returncode, leerem Output (``catch``-Leerstring) oder JSON-Parse-
    Fehler: leere Liste + Log-Warning. Kein Crash.

    Eintraege ohne ``Name`` ODER ohne ``Version`` werden uebersprungen —
    viele virtuelle Geraete tragen keine Treiber-Version.

    Returns:
        Liste der gefundenen:class:`SoftwareItem` mit
        ``source="driver"``, ``winget_id=None`` und
        ``is_update_available=False``.
    """
    if sys.platform != "win32":
        return []

    try:
        completed = run_hidden(
            ["powershell", "-NoProfile", "-Command", _DRIVER_PS],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_DRIVER_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "Treiber-Inventar: Timeout nach %ds — leere Liste.",
            _DRIVER_TIMEOUT_S,
        )
        return []
    except FileNotFoundError:
        log.warning("PowerShell nicht im PATH — leere Liste (Treiber).")
        return []
    except OSError as e:
        log.warning("Treiber-Inventar fehlgeschlagen: %s — leere Liste.", e)
        return []

    if completed.returncode != 0:
        stderr_excerpt = (completed.stderr or "")[:200]
        log.warning(
            "Treiber-Inventar exit=%d, stderr=%r — leere Liste.",
            completed.returncode,
            stderr_excerpt,
        )
        return []

    raw = (completed.stdout or "").strip()
    if not raw:
        # Leerer Output: keine passenden Geraete ODER der ``catch``-Zweig
        # hat einen Leerstring zurueckgegeben. Beides ist kein Fehler -> [].
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Treiber-Inventar: JSON-Parse-Fehler %s — leere Liste.", e)
        return []

    # ConvertTo-Json liefert bei einem einzigen Geraet ein Objekt statt Liste.
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        log.warning(
            "Treiber-Inventar: erwartete Liste, bekam %s — leere Liste.",
            type(data).__name__,
        )
        return []

    items: list[SoftwareItem] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("Name")
        version = entry.get("Version")
        # Geraete ohne Treiber-Version (viele virtuelle Geraete) ueberspringen
        # — ein Inventar-Eintrag ohne Version waere wertlos.
        if not name or not version:
            continue
        items.append(
            SoftwareItem(
                name=str(name),
                version=str(version),
                winget_id=None,
                source="driver",
                is_update_available=False,
            )
        )
    return items


def _light_norm(name: str) -> str:
    """Leichte Normalisierung: lowercase + Whitespace-Kollaps.

    ABWEICHUNG zu:func:`core.patch_normalizer.normalize_name`: ``normalize_name`` strippt Versions-/Noise-Tokens und wuerde
    distinkte Geraete-/Laufzeit-Namen kollabieren (zwei verschiedene
    Treiber -> dieselbe synthetische Id -> stille Ueberschreibung derselben
    ``inventory_snapshot``-PK-Zeile). Diese leichte Variante haelt
    verschiedene ``FriendlyName``/Familien distinkt UND bleibt ueber
    Versions-Updates stabil (lowercase + Whitespace, sonst unveraendert).

    Args:
        name: Roh-Anzeigename (z.B. ``"NVIDIA GeForce RTX 4070"``).

    Returns:
        Leicht normalisierter Name (``"nvidia geforce rtx 4070"``).
    """
    return re.sub(r"\s+", " ", name.strip().lower())


def _with_synthetic_id(item: SoftwareItem) -> SoftwareItem:
    """Weist Registry-/MSIX-Items eine stabile synthetische ``winget_id`` zu.

    Registry- und MSIX-Apps liefern ``winget_id=None``. Damit sie mit dem
    aktuellen ``inventory_snapshot``-Schema (PRIMARY KEY ``winget_id``)
    persistiert werden koennen und ueber Neustart/Daily-Refresh erhalten
    bleiben, bekommen sie hier eine stabile synthetische Id:

    * Registry → ``regid:<normalisierter Name>`` — der normalisierte Name
      (ohne Versions-Suffix) haelt die Id ueber Versions-Updates stabil,
      sodass dieselbe App dieselbe PK-Zeile aktualisiert statt zu duplizieren.
    * MSIX → ``msix:<Paketname>`` — MSIX-Paketnamen sind bereits stabile
      Identifier (z.B. ``Microsoft.Photos``).
    * Windows-Update → ``wu:<KB-Nummer>`` (z.B. ``wu:KB5039212``) — die
      KB-Nummer aus dem Titel haelt das Update ueber Re-Scans stabil;
      ohne KB-Nummer faellt es auf ``wu:<normalisierter Titel>`` zurueck.
    *.NET-Laufzeit → ``dotnet:<leicht normalisierter Name>`` — der Name
      traegt bereits die Versions-Familie (z.B. ``".NET Runtime 8.0"``),
      sodass verschiedene Majors distinkte stabile Ids bekommen; ein
      Patch-Update innerhalb einer Familie (8.0.11 → 8.0.12) behaelt
      dieselbe Id.
    * Geraetetreiber → ``drv:<leicht normalisierter FriendlyName>`` — der
      ``FriendlyName`` (z.B. ``"NVIDIA GeForce RTX 4070"``) haelt
      verschiedene Geraete distinkt UND bleibt ueber Treiber-Versions-
      Updates stabil (dieselbe PK-Zeile statt Duplikat).
    * winget-Quelle OHNE Katalog-Id → ``wgname:<normalisierter Name>`` —
      manche Apps liefern ``source="winget"`` mit leerem ``Id``-Feld
      (z.B. KeePassXC). Ohne synthetische Id wuerden sie in ``full_scan``
      verworfen und aus der DB verschwinden. Mangels echter Id sind sie
      sichtbar, aber nicht via winget patchbar.

    Items mit echter ``winget_id`` (winget-Quelle) bleiben unveraendert.
    Der Doppelpunkt im Praefix ist in echten winget-Ids unzulaessig — die
    synthetische Id wird damit nie an ein winget-Kommando gereicht (Gates in
:mod:`core.patch_upgrade`, ``batch_upgrade_service`` und der GUI pruefen
    via:func:`core.patch_id_utils.is_synthetic_id`).

    Args:
        item: Ein gesammeltes:class:`SoftwareItem` (beliebige Quelle).

    Returns:
        Das Item mit zugewiesener synthetischer Id, oder das unveraenderte
        Item wenn bereits eine ``winget_id`` gesetzt ist oder die Quelle
        kein synthetisches Praefix kennt.
    """
    # Items mit echtem Identifier nicht anfassen: ``winget_id`` (Catalog)
    # oder ``store_id`` (Microsoft-Store). Store-Apps sind ueber
    # ``winget upgrade --source msstore`` patchbar — sie bekommen KEINE
    # synthetische Id, sonst verloeren sie ihren upgradebaren Status.
    if item.winget_id is not None or item.store_id is not None:
        return item
    if item.source == "registry":
        synthetic = f"regid:{normalize_name(item.name)}"
    elif item.source == "msix":
        synthetic = f"msix:{item.name}"
    elif item.source == "windows_update":
        # Stabiler Identifier-Kern: die KB-Nummer aus dem Titel
        # (z.B. "...(KB5039212)" -> "KB5039212"). Ein KB-Update behaelt
        # dieselbe Id ueber Re-Scans, statt sich zu duplizieren. Updates
        # ohne KB (z.B. manche Treiber/Defender-Definitionen) fallen auf
        # den normalisierten Titel zurueck.
        kb_match = _KB_PATTERN.search(item.name)
        key = kb_match.group(0).upper() if kb_match else normalize_name(item.name)
        synthetic = f"wu:{key}"
    elif item.source == "dotnet":
        # Der Name traegt die Versions-Familie (".NET Runtime 8.0").
        # ABWEICHUNG: ``normalize_name`` wuerde hier
        # genau die Familie wegputzen (".NET Runtime 8.0" -> ".net",
        # ".NET Runtime 6.0" -> ".net") — Runtime/Desktop sind Noise-Terme
        # und " 8.0" matcht das Versions-Pattern. Damit kollidierten
        # verschiedene Majors auf EINER ``dotnet:``-Id und damit auf
        # EINER ``inventory_snapshot``-PK-Zeile (stille Ueberschreibung).
        # Stattdessen leichte Normalisierung (lowercase + Whitespace),
        # die die Familie+Major.Minor erhaelt: verschiedene Majors ->
        # distinkte Ids, Patch-Updates (8.0.11 -> 8.0.12) -> dieselbe Id.
        synthetic = f"dotnet:{_light_norm(item.name)}"
    elif item.source == "driver":
        # Wie bei dotnet: ``normalize_name`` wuerde
        # Modell-/Versions-Tokens aus dem ``FriendlyName`` strippen und
        # distinkte Treiber auf EINE Id kollabieren. Leichte Normalisierung
        # (lowercase + Whitespace) haelt verschiedene Geraete distinkt UND
        # bleibt ueber Treiber-Versions-Updates stabil. (Kollisions-Hinweis:
        # zwei identisch benannte Geraete teilen sich eine Id — akzeptabler
        # Edge-Case; Name-Stabilitaet hat Vorrang vor absoluter Eindeutigkeit.)
        synthetic = f"drv:{_light_norm(item.name)}"
    elif item.source == "winget":
        # winget-Quelle, aber OHNE Katalog-Id (winget_id/store_id beide None):
        # ``Get-WinGetPackage``/der Tabular-Fallback liefern fuer manche Apps
        # (z.B. KeePassXC) source="winget" mit leerem Id-Feld. Ohne synthetische
        # Id fielen diese frueher in den else-Zweig, blieben winget_id=None und
        # wurden in ``full_scan`` verworfen (Live-Test 2026-07-01: 12 Updates
        # live, aber nur 3 aus der DB). Sie bekommen jetzt eine stabile
        # ``wgname:``-Id ueber den normalisierten Namen — damit persistierbar
        # und sichtbar. is_synthetic_id haelt sie fail-closed aus allen
        # winget-Command-Gates heraus: ohne echte Id ist kein ``winget upgrade``
        # moeglich, die Zeile ist sichtbar aber nicht batch-patchbar.
        synthetic = f"wgname:{normalize_name(item.name)}"
    else:
        return item
    return dataclasses.replace(item, winget_id=synthetic)


def collect_all() -> list[SoftwareItem]:
    """Kombiniert winget + Registry + MSIX + Windows-Update +.NET + Treiber.

    Reihenfolge der Quellen (= Konflikt-Aufloesung):

    1. winget (vollstaendigste Quelle, mit ``Id``)
    2. Registry-Eintraege (HKLM + HKCU), deren
       ``(name.lower, version)`` nicht bereits aus winget kommt
    3. MSIX-Eintraege, deren ``(name.lower, version)`` nicht aus
       winget oder Registry kommt
    4. Windows-Update-Eintraege (ausstehende OS/KB/.NET/Treiber-Patches),
       deren ``(name.lower, version)`` nicht aus den vorherigen Quellen
       kommt — in der Praxis kollidieren sie nie (Update-Titel +
       ``version="ausstehend"`` sind disjunkt von installierter Software).
    5..NET-Laufzeit-Eintraege (installierte.NET-Framework- und
.NET-Core/5+-Versionen), deren ``(name.lower, version)`` nicht
       aus den vorherigen Quellen kommt. Reine Inventar-Sichtbarkeit
       ohne Update-Erkennung — sie erscheinen als ``up_to_date``.
    6. Treiber-Eintraege (installierte Geraetetreiber der kuratierten
       Klassen GPU/Netzwerk/Storage), deren ``(name.lower, version)``
       nicht aus den vorherigen Quellen kommt. Reine Inventar-Sichtbarkeit
       ohne Update-Erkennung — sie erscheinen als ``up_to_date``
       (Treiber-Updates kommen ueber Windows-Update, Quelle 4).

    Registry-/MSIX-/Windows-Update-/.NET-/Treiber-Eintraege ohne echte
    ``winget_id`` bekommen via:func:`_with_synthetic_id` eine stabile
    synthetische Id (``regid:`` / ``msix:`` / ``wu:`` / ``dotnet:`` /
    ``drv:``), damit sie persistiert werden und ueber Neustart erhalten
    bleiben. winget-Items gewinnen im Dedup weiterhin — die synthetische
    Zuweisung passiert nur auf den nachgelagerten Listen.

    Dedup-Schluessel ``(name.lower, version)`` (statt nur ``name``):
    Mehrfachinstallationen mit gleichem Anzeigenamen aber
    verschiedenen Versionen — z.B. ``Python 3.11`` und ``Python 3.12``
    parallel installiert — bleiben **beide** erhalten. Echte Duplikate
    (gleicher Name + gleiche Version aus zwei Quellen, oder MSIX-
    Architektur-Varianten) werden weiterhin entfernt.

    Returns:
        Kombinierte Liste in Quelle-Reihenfolge: winget, dann
        nicht-doppelte Registry, dann nicht-doppelte MSIX, dann
        nicht-doppelte Windows-Updates, dann nicht-doppelte
.NET-Laufzeiten, zuletzt nicht-doppelte Treiber.

.. note::
        Seit 2026-05-06 (Bug-3-Fix) nutzt diese Funktion
:func:`collect_winget_inventory` statt:func:`collect_winget`
        direkt. Damit greift bei verfuegbarem ``Microsoft.WinGet.Client``-
        Modul der locale-stabile JSON-Pfad mit Update-Info im
        SoftwareItem; ohne Modul der Tabular-Fallback. Registry- und
        MSIX-Pfad sind unveraendert.
    """
    # Synthetische Ids fuer ALLE Quellen anwenden: ``collect_winget_inventory``
    # liefert ueber das PowerShell-Modul auch ARP-/Registry-Items
    # (source="registry", winget_id=None) — auch die brauchen eine
    # synthetische Id, damit sie persistierbar sind. Fuer echte winget-/
    # Store-Items ist ``_with_synthetic_id`` ein No-op.
    winget_items = [_with_synthetic_id(item) for item in collect_winget_inventory()]
    registry_items = [_with_synthetic_id(item) for item in collect_registry()]
    appx_items = [_with_synthetic_id(item) for item in collect_appx()]
    wu_items = [_with_synthetic_id(item) for item in collect_windows_update()]
    dotnet_items = [_with_synthetic_id(it) for it in collect_dotnet_runtimes()]
    driver_items = [_with_synthetic_id(it) for it in collect_drivers()]

    def _dedup_key(item: SoftwareItem) -> tuple[str, str]:
        return (item.name.lower(), item.version)

    seen: set[tuple[str, str]] = set()
    winget_extras: list[SoftwareItem] = []
    for item in winget_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        winget_extras.append(item)

    registry_extras: list[SoftwareItem] = []
    for item in registry_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        registry_extras.append(item)

    appx_extras: list[SoftwareItem] = []
    for item in appx_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        appx_extras.append(item)

    wu_extras: list[SoftwareItem] = []
    for item in wu_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        wu_extras.append(item)

    dotnet_extras: list[SoftwareItem] = []
    for item in dotnet_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        dotnet_extras.append(item)

    driver_extras: list[SoftwareItem] = []
    for item in driver_items:
        key = _dedup_key(item)
        if key in seen:
            continue
        seen.add(key)
        driver_extras.append(item)

    return (
        winget_extras
        + registry_extras
        + appx_extras
        + wu_extras
        + dotnet_extras
        + driver_extras
    )


def _read_str(key: object, name: str) -> str | None:
    """Liest einen REG_SZ-Wert oder gibt ``None`` bei Fehlen/Fehler.

    Ausgelagert, damit Tests die Registry-Read-Logik separat steuern
    koennen ohne fuer jeden Sub-Key eine eigene Mock-Hierarchie
    aufbauen zu muessen.

    Args:
        key: Geoeffneter Registry-Sub-Key (Typ ``winreg.HKEYType``).
        name: Wert-Name (z.B. ``"DisplayName"``).

    Returns:
        Wert als String, oder ``None`` wenn der Wert fehlt, leer ist
        oder beim Lesen ein OSError auftritt.
    """
    try:
        import winreg  # type: ignore[import-not-found] # nur Windows

        value, _type = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    return str(value) if value else None


# ---------------------------------------------------------------------------
# Re-Exports — Bug-Fix-Sprint (C-6) hat den Detection-Pfad und den
# winget-Modul-Pfad in eigene Module ausgegliedert
# (:mod:`core.patch_module_detection`,:mod:`core.patch_winget_module`).
# Diese Re-Exports erhalten die ``from core.patch_collector import …``-API
# fuer alle Caller (Tests, Production-Code, Sub-Tools).
# ---------------------------------------------------------------------------

from core.patch_module_detection import (  # noqa: E402, F401 — Re-Export
    MODULE_REASON_CLASSES,
    ModuleStatus,
    ModuleStatusDetail,
    detect_winget_module,
    get_winget_module_status,
)
from core.patch_winget_module import collect_winget_module  # noqa: E402, F401

__all__ = [
    "MODULE_REASON_CLASSES",
    "ModuleStatus",
    "ModuleStatusDetail",
    "SoftwareItem",
    "SoftwareSource",
    "collect_all",
    "collect_appx",
    "collect_dotnet_runtimes",
    "collect_drivers",
    "collect_registry",
    "collect_winget",
    "collect_winget_inventory",
    "collect_windows_update",
    "collect_winget_module",
    "detect_winget_module",
    "get_winget_module_status",
]

def collect_winget_inventory() -> list[SoftwareItem]:
    """Primaerer winget-Inventar-Pfad mit Fallback.

    Bei:attr:`ModuleStatus.AVAILABLE` ruft
:func:`collect_winget_module` auf (locale-stabiles JSON-Schema,
    Update-Info inline im SoftwareItem). Andernfalls Fallback auf
:func:`collect_winget` (Tabular, locale-fragil aber funktional
    auf DE/EN).

    Wird in:func:`collect_all` statt ``collect_winget`` direkt
    verwendet — die Detection-Logik liegt damit in einer Stelle, nicht
    bei jedem Caller.
    """
    status = get_winget_module_status()
    if status.status == ModuleStatus.AVAILABLE:
        return collect_winget_module()
    log.info(
        "winget-Modul nicht verfuegbar (%s) — Tabular-Fallback aktiv. "
        "Patch-Monitor zeigt mit Modul mehr Daten und ist locale-stabil.",
        status.reason,
    )
    return collect_winget()
