"""
windows_scanner — Windows-spezifischer System-Scanner.

Liest installierte Software aus der Windows-Registry,
erkennt Antivirus/Firewall über das Windows Security Center via PowerShell/CIM
(``Get-CimInstance`` / ``Get-NetFirewallProfile``, dependency-frei — kein
``wmi``-Paket), prüft BitLocker-Status.

Schichtzugehörigkeit: data/ — darf OS-APIs und externe Libraries nutzen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import platform
import subprocess
import winreg
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from core.console_encoding import console_encoding
from core.logger import get_logger
from tools.system_scanner.domain.entities import (
    InstalledSoftware,
    OSInfo,
    ScanResult,
    SecurityComponent,
)
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType, OSPlatform
from tools.system_scanner.domain.interfaces import ISystemScanner

log = get_logger(__name__)

# Registry-Pfade für installierte Software
_REG_UNINSTALL_PATHS: list[tuple[int, str]] = [
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
]

# Sicherheitsrelevante Software-Namen (Teilstring-Match, case-insensitive)
_SECURITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "defender",
        "avast",
        "kaspersky",
        "eset",
        "bitdefender",
        "clamav",
        "sophos",
        "malwarebytes",
        "norton",
        "mcafee",
        "trend micro",
        "firewall",
        "little snitch",
        "vpn",
        "openvpn",
        "wireguard",
        "nordvpn",
        "expressvpn",
        "protonvpn",
        "bitwarden",
        "keepass",
        "1password",
        "lastpass",
        "dashlane",
        "teamviewer",
        "anydesk",
        "veracrypt",
        "bitlocker",
        "chrome",
        "firefox",
        "edge",
        "brave",
        "opera",
    }
)

# WMI-Klassen für Security Center
_WMI_AV_CLASS = "AntiVirusProduct"
_WMI_FIREWALL_CLASS = "FirewallProduct"


def _read_registry_software() -> list[InstalledSoftware]:
    """Liest installierte Software aus der Windows-Registry.

    Returns:
        Liste erkannter Softwarepakete.
    """
    found: dict[str, InstalledSoftware] = {}

    for hive, subkey in _REG_UNINSTALL_PATHS:
        try:
            with winreg.OpenKey(hive, subkey) as reg_key:
                count = winreg.QueryInfoKey(reg_key)[0]
                for i in range(count):
                    try:
                        sub_name = winreg.EnumKey(reg_key, i)
                        with winreg.OpenKey(reg_key, sub_name) as entry:
                            name = _read_reg_value(entry, "DisplayName")
                            if not name:
                                continue
                            version = _read_reg_value(entry, "DisplayVersion") or ""
                            vendor = _read_reg_value(entry, "Publisher") or ""
                            install_date = _read_reg_value(entry, "InstallDate") or ""
                            is_sec = any(
                                kw in name.lower() for kw in _SECURITY_KEYWORDS
                            )
                            key = name.lower().strip()
                            if key not in found:
                                found[key] = InstalledSoftware(
                                    name=name,
                                    version=version,
                                    vendor=vendor,
                                    install_date=install_date,
                                    is_security_relevant=is_sec,
                                )
                    except OSError:
                        continue
        except OSError as exc:
            log.debug("Registry-Pfad nicht erreichbar: %s — %s", subkey, exc)

    return list(found.values())


def _read_reg_value(key: winreg.HKEYType, value_name: str) -> str | None:
    """Liest einen String-Wert aus einem Registry-Key.

    Args:
        key: Geöffneter Registry-Key.
        value_name: Name des Werts.

    Returns:
        String-Wert oder None wenn nicht vorhanden.
    """
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return str(value) if value else None
    except OSError:
        return None


def _run_powershell_json(command: str) -> dict | list | None:
    """Führt einen PowerShell-Befehl aus und parst dessen JSON-Ausgabe.

    Gleicher subprocess-/CIM-Pfad wie in:mod:`core.hardware_fingerprint`
    (``CREATE_NO_WINDOW``, Timeout, kein Konsolen-Fenster). Bewusst PowerShell
    statt des ``wmi``-PyPI-Pakets (war nicht deklariert/installiert) oder
    ``wmic`` (ab Windows 11 Build 26200 entfernt).

    Args:
        command: PowerShell-Befehl, dessen STDOUT gültiges JSON ist
            (üblicherweise via ``ConvertTo-Json -Compress``).

    Returns:
        Das geparste JSON (``dict`` bei einem Treffer, ``list`` bei mehreren)
        oder ``None`` bei Fehler/leerer Ausgabe.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=12,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("PowerShell-Abfrage fehlgeschlagen: %s", exc)
        return None
    out = result.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except (ValueError, TypeError) as exc:
        log.warning("PowerShell-JSON nicht parsebar: %s", exc)
        return None


def _query_wmi_security_center(
    product_class: str,
) -> list[dict[str, str]]:
    """Abfrage des Windows Security Centers (``root\\SecurityCenter2``).

    Fragt Antivirus- oder Firewall-Produkte via PowerShell ``Get-CimInstance``
    ab — derselbe dependency-freie subprocess-Pfad wie
:mod:`core.hardware_fingerprint`. Früher wurde das optionale ``wmi``-PyPI-
    Paket importiert; das war weder in den Dependencies deklariert noch
    installiert, sodass die AV-/Firewall-Erkennung auf JEDEM Windows-Host still
    ausfiel.

    Args:
        product_class: WMI-Klasse ("AntiVirusProduct" oder "FirewallProduct").

    Returns:
        Liste von Produkt-Dicts mit "displayName", "productState" und
        "pathToSignedProductExe". Leere Liste, wenn nichts registriert ist ODER
        die Abfrage scheitert (der Aufrufer behandelt beide Fälle).
    """
    raw = _run_powershell_json(
        f"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName {product_class} "
        "-ErrorAction Stop | "
        "Select-Object displayName, productState, pathToSignedProductExe | "
        "ConvertTo-Json -Compress"
    )
    if raw is None:
        return []
    # ConvertTo-Json liefert bei genau einem Treffer ein Objekt, sonst eine Liste.
    records = raw if isinstance(raw, list) else [raw]
    result: list[dict[str, str]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        result.append(
            {
                "displayName": str(rec.get("displayName") or ""),
                "productState": str(rec.get("productState") or "0"),
                "pathToSignedProductExe": str(rec.get("pathToSignedProductExe") or ""),
            }
        )
    return result


def _get_windows_firewall_fallback() -> tuple[ComponentStatus, str]:
    """Ermittelt den Status der eingebauten Windows-Firewall.

    Fallback für den häufigsten Fall: die eingebaute Windows-Firewall
    registriert sich NICHT als ``FirewallProduct`` im Security Center (nur
    Drittanbieter tun das), ist aber meist die einzige Firewall. Liest die
    Profil-Zustände via ``Get-NetFirewallProfile`` / S-2).

    Returns:
        ``(Status, Detail)``: ACTIVE wenn mindestens ein Profil aktiv ist,
        INACTIVE wenn alle deaktiviert sind, UNKNOWN wenn die Abfrage scheitert.
    """
    raw = _run_powershell_json(
        "Get-NetFirewallProfile -ErrorAction Stop | "
        "Select-Object Name, Enabled | ConvertTo-Json -Compress"
    )
    if raw is None:
        return (
            ComponentStatus.UNKNOWN,
            "Firewall-Status konnte nicht ermittelt werden",
        )
    profiles = raw if isinstance(raw, list) else [raw]
    aktive = [
        str(p.get("Name", "?"))
        for p in profiles
        if isinstance(p, dict) and p.get("Enabled") in (1, True, "1", "True")
    ]
    if aktive:
        return (
            ComponentStatus.ACTIVE,
            f"Windows-Firewall aktiv (Profile: {', '.join(aktive)})",
        )
    return (
        ComponentStatus.INACTIVE,
        "Windows-Firewall auf allen Profilen deaktiviert",
    )


def _build_firewall_components() -> list[SecurityComponent]:
    """Baut die Firewall-Sicherheitskomponenten (Drittprodukte + Backstop).

    Listet alle im Security Center registrierten Drittanbieter-Firewalls
    (``FirewallProduct``) mit ihrem Status. Ist KEINE davon aktiv, wird
    zusaetzlich die eingebaute Windows-Firewall geprueft und als eigene
    Komponente ergaenzt — ein Drittanbieter (z.B. Bitdefender) kann eine
    inaktive/sekundaere Firewall registrieren, waehrend die Windows-Defender-
    Firewall die tatsaechlich aktive ist. Frueher vertraute der Scan NUR dem
    Drittprodukt und meldete dann faelschlich "keine aktive Firewall"
    (False-Negative). Die eingebaute FW registriert sich ohnehin NICHT
    als WSC-FirewallProduct/S-2) -> kein Duplikat.

    Returns:
        Liste der Firewall-``SecurityComponent``s (mindestens eine).
    """
    fw_products = _query_wmi_security_center(_WMI_FIREWALL_CLASS)
    components: list[SecurityComponent] = []
    any_active = False
    for fw in fw_products:
        status = _parse_product_state(fw.get("productState", "0"))
        components.append(
            SecurityComponent(
                name=fw.get("displayName", "Unbekannte Firewall"),
                type=ComponentType.FIREWALL,
                status=status,
            )
        )
        if status == ComponentStatus.ACTIVE:
            any_active = True
    if not any_active:
        fw_status, fw_detail = _get_windows_firewall_fallback()
        components.append(
            SecurityComponent(
                name="Windows Firewall",
                type=ComponentType.FIREWALL,
                status=fw_status,
                detail=fw_detail,
            )
        )
    return components


def _parse_product_state(state_str: str) -> ComponentStatus:
    """Parst den WMI-ProductState in einen ComponentStatus.

    ProductState ist eine 6-stellige Hex-Zahl.
    Bits 12-15 (nibble 3) codieren den Aktivitätsstatus:
      0x10 = aktiv, 0x01 = inaktiv.

    Args:
        state_str: ProductState als Dezimalstring.

    Returns:
        Erkannter ComponentStatus.
    """
    try:
        state = int(state_str)
        # Nibble an Position 3 (0-indexed von rechts): 0x..X..
        nibble = (state >> 12) & 0xF
        if nibble == 1:
            return ComponentStatus.ACTIVE
        if nibble == 0:
            return ComponentStatus.INACTIVE
        return ComponentStatus.UNKNOWN
    except (ValueError, TypeError):
        log.debug("Ungültiger ProductState: %s", state_str)
        return ComponentStatus.UNKNOWN


def _get_bitlocker_status() -> ComponentStatus:
    """Prüft den BitLocker-Status über manage-bde.

    Returns:
        Erkannter ComponentStatus für BitLocker.
    """
    try:
        result = subprocess.run(
            ["manage-bde", "-status", "C:"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        output = (result.stdout or "").lower()
        if "protection on" in output or "schutz aktiviert" in output:
            return ComponentStatus.ACTIVE
        if "protection off" in output or "schutz deaktiviert" in output:
            return ComponentStatus.INACTIVE
        return ComponentStatus.UNKNOWN
    except FileNotFoundError:
        log.debug("manage-bde nicht gefunden — BitLocker-Status unbekannt")
        return ComponentStatus.UNKNOWN
    except subprocess.TimeoutExpired:
        log.warning("manage-bde Timeout — BitLocker-Status unbekannt")
        return ComponentStatus.UNKNOWN
    except OSError as exc:
        log.warning("BitLocker-Abfrage fehlgeschlagen: %s", exc)
        return ComponentStatus.UNKNOWN


def _get_os_info() -> OSInfo:
    """Liest Windows-Betriebssystem-Informationen.

    Returns:
        OSInfo-Objekt mit OS-Details.
    """
    from tools.system_scanner.domain.entities import OSInfo

    uname = platform.uname()
    return OSInfo(
        platform=OSPlatform.WINDOWS,
        name=f"Windows {platform.release()}",
        version=platform.version(),
        build=uname.version,
        architecture=platform.machine(),
        last_update="",
        update_status=ComponentStatus.UNKNOWN,
    )


def _detect_browsers(
    software_list: list[InstalledSoftware],
) -> list[SecurityComponent]:
    """Leitet installierte Browser aus der Software-Liste ab — jeder EINMAL.

    Microsoft Edge erscheint in der Windows-Software-Liste mehrfach (der
    Browser selbst, ``Microsoft Edge Update``, ``Microsoft Edge WebView2
    Runtime``). Ohne Dedup/Ausschluss wurde Edge mehrfach als Komponente
    gelistet (Patrick-Live-Test 2026-06-25). Begleitkomponenten (Updater/
    Runtime) werden ausgeschlossen, jeder Browser-Anzeigename nur einmal
    aufgenommen.

    Args:
        software_list: installierte Software (Registry).

    Returns:
        Liste eindeutiger Browser-:class:`SecurityComponent`.
    """
    browser_keywords = {
        "chrome": "Google Chrome",
        "firefox": "Mozilla Firefox",
        "microsoft edge": "Microsoft Edge",
        "brave": "Brave",
        "opera": "Opera",
    }
    # Begleitkomponenten, die ein Browser-Keyword enthalten, aber NICHT der
    # Browser selbst sind (Updater/Runtime) — vom Match ausschliessen.
    browser_excludes = ("webview", "update", "runtime")
    seen: set[str] = set()
    out: list[SecurityComponent] = []
    for sw in software_list:
        name_lower = sw.name.lower()
        if any(x in name_lower for x in browser_excludes):
            continue
        for kw, display_name in browser_keywords.items():
            if kw in name_lower and display_name not in seen:
                seen.add(display_name)
                out.append(
                    SecurityComponent(
                        name=display_name,
                        type=ComponentType.BROWSER,
                        status=ComponentStatus.ACTIVE,
                        version=sw.version,
                    )
                )
                break
    return out


class WindowsScanner(ISystemScanner):
    """System-Scanner-Implementierung für Windows."""

    def scan(self) -> ScanResult:
        """Führt einen vollständigen Windows-System-Scan durch.

        Liest Registry-Software, WMI Security Center und BitLocker-Status.
        Fehler einzelner Teilschritte werden als Warnungen protokolliert —
        der Scan bricht nicht ab.

        Returns:
            Vollständiges ScanResult.
        """
        import uuid

        start = datetime.now(tz=UTC)
        warnings: list[str] = []
        security_components: list[SecurityComponent] = []

        # OS-Info
        try:
            os_info = _get_os_info()
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("OS-Info-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"OS-Info nicht verfügbar: {exc}")
            from tools.system_scanner.domain.entities import OSInfo

            os_info = OSInfo(platform=OSPlatform.WINDOWS)

        # Software aus Registry
        try:
            software_list = _read_registry_software()
            log.debug("Registry: %d Pakete gefunden", len(software_list))
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Registry-Scan fehlgeschlagen: %s", exc)
            warnings.append(f"Software-Liste nicht verfügbar: {exc}")
            software_list = []

        # E3): Die drei langsamen Subprocess-Probes (AV /
        # Firewall / BitLocker) liefen bisher sequentiell (~46 s = Summe). Sie
        # teilen keinen veränderlichen Zustand und ``subprocess.run`` gibt das
        # GIL frei — daher parallel über einen ThreadPool (Wall-Clock = Maximum
        # statt Summe). Jede Probe wird unabhängig über ihr eigenes
        # ``future.result`` in einem eigenen try/except eingesammelt; eine
        # fehlschlagende Probe bricht weder die anderen noch den Scan ab
        # (identische Fehler-Isolation wie zuvor).
        with ThreadPoolExecutor(max_workers=3) as executor:
            av_future = executor.submit(_query_wmi_security_center, _WMI_AV_CLASS)
            firewall_future = executor.submit(_build_firewall_components)
            bitlocker_future = executor.submit(_get_bitlocker_status)

            # Antivirus via WMI
            try:
                av_products = av_future.result()
                if av_products:
                    for av in av_products:
                        status = _parse_product_state(av.get("productState", "0"))
                        security_components.append(
                            SecurityComponent(
                                name=av.get("displayName", "Unbekanntes AV"),
                                type=ComponentType.ANTIVIRUS,
                                status=status,
                                detail=av.get("pathToSignedProductExe", ""),
                            )
                        )
                else:
                    security_components.append(
                        SecurityComponent(
                            name="Antivirus",
                            type=ComponentType.ANTIVIRUS,
                            status=ComponentStatus.UNKNOWN,
                            detail="Kein AV-Produkt im Security Center gefunden",
                        )
                    )
            except (OSError, RuntimeError, AttributeError, KeyError) as exc:
                log.warning("AV-Abfrage fehlgeschlagen: %s", exc)
                warnings.append(f"Antivirus-Status nicht verfügbar: {exc}")

            # Firewall via WMI (+ eingebaute Windows-Firewall als Backstop)
            try:
                security_components.extend(firewall_future.result())
            except (OSError, RuntimeError, AttributeError, KeyError) as exc:
                log.warning("Firewall-Abfrage fehlgeschlagen: %s", exc)
                warnings.append(f"Firewall-Status nicht verfügbar: {exc}")

            # BitLocker
            try:
                bitlocker_status = bitlocker_future.result()
                security_components.append(
                    SecurityComponent(
                        name="BitLocker",
                        type=ComponentType.ENCRYPTION,
                        status=bitlocker_status,
                        detail="Laufwerk C:",
                    )
                )
            except (OSError, RuntimeError, AttributeError, KeyError) as exc:
                log.warning("BitLocker-Abfrage fehlgeschlagen: %s", exc)
                warnings.append(f"BitLocker-Status nicht verfügbar: {exc}")

        # Browser aus Software-Liste ableiten (jeder Browser nur EINMAL).
        security_components.extend(_detect_browsers(software_list))

        # Remote-Access-Tools aus Software-Liste
        remote_keywords = {"teamviewer": "TeamViewer", "anydesk": "AnyDesk"}
        for sw in software_list:
            name_lower = sw.name.lower()
            for kw, display_name in remote_keywords.items():
                if kw in name_lower:
                    security_components.append(
                        SecurityComponent(
                            name=display_name,
                            type=ComponentType.REMOTE_ACCESS,
                            status=ComponentStatus.RISK,
                            version=sw.version,
                            detail="Remote-Access-Tool erkannt — Sicherheitsrisiko prüfen",
                        )
                    )
                    break

        end = datetime.now(tz=UTC)
        duration = (end - start).total_seconds()

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=start,
            os_info=os_info,
            software_list=software_list,
            security_components=security_components,
            scan_duration_s=duration,
            warnings=warnings,
        )
