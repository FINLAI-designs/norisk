"""
macos_scanner — macOS-spezifischer System-Scanner.

Liest Software über system_profiler, prüft XProtect/Gatekeeper,
FileVault und macOS-Firewall.

Schichtzugehörigkeit: data/ — darf Subprozesse und OS-APIs nutzen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import platform
import subprocess
from datetime import UTC, datetime

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

_SECURITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "antivirus",
        "malware",
        "sophos",
        "kaspersky",
        "bitdefender",
        "avast",
        "clamav",
        "eset",
        "little snitch",
        "lulu",
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
        "chrome",
        "firefox",
        "safari",
        "brave",
        "opera",
    }
)


def _run_subprocess(cmd: list[str], timeout: int = 30) -> str:
    """Führt einen Subprozess aus und gibt stdout zurück.

    Args:
        cmd: Befehl als Liste.
        timeout: Timeout in Sekunden.

    Returns:
        Stdout als String (leer bei Fehler).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout
    except FileNotFoundError:
        log.debug("Befehl nicht gefunden: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        log.warning("Timeout bei: %s", " ".join(cmd))
        return ""
    except OSError as exc:
        log.warning("Subprozess-Fehler bei %s: %s", cmd[0], exc)
        return ""


def _get_applications() -> list[InstalledSoftware]:
    """Liest installierte Apps über system_profiler.

    Returns:
        Liste erkannter Softwarepakete.
    """
    output = _run_subprocess(
        ["system_profiler", "SPApplicationsDataType", "-json"], timeout=60
    )
    if not output:
        return []

    try:
        data = json.loads(output)
        apps = data.get("SPApplicationsDataType", [])
        result = []
        for app in apps:
            name = app.get("_name", "")
            version = app.get("version", "")
            obtained = app.get("obtained_from", "")
            last_modified = app.get("lastModified", "")
            if not name:
                continue
            is_sec = any(kw in name.lower() for kw in _SECURITY_KEYWORDS)
            result.append(
                InstalledSoftware(
                    name=name,
                    version=version,
                    vendor=obtained,
                    install_date=last_modified,
                    is_security_relevant=is_sec,
                )
            )
        return result
    except (json.JSONDecodeError, KeyError) as exc:
        log.warning("system_profiler JSON-Parsing fehlgeschlagen: %s", exc)
        return []


def _get_os_info() -> OSInfo:
    """Liest macOS Betriebssystem-Informationen.

    Returns:
        OSInfo-Objekt.
    """
    uname = platform.uname()
    sw_output = _run_subprocess(["system_profiler", "SPSoftwareDataType", "-json"])
    build = ""
    if sw_output:
        try:
            data = json.loads(sw_output)
            sw = data.get("SPSoftwareDataType", [{}])[0]
            build = sw.get("os_version", "")
        except (json.JSONDecodeError, IndexError, KeyError):
            pass

    return OSInfo(
        platform=OSPlatform.MACOS,
        name=f"macOS {platform.mac_ver()[0]}",
        version=platform.mac_ver()[0],
        build=build or uname.release,
        architecture=platform.machine(),
        update_status=ComponentStatus.UNKNOWN,
    )


def _get_filevault_status() -> ComponentStatus:
    """Prüft FileVault-Status.

    Returns:
        ComponentStatus basierend auf fdesetup-Ausgabe.
    """
    output = _run_subprocess(["fdesetup", "status"])
    if "on" in output.lower():
        return ComponentStatus.ACTIVE
    if "off" in output.lower():
        return ComponentStatus.INACTIVE
    return ComponentStatus.UNKNOWN


def _get_firewall_status() -> ComponentStatus:
    """Prüft macOS Application-Firewall-Status.

    Returns:
        ComponentStatus basierend auf socketfilterfw-Ausgabe.
    """
    output = _run_subprocess(
        [
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ]
    )
    if "enabled" in output.lower():
        return ComponentStatus.ACTIVE
    if "disabled" in output.lower():
        return ComponentStatus.INACTIVE
    return ComponentStatus.UNKNOWN


def _get_gatekeeper_status() -> ComponentStatus:
    """Prüft Gatekeeper-Status.

    Returns:
        ComponentStatus.
    """
    output = _run_subprocess(["spctl", "--status"])
    if "enabled" in output.lower():
        return ComponentStatus.ACTIVE
    if "disabled" in output.lower():
        return ComponentStatus.INACTIVE
    return ComponentStatus.UNKNOWN


class MacOSScanner(ISystemScanner):
    """System-Scanner-Implementierung für macOS."""

    def scan(self) -> ScanResult:
        """Führt einen vollständigen macOS System-Scan durch.

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
            log.warning("OS-Info fehlgeschlagen: %s", exc)
            warnings.append(f"OS-Info nicht verfügbar: {exc}")
            os_info = OSInfo(platform=OSPlatform.MACOS)

        # Installierte Apps
        try:
            software_list = _get_applications()
            log.debug("system_profiler: %d Apps gefunden", len(software_list))
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("App-Liste fehlgeschlagen: %s", exc)
            warnings.append(f"Software-Liste nicht verfügbar: {exc}")
            software_list = []

        # FileVault
        try:
            fv_status = _get_filevault_status()
            security_components.append(
                SecurityComponent(
                    name="FileVault",
                    type=ComponentType.ENCRYPTION,
                    status=fv_status,
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("FileVault-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"FileVault-Status nicht verfügbar: {exc}")

        # Firewall
        try:
            fw_status = _get_firewall_status()
            security_components.append(
                SecurityComponent(
                    name="macOS Firewall",
                    type=ComponentType.FIREWALL,
                    status=fw_status,
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Firewall-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"Firewall-Status nicht verfügbar: {exc}")

        # Gatekeeper (als AV-Äquivalent)
        try:
            gk_status = _get_gatekeeper_status()
            security_components.append(
                SecurityComponent(
                    name="Gatekeeper / XProtect",
                    type=ComponentType.ANTIVIRUS,
                    status=gk_status,
                    detail="macOS eingebauter Malware-Schutz",
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Gatekeeper-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"Gatekeeper-Status nicht verfügbar: {exc}")

        # Browser aus App-Liste
        browser_keywords = {
            "google chrome": "Google Chrome",
            "firefox": "Mozilla Firefox",
            "safari": "Safari",
            "brave browser": "Brave",
            "opera": "Opera",
        }
        for sw in software_list:
            name_lower = sw.name.lower()
            for kw, display_name in browser_keywords.items():
                if kw in name_lower:
                    security_components.append(
                        SecurityComponent(
                            name=display_name,
                            type=ComponentType.BROWSER,
                            status=ComponentStatus.ACTIVE,
                            version=sw.version,
                        )
                    )
                    break

        # Remote-Access
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
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=start,
            os_info=os_info,
            software_list=software_list,
            security_components=security_components,
            scan_duration_s=(end - start).total_seconds(),
            warnings=warnings,
        )
