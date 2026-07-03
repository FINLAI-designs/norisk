"""
linux_scanner — Linux-spezifischer System-Scanner.

Liest installierte Software über dpkg/rpm/pacman,
prüft Firewall-Status (ufw/firewalld/iptables),
liest /etc/os-release und Unattended-Upgrades-Konfiguration.

Schichtzugehörigkeit: data/ — darf Subprozesse und OS-APIs nutzen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

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
        "clamav",
        "sophos",
        "kaspersky",
        "eset",
        "bitdefender",
        "malware",
        "antivirus",
        "firewall",
        "ufw",
        "firewalld",
        "iptables",
        "nftables",
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
        "teamviewer",
        "anydesk",
        "veracrypt",
        "luks",
        "cryptsetup",
        "chromium",
        "firefox",
        "brave",
        "opera",
    }
)


def _run(cmd: list[str], timeout: int = 20) -> str:
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


def _read_os_release() -> dict[str, str]:
    """Liest /etc/os-release.

    Returns:
        Dict mit OS-Release-Feldern.
    """
    info: dict[str, str] = {}
    try:
        content = Path("/etc/os-release").read_text(encoding="utf-8")
        for line in content.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip().strip('"')
    except OSError as exc:
        log.debug("/etc/os-release nicht lesbar: %s", exc)
    return info


def _get_os_info() -> OSInfo:
    """Liest Linux Betriebssystem-Informationen.

    Returns:
        OSInfo-Objekt.
    """
    os_release = _read_os_release()
    name = os_release.get(
        "PRETTY_NAME",
        f"Linux {platform.release()}",
    )
    version = os_release.get("VERSION_ID", platform.release())
    return OSInfo(
        platform=OSPlatform.LINUX,
        name=name,
        version=version,
        build=platform.release(),
        architecture=platform.machine(),
        update_status=ComponentStatus.UNKNOWN,
    )


def _get_packages_dpkg() -> list[InstalledSoftware]:
    """Liest installierte Pakete über dpkg.

    Returns:
        Paketliste.
    """
    output = _run(["dpkg", "-l"])
    packages = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "ii":
            name = parts[1]
            version = parts[2]
            is_sec = any(kw in name.lower() for kw in _SECURITY_KEYWORDS)
            packages.append(
                InstalledSoftware(
                    name=name,
                    version=version,
                    is_security_relevant=is_sec,
                )
            )
    return packages


def _get_packages_rpm() -> list[InstalledSoftware]:
    """Liest installierte Pakete über rpm.

    Returns:
        Paketliste.
    """
    output = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"])
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 1:
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            vendor = parts[2] if len(parts) > 2 else ""
            is_sec = any(kw in name.lower() for kw in _SECURITY_KEYWORDS)
            packages.append(
                InstalledSoftware(
                    name=name,
                    version=version,
                    vendor=vendor,
                    is_security_relevant=is_sec,
                )
            )
    return packages


def _get_packages_pacman() -> list[InstalledSoftware]:
    """Liest installierte Pakete über pacman.

    Returns:
        Paketliste.
    """
    output = _run(["pacman", "-Q"])
    packages = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            is_sec = any(kw in name.lower() for kw in _SECURITY_KEYWORDS)
            packages.append(
                InstalledSoftware(
                    name=name,
                    version=version,
                    is_security_relevant=is_sec,
                )
            )
    return packages


def _detect_package_manager_and_list() -> list[InstalledSoftware]:
    """Erkennt den Paketmanager und liest die Paketliste.

    Returns:
        Paketliste (leer wenn kein Paketmanager erkannt).
    """
    if _run(["dpkg", "--version"]):
        return _get_packages_dpkg()
    if _run(["rpm", "--version"]):
        return _get_packages_rpm()
    if _run(["pacman", "--version"]):
        return _get_packages_pacman()
    log.debug("Kein bekannter Paketmanager gefunden")
    return []


def _get_ufw_status() -> ComponentStatus:
    """Prüft ufw-Firewall-Status.

    Returns:
        ComponentStatus.
    """
    output = _run(["ufw", "status"])
    output_lower = output.lower()
    # "inactive" muss vor "active" geprüft werden (Teilstring-Überlappung)
    if "inactive" in output_lower:
        return ComponentStatus.INACTIVE
    if "active" in output_lower:
        return ComponentStatus.ACTIVE
    return ComponentStatus.UNKNOWN


def _get_firewalld_status() -> ComponentStatus:
    """Prüft firewalld-Status via systemctl.

    Returns:
        ComponentStatus.
    """
    output = _run(["systemctl", "is-active", "firewalld"])
    if "active" in output.lower():
        return ComponentStatus.ACTIVE
    return ComponentStatus.INACTIVE


def _get_firewall_status() -> tuple[str, ComponentStatus]:
    """Erkennt und prüft die aktive Firewall.

    Returns:
        Tupel (Name, Status).
    """
    # ufw zuerst
    ufw_output = _run(["ufw", "status"])
    if ufw_output:
        status = _get_ufw_status()
        return "ufw", status

    # firewalld
    fw_output = _run(["systemctl", "is-active", "firewalld"])
    if fw_output.strip() == "active":
        return "firewalld", ComponentStatus.ACTIVE

    # iptables als Fallback
    ipt_output = _run(["iptables", "-L"])
    if ipt_output:
        return "iptables", ComponentStatus.UNKNOWN

    return "Firewall", ComponentStatus.UNKNOWN


def _get_luks_status() -> ComponentStatus:
    """Prüft ob LUKS-verschlüsselte Laufwerke vorhanden sind.

    Returns:
        ComponentStatus.ACTIVE wenn LUKS erkannt, sonst UNKNOWN.
    """
    output = _run(["lsblk", "-o", "TYPE"])
    if "crypt" in output.lower():
        return ComponentStatus.ACTIVE
    return ComponentStatus.UNKNOWN


def _get_unattended_upgrades_status() -> ComponentStatus:
    """Prüft ob Unattended-Upgrades aktiv ist.

    Returns:
        ComponentStatus.
    """
    output = _run(["systemctl", "is-active", "unattended-upgrades"])
    if "active" in output.lower():
        return ComponentStatus.ACTIVE
    output2 = _run(["systemctl", "is-active", "apt-daily-upgrade"])
    if "active" in output2.lower():
        return ComponentStatus.ACTIVE
    return ComponentStatus.INACTIVE


class LinuxScanner(ISystemScanner):
    """System-Scanner-Implementierung für Linux."""

    def scan(self) -> ScanResult:
        """Führt einen vollständigen Linux System-Scan durch.

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
            os_info = OSInfo(platform=OSPlatform.LINUX)

        # Pakete
        try:
            software_list = _detect_package_manager_and_list()
            log.debug("Paketmanager: %d Pakete gefunden", len(software_list))
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Paket-Scan fehlgeschlagen: %s", exc)
            warnings.append(f"Software-Liste nicht verfügbar: {exc}")
            software_list = []

        # Firewall
        try:
            fw_name, fw_status = _get_firewall_status()
            security_components.append(
                SecurityComponent(
                    name=fw_name,
                    type=ComponentType.FIREWALL,
                    status=fw_status,
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Firewall-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"Firewall-Status nicht verfügbar: {exc}")

        # LUKS-Verschlüsselung
        try:
            luks_status = _get_luks_status()
            security_components.append(
                SecurityComponent(
                    name="LUKS",
                    type=ComponentType.ENCRYPTION,
                    status=luks_status,
                    detail="Festplattenverschlüsselung",
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("LUKS-Abfrage fehlgeschlagen: %s", exc)
            warnings.append(f"LUKS-Status nicht verfügbar: {exc}")

        # Auto-Updates
        try:
            update_status = _get_unattended_upgrades_status()
            security_components.append(
                SecurityComponent(
                    name="Automatische Updates",
                    type=ComponentType.OS_UPDATE,
                    status=update_status,
                    detail="unattended-upgrades / apt-daily-upgrade",
                )
            )
        except (OSError, RuntimeError, AttributeError, KeyError) as exc:
            log.warning("Update-Status fehlgeschlagen: %s", exc)
            warnings.append(f"Update-Status nicht verfügbar: {exc}")

        # Browser aus Paketliste
        browser_keywords = {
            "chromium": "Chromium",
            "firefox": "Mozilla Firefox",
            "brave": "Brave",
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
