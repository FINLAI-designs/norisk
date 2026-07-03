"""
platform_scanner — Plattform-Erkennung und Delegation an den passenden Scanner.

Erkennt das aktuelle Betriebssystem und delegiert den Scan an
WindowsScanner, MacOSScanner oder LinuxScanner.

Schichtzugehörigkeit: data/ — darf OS-spezifische Module importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import platform

from core.exceptions import ConfigurationError
from core.logger import get_logger
from tools.system_scanner.domain.entities import ScanResult
from tools.system_scanner.domain.enums import OSPlatform
from tools.system_scanner.domain.interfaces import ISystemScanner

log = get_logger(__name__)


def _detect_platform() -> OSPlatform:
    """Erkennt das aktuelle Betriebssystem.

    Returns:
        Erkannte OSPlatform.
    """
    system = platform.system().lower()
    if system == "windows":
        return OSPlatform.WINDOWS
    if system == "darwin":
        return OSPlatform.MACOS
    if system == "linux":
        return OSPlatform.LINUX
    return OSPlatform.UNKNOWN


def _create_scanner(os_platform: OSPlatform) -> ISystemScanner:
    """Erstellt den passenden Scanner für die Plattform.

    Args:
        os_platform: Erkannte Plattform.

    Returns:
        Plattformspezifischer ISystemScanner.

    Raises:
        RuntimeError: Wenn die Plattform nicht unterstützt wird.
    """
    if os_platform == OSPlatform.WINDOWS:
        from tools.system_scanner.data.windows_scanner import WindowsScanner

        return WindowsScanner()
    if os_platform == OSPlatform.MACOS:
        from tools.system_scanner.data.macos_scanner import MacOSScanner

        return MacOSScanner()
    if os_platform == OSPlatform.LINUX:
        from tools.system_scanner.data.linux_scanner import LinuxScanner

        return LinuxScanner()
    raise ConfigurationError(f"Nicht unterstützte Plattform: {os_platform}")


class PlatformScanner(ISystemScanner):
    """Plattform-unabhängiger System-Scanner.

    Erkennt das OS beim ersten Aufruf und delegiert an den
    passenden plattformspezifischen Scanner.
    """

    def __init__(self) -> None:
        """Initialisiert den PlatformScanner."""
        self._platform = _detect_platform()
        log.debug("PlatformScanner: erkannte Plattform %s", self._platform.value)

    @property
    def detected_platform(self) -> OSPlatform:
        """Erkannte Plattform (read-only).

        Returns:
            OSPlatform.
        """
        return self._platform

    def scan(self) -> ScanResult:
        """Führt einen plattformgerechten System-Scan durch.

        Args:
            Keine.

        Returns:
            Scan-Ergebnis vom plattformspezifischen Scanner.

        Raises:
            RuntimeError: Wenn die Plattform nicht unterstützt wird.
        """
        scanner = _create_scanner(self._platform)
        log.info("System-Scan gestartet auf %s", self._platform.value)
        result = scanner.scan()
        log.info(
            "System-Scan abgeschlossen: %d Komponenten, %.1fs",
            len(result.security_components),
            result.scan_duration_s,
        )
        return result
