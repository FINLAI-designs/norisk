"""
system_compliance_service — Compliance-Aggregat fuer den System-Scanner.

Iter 2f: Vereint OS-EOL-Resolver und Windows-Lizenz-
Compliance-Checker in einem Service, den das Scanner-Widget aufruft.
Auf Non-Windows / unbekannten OS-Versionen liefert der Service
fail-safe-Defaults — der Scanner-Pfad darf nie crashen.

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass

from core.logger import get_logger
from core.os_eol_resolver import OsEolStatus, resolve_os
from tools.system_scanner.data.license_compliance_checker import (
    LicenseStatus,
    WindowsLicenseInfo,
    check_windows_license,
)

# Re-export fuer GUI-Konsumenten — vermeidet Hex-Contract-Verletzung
# (gui darf nicht direkt aus data importieren).
__all__ = [
    "LicenseStatus",
    "SystemComplianceInfo",
    "SystemComplianceService",
    "WindowsLicenseInfo",
]

_log = get_logger(__name__)


@dataclass(frozen=True)
class SystemComplianceInfo:
    """Compliance-Aggregat fuer den Scanner-Banner.

    Attributes:
        os_eol::class:`OsEolStatus` der erkannten OS-Version.
        license::class:`WindowsLicenseInfo` der Aktivierungs-Probe.
                    Auf Non-Windows: Status ``NOT_APPLICABLE``.
        has_warnings: ``True`` wenn EOL ODER nicht-konformer Lizenzstatus.
    """

    os_eol: OsEolStatus
    license: WindowsLicenseInfo
    has_warnings: bool


class SystemComplianceService:
    """Aggregiert OS-EOL + Lizenz-Compliance fuer das Scanner-UI."""

    def gather(self, os_name: str) -> SystemComplianceInfo:
        """Sammelt die zwei Compliance-Signale.

        Args:
            os_name: Anzeigename des erkannten OS (``OSInfo.name``).

        Returns:
:class:`SystemComplianceInfo` mit beiden Probe-Ergebnissen
            und ``has_warnings``-Flag.
        """
        try:
            os_eol = resolve_os(os_name)
        except Exception as exc:  # noqa: BLE001 — Resolver darf nie crashen
            _log.warning(
                "SystemComplianceService: resolve_os fehlgeschlagen (%s)",
                type(exc).__name__,
            )
            # Direkt konstruierter fail-safe Default — kein zweiter
            # resolve_os-Call, damit ein durchgehend gemockter Resolver
            # auch fail-safe wird.
            os_eol = OsEolStatus(
                os_name=os_name,
                matched_entry=None,
                is_eol=False,
                days_until_eol=None,
                is_expiring_soon=False,
            )

        try:
            license_info = check_windows_license()
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "SystemComplianceService: license_check fehlgeschlagen (%s)",
                type(exc).__name__,
            )
            # Fall-back-Konstruktion: importiere lokal um Top-Level-
            # Abhaengigkeit minimal zu halten.
            from tools.system_scanner.data.license_compliance_checker import (  # noqa: PLC0415
                LicenseStatus,
            )

            license_info = WindowsLicenseInfo(
                status=LicenseStatus.UNKNOWN,
                message=f"Lizenz-Check fehlgeschlagen: {type(exc).__name__}",
                source="none",
            )

        has_warnings = (
            os_eol.is_eol
            or os_eol.is_expiring_soon
            or license_info.needs_attention
        )
        return SystemComplianceInfo(
            os_eol=os_eol,
            license=license_info,
            has_warnings=has_warnings,
        )
