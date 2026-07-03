"""
test_system_compliance_service.

Tests fuer den:class:`SystemComplianceService`. Wir patchen die zwei
externen Probes via ``monkeypatch``, damit die Tests deterministisch
ohne echte Windows-Probes laufen.
"""

from __future__ import annotations

from datetime import date

import pytest

from core.os_eol_resolver import OsEolEntry, OsEolStatus
from tools.system_scanner.application.system_compliance_service import (
    LicenseStatus,
    SystemComplianceService,
    WindowsLicenseInfo,
)


def _fake_os_eol(*, is_eol: bool, is_expiring_soon: bool) -> OsEolStatus:
    return OsEolStatus(
        os_name="Test OS",
        matched_entry=OsEolEntry(
            name="Windows 10",
            family="windows-client",
            eol_date=date(2025, 10, 14),
        ),
        is_eol=is_eol,
        days_until_eol=-30 if is_eol else 100,
        is_expiring_soon=is_expiring_soon,
    )


def _fake_license(status: LicenseStatus) -> WindowsLicenseInfo:
    return WindowsLicenseInfo(
        status=status,
        message=f"Status {status.name}",
        source="slmgr",
    )


class TestComplianceAggregat:
    def test_clean_setup_keine_warnings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Windows 11 (kein EOL, nicht expiring soon) + LICENSED
        clean_eol = OsEolStatus(
            os_name="Windows 11",
            matched_entry=OsEolEntry(
                name="Windows 11",
                family="windows-client",
                eol_date=date(2031, 10, 14),
            ),
            is_eol=False,
            days_until_eol=1977,
            is_expiring_soon=False,
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.resolve_os",
            lambda os_name: clean_eol,
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.check_windows_license",
            lambda: _fake_license(LicenseStatus.LICENSED),
        )
        info = SystemComplianceService().gather("Windows 11 Pro")
        assert info.has_warnings is False
        assert info.os_eol.is_eol is False
        assert info.license.is_compliant is True

    def test_eol_setzt_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.resolve_os",
            lambda os_name: _fake_os_eol(is_eol=True, is_expiring_soon=False),
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.check_windows_license",
            lambda: _fake_license(LicenseStatus.LICENSED),
        )
        info = SystemComplianceService().gather("Windows 10 Pro")
        assert info.has_warnings is True

    def test_unlicensed_setzt_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clean_eol = OsEolStatus(
            os_name="Windows 11",
            matched_entry=OsEolEntry(
                name="Windows 11",
                family="windows-client",
                eol_date=date(2031, 10, 14),
            ),
            is_eol=False,
            days_until_eol=1977,
            is_expiring_soon=False,
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.resolve_os",
            lambda os_name: clean_eol,
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.check_windows_license",
            lambda: _fake_license(LicenseStatus.UNLICENSED),
        )
        info = SystemComplianceService().gather("Windows 11 Pro")
        assert info.has_warnings is True

    def test_resolver_crash_failsafe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_resolve(_os_name: str) -> OsEolStatus:
            raise RuntimeError("DB kaputt")

        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.resolve_os",
            broken_resolve,
        )
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.check_windows_license",
            lambda: _fake_license(LicenseStatus.LICENSED),
        )
        info = SystemComplianceService().gather("Windows 10 Pro")
        # Crash fuehrt zu Fallback-Status — fail-safe, keine Exception.
        assert info.os_eol.matched_entry is None

    def test_license_crash_failsafe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clean_eol = _fake_os_eol(is_eol=False, is_expiring_soon=False)
        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.resolve_os",
            lambda os_name: clean_eol,
        )

        def broken_license() -> WindowsLicenseInfo:
            raise OSError("subprocess died")

        monkeypatch.setattr(
            "tools.system_scanner.application.system_compliance_service.check_windows_license",
            broken_license,
        )
        info = SystemComplianceService().gather("Windows 10 Pro")
        assert info.license.status is LicenseStatus.UNKNOWN
        assert "fehlgeschlagen" in info.license.message.lower()
