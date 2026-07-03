"""
test_license_compliance_checker.

Tests fuer den Windows-Lizenz-Compliance-Checker. Wir testen die
Parser-Funktionen direkt (deterministisch). Die ``check_windows_license``-
Public-API wird nur auf einem Smoke-Pfad geprueft, weil sie echte
subprocess-Calls macht — auf Non-Windows liefert sie ``NOT_APPLICABLE``,
auf Windows liefert sie ein echtes Ergebnis.
"""

from __future__ import annotations

import platform

import pytest

from tools.system_scanner.data.license_compliance_checker import (
    LicenseStatus,
    _parse_slmgr_xpr,
    _parse_wmi_license_status,
    check_windows_license,
)

# ---------------------------------------------------------------------------
# slmgr-Parser
# ---------------------------------------------------------------------------


class TestParseSlmgr:
    def test_permanent_aktiviert_deutsch(self) -> None:
        out = "Der Computer ist permanent aktiviert."
        status, message = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.LICENSED
        assert "permanent" in message.lower()

    def test_permanent_activated_englisch(self) -> None:
        out = "The machine is permanently activated."
        status, message = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.LICENSED

    def test_befristete_aktivierung_deutsch(self) -> None:
        out = "Initial grace period laeuft am 2026-08-12 ab."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.OOB_GRACE

    def test_befristete_aktivierung_englisch(self) -> None:
        out = "The expiration date for this license is 2026-08-12."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.OOB_GRACE

    def test_test_modus_deutsch(self) -> None:
        out = "Windows befindet sich im Test-Modus."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.OOT_GRACE

    def test_notification_mode_englisch(self) -> None:
        out = "Windows is in notification mode."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.NOTIFICATION

    def test_benachrichtigungs_modus_deutsch(self) -> None:
        out = "Windows befindet sich im Benachrichtigungsmodus."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.NOTIFICATION

    def test_nicht_aktiviert(self) -> None:
        out = "Windows ist nicht aktiviert."
        status, _ = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.UNLICENSED

    def test_unbekannte_ausgabe_wird_unknown(self) -> None:
        out = "Some arbitrary garbage output"
        status, message = _parse_slmgr_xpr(out)
        assert status is LicenseStatus.UNKNOWN
        assert "konnte nicht geparsed" in message

    def test_leere_ausgabe(self) -> None:
        status, _ = _parse_slmgr_xpr("")
        assert status is LicenseStatus.UNKNOWN


# ---------------------------------------------------------------------------
# WMI-Parser
# ---------------------------------------------------------------------------


class TestParseWmi:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("0", LicenseStatus.UNLICENSED),
            ("1", LicenseStatus.LICENSED),
            ("2", LicenseStatus.OOB_GRACE),
            ("3", LicenseStatus.OOT_GRACE),
            ("4", LicenseStatus.NON_GENUINE_GRACE),
            ("5", LicenseStatus.NOTIFICATION),
            ("6", LicenseStatus.EXTENDED_GRACE),
        ],
    )
    def test_alle_codes(self, raw: str, expected: LicenseStatus) -> None:
        status, _ = _parse_wmi_license_status(raw)
        assert status is expected

    def test_code_in_powershell_output(self) -> None:
        """PowerShell-Output enthaelt oft Whitespace/Newlines."""
        out = "\r\n1\r\n"
        status, _ = _parse_wmi_license_status(out)
        assert status is LicenseStatus.LICENSED

    def test_unbekannter_code(self) -> None:
        # Reine Whitespace ohne Zahl
        status, _ = _parse_wmi_license_status("hello world")
        assert status is LicenseStatus.UNKNOWN

    def test_kein_match(self) -> None:
        status, message = _parse_wmi_license_status("error: something")
        assert status is LicenseStatus.UNKNOWN
        assert "keinen Status-Code" in message


# ---------------------------------------------------------------------------
# Smoke der Public-API
# ---------------------------------------------------------------------------


class TestCheckWindowsLicense:
    def test_non_windows_liefert_not_applicable(self) -> None:
        if platform.system() == "Windows":
            pytest.skip("Test ist nur fuer Non-Windows-Plattformen.")
        info = check_windows_license()
        assert info.status is LicenseStatus.NOT_APPLICABLE
        assert info.source == "none"
        assert info.is_compliant is False
        assert info.needs_attention is False  # NOT_APPLICABLE != needs_attention

    def test_windows_liefert_konkretes_ergebnis(self) -> None:
        if platform.system() != "Windows":
            pytest.skip("Test ist nur fuer Windows.")
        info = check_windows_license()
        # Wir machen keine Annahme ueber die konkrete Status-Klasse —
        # der Test prueft nur, dass die API ein gueltiges Ergebnis liefert.
        assert info.status is not None
        assert info.source in ("slmgr", "wmi", "none")
        assert isinstance(info.message, str)


# ---------------------------------------------------------------------------
# is_compliant / needs_attention
# ---------------------------------------------------------------------------


class TestLicenseInfoProperties:
    def test_licensed_ist_compliant(self) -> None:
        from tools.system_scanner.data.license_compliance_checker import (
            WindowsLicenseInfo,
        )

        info = WindowsLicenseInfo(
            status=LicenseStatus.LICENSED,
            message="ok",
            source="slmgr",
        )
        assert info.is_compliant is True
        assert info.needs_attention is False

    @pytest.mark.parametrize(
        "status",
        [
            LicenseStatus.UNLICENSED,
            LicenseStatus.OOB_GRACE,
            LicenseStatus.OOT_GRACE,
            LicenseStatus.NON_GENUINE_GRACE,
            LicenseStatus.NOTIFICATION,
            LicenseStatus.EXTENDED_GRACE,
        ],
    )
    def test_nicht_licensed_braucht_aufmerksamkeit(
        self, status: LicenseStatus
    ) -> None:
        from tools.system_scanner.data.license_compliance_checker import (
            WindowsLicenseInfo,
        )

        info = WindowsLicenseInfo(status=status, message="x", source="slmgr")
        assert info.is_compliant is False
        assert info.needs_attention is True

    def test_not_applicable_nicht_kompliant_aber_keine_warnung(self) -> None:
        from tools.system_scanner.data.license_compliance_checker import (
            WindowsLicenseInfo,
        )

        info = WindowsLicenseInfo(
            status=LicenseStatus.NOT_APPLICABLE,
            message="non-windows",
            source="none",
        )
        assert info.is_compliant is False
        assert info.needs_attention is False

    def test_unknown_ist_nicht_messbar_keine_warnung(self) -> None:
        # ein Probe-Fehlschlag/Timeout (UNKNOWN) ist KEIN Lizenz-Verstoss
        # -> needs_attention False, damit das Banner ihn neutral (nicht rot) zeigt.
        from tools.system_scanner.data.license_compliance_checker import (
            WindowsLicenseInfo,
        )

        info = WindowsLicenseInfo(
            status=LicenseStatus.UNKNOWN,
            message="Lizenz-Status nicht ermittelbar (Zeitüberschreitung)",
            source="none",
        )
        assert info.is_compliant is False
        assert info.needs_attention is False
