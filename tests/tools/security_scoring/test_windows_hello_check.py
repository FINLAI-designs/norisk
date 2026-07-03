"""Tests für ``check_windows_hello``.

Deckt ab:
    * Nicht-Windows-Fall → UNBEKANNT.
    * Registry liefert Enabled=1 → AKTIV.
    * Registry liefert Enabled=0 und kein Biometric-Device → INAKTIV.
    * Registry nicht vorhanden + Biometric-Device-Count > 0 → AKTIV.
    * Registry nicht vorhanden + Biometric-Device-Count = 0 → UNBEKANNT.
    * Registry + PowerShell beide fehlerhaft → UNBEKANNT.
"""

from __future__ import annotations

import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

from tools.security_scoring.data import os_detection
from tools.security_scoring.data.os_detection import (
    STATUS_AKTIV,
    STATUS_INAKTIV,
    STATUS_UNBEKANNT,
    check_windows_hello,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen: stubs für winreg
# ---------------------------------------------------------------------------


class _WinregFake:
    """Minimaler winreg-Stub mit konfigurierbaren Werten."""

    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_CURRENT_USER = 0x80000001

    def __init__(self, werte: dict | None = None) -> None:
        self._werte = werte or {}

    def OpenKey(self, hive, pfad):  # noqa: N802 — winreg-API-Name
        schluessel = (hive, pfad)
        if schluessel not in self._werte:
            raise FileNotFoundError(pfad)

        class _KeyCtx:
            def __enter__(self_inner):
                return schluessel

            def __exit__(self_inner, *_exc):
                return False

        return _KeyCtx()

    def QueryValueEx(self, key, wert_name):  # noqa: N802 — winreg-API-Name
        wert = self._werte.get(key, {}).get(wert_name)
        if wert is None:
            raise FileNotFoundError(wert_name)
        return wert, 4  # REG_DWORD


def _install_winreg_fake(werte: dict | None) -> types.ModuleType:
    """Registriert ein Fake-``winreg``-Modul unter ``sys.modules``."""
    fake = _WinregFake(werte)
    module = types.ModuleType("winreg")
    module.HKEY_LOCAL_MACHINE = fake.HKEY_LOCAL_MACHINE  # type: ignore[attr-defined]
    module.HKEY_CURRENT_USER = fake.HKEY_CURRENT_USER  # type: ignore[attr-defined]
    module.OpenKey = fake.OpenKey  # type: ignore[attr-defined]
    module.QueryValueEx = fake.QueryValueEx  # type: ignore[attr-defined]
    sys.modules["winreg"] = module
    return module


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCheckWindowsHello:
    """Tests für die Windows-Hello-Erkennung."""

    def test_non_windows_gibt_unbekannt(self) -> None:
        with patch.object(os_detection.sys, "platform", "linux"):
            result = check_windows_hello()
        assert result.status == STATUS_UNBEKANNT
        assert "Windows" in result.detail

    def test_registry_enabled_1_gibt_aktiv(self) -> None:
        werte = {
            (0x80000002, r"SOFTWARE\Microsoft\Policies\PassportForWork"): {
                "Enabled": 1,
            }
        }
        _install_winreg_fake(werte)
        with patch.object(os_detection.sys, "platform", "win32"):
            result = check_windows_hello()
        assert result.status == STATUS_AKTIV
        assert "Windows Hello" in result.detail or "MFA" in result.detail

    def test_registry_enabled_0_ohne_biometric_gibt_inaktiv(self) -> None:
        werte = {
            (
                0x80000001,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
            ): {"Enabled": 0}
        }
        _install_winreg_fake(werte)
        fake_run = MagicMock(
            return_value=MagicMock(stdout="0\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_windows_hello()
        assert result.status == STATUS_INAKTIV

    def test_biometric_device_erkannt_gibt_aktiv(self) -> None:
        # Registry liefert nichts; PowerShell liefert Count > 0.
        _install_winreg_fake({})
        fake_run = MagicMock(
            return_value=MagicMock(stdout="2\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_windows_hello()
        assert result.status == STATUS_AKTIV

    def test_kein_registry_kein_biometric_gibt_unbekannt(self) -> None:
        # Registry nicht lesbar und PowerShell wirft → UNBEKANNT.
        _install_winreg_fake({})
        fake_run = MagicMock(
            side_effect=subprocess.CalledProcessError(1, "powershell.exe")
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_windows_hello()
        assert result.status == STATUS_UNBEKANNT

    def test_powershell_timeout_gibt_unbekannt_bei_fehlender_registry(self) -> None:
        _install_winreg_fake({})
        fake_run = MagicMock(
            side_effect=subprocess.TimeoutExpired("powershell.exe", 10),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_windows_hello()
        assert result.status == STATUS_UNBEKANNT

    def test_powershell_liefert_null_count_ohne_registry_gibt_unbekannt(self) -> None:
        # Kein Registry-Eintrag → gelesen==False → biometric=False → UNBEKANNT
        # (beide Quellen None/False ohne positiven Beweis).
        _install_winreg_fake({})
        fake_run = MagicMock(return_value=MagicMock(stdout="0\n", returncode=0))
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_windows_hello()
        # Beide Quellen liefern kein eindeutiges "inaktiv" → UNBEKANNT.
        assert result.status == STATUS_UNBEKANNT
