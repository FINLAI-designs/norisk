"""Tests für ``check_installed_password_managers``.

Deckt ab:
    * Nicht-Windows-Fall → UNBEKANNT.
    * Erkennung aller Whitelist-Einträge (einzeln) über ``Get-AppxPackage``.
    * Registry-Fallback (Uninstall-Liste).
    * Keine Erkennung → INAKTIV.
    * PowerShell wirft + Registry leer → UNBEKANNT.
    * Case-Insensitive Matching.
"""

from __future__ import annotations

import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from tools.security_scoring.data import os_detection
from tools.security_scoring.data.os_detection import (
    STATUS_AKTIV,
    STATUS_INAKTIV,
    STATUS_UNBEKANNT,
    check_installed_password_managers,
)
from tools.security_scoring.domain.org_security import BEKANNTE_PASSWORT_MANAGER

# ---------------------------------------------------------------------------
# winreg-Fake (Enum-fähig)
# ---------------------------------------------------------------------------


class _WinregFake:
    """winreg-Stub, der EnumKey + QueryValueEx für Uninstall-Keys liefert."""

    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_CURRENT_USER = 0x80000001

    def __init__(
        self, uninstall_eintraege: dict[tuple[int, str], list[str]] | None = None
    ) -> None:
        """Args:
            uninstall_eintraege: Map ``(hive, pfad) → [DisplayName,...]``.
        """
        self._eintraege = uninstall_eintraege or {}

    def OpenKey(self, hive_oder_key, pfad):  # noqa: N802 — winreg-API
        # Fall A: root-key geöffnet: (hive, pfad) gewünscht.
        if isinstance(hive_oder_key, int):
            schluessel = (hive_oder_key, pfad)
            if schluessel not in self._eintraege:
                raise FileNotFoundError(pfad)
            names = self._eintraege[schluessel]
            return _RootKeyCtx(schluessel, names)
        # Fall B: subkey eines root-keys geöffnet.
        return _SubKeyCtx(hive_oder_key, pfad)

    def EnumKey(self, key_ctx, index):  # noqa: N802 — winreg-API
        names = key_ctx.names
        if index >= len(names):
            raise OSError("No more items")
        return f"sub_{index}"

    def QueryValueEx(self, key_ctx, wert_name):  # noqa: N802 — winreg-API
        if wert_name != "DisplayName":
            raise FileNotFoundError(wert_name)
        return key_ctx.display_name, 1


class _RootKeyCtx:
    def __init__(self, schluessel, names):
        self.schluessel = schluessel
        self.names = names

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _SubKeyCtx:
    def __init__(self, parent_ctx, subname):
        # parent_ctx ist _RootKeyCtx
        try:
            index = int(subname.split("_")[-1])
            self.display_name = parent_ctx.names[index]
        except (ValueError, IndexError):
            self.display_name = ""

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _install_winreg_fake(
    uninstall_eintraege: dict | None = None,
) -> types.ModuleType:
    fake = _WinregFake(uninstall_eintraege)
    module = types.ModuleType("winreg")
    module.HKEY_LOCAL_MACHINE = fake.HKEY_LOCAL_MACHINE  # type: ignore[attr-defined]
    module.HKEY_CURRENT_USER = fake.HKEY_CURRENT_USER  # type: ignore[attr-defined]
    module.OpenKey = fake.OpenKey  # type: ignore[attr-defined]
    module.EnumKey = fake.EnumKey  # type: ignore[attr-defined]
    module.QueryValueEx = fake.QueryValueEx  # type: ignore[attr-defined]
    sys.modules["winreg"] = module
    return module


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCheckInstalledPasswordManagers:
    """Tests für die Passwort-Manager-Erkennung."""

    def test_non_windows_gibt_unbekannt(self) -> None:
        with patch.object(os_detection.sys, "platform", "linux"):
            result = check_installed_password_managers()
        assert result.status == STATUS_UNBEKANNT
        assert result.erkannt == []

    @pytest.mark.parametrize("manager", list(BEKANNTE_PASSWORT_MANAGER))
    def test_jeder_whitelist_eintrag_wird_erkannt(self, manager: str) -> None:
        _install_winreg_fake({})
        fake_run = MagicMock(
            return_value=MagicMock(stdout=f"Microsoft.Windows\n{manager}\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.status == STATUS_AKTIV
        assert manager in result.erkannt

    def test_mehrere_manager_gleichzeitig(self) -> None:
        _install_winreg_fake({})
        ausgabe = "1Password\nBitwarden\nrandomapp\n"
        fake_run = MagicMock(return_value=MagicMock(stdout=ausgabe, returncode=0))
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.status == STATUS_AKTIV
        assert "1Password" in result.erkannt
        assert "Bitwarden" in result.erkannt

    def test_registry_fallback_erkennt_manager(self) -> None:
        # Appx liefert nichts Interessantes, aber Registry nennt KeePass.
        uninstall = {
            (
                0x80000002,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ): ["KeePass Password Safe 2", "Some Other App"],
        }
        _install_winreg_fake(uninstall)
        fake_run = MagicMock(
            return_value=MagicMock(stdout="nothing-to-see\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.status == STATUS_AKTIV
        assert "KeePass" in result.erkannt

    def test_keine_erkennung_gibt_inaktiv(self) -> None:
        _install_winreg_fake({})
        fake_run = MagicMock(
            return_value=MagicMock(stdout="Microsoft.Edge\nZoom\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.status == STATUS_INAKTIV
        assert result.erkannt == []

    def test_alle_quellen_fehlgeschlagen_gibt_unbekannt(self) -> None:
        # Registry nicht verfügbar + PowerShell wirft → beide Quellen liefern None.
        fake_run = MagicMock(
            side_effect=subprocess.CalledProcessError(1, "powershell.exe")
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ), patch.dict(sys.modules, {"winreg": None}):
            # winreg-Import schlägt fehl → registry-Ergebnis = None.
            result = check_installed_password_managers()
        assert result.status == STATUS_UNBEKANNT

    def test_case_insensitive_matching(self) -> None:
        _install_winreg_fake({})
        fake_run = MagicMock(
            return_value=MagicMock(stdout="bitwarden\n", returncode=0),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.status == STATUS_AKTIV
        assert "Bitwarden" in result.erkannt

    def test_erkannte_liste_ist_sortiert(self) -> None:
        _install_winreg_fake({})
        fake_run = MagicMock(
            return_value=MagicMock(
                stdout="NordPass\n1Password\nBitwarden\n", returncode=0
            ),
        )
        with patch.object(os_detection.sys, "platform", "win32"), patch.object(
            os_detection.subprocess, "run", fake_run
        ):
            result = check_installed_password_managers()
        assert result.erkannt == sorted(result.erkannt)
