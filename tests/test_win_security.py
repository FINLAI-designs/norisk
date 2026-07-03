"""Tests für core.win_security F-C-3, Security-Gate).

Drei Blöcke, alle plattformunabhängig (kein echtes pywin32 / kein echter
WinAPI-Aufruf):

1. ``evaluate_path_trust`` — reine Entscheidungslogik mit synthetischen ACEs.
2. ``assess_install_path_trust`` — Orchestrierung (Prefix + DACL), mit gemockter
   win32-Extraktion und gemocktem Prefix-Filter.
3. ``harden_dll_search_path`` — DLL-Härtung mit gemocktem ``ctypes.WinDLL``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core import win_security
from core.win_security import (
    PathTrustVerdict,
    assess_install_path_trust,
    evaluate_path_trust,
    harden_dll_search_path,
)

_MOD = "core.win_security"

# Well-Known-SIDs (Spiegel der Modul-Konstanten).
_SYSTEM = "S-1-5-18"
_ADMIN = "S-1-5-32-544"
_TRUSTED_INSTALLER = (
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)
_AUTH_USERS = "S-1-5-11"
_EVERYONE = "S-1-1-0"
_USERS = "S-1-5-32-545"
_CREATOR_OWNER = "S-1-3-0"
_NON_ADMIN_USER = "S-1-5-21-1-2-3-1001"

# ACE-Typen.
_ALLOW = 0
_DENY = 1

# Access-Masks.
_WRITE_DATA = 0x0002
_DELETE = 0x00010000
_GENERIC_WRITE = 0x40000000
_GENERIC_ALL = 0x10000000
_READ_EXECUTE = 0x001200A9  # Users-Standard auf Program Files (keine Tamper-Bits)
_WRITE_ATTRIBUTES = 0x0100  # bewusst NICHT als Tamper gewertet


class TestEvaluatePathTrust:
    def test_owner_admin_users_nur_read_execute_ist_trusted(self) -> None:
        aces = [(_ALLOW, _USERS, _READ_EXECUTE), (_ALLOW, _ADMIN, _GENERIC_ALL)]
        trusted, _reason, offenders = evaluate_path_trust(_ADMIN, aces)
        assert trusted is True
        assert offenders == ()

    def test_owner_system_leere_dacl_ist_trusted(self) -> None:
        trusted, _reason, _off = evaluate_path_trust(_SYSTEM, [])
        assert trusted is True

    def test_owner_trusted_installer_ist_trusted(self) -> None:
        trusted, _reason, _off = evaluate_path_trust(_TRUSTED_INSTALLER, [])
        assert trusted is True

    def test_nicht_admin_owner_ist_untrusted(self) -> None:
        # Owner hat implizit WRITE_DAC -> kann sich selbst Schreibrechte geben.
        trusted, reason, offenders = evaluate_path_trust(_NON_ADMIN_USER, [])
        assert trusted is False
        assert _NON_ADMIN_USER in offenders
        assert "Besitzer" in reason

    def test_authenticated_users_write_data_ist_untrusted(self) -> None:
        aces = [(_ALLOW, _AUTH_USERS, _WRITE_DATA)]
        trusted, _reason, offenders = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is False
        assert _AUTH_USERS in offenders

    def test_everyone_generic_write_ist_untrusted(self) -> None:
        aces = [(_ALLOW, _EVERYONE, _GENERIC_WRITE)]
        trusted, _reason, _off = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is False

    def test_users_delete_ist_untrusted(self) -> None:
        aces = [(_ALLOW, _USERS, _DELETE)]
        trusted, _reason, _off = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is False

    def test_creator_owner_erbt_trusted_owner(self) -> None:
        # CREATOR OWNER mit Vollzugriff, Owner aber vertrauenswürdig -> trusted.
        aces = [(_ALLOW, _CREATOR_OWNER, _GENERIC_ALL)]
        trusted, _reason, _off = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is True

    def test_deny_ace_wird_ignoriert(self) -> None:
        # DENY für Users (Schreiben) + kein untrusted ALLOW -> trusted.
        aces = [(_DENY, _USERS, _WRITE_DATA), (_ALLOW, _USERS, _READ_EXECUTE)]
        trusted, _reason, _off = evaluate_path_trust(_ADMIN, aces)
        assert trusted is True

    def test_write_attributes_allein_ist_kein_tamper(self) -> None:
        aces = [(_ALLOW, _USERS, _WRITE_ATTRIBUTES)]
        trusted, _reason, _off = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is True

    def test_mehrere_offender_werden_alle_gemeldet(self) -> None:
        aces = [
            (_ALLOW, _EVERYONE, _WRITE_DATA),
            (_ALLOW, _AUTH_USERS, _GENERIC_ALL),
        ]
        trusted, _reason, offenders = evaluate_path_trust(_SYSTEM, aces)
        assert trusted is False
        assert set(offenders) == {_EVERYONE, _AUTH_USERS}


def _norm(p) -> str:
    return os.path.normcase(os.path.normpath(os.path.realpath(str(p))))


class TestAssessInstallPathTrust:
    def test_prefix_fehlschlag_lehnt_ohne_acl_ab(self, monkeypatch) -> None:
        # Keine geschützte Wurzel passt -> sofortige Ablehnung, ACL ungeprüft.
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: None)

        def boom(_p):  # darf nicht aufgerufen werden
            raise AssertionError("ACL nicht prüfen, wenn Prefix schon scheitert")

        monkeypatch.setattr(f"{_MOD}._read_path_security", boom)
        verdict = assess_install_path_trust(r"C:\Users\bob\app\norisk-collector.exe")
        assert verdict.trusted is False
        assert "geschützten System-Verzeichnis" in verdict.reason
        # P3-Fix: kein Sentinel-Token im SID-typisierten Feld.
        assert verdict.untrusted_principals == ()

    def test_prefix_ok_und_alle_knoten_trusted_ist_trusted(self, monkeypatch, tmp_path) -> None:
        root = _norm(tmp_path)
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: root)
        calls: list[str] = []

        def fake_read(path: Path):
            calls.append(str(path))
            return _SYSTEM, [(_ALLOW, _USERS, _READ_EXECUTE)]

        monkeypatch.setattr(f"{_MOD}._read_path_security", fake_read)
        verdict = assess_install_path_trust(str(tmp_path / "NoRisk" / "x.exe"))
        assert verdict.trusted is True
        # Datei + Zwischenverzeichnisse bis (exklusive) zur Wurzel: x.exe, NoRisk.
        assert len(calls) == 2

    def test_verzeichnis_untrusted_obwohl_datei_ok(self, monkeypatch, tmp_path) -> None:
        root = _norm(tmp_path)
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: root)

        def fake_read(path: Path):
            if str(path).lower().endswith(".exe"):
                return _SYSTEM, [(_ALLOW, _USERS, _READ_EXECUTE)]
            return _NON_ADMIN_USER, []  # Eltern-Verzeichnis: Nicht-Admin-Owner

        monkeypatch.setattr(f"{_MOD}._read_path_security", fake_read)
        verdict = assess_install_path_trust(str(tmp_path / "NoRisk" / "x.exe"))
        assert verdict.trusted is False
        assert "Besitzer" in verdict.reason

    def test_writable_grandparent_wird_abgelehnt(self, monkeypatch, tmp_path) -> None:
        # P1: Datei + Eltern admin-only, aber GROSSELTERN benutzer-beschreibbar
        # -> EoP-Pivot, muss abgelehnt werden (Ancestor-Walk).
        root = _norm(tmp_path)
        grandparent = _norm(tmp_path / "NoRisk")
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: root)

        def fake_read(path: Path):
            if _norm(path) == grandparent:
                return _NON_ADMIN_USER, []  # benutzer-besessenes Zwischenverzeichnis
            return _SYSTEM, [(_ALLOW, _USERS, _READ_EXECUTE)]

        monkeypatch.setattr(f"{_MOD}._read_path_security", fake_read)
        verdict = assess_install_path_trust(str(tmp_path / "NoRisk" / "bin" / "x.exe"))
        assert verdict.trusted is False
        assert "NoRisk" in verdict.reason

    def test_null_dacl_ist_untrusted(self, monkeypatch, tmp_path) -> None:
        root = _norm(tmp_path)
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: root)
        monkeypatch.setattr(f"{_MOD}._read_path_security", lambda _p: (_SYSTEM, None))
        verdict = assess_install_path_trust(str(tmp_path / "x.exe"))
        assert verdict.trusted is False
        assert "NULL-DACL" in verdict.reason

    def test_acl_lesefehler_ist_fail_closed(self, monkeypatch, tmp_path) -> None:
        root = _norm(tmp_path)
        monkeypatch.setattr(f"{_MOD}._matched_trusted_root", lambda _p: root)

        def boom(_p):
            raise OSError("Zugriff verweigert")

        monkeypatch.setattr(f"{_MOD}._read_path_security", boom)
        verdict = assess_install_path_trust(str(tmp_path / "x.exe"))
        assert verdict.trusted is False
        assert "nicht prüfbar" in verdict.reason


class TestAncestorWalk:
    def test_matched_root_unter_programfiles(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("ProgramFiles", str(tmp_path))
        root = win_security._matched_trusted_root(tmp_path / "NoRisk" / "x.exe")
        assert root == os.path.normcase(os.path.normpath(str(tmp_path)))

    def test_matched_root_ausserhalb_ist_none(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "PF"))
        assert win_security._matched_trusted_root(tmp_path / "Users" / "x.exe") is None

    def test_ancestors_bis_root_exklusiv(self, tmp_path) -> None:
        root = os.path.normcase(os.path.normpath(str(tmp_path)))
        chain = win_security._ancestors_up_to_root(tmp_path / "NoRisk" / "bin" / "x.exe", root)
        names = [p.name for p in chain]
        assert names[0] == "bin"
        assert "NoRisk" in names
        # Die Wurzel selbst wird NICHT inspiziert (per Allowlist OS-geschützt).
        chain_norm = [os.path.normcase(os.path.normpath(str(p))) for p in chain]
        assert root not in chain_norm


class TestIsUnderTrustedRoot:
    def test_pfad_unter_programfiles_ist_drunter(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("ProgramFiles", str(tmp_path))
        target = tmp_path / "NoRisk" / "norisk-collector.exe"
        assert win_security._is_under_trusted_root(target) is True

    def test_pfad_ausserhalb_ist_nicht_drunter(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "PF"))
        target = tmp_path / "Users" / "bob" / "x.exe"
        assert win_security._is_under_trusted_root(target) is False

    def test_praefix_an_verzeichnisgrenze_kein_treffer(self, monkeypatch, tmp_path) -> None:
        # "<root>Evil" darf NICHT als unter "<root>" zählen.
        root = tmp_path / "PF"
        monkeypatch.setenv("ProgramFiles", str(root))
        target = Path(str(root) + "Evil") / "x.exe"
        assert win_security._is_under_trusted_root(target) is False


class TestHardenDllSearchPath:
    def test_nicht_windows_gibt_false(self, monkeypatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        assert harden_dll_search_path() is False

    def test_windows_erfolg_setzt_default_dirs(self, monkeypatch) -> None:
        import ctypes

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        fake_kernel32 = MagicMock()
        fake_kernel32.SetDefaultDllDirectories = MagicMock(return_value=1)
        monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: fake_kernel32, raising=False)
        assert harden_dll_search_path() is True
        fake_kernel32.SetDefaultDllDirectories.assert_called_once_with(
            win_security._LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
        )

    def test_windows_fehlschlag_gibt_false(self, monkeypatch) -> None:
        import ctypes

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        fake_kernel32 = MagicMock()
        fake_kernel32.SetDefaultDllDirectories = MagicMock(return_value=0)
        monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: fake_kernel32, raising=False)
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
        assert harden_dll_search_path() is False

    def test_frozen_nimmt_bundle_dirs_wieder_auf(self, monkeypatch, tmp_path) -> None:
        import ctypes
        import os

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "meipass"), raising=False)
        monkeypatch.setattr(sys, "executable", str(tmp_path / "dist" / "norisk-collector.exe"))
        fake_kernel32 = MagicMock()
        fake_kernel32.SetDefaultDllDirectories = MagicMock(return_value=1)
        monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: fake_kernel32, raising=False)
        added: list[str] = []
        monkeypatch.setattr(os, "add_dll_directory", lambda d: added.append(d), raising=False)
        assert harden_dll_search_path() is True
        assert str(tmp_path / "meipass") in added
        assert str(tmp_path / "dist") in added


def test_path_trust_verdict_ist_frozen() -> None:
    v = PathTrustVerdict(trusted=True, reason="ok", checked_path="C:/x")
    with pytest.raises((AttributeError, TypeError)):
        v.trusted = False  # type: ignore[misc]
