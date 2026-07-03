"""
test_hardening_probe — pytest-Tests fuer
``core.probes.hardening_probe`` + ``core.probes.mock_hardening_probe``.

Probe-Port + Test-Doppelgaenger / Probe-Promotion nach
core/probes/). Pure Logik, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from core.probes.hardening_probe import (
    HIVE_HKCU,
    HIVE_HKLM,
    IHardeningProbe,
    ProbeResult,
)
from core.probes.mock_hardening_probe import MockHardeningProbe

# ===========================================================================
# ProbeResult Dataclass
# ===========================================================================


class TestProbeResult:
    def test_default_success_returncode_zero(self):
        result = ProbeResult(success=True)
        assert result.returncode == 0
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.error == ""

    def test_frozen(self):
        result = ProbeResult(success=True)
        with pytest.raises(Exception):  # noqa: B017, BLE001 — FrozenInstanceError
            result.success = False  # type: ignore[misc]

    def test_failed_with_error_message(self):
        result = ProbeResult(success=False, error="Timeout", returncode=-1)
        assert not result.success
        assert result.error == "Timeout"
        assert result.returncode == -1


# ===========================================================================
# Hive-Konstanten
# ===========================================================================


class TestHiveConstants:
    def test_hive_strings_stable(self):
        # Werte werden vom Production-Adapter (Phase 3.3) erwartet
        assert HIVE_HKLM == "HKLM"
        assert HIVE_HKCU == "HKCU"


# ===========================================================================
# IHardeningProbe — Interface-Vertrag
# ===========================================================================


class TestIHardeningProbeAbstract:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError, match="abstract"):
            IHardeningProbe()  # type: ignore[abstract]

    def test_mock_subclass_works(self):
        # MockHardeningProbe ist die Test-Implementation
        probe = MockHardeningProbe()
        assert isinstance(probe, IHardeningProbe)


# ===========================================================================
# MockHardeningProbe — is_available
# ===========================================================================


class TestMockAvailable:
    def test_default_available_true(self):
        assert MockHardeningProbe().is_available() is True

    def test_explicit_unavailable(self):
        assert MockHardeningProbe(available=False).is_available() is False


# ===========================================================================
# MockHardeningProbe — Registry
# ===========================================================================


class TestMockRegistry:
    def test_unset_value_returns_none(self):
        probe = MockHardeningProbe()
        assert probe.read_registry_value(HIVE_HKLM, "X\\Y", "Z") is None

    def test_set_value_then_read(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(
            HIVE_HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA",
            "1",
        )
        assert (
            probe.read_registry_value(
                HIVE_HKLM,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "EnableLUA",
            )
            == "1"
        )

    def test_different_hives_are_separate_keys(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, "k", "v", "lm-val")
        probe.set_registry_value(HIVE_HKCU, "k", "v", "cu-val")
        assert probe.read_registry_value(HIVE_HKLM, "k", "v") == "lm-val"
        assert probe.read_registry_value(HIVE_HKCU, "k", "v") == "cu-val"

    def test_clear_registry_value(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, "k", "v", "x")
        assert probe.read_registry_value(HIVE_HKLM, "k", "v") == "x"
        probe.clear_registry_value(HIVE_HKLM, "k", "v")
        assert probe.read_registry_value(HIVE_HKLM, "k", "v") is None

    def test_clear_nonexistent_does_not_raise(self):
        probe = MockHardeningProbe()
        # Idempotent: kein KeyError wenn nicht vorhanden
        probe.clear_registry_value(HIVE_HKLM, "x", "y")


# ===========================================================================
# MockHardeningProbe — run_command
# ===========================================================================


class TestMockRunCommand:
    def test_unset_command_returns_failure(self):
        probe = MockHardeningProbe()
        result = probe.run_command("netsh", ["advfirewall"])
        assert not result.success
        assert "no result" in result.error
        assert result.returncode == -1

    def test_set_command_result_success(self):
        probe = MockHardeningProbe()
        probe.set_command_result(
            "netsh",
            ["advfirewall", "show", "allprofiles", "state"],
            stdout="Domain Profile Settings:\nState                                 ON",
        )
        result = probe.run_command(
            "netsh", ["advfirewall", "show", "allprofiles", "state"]
        )
        assert result.success
        assert "State" in result.stdout

    def test_set_command_result_failure(self):
        probe = MockHardeningProbe()
        probe.set_command_result(
            "manage-bde",
            ["-status"],
            success=False,
            stderr="Zugriff verweigert",
            returncode=87,
        )
        result = probe.run_command("manage-bde", ["-status"])
        assert not result.success
        assert "Zugriff verweigert" in result.stderr
        assert result.returncode == 87

    def test_different_args_are_separate_lookups(self):
        probe = MockHardeningProbe()
        probe.set_command_result("net", ["user", "Guest"], stdout="Account active No")
        probe.set_command_result("net", ["accounts"], stdout="Minimum password length: 8")

        guest = probe.run_command("net", ["user", "Guest"])
        accounts = probe.run_command("net", ["accounts"])
        assert "Account active No" in guest.stdout
        assert "password length: 8" in accounts.stdout

    def test_default_empty_args(self):
        probe = MockHardeningProbe()
        probe.set_command_result("simple-tool", stdout="ok")
        result = probe.run_command("simple-tool", [])
        assert result.stdout == "ok"


# ===========================================================================
# MockHardeningProbe — run_powershell
# ===========================================================================


class TestMockRunPowershell:
    def test_unset_script_returns_failure(self):
        probe = MockHardeningProbe()
        result = probe.run_powershell("Get-SmbServerConfiguration")
        assert not result.success
        assert "no result for script" in result.error

    def test_set_powershell_result_success(self):
        probe = MockHardeningProbe()
        probe.set_powershell_result(
            "Get-SmbServerConfiguration",
            stdout="EnableSMB1Protocol : False",
        )
        result = probe.run_powershell("Get-SmbServerConfiguration")
        assert result.success
        assert "EnableSMB1Protocol : False" in result.stdout

    def test_powershell_failure_with_stderr(self):
        probe = MockHardeningProbe()
        probe.set_powershell_result(
            "Get-X",
            success=False,
            stderr="ScriptHalted",
            returncode=1,
        )
        result = probe.run_powershell("Get-X")
        assert not result.success
        assert result.returncode == 1


# ===========================================================================
# Determinismus / Idempotenz
# ===========================================================================


class TestDeterminism:
    """Wiederholte Aufrufe liefern identische Ergebnisse."""

    def test_registry_read_idempotent(self):
        probe = MockHardeningProbe()
        probe.set_registry_value(HIVE_HKLM, "k", "v", "value")
        results = [
            probe.read_registry_value(HIVE_HKLM, "k", "v") for _ in range(5)
        ]
        assert all(r == "value" for r in results)

    def test_command_idempotent(self):
        probe = MockHardeningProbe()
        probe.set_command_result("tool", ["arg"], stdout="x")
        results = [probe.run_command("tool", ["arg"]).stdout for _ in range(5)]
        assert all(r == "x" for r in results)
