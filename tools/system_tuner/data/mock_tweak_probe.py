"""
mock_tweak_probe — In-Memory-Test-Adapter fuer ITweakProbe.

Deterministischer Doppelgaenger fuer Engine-Tests: haelt Registry-Werte und
Dienst-Starttypen im Speicher, fuehrt Writes/Deletes/Set wirklich (in-memory)
aus, sodass anschliessendes Read den neuen Zustand zeigt (fuer Verify-Readback).

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.probes.hardening_probe import ProbeResult
from tools.system_tuner.domain.enums import RegistryValueType, ServiceStartMode
from tools.system_tuner.domain.interfaces import ITweakProbe


class MockTweakProbe(ITweakProbe):
    """In-Memory ITweakProbe fuer Tests (Writes wirken auf den Lese-Pfad)."""

    def __init__(self, *, available: bool = True, fail_writes: bool = False) -> None:
        self._available = available
        self._fail_writes = fail_writes
        self._registry: dict[tuple[str, str, str], str] = {}
        self._services: dict[str, ServiceStartMode] = {}

    # -- read -----------------------------------------------------------
    def is_available(self) -> bool:
        return self._available

    def read_registry_value(
        self, hive: str, key_path: str, value_name: str
    ) -> str | None:
        return self._registry.get((hive, key_path, value_name))

    def read_service_start_mode(self, service_name: str) -> ServiceStartMode | None:
        return self._services.get(service_name)

    # -- write ----------------------------------------------------------
    def write_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_type: RegistryValueType,
        value: str | int,
    ) -> ProbeResult:
        if self._fail_writes:
            return ProbeResult(success=False, error="Mock: write disabled", returncode=-1)
        self._registry[(hive, key_path, value_name)] = str(value)
        return ProbeResult(success=True)

    def delete_registry_value(
        self, hive: str, key_path: str, value_name: str
    ) -> ProbeResult:
        if self._fail_writes:
            return ProbeResult(success=False, error="Mock: write disabled", returncode=-1)
        self._registry.pop((hive, key_path, value_name), None)
        return ProbeResult(success=True)

    def set_service_start_mode(
        self, service_name: str, mode: ServiceStartMode
    ) -> ProbeResult:
        if self._fail_writes:
            return ProbeResult(success=False, error="Mock: write disabled", returncode=-1)
        self._services[service_name] = mode
        return ProbeResult(success=True)

    # -- Test-Konfiguration --------------------------------------------
    def set_registry_value(
        self, hive: str, key_path: str, value_name: str, value: str
    ) -> None:
        self._registry[(hive, key_path, value_name)] = value

    def set_service(self, service_name: str, mode: ServiceStartMode) -> None:
        self._services[service_name] = mode
