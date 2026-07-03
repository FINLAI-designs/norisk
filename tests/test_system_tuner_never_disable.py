"""
test_system_tuner_never_disable — NEVER_DISABLE-Invariante (system_tuner Phase 1a).

Prueft die Domain-Konstante + Drift-Schutz gegen den mitgelieferten
YAML-Spiegel (die YAML darf die Konstante nur ERWEITERN, nie verkleinern).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tools.system_tuner.domain.never_disable import (
    NEVER_BLOCK_ENDPOINTS,
    NEVER_DISABLE_SERVICES,
    is_never_block_endpoint,
    is_never_disable_service,
    is_never_touch_registry,
)


def _yaml() -> dict:
    path = (
        Path(__file__).resolve().parents[1]
        / "resources"
        / "system_tuner"
        / "NEVER_DISABLE.yaml"
    )
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class TestCanonicalSet:
    def test_critical_services_present(self):
        for svc in ("windefend", "wuauserv", "bits", "cryptsvc", "rpcss", "eventlog"):
            assert svc in NEVER_DISABLE_SERVICES

    def test_service_check_case_insensitive(self):
        assert is_never_disable_service("WinDefend")
        assert is_never_disable_service("  WUAUSERV ")
        assert not is_never_disable_service("DiagTrack")

    def test_registry_check(self):
        assert is_never_touch_registry(
            "HKLM",
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            "DisableAntiSpyware",
        )
        assert not is_never_touch_registry("HKLM", "SOFTWARE\\Foo", "Bar")

    def test_endpoint_check(self):
        assert is_never_block_endpoint("settings-win.data.microsoft.com")
        assert is_never_block_endpoint("LOGIN.LIVE.COM")
        assert not is_never_block_endpoint("example.com")


class TestNoDrift:
    """Der YAML-Spiegel muss die kanonische Konstante als Teilmenge enthalten."""

    def test_yaml_superset_of_services(self):
        yaml_services = {s.strip().lower() for s in _yaml().get("services", [])}
        missing = NEVER_DISABLE_SERVICES - yaml_services
        assert not missing, f"NEVER_DISABLE.yaml fehlen Dienste: {sorted(missing)}"

    def test_yaml_superset_of_endpoints(self):
        yaml_endpoints = {e.strip().lower() for e in _yaml().get("endpoints", [])}
        missing = NEVER_BLOCK_ENDPOINTS - yaml_endpoints
        assert not missing, f"NEVER_DISABLE.yaml fehlen Endpoints: {sorted(missing)}"
