"""
core.probes — Geteilte System-Probe-Ports & Adapter.

Fail-safe Abstraktion fuer plattform-spezifische System-Aufrufe
(Registry-Read, Command, PowerShell). Hochgezogen aus
``tools/system_scanner``-Folge), damit ``system_scanner``
(read-only Hardening-Checks) und ``system_tuner`` (Datenschutz/
Telemetrie-Scan + Apply) denselben Port und Test-Doppelgaenger teilen.

Convenience-Re-Exports — Consumer koennen auch direkt aus den
Submodulen importieren.
"""

from __future__ import annotations

from core.probes.hardening_probe import (
    HIVE_HKCU,
    HIVE_HKLM,
    IHardeningProbe,
    ProbeResult,
)
from core.probes.mock_hardening_probe import MockHardeningProbe
from core.probes.windows_hardening_probe import WindowsHardeningProbe

__all__ = [
    "HIVE_HKCU",
    "HIVE_HKLM",
    "IHardeningProbe",
    "MockHardeningProbe",
    "ProbeResult",
    "WindowsHardeningProbe",
]
