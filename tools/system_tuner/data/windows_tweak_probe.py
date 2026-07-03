"""
windows_tweak_probe — Production-Adapter fuer ITweakProbe (Phase 2 Apply).

Erweitert den read-only:class:`core.probes.windows_hardening_probe.
WindowsHardeningProbe` um Schreib-/Loesch-Ops (Registry via winreg, Dienst-
Starttyp via ``sc config``). **Windows-only**; HKLM-Writes + ``sc config``
brauchen Admin-Rechte. Wirft nie — Fehler landen im:class:`ProbeResult`.

WICHTIG: Diese Ops mutieren den System-Zustand. Sie werden ausschliesslich
ueber die ``TweakEngine`` aufgerufen, die fail-closed prueft (NEVER_DISABLE
pro Op, Snapshot, Verify, Sign-off-Gate). Der elevated Round-Trip (R5) +
Restore-Point (R6) folgen im reviewten Phase-2-Sprint.

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import sys
from typing import Any, Final

from core.logger import get_logger
from core.probes.hardening_probe import HIVE_HKCU, HIVE_HKLM, ProbeResult
from core.probes.windows_hardening_probe import WindowsHardeningProbe
from tools.system_tuner.domain.enums import RegistryValueType, ServiceStartMode
from tools.system_tuner.domain.interfaces import ITweakProbe

log = get_logger(__name__)

_WINDOWS: Final[bool] = sys.platform == "win32"
_SERVICES_KEY: Final[str] = "SYSTEM\\CurrentControlSet\\Services"

#: Registry-``Start``-Wert -> Starttyp.
_START_VALUE_TO_MODE: Final[dict[str, ServiceStartMode]] = {
    "0": ServiceStartMode.AUTOMATIC,
    "1": ServiceStartMode.AUTOMATIC,
    "2": ServiceStartMode.AUTOMATIC,
    "3": ServiceStartMode.MANUAL,
    "4": ServiceStartMode.DISABLED,
}

#: Starttyp -> ``sc config start=``-Argument.
_MODE_TO_SC: Final[dict[ServiceStartMode, str]] = {
    ServiceStartMode.AUTOMATIC: "auto",
    ServiceStartMode.MANUAL: "demand",
    ServiceStartMode.DISABLED: "disabled",
}


def _not_windows() -> ProbeResult:
    return ProbeResult(
        success=False, error="WindowsTweakProbe: nicht-Windows-Plattform", returncode=-1
    )


class WindowsTweakProbe(WindowsHardeningProbe, ITweakProbe):
    """Read (geerbt) + Write (Registry/Dienst) auf der echten Windows-Maschine."""

    # ------------------------------------------------------------------
    # read (zusaetzlich zum geerbten read_registry_value)
    # ------------------------------------------------------------------
    def read_service_start_mode(self, service_name: str) -> ServiceStartMode | None:
        raw = self.read_registry_value(
            HIVE_HKLM, f"{_SERVICES_KEY}\\{service_name}", "Start"
        )
        if raw is None:
            return None
        return _START_VALUE_TO_MODE.get(raw.strip())

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------
    def write_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_type: RegistryValueType,
        value: str | int,
    ) -> ProbeResult:
        if not _WINDOWS:
            return _not_windows()
        import winreg  # noqa: PLC0415

        hive_const = _resolve_hive(winreg, hive)
        if hive_const is None:
            return ProbeResult(success=False, error=f"Unbekannter Hive: {hive!r}", returncode=-1)
        type_const, data = _coerce_value(winreg, value_type, value)
        if type_const is None:
            return ProbeResult(
                success=False, error=f"Unbekannter value_type: {value_type!r}", returncode=-1
            )
        try:
            key = winreg.CreateKeyEx(  # type: ignore[attr-defined]
                hive_const, key_path, 0, winreg.KEY_SET_VALUE
            )
            try:
                winreg.SetValueEx(key, value_name, 0, type_const, data)  # type: ignore[attr-defined]
            finally:
                winreg.CloseKey(key)  # type: ignore[attr-defined]
        except OSError as exc:
            log.warning("Registry-Write fehlgeschlagen %s\\%s\\%s: %s", hive, key_path, value_name, exc)
            return ProbeResult(success=False, error=f"Registry-Write: {exc}", returncode=-1)
        return ProbeResult(success=True)

    def delete_registry_value(
        self, hive: str, key_path: str, value_name: str
    ) -> ProbeResult:
        if not _WINDOWS:
            return _not_windows()
        import winreg  # noqa: PLC0415

        hive_const = _resolve_hive(winreg, hive)
        if hive_const is None:
            return ProbeResult(success=False, error=f"Unbekannter Hive: {hive!r}", returncode=-1)
        try:
            key = winreg.OpenKey(  # type: ignore[attr-defined]
                hive_const, key_path, 0, winreg.KEY_SET_VALUE
            )
            try:
                winreg.DeleteValue(key, value_name)  # type: ignore[attr-defined]
            finally:
                winreg.CloseKey(key)  # type: ignore[attr-defined]
        except FileNotFoundError:
            return ProbeResult(success=True)  # schon weg = Ziel erreicht
        except OSError as exc:
            return ProbeResult(success=False, error=f"Registry-Delete: {exc}", returncode=-1)
        return ProbeResult(success=True)

    def set_service_start_mode(
        self, service_name: str, mode: ServiceStartMode
    ) -> ProbeResult:
        if not _WINDOWS:
            return _not_windows()
        sc_arg = _MODE_TO_SC.get(mode)
        if sc_arg is None:
            return ProbeResult(success=False, error=f"Unbekannter Modus: {mode!r}", returncode=-1)
        # ``sc config <name> start= <wert>`` — "start=" und Wert als getrennte argv.
        return self.run_command("sc", ["config", service_name, "start=", sc_arg])


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _resolve_hive(winreg_module: Any, hive: str) -> int | None:
    if hive == HIVE_HKLM:
        return int(winreg_module.HKEY_LOCAL_MACHINE)
    if hive == HIVE_HKCU:
        return int(winreg_module.HKEY_CURRENT_USER)
    return None


def _coerce_value(
    winreg_module: Any, value_type: RegistryValueType, value: str | int
) -> tuple[int | None, str | int]:
    """Mappt RegistryValueType auf die winreg-Konstante + konvertiert den Wert.

    A8: ``int(value)`` ist gegen ungueltige Katalog-/Plan-Werte abgesichert —
    ein nicht-numerisches ``desired`` fuer DWORD/QWORD fuehrt zu ``(None, value)``
    (der Caller liefert dann ein fail-safes ProbeResult, statt zu werfen).
    """
    try:
        if value_type is RegistryValueType.REG_DWORD:
            return int(winreg_module.REG_DWORD), int(value)
        if value_type is RegistryValueType.REG_QWORD:
            return int(winreg_module.REG_QWORD), int(value)
    except (TypeError, ValueError):
        return None, value
    if value_type is RegistryValueType.REG_SZ:
        return int(winreg_module.REG_SZ), str(value)
    return None, value
