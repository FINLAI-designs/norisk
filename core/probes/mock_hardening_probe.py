"""
mock_hardening_probe — Test-Adapter fuer IHardeningProbe.

Deterministischer Mock-Adapter fuer Unit-Tests aller Probe-Consumer
(``WindowsHardeningScanner`` in ``system_scanner``, Scan-/Engine-Logik
in ``system_tuner``). Erlaubt das Injizieren beliebiger Registry-Werte,
Command-Outputs und PowerShell-Ergebnisse ohne tatsaechliche
subprocess- / winreg-Aufrufe.

Geteiltes Utility (core/probes/): urspruenglich
``tools/system_scanner/data/mock_hardening_probe.py``. Reiner In-Memory-
Doppelgaenger (keine Test-Framework-Dependency) — darf daher in core/
liegen.

Pattern: vor dem Test wird die Mock-Probe befuellt:

.. code-block:: python

    probe = MockHardeningProbe
    probe.set_registry_value(
        HIVE_HKLM,
        "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System",
        "EnableLUA",
        "1",
)
    probe.set_command_result("netsh", success=True, stdout="...")

    scanner = WindowsHardeningScanner(probe)
    result = scanner.check_uac

Schichtzugehoerigkeit: core/probes/ — Adapter-Implementation des
Ports:class:`IHardeningProbe`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.probes.hardening_probe import (
    IHardeningProbe,
    ProbeResult,
)


class MockHardeningProbe(IHardeningProbe):
    """Test-Adapter fuer:class:`IHardeningProbe`.

    Speichert Registry-Werte und Command-/PowerShell-Outputs in
    internen Dicts und liefert sie bei Aufrufen zurueck. Default-
    Verhalten: nicht-gesetzte Werte liefern ``None`` (Registry) oder
    ``ProbeResult(success=False, error="not configured")``
    (Command/PowerShell).
    """

    def __init__(self, *, available: bool = True) -> None:
        """Initialisiert die Mock-Probe.

        Args:
            available: Default-Returnwert fuer:meth:`is_available`.
                Tests koennen Production-Adapter-Verhalten simulieren
                (z. B. "nicht-Windows" → False) indem sie ``False``
                setzen.
        """
        self._available = available
        # Registry: (hive, key_path, value_name) → value-str
        self._registry: dict[tuple[str, str, str], str] = {}
        # Commands: (executable, tuple(args)) → ProbeResult
        self._commands: dict[tuple[str, tuple[str, ...]], ProbeResult] = {}
        # PowerShell: script-string → ProbeResult
        self._powershell: dict[str, ProbeResult] = {}

    # ------------------------------------------------------------------
    # IHardeningProbe-Implementierung
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return self._available

    def read_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
    ) -> str | None:
        """Liefert gesetzten Mock-Wert oder ``None``."""
        return self._registry.get((hive, key_path, value_name))

    def run_command(
        self,
        executable: str,
        args: list[str],
        *,
        timeout: int = 30,
    ) -> ProbeResult:
        """Liefert gesetztes Mock-Ergebnis oder Default-Fehler.

        Args:
            executable: Tool-Name (Mock-Lookup-Key).
            args: Argumente-Liste (wird zu Tuple fuer Hash-Equality).
            timeout: Wird ignoriert — Mock laeuft synchron sofort.
        """
        _ = timeout
        key = (executable, tuple(args))
        if key in self._commands:
            return self._commands[key]
        return ProbeResult(
            success=False,
            error=f"MockHardeningProbe: no result for {executable} {' '.join(args)}",
            returncode=-1,
        )

    def run_powershell(
        self,
        script: str,
        *,
        timeout: int = 30,
    ) -> ProbeResult:
        """Liefert gesetztes Mock-Ergebnis fuer das Skript oder Default."""
        _ = timeout
        if script in self._powershell:
            return self._powershell[script]
        return ProbeResult(
            success=False,
            error=f"MockHardeningProbe: no result for script {script[:50]!r}",
            returncode=-1,
        )

    # ------------------------------------------------------------------
    # Mock-Konfiguration (von Tests aufgerufen)
    # ------------------------------------------------------------------

    def set_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value: str,
    ) -> None:
        """Setzt einen Registry-Wert, den:meth:`read_registry_value` zurueckliefert."""
        self._registry[(hive, key_path, value_name)] = value

    def clear_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
    ) -> None:
        """Entfernt einen gesetzten Registry-Wert (read returnt dann None)."""
        self._registry.pop((hive, key_path, value_name), None)

    def set_command_result(
        self,
        executable: str,
        args: list[str] | None = None,
        *,
        success: bool = True,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        error: str = "",
    ) -> None:
        """Setzt das Ergebnis fuer einen Command-Aufruf.

        Args:
            executable: Tool-Name (Lookup-Key).
            args: Argumente-Liste (Default leere Liste). Wird fuer
                Hash-Equality zu Tuple konvertiert.
            success/stdout/stderr/returncode/error: Felder des
:class:`ProbeResult`.
        """
        result = ProbeResult(
            success=success,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            error=error,
        )
        self._commands[(executable, tuple(args or []))] = result

    def set_powershell_result(
        self,
        script: str,
        *,
        success: bool = True,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        error: str = "",
    ) -> None:
        """Setzt das Ergebnis fuer ein PowerShell-Skript."""
        self._powershell[script] = ProbeResult(
            success=success,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            error=error,
        )
