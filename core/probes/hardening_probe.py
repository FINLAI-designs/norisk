"""
hardening_probe — Port (Interface) fuer System-Probes.

Geteiltes Utility (core/probes/-Folge / system_tuner-Phase 0):
urspruenglich ``tools/system_scanner/domain/hardening_probe.py``. Nach
``core/probes/`` hochgezogen, damit sowohl ``system_scanner`` (read-only
Hardening-Checks) als auch ``system_tuner`` (Datenschutz/Telemetrie-Scan
+ Apply) denselben fail-safe Probe-Port und Test-Doppelgaenger teilen,
ohne Cross-Tool-Import (Contract 5: core < tools < apps bleibt KEPT).

Abstraktion fuer die plattform-spezifischen System-Aufrufe. Reiner
Port — kein Code-Pfad zu ``subprocess``, ``winreg`` oder PowerShell.
Adapter implementieren das Interface:

    core/probes/hardening_probe.py → IHardeningProbe (Port — dieses Modul)
    core/probes/windows_hardening_probe.py → WindowsHardeningProbe (Production-Adapter, read-only)
    core/probes/mock_hardening_probe.py → MockHardeningProbe (Test-Adapter)

Die Probe bietet drei Operationen — Registry-Read, Command-Run und
PowerShell-Skript — plus einen ``is_available``-Gate-Check fuer das OS.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Ergebnis eines Command-/PowerShell-Aufrufs.

    Frozen + slots: unveraenderbar, speicherarm. Wird vom Scanner an
    die Check-Logik weitergereicht.

    Attributes:
        success: ``True`` wenn ``returncode == 0`` und kein Probe-
            Internal-Fehler (z. B. Timeout, FileNotFound). Caller
            soll **immer** ``success`` pruefen — ``returncode`` allein
            ist nicht aussagekraeftig wenn das Tool gar nicht aufgerufen
            werden konnte.
        stdout: Standard-Output des Aufrufs (UTF-8 dekodiert, Leerstring
            wenn kein Output).
        stderr: Standard-Error (UTF-8 dekodiert).
        returncode: Exit-Code des Aufrufs (-1 wenn Probe-Internal-
            Fehler, z. B. Timeout).
        error: Menschen-lesbarer Fehlertext bei ``success=False``
            (z. B. ``"Timeout nach 30s"``). Leer bei success.
    """

    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# Registry-Hives — als String-Konstanten (Adapter-unabhaengig)
# ---------------------------------------------------------------------------

#: Top-Level-Schluessel fuer Windows-Registry-Aufrufe. Werte sind die
#: kanonischen Namen aus ``winreg`` (Hive-Strings), damit das Interface
#: ohne winreg-Import benutzbar bleibt.
HIVE_HKLM: str = "HKLM"
HIVE_HKCU: str = "HKCU"


# ---------------------------------------------------------------------------
# Port (Interface)
# ---------------------------------------------------------------------------


class IHardeningProbe(ABC):
    """Port fuer plattform-spezifische System-Probes.

    Adapter implementieren die 4 abstrakten Methoden. Die Pflicht-
    Semantik:

    * **Pure-Function-Vertrag fuer Tests**: zwei aufeinanderfolgende
      Aufrufe mit gleichen Parametern liefern dasselbe ProbeResult
      (Mock + Production). Falls die Production-Variante doch
      System-State liest, ist das ``MockHardeningProbe``-Vertrag.
    * **Keine Exceptions** fuer "Probe konnte nicht ausgefuehrt werden"
      — stattdessen ``ProbeResult(success=False, error=...)``. Damit
      sind die Check-Methoden im Scanner einfach geradeaus zu
      schreiben (kein try/except auf jeder Probe-Aufruf-Stelle).
    * **Sichere Defaults**: Timeout per Argument, Probe-Selbst-Crash
      → ``success=False`` (kein Crash-Propagieren in den Scanner).
    """

    @abstractmethod
    def is_available(self) -> bool:
        """True wenn der Adapter auf der aktuellen Plattform laufen kann.

        Production-Adapter (Windows): ``sys.platform == "win32"``.
        Mock-Adapter: immer ``True``.

        Returns:
            True wenn Probes verwendbar, False sonst.
        """

    @abstractmethod
    def read_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
    ) -> str | None:
        """Liest einen Windows-Registry-Wert.

        Args:
            hive: ``HIVE_HKLM`` oder ``HIVE_HKCU``.
            key_path: Schluessel-Pfad **ohne** Hive-Praefix, z. B.
                ``"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"``.
            value_name: Name des Werts unterhalb des Keys.

        Returns:
            Wert als String (auch numerische Werte werden zu String
            konvertiert — ``"1"`` statt ``1``), oder ``None`` wenn:

            * Hive ungueltig
            * Key existiert nicht
            * Value existiert nicht
            * Probe-Crash / Permission-Denied

            Caller muss ``None`` als "unbekannt" interpretieren und
            das Check-Ergebnis als ``passed=False`` mit
            entsprechendem ``detail`` setzen.
        """

    @abstractmethod
    def run_command(
        self,
        executable: str,
        args: list[str],
        *,
        timeout: int = 30,
    ) -> ProbeResult:
        """Fuehrt einen externen Befehl aus (subprocess-Wrapper).

        Beispiele:

        * ``run_command("netsh", ["advfirewall", "show", "allprofiles", "state"])``
        * ``run_command("net", ["accounts"])``
        * ``run_command("manage-bde", ["-status", "C:"])``

        Args:
            executable: Name der ausfuehrbaren Datei. Ohne Pfad — das
                System sucht via PATH (Production-Adapter).
            args: Argumente-Liste (subprocess-Convention: kein Shell-
                Splitting).
            timeout: Sekunden bis zum Probe-Abbruch. Default 30 s.

        Returns:
:class:`ProbeResult` mit ``success`` reflektiert ob der
            Aufruf erfolgreich war.
        """

    @abstractmethod
    def run_powershell(
        self,
        script: str,
        *,
        timeout: int = 30,
    ) -> ProbeResult:
        """Fuehrt ein PowerShell-Skript aus.

        Production-Adapter ruft typisch ``powershell.exe -NoProfile
        -Command "..."`` auf. Wenn Skript >1 Zeile: per
        ``-EncodedCommand`` (base64 UTF-16-LE).

        Beispiel:

        * ``run_powershell("Get-SmbServerConfiguration | Select EnableSMB1Protocol")``

        Args:
            script: PowerShell-Skript (String — kann auch ein einzelner
                Cmdlet-Aufruf sein).
            timeout: Sekunden bis zum Probe-Abbruch.

        Returns:
:class:`ProbeResult`.
        """
