"""
os_detection — Auto-Detection von Windows-Hello und Passwort-Manager-Installationen.

Liefert neutrale Faktenstatus (``"aktiv"`` / ``"inaktiv"`` / ``"unbekannt"``) —
keine Wertung, keine Empfehlung. Auf nicht-Windows-Systemen wird stets
``"unbekannt"`` zurückgegeben, damit der User das Ergebnis manuell
bestätigen kann.

Sicherheitsdesign:
  - Keine Netzwerkaufrufe
  - Registry-Zugriff nur lesend, mit explizitem Fehlerhandling
  - Externe Prozesse (PowerShell) mit fixiertem Argument-Array
    (kein ``shell=True``), kurzem Timeout und begrenzter Ausgabe

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from core.logger import get_logger
from tools.security_scoring.domain.org_security import BEKANNTE_PASSWORT_MANAGER

log = get_logger(__name__)

STATUS_AKTIV = "aktiv"
STATUS_INAKTIV = "inaktiv"
STATUS_UNBEKANNT = "unbekannt"

_POWERSHELL_TIMEOUT_SEC = 10

# Registry-Pfade für die Deinstallations-Liste klassischer Installer.
_UNINSTALL_REGISTRY_PATHS: tuple[tuple[int, str], ...] = (
    # HKEY_LOCAL_MACHINE
    (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (0x80000002, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    # HKEY_CURRENT_USER
    (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)


@dataclass
class WindowsHelloStatus:
    """Ergebnis der Windows-Hello-Auto-Detection.

    Attributes:
        status: ``"aktiv"`` / ``"inaktiv"`` / ``"unbekannt"``.
        detail: Kurze Faktenbeschreibung für das Label.
    """

    status: str
    detail: str


@dataclass
class PasswortManagerStatus:
    """Ergebnis der Passwort-Manager-Auto-Detection.

    Attributes:
        erkannt: Liste der erkannten Passwort-Manager-Namen.
        status: ``"aktiv"`` wenn mindestens einer erkannt, sonst
                  ``"inaktiv"`` oder ``"unbekannt"`` bei Detection-Fehler.
        detail: Formatierte Faktenbeschreibung für das Label.
    """

    erkannt: list[str]
    status: str
    detail: str


# ---------------------------------------------------------------------------
# Windows Hello
# ---------------------------------------------------------------------------


def check_windows_hello() -> WindowsHelloStatus:
    """Prüft ob Windows Hello für den aktuellen User aktiv ist.

    Strategie:
      1. Registry-Check: ``HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\``
         ``Authentication\\LogonUI\\UserSwitch`` — Wert ``Enabled``.
      2. Fallback: PowerShell ``Get-CimInstance Win32_BiometricDevice`` für
         installierte Biometric-Devices.

    Returns:
        WindowsHelloStatus mit status ∈ {aktiv, inaktiv, unbekannt}.
    """
    if sys.platform != "win32":
        return WindowsHelloStatus(
            status=STATUS_UNBEKANNT,
            detail="Auto-Erkennung nur unter Windows möglich.",
        )

    try:
        import winreg  # type: ignore[import-not-found] # noqa: PLC0415
    except ImportError:
        return WindowsHelloStatus(
            status=STATUS_UNBEKANNT,
            detail="Auto-Erkennung nicht möglich (winreg nicht verfügbar).",
        )

    registry_aktiv = _pruefe_hello_registry(winreg)
    if registry_aktiv is True:
        return WindowsHelloStatus(
            status=STATUS_AKTIV,
            detail="Windows-Login-MFA aktiv (via Windows Hello).",
        )

    biometric_aktiv = _pruefe_biometric_devices()
    if biometric_aktiv is True:
        return WindowsHelloStatus(
            status=STATUS_AKTIV,
            detail="Windows-Login-MFA aktiv (Biometric Device erkannt).",
        )

    if registry_aktiv is False and biometric_aktiv is False:
        return WindowsHelloStatus(
            status=STATUS_INAKTIV,
            detail="Windows-Login ohne zweiten Faktor.",
        )

    return WindowsHelloStatus(
        status=STATUS_UNBEKANNT,
        detail="Auto-Erkennung nicht möglich — bitte manuell prüfen.",
    )


def _pruefe_hello_registry(winreg) -> bool | None:  # noqa: ANN001
    """Liest den Hello-Passport-Status aus der Registry.

    Returns:
        True / False wenn eindeutig lesbar, None bei Fehler.
    """
    pfade = (
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Policies\PassportForWork",
            "Enabled",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
            "Enabled",
        ),
    )
    gelesen = False
    for hive, pfad, wert_name in pfade:
        try:
            with winreg.OpenKey(hive, pfad) as key:
                value, _ = winreg.QueryValueEx(key, wert_name)
                gelesen = True
                if int(value) == 1:
                    return True
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.debug(
                "Windows-Hello-Registry-Zugriff fehlgeschlagen (%s): %s",
                pfad,
                type(exc).__name__,
            )
            continue
    return False if gelesen else None


def _pruefe_biometric_devices() -> bool | None:
    """Prüft ob Biometric-Devices registriert sind.

    Returns:
        True / False wenn PowerShell erfolgreich, None bei Fehler.
    """
    try:
        ergebnis = _run_powershell(
            "Get-CimInstance -ClassName Win32_PnPEntity -Filter "
            "\"PNPClass = 'Biometric'\" | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.debug("Biometric-Device-Check fehlgeschlagen: %s", type(exc).__name__)
        return None
    try:
        return int(ergebnis.strip() or "0") > 0
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Passwort-Manager
# ---------------------------------------------------------------------------


def check_installed_password_managers() -> PasswortManagerStatus:
    """Detektiert installierte Passwort-Manager aus der Whitelist.

    Sucht in zwei Quellen:
      1. ``Get-AppxPackage`` (Microsoft-Store-Apps, nur Windows).
      2. Windows-Registry ``Uninstall``-Liste (klassische Installer).

    Die Whitelist ``BEKANNTE_PASSWORT_MANAGER`` enthält nur die definierten
    Namen — unbekannte Installer werden nicht als Passwort-Manager gewertet.

    Returns:
        PasswortManagerStatus mit erkannten Namen und Gesamtstatus.
    """
    if sys.platform != "win32":
        return PasswortManagerStatus(
            erkannt=[],
            status=STATUS_UNBEKANNT,
            detail="Auto-Erkennung nur unter Windows möglich.",
        )

    versucht = False
    erkannt: set[str] = set()

    appx_ergebnis = _erkenne_ueber_appx()
    if appx_ergebnis is not None:
        versucht = True
        erkannt.update(appx_ergebnis)

    registry_ergebnis = _erkenne_ueber_registry()
    if registry_ergebnis is not None:
        versucht = True
        erkannt.update(registry_ergebnis)

    if not versucht:
        return PasswortManagerStatus(
            erkannt=[],
            status=STATUS_UNBEKANNT,
            detail="Auto-Erkennung nicht möglich — bitte manuell prüfen.",
        )

    liste = sorted(erkannt)
    if liste:
        return PasswortManagerStatus(
            erkannt=liste,
            status=STATUS_AKTIV,
            detail="Passwort-Manager installiert: " + ", ".join(liste) + ".",
        )
    return PasswortManagerStatus(
        erkannt=[],
        status=STATUS_INAKTIV,
        detail="Kein Passwort-Manager aus der bekannten Liste erkannt.",
    )


def _erkenne_ueber_appx() -> list[str] | None:
    """Erkennt Passwort-Manager über ``Get-AppxPackage``.

    Returns:
        Liste erkannter Namen, oder None bei Detection-Fehler.
    """
    try:
        ausgabe = _run_powershell(
            "Get-AppxPackage | Select-Object -ExpandProperty Name"
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.debug("Get-AppxPackage fehlgeschlagen: %s", type(exc).__name__)
        return None
    return _matche_whitelist(ausgabe.splitlines())


def _erkenne_ueber_registry() -> list[str] | None:
    """Erkennt Passwort-Manager aus der Uninstall-Registry.

    Returns:
        Liste erkannter Namen, oder None bei Detection-Fehler.
    """
    try:
        import winreg  # type: ignore[import-not-found] # noqa: PLC0415
    except ImportError:
        return None

    display_names: list[str] = []
    for hive, pfad in _UNINSTALL_REGISTRY_PATHS:
        try:
            with winreg.OpenKey(hive, pfad) as key:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(key, subkey_name) as sub:
                            name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            if isinstance(name, str):
                                display_names.append(name)
                    except (FileNotFoundError, OSError):
                        continue
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.debug(
                "Uninstall-Registry-Zugriff fehlgeschlagen (%s): %s",
                pfad,
                type(exc).__name__,
            )
            continue
    return _matche_whitelist(display_names)


def _matche_whitelist(eintraege: list[str]) -> list[str]:
    """Gibt Whitelist-Treffer aus der Eintragsliste zurück (eindeutig, sortiert)."""
    gefunden: set[str] = set()
    for eintrag in eintraege:
        text_low = (eintrag or "").lower()
        for manager in BEKANNTE_PASSWORT_MANAGER:
            if manager.lower() in text_low:
                gefunden.add(manager)
    return sorted(gefunden)


def _run_powershell(command: str) -> str:
    """Ruft PowerShell mit einem fixen Kommando auf.

    Args:
        command: PowerShell-Kommando (wird via ``-Command`` übergeben).

    Returns:
        Stdout als String.

    Raises:
        subprocess.TimeoutExpired: Bei Überschreiten des Timeouts.
        FileNotFoundError: Wenn powershell.exe nicht auffindbar ist.
        subprocess.CalledProcessError: Bei nicht-Null Exit-Code.
    """
    result = subprocess.run(  # noqa: S603
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=_POWERSHELL_TIMEOUT_SEC,
        check=True,
    )
    return result.stdout
