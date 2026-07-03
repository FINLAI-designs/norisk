"""
license_compliance_checker — Windows-Aktivierungsstatus.

Iter 2f: Prueft den Windows-Lizenz-Status fuer
das Compliance-Banner im System-Scanner. Patrick-Direktive 2026-05-16:
beides — erst ``slmgr.vbs /xpr``, bei Fehler PowerShell-WMI als Fallback.

Auf Non-Windows-Systemen wird der Check stillschweigend uebersprungen
(Status ``NOT_APPLICABLE``).

Schichtzugehoerigkeit: data/ — darf Subprocess-Aufrufe nutzen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import platform
import re
import subprocess  # noqa: S404 # nosec B404 — Probes mit Whitelisted-Argumenten
from dataclasses import dataclass
from enum import Enum

from core.console_encoding import console_encoding
from core.logger import get_logger

log = get_logger(__name__)

_PROBE_TIMEOUT_S: float = 8.0


class LicenseStatus(Enum):
    """Windows-Lizenz-Status nach WMI ``LicenseStatus``-Konvention.

    Werte stammen aus der Microsoft-Doku zu:class:`SoftwareLicensingProduct`.
    Wir mappen ``slmgr``-Output ebenfalls auf diese Werte, damit beide
    Pfade ein einheitliches Ergebnis liefern.
    """

    UNLICENSED = 0  # Keine Lizenz vorhanden — kritisch.
    LICENSED = 1  # Permanent aktiviert — ok.
    OOB_GRACE = 2  # Out-of-Box-Grace — funktionierend, Zeitfenster.
    OOT_GRACE = 3  # Out-of-Tolerance-Grace — Lizenz abgelaufen, Schonfrist.
    NON_GENUINE_GRACE = 4  # NonGenuine-Grace — Hardware-Wechsel/Tampering.
    NOTIFICATION = 5  # Notification-Mode — Aktivierungs-Aufforderung.
    EXTENDED_GRACE = 6  # Extended-Grace — verlaengerte Schonfrist.

    # Spezielle "no measurement"-Stufen:
    NOT_APPLICABLE = -1  # Non-Windows-Plattform.
    UNKNOWN = -2  # Probe schlug fehl (slmgr/WMI nicht aufrufbar).


@dataclass(frozen=True)
class WindowsLicenseInfo:
    """Resultat des Compliance-Checks.

    Attributes:
        status: Gemappte:class:`LicenseStatus`.
        message: User-lesbare Zusammenfassung (z. B.
                   ``"Computer ist permanent aktiviert"``).
        source: Probe-Pfad (``"slmgr"`` / ``"wmi"`` / ``"none"``).
        raw_output: Roh-Ausgabe der Probe (fuer Log/Debug).
    """

    status: LicenseStatus
    message: str
    source: str
    raw_output: str = ""

    @property
    def is_compliant(self) -> bool:
        """``True`` wenn Status ``LICENSED`` (permanent aktiviert)."""
        return self.status is LicenseStatus.LICENSED

    @property
    def needs_attention(self) -> bool:
        """``True`` nur bei einem BEWERTBAREN Status, der Handlung erfordert.

        ``UNKNOWN`` (Probe nicht aufrufbar / Zeitueberschreitung — z. B.
        WMI langsam) ist KEIN Lizenz-Verstoss, sondern "nicht messbar". Frueher
        floss UNKNOWN hier mit ``True`` ein und erschien im Compliance-Banner als
        roter Alarm ("WMI-Probe nicht aufrufbar: TimeoutExpired"). Wie bei den
        Hardening-Checks (``measurable=False``) wird ein Mess-Fehlschlag neutral
        gezeigt, nicht als Befund. ``NOT_APPLICABLE`` (Non-Windows) ebenso.
        """
        return self.status not in (
            LicenseStatus.LICENSED,
            LicenseStatus.NOT_APPLICABLE,
            LicenseStatus.UNKNOWN,
        )


# ---------------------------------------------------------------------------
# slmgr-Parser
# ---------------------------------------------------------------------------


def _parse_slmgr_xpr(stdout: str) -> tuple[LicenseStatus, str]:
    """Mappt ``slmgr.vbs /xpr``-Output auf einen Lizenz-Status.

    ``slmgr.vbs /xpr`` liefert deutsche oder englische Texte je nach
    System-Locale. Wir machen ein robustes Mehrsprachen-Match.

    Bekannte Strings:
    - DE: "Der Computer ist permanent aktiviert."
    - EN: "The machine is permanently activated."
    - DE: "Windows befindet sich im Test-Modus." / "im Benachrichtigungsmodus"
    - EN: "Windows is in notification mode" / "test mode"
    - DE: "Fehler:" / EN: "Error:"
    """
    text = stdout.strip()
    lower = text.lower()

    # Permanent aktiviert
    if re.search(r"permanent\s+aktiviert", lower) or re.search(
        r"permanently\s+activated", lower
    ):
        return (LicenseStatus.LICENSED, "Computer ist permanent aktiviert.")

    # Befristete Aktivierung (Lizenz laeuft am... ab)
    if re.search(
        r"laeuft\s+am\s+\d|expires?\s+on|expiration\s+date", lower
    ):
        return (
            LicenseStatus.OOB_GRACE,
            "Computer hat befristete Aktivierung — Ablauf-Datum pruefen.",
        )

    # Test-Modus / Benachrichtigungs-Modus
    if "test-modus" in lower or "test mode" in lower:
        return (
            LicenseStatus.OOT_GRACE,
            "Windows ist im Test-Modus — Aktivierung erforderlich.",
        )
    if "benachrichtigung" in lower or "notification" in lower:
        return (
            LicenseStatus.NOTIFICATION,
            "Windows ist im Benachrichtigungs-Modus — Aktivierung faellig.",
        )

    # Nicht aktiviert
    if "nicht aktiviert" in lower or "not activated" in lower:
        return (LicenseStatus.UNLICENSED, "Windows ist nicht aktiviert.")

    # Fehler-Kanal
    if lower.startswith("error") or lower.startswith("fehler"):
        return (LicenseStatus.UNKNOWN, f"slmgr-Fehler: {text}")

    # Unbekannter Output — Output behalten fuer Diagnose
    return (LicenseStatus.UNKNOWN, f"slmgr-Ausgabe konnte nicht geparsed werden: {text}")


# ---------------------------------------------------------------------------
# WMI-Fallback
# ---------------------------------------------------------------------------


_WMI_MESSAGES: dict[int, str] = {
    0: "Lizenz nicht installiert — Windows ist nicht aktiviert.",
    1: "Computer ist permanent aktiviert.",
    2: "OOB-Grace-Period: initiale Aktivierungsfrist laeuft.",
    3: "OOT-Grace-Period: Aktivierungsfrist abgelaufen, Schonzeit aktiv.",
    4: "NonGenuine-Grace: Lizenz als nicht-genuine markiert.",
    5: "Notification-Mode: Aktivierungsaufforderung wird angezeigt.",
    6: "Extended-Grace: verlaengerte Schonfrist.",
}


def _parse_wmi_license_status(stdout: str) -> tuple[LicenseStatus, str]:
    """Parst die PowerShell-Ausgabe vom WMI-Query.

    Erwartet eine Zeile mit der ``LicenseStatus``-Zahl (0-6).
    """
    match = re.search(r"\b([0-6])\b", stdout)
    if match is None:
        return (
            LicenseStatus.UNKNOWN,
            f"WMI-Ausgabe lieferte keinen Status-Code: {stdout.strip()}",
        )
    code = int(match.group(1))
    try:
        status = LicenseStatus(code)
    except ValueError:
        return (
            LicenseStatus.UNKNOWN,
            f"Unbekannter WMI-LicenseStatus-Code: {code}",
        )
    message = _WMI_MESSAGES.get(code, f"LicenseStatus={code}")
    return (status, message)


# ---------------------------------------------------------------------------
# Probe-Funktionen
# ---------------------------------------------------------------------------


def _probe_slmgr() -> tuple[LicenseStatus, str, str]:
    """Aufruf ``cscript //Nologo slmgr.vbs /xpr``.

    Returns:
        ``(status, message, raw_output)``. Bei Fehler:
        ``(UNKNOWN, "<reason>", raw)``.
    """
    try:
        result = subprocess.run(  # noqa: S603, S607 # nosec B603 B607
            ["cscript", "//Nologo", "C:\\Windows\\System32\\slmgr.vbs", "/xpr"],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        return (
            LicenseStatus.UNKNOWN,
            f"slmgr-Probe nicht aufrufbar: {type(exc).__name__}",
            "",
        )
    raw = (result.stdout or "") + (result.stderr or "")
    status, message = _parse_slmgr_xpr(raw)
    return (status, message, raw)


def _probe_wmi() -> tuple[LicenseStatus, str, str]:
    """Aufruf PowerShell + Get-CimInstance.

    Returns:
        Wie:func:`_probe_slmgr`.
    """
    ps_command = (
        "$p = Get-CimInstance -ClassName SoftwareLicensingProduct "
        "-Filter \"Name like 'Windows%' AND PartialProductKey IS NOT NULL\" "
        "| Select-Object -First 1; "
        "if ($p) { $p.LicenseStatus } else { 'no-product' }"
    )
    try:
        result = subprocess.run(  # noqa: S603, S607 # nosec B603 B607
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                ps_command,
            ],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        return (
            LicenseStatus.UNKNOWN,
            f"WMI-Probe nicht aufrufbar: {type(exc).__name__}",
            "",
        )
    raw = (result.stdout or "") + (result.stderr or "")
    if "no-product" in raw.lower():
        return (
            LicenseStatus.UNLICENSED,
            "Kein Windows-Produkt mit Lizenz-Schluessel registriert.",
            raw,
        )
    status, message = _parse_wmi_license_status(raw)
    return (status, message, raw)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_windows_license() -> WindowsLicenseInfo:
    """Prueft den Windows-Aktivierungs-Status.

    Pipeline:
        1. Falls Non-Windows: ``NOT_APPLICABLE``.
        2. ``slmgr.vbs /xpr`` aufrufen, Ausgabe parsen.
        3. Bei slmgr-Status ``UNKNOWN``: WMI-Fallback via PowerShell.
        4. Wenn auch WMI ``UNKNOWN`` liefert: zurueck mit dem
           informativeren der beiden Messages.

    Returns:
:class:`WindowsLicenseInfo` mit Status, Message und Source.
    """
    if platform.system() != "Windows":
        return WindowsLicenseInfo(
            status=LicenseStatus.NOT_APPLICABLE,
            message="Lizenz-Compliance-Check nur unter Windows verfuegbar.",
            source="none",
        )

    slmgr_status, slmgr_message, slmgr_raw = _probe_slmgr()
    if slmgr_status is not LicenseStatus.UNKNOWN:
        log.info("license_check source=slmgr status=%s", slmgr_status.name)
        return WindowsLicenseInfo(
            status=slmgr_status,
            message=slmgr_message,
            source="slmgr",
            raw_output=slmgr_raw,
        )

    log.info("license_check slmgr lieferte UNKNOWN — Fallback auf WMI.")
    wmi_status, wmi_message, wmi_raw = _probe_wmi()
    if wmi_status is not LicenseStatus.UNKNOWN:
        log.info("license_check source=wmi status=%s", wmi_status.name)
        return WindowsLicenseInfo(
            status=wmi_status,
            message=wmi_message,
            source="wmi",
            raw_output=wmi_raw,
        )

    # Beide Proben UNKNOWN (z. B. WMI langsam -> Timeout).: das ist KEIN
    # Lizenz-Problem, sondern "nicht messbar" — eine ruhige, nutzerlesbare
    # Meldung statt des technischen "WMI-Probe nicht aufrufbar: TimeoutExpired".
    # Die konkreten Probe-Gruende bleiben in raw_output (Log/Diagnose) + Log unten.
    log.info(
        "license_check beide Proben UNKNOWN (slmgr+wmi) — nicht messbar: %s | %s",
        slmgr_message,
        wmi_message,
    )
    return WindowsLicenseInfo(
        status=LicenseStatus.UNKNOWN,
        message=(
            "Lizenz-Status nicht ermittelbar (Probe nicht verfügbar oder "
            "Zeitüberschreitung) — kein Hinweis auf ein Lizenzproblem."
        ),
        source="none",
        raw_output=slmgr_raw + "\n---\n" + wmi_raw,
    )
