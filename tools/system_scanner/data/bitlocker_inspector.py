"""
bitlocker_inspector — Windows-BitLocker-Status-Probe.

Iter 3f, 2026-05-16, NoRisk-Audit-Paket-3 §6.3): Prueft pro
gemountetem Volume:

- ist BitLocker aktiviert?
- welche Schutz-Mechanismen (Protectors) sind hinterlegt?
  (TpmProtector / NumericalPassword / RecoveryPassword / Tpm+Pin / etc.)
- wo liegt der Recovery-Key? (TPM-only / Active-Directory / Microsoft-
  Account / Numerical-Password-allein / unbekannt)

Ergebnis ist eine Liste:class:`BitLockerVolumeProbe` — die Compliance-
Bewertung passiert in der Application-Schicht
(``bitlocker_compliance.py``).

Patrick-Direktive 2026-05-16 (analog Win-Lic-Check): beides —
PowerShell ``Get-BitLockerVolume`` als bevorzugter Pfad, ``manage-bde``-
Fallback wenn Modul nicht greift. Auf Non-Windows wird stillschweigend
``NOT_APPLICABLE`` geliefert.

Schichtzugehoerigkeit: data/ — darf Subprocess-Aufrufe nutzen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import json
import platform
import re
import subprocess  # noqa: S404 # nosec B404 — Probes mit Whitelisted-Argumenten
from dataclasses import dataclass, field
from enum import Enum

from core.console_encoding import console_encoding
from core.logger import get_logger

log = get_logger(__name__)

_PROBE_TIMEOUT_S: float = 10.0


class BitLockerOverallStatus(Enum):
    """Status der gesamten BitLocker-Probe (alle Volumes zusammen)."""

    NOT_APPLICABLE = "not_applicable"  # Non-Windows
    UNKNOWN = "unknown"  # Probe nicht aufrufbar
    NO_VOLUMES_PROTECTED = "no_volumes_protected"  # alle Volumes off
    PARTIALLY_PROTECTED = "partially_protected"  # einige on, andere off
    FULLY_PROTECTED = "fully_protected"  # alle Fixed-Volumes on


class BitLockerVolumeStatus(Enum):
    """Status eines einzelnen Volumes (entspricht Windows' VolumeStatus-API)."""

    FULLY_ENCRYPTED = "fully_encrypted"
    FULLY_DECRYPTED = "fully_decrypted"
    ENCRYPTION_IN_PROGRESS = "encryption_in_progress"
    DECRYPTION_IN_PROGRESS = "decryption_in_progress"
    UNKNOWN = "unknown"

    @classmethod
    def from_label(cls, label: str) -> BitLockerVolumeStatus:
        """Robuste Konvertierung — Windows-API-Strings sind localisiert."""
        cleaned = label.strip().lower().replace("-", "").replace(" ", "")
        mapping = {
            "fullyencrypted": cls.FULLY_ENCRYPTED,
            "fullydecrypted": cls.FULLY_DECRYPTED,
            "encryptioninprogress": cls.ENCRYPTION_IN_PROGRESS,
            "decryptioninprogress": cls.DECRYPTION_IN_PROGRESS,
        }
        return mapping.get(cleaned, cls.UNKNOWN)


class RecoveryKeyLocation(Enum):
    """Wo liegt der BitLocker-Recovery-Key fuer dieses Volume?

    Beste-Praxis: ``ACTIVE_DIRECTORY`` oder ``MICROSOFT_ACCOUNT`` (in
    Konsumenten-Geraeten). ``LOCAL_NUMERICAL_ONLY`` heisst: der User hat
    nur einen Print/Datei und keine Cloud-Verwahrung — bei Geraete-
    Diebstahl + Festplatten-Defekt kommt er nicht mehr an die Daten.
    """

    TPM_ONLY = "tpm_only"  # nur TPM, kein expliziter Recovery-Schluessel
    ACTIVE_DIRECTORY = "active_directory"  # AD-Backup vorhanden
    MICROSOFT_ACCOUNT = "microsoft_account"  # Azure-AD / MS-Account
    LOCAL_NUMERICAL_ONLY = "local_numerical_only"  # nur lokale Numerical-Pass
    NONE = "none"  # kein Recovery-Key konfiguriert
    UNKNOWN = "unknown"


# Mapping von Protector-Typ-Strings auf eine kanonische Set.
# Quelle: Microsoft.BitLockerProtectorType-Enum.
_PROTECTOR_NORMALIZE: dict[str, str] = {
    "tpm": "tpm",
    "tpmandpin": "tpm_and_pin",
    "tpmandstartupkey": "tpm_and_startup_key",
    "tpmandpinandstartupkey": "tpm_and_pin_and_startup_key",
    "recoverypassword": "numerical_password",
    "numericalpassword": "numerical_password",
    "passphrase": "passphrase",  # noqa: S105 # nosec B105 — BitLocker-Protector-Typ, kein Geheimnis
    "externalkey": "external_key",
    "publickey": "public_key",
    "ad": "ad_account",
    "adaccountorgroup": "ad_account",
    "microsoftaccount": "microsoft_account",
}


@dataclass(frozen=True)
class BitLockerVolumeProbe:
    """Ergebnis einer Pro-Volume-Probe.

    Attributes:
        mount_point: Z. B. ``"C:"``. Kann leer sein.
        protection_on: Ist BitLocker auf diesem Volume aktiv?
        volume_status::class:`BitLockerVolumeStatus`.
        encryption_method: Klartext (z. B. ``"XtsAes256"``). Optional.
        protector_types: Normalisierte Set, z. B.
                            ``{"tpm", "numerical_password"}``.
        key_location::class:`RecoveryKeyLocation` — gemappt aus den
                            protector_types.
        raw_message: Roh-Ausgabe-Snippet fuer Log/Debug.
    """

    mount_point: str
    protection_on: bool
    volume_status: BitLockerVolumeStatus
    encryption_method: str = ""
    protector_types: frozenset[str] = field(default_factory=frozenset)
    key_location: RecoveryKeyLocation = RecoveryKeyLocation.UNKNOWN
    raw_message: str = ""


@dataclass(frozen=True)
class BitLockerReport:
    """Aggregierter Probe-Befund ueber alle gemounteten Fixed-Volumes.

    Attributes:
        status::class:`BitLockerOverallStatus`.
        volumes: Liste pro-Volume-Probes.
        source: Welcher Probe-Pfad gegriffen hat
                     (``"powershell"`` / ``"manage-bde"`` / ``"none"``).
        message: User-lesbare Zusammenfassung fuer Banner-Text.
        raw_output: Roh-Ausgabe des Probe-Aufrufs (Log/Diagnose).
    """

    status: BitLockerOverallStatus
    volumes: list[BitLockerVolumeProbe]
    source: str
    message: str
    raw_output: str = ""

    @property
    def has_volumes(self) -> bool:
        return bool(self.volumes)


# ---------------------------------------------------------------------------
# Probe-Funktionen
# ---------------------------------------------------------------------------


def _probe_powershell() -> tuple[list[BitLockerVolumeProbe], str]:
    """Probe via PowerShell ``Get-BitLockerVolume`` (bevorzugter Pfad).

    Returns:
        ``(volumes, raw_output)``. Bei Probe-Fehler: leere Liste.
    """
    ps_command = (
        "Get-BitLockerVolume | "
        "Where-Object { $_.VolumeType -eq 'OperatingSystem' "
        "  -or $_.VolumeType -eq 'Data' } | "
        "ForEach-Object { "
        "  $protectors = @($_.KeyProtector | ForEach-Object { "
        "    $_.KeyProtectorType.ToString() "
        "  }); "
        "  [PSCustomObject]@{ "
        "    MountPoint = $_.MountPoint; "
        "    ProtectionStatus = $_.ProtectionStatus.ToString(); "
        "    VolumeStatus = $_.VolumeStatus.ToString(); "
        "    EncryptionMethod = $_.EncryptionMethod.ToString(); "
        "    Protectors = $protectors "
        "  } "
        "} | ConvertTo-Json -Depth 3"
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
        log.info("bitlocker_powershell_probe_unavailable error=%s", type(exc).__name__)
        return ([], "")

    raw = (result.stdout or "") + (result.stderr or "")
    volumes = _parse_powershell_json(result.stdout or "")
    return (volumes, raw)


def _parse_powershell_json(stdout: str) -> list[BitLockerVolumeProbe]:
    """Parst die JSON-Ausgabe von ``ConvertTo-Json`` zu Probe-Objekten."""
    cleaned = stdout.strip()
    if not cleaned:
        return []
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        log.warning("bitlocker_powershell_json_invalid bytes=%d", len(cleaned))
        return []
    # ConvertTo-Json liefert bei genau einem Volume kein Array, sondern
    # einen einzelnen Dict. Wir normalisieren.
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    volumes: list[BitLockerVolumeProbe] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        mount = str(entry.get("MountPoint", "") or "").strip()
        protection_str = str(entry.get("ProtectionStatus", "")).lower()
        protection_on = protection_str == "on"
        volume_status_label = str(entry.get("VolumeStatus", ""))
        encryption_method = str(entry.get("EncryptionMethod", "") or "").strip()
        raw_protectors = entry.get("Protectors", []) or []
        if isinstance(raw_protectors, str):  # Single-Wert wird zu String
            raw_protectors = [raw_protectors]
        protector_types = frozenset(
            _normalize_protector(p) for p in raw_protectors if p
        )
        volumes.append(
            BitLockerVolumeProbe(
                mount_point=mount,
                protection_on=protection_on,
                volume_status=BitLockerVolumeStatus.from_label(volume_status_label),
                encryption_method=encryption_method,
                protector_types=protector_types,
                key_location=_classify_key_location(protector_types),
                raw_message="powershell",
            )
        )
    return volumes


def _probe_manage_bde() -> tuple[list[BitLockerVolumeProbe], str]:
    """Fallback-Probe via ``manage-bde -status``.

    manage-bde liefert plaintext, gruppiert pro Volume. Wir parsen
    line-by-line — der Pfad ist deutlich rauer als der PowerShell-JSON-
    Pfad, aber Stable-Win-CLI.
    """
    try:
        result = subprocess.run(  # noqa: S603, S607 # nosec B603 B607
            [
                "C:\\Windows\\System32\\manage-bde.exe",
                "-status",
                "-protectors",
            ],
            capture_output=True,
            encoding=console_encoding(),
            errors="replace",
            timeout=_PROBE_TIMEOUT_S,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        log.info(
            "bitlocker_manage_bde_unavailable error=%s",
            type(exc).__name__,
        )
        return ([], "")

    raw = (result.stdout or "") + (result.stderr or "")
    return (_parse_manage_bde(raw), raw)


_VOLUME_HEADER_RE = re.compile(
    r"Volume\s+([A-Za-z]:)", re.IGNORECASE
)
_PROTECTION_RE = re.compile(
    r"Protection Status:\s*(.+)", re.IGNORECASE
)
_VOLUME_STATUS_RE = re.compile(
    r"Conversion Status:\s*(.+)", re.IGNORECASE
)
_ENC_METHOD_RE = re.compile(
    r"Encryption Method:\s*(.+)", re.IGNORECASE
)
# Recovery-Key-Indikatoren — manage-bde rendert nur en-locale-zuverlaessig.
_PROTECTOR_LINE_RE = re.compile(
    r"^\s+(TPM|TPM And PIN|Numerical Password|Recovery Password|"
    r"AD Account or Group|Active Directory|External Key|Microsoft Account|"
    r"Passphrase|Public Key|Startup Key)\b",
    re.IGNORECASE,
)


def _parse_manage_bde(stdout: str) -> list[BitLockerVolumeProbe]:
    """Parst die Plaintext-Ausgabe von ``manage-bde -status``."""
    if not stdout.strip():
        return []
    volumes: list[BitLockerVolumeProbe] = []
    current_mount: str = ""
    current_protection: bool = False
    current_status: BitLockerVolumeStatus = BitLockerVolumeStatus.UNKNOWN
    current_method: str = ""
    current_protectors: set[str] = set()

    def _flush() -> None:
        if current_mount:
            volumes.append(
                BitLockerVolumeProbe(
                    mount_point=current_mount,
                    protection_on=current_protection,
                    volume_status=current_status,
                    encryption_method=current_method,
                    protector_types=frozenset(current_protectors),
                    key_location=_classify_key_location(
                        frozenset(current_protectors)
                    ),
                    raw_message="manage-bde",
                )
            )

    for line in stdout.splitlines():
        m = _VOLUME_HEADER_RE.search(line)
        if m:
            # Neue Volume-Sektion → vorherige zuerst flushen.
            _flush()
            current_mount = m.group(1).upper()
            current_protection = False
            current_status = BitLockerVolumeStatus.UNKNOWN
            current_method = ""
            current_protectors = set()
            continue
        mm = _PROTECTION_RE.search(line)
        if mm:
            # manage-bde rendert "Protection On" / "Protection Off" —
            # naiver Substring-Match wuerde "Off" ebenfalls als "on"
            # erkennen (protect-i-ON in Off-Strings).
            value = mm.group(1).strip().lower()
            current_protection = (
                value == "protection on" or value == "on"
            )
            continue
        mm = _VOLUME_STATUS_RE.search(line)
        if mm:
            current_status = BitLockerVolumeStatus.from_label(mm.group(1))
            continue
        mm = _ENC_METHOD_RE.search(line)
        if mm:
            current_method = mm.group(1).strip()
            continue
        mm = _PROTECTOR_LINE_RE.match(line)
        if mm:
            current_protectors.add(_normalize_protector(mm.group(1)))

    _flush()
    return volumes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_protector(raw: str) -> str:
    """Normalisiert einen Protector-Typ-String auf ein bekanntes Token."""
    cleaned = (
        (raw or "").strip().lower().replace("-", "").replace(" ", "").replace("_", "")
    )
    return _PROTECTOR_NORMALIZE.get(cleaned, cleaned or "unknown")


def _classify_key_location(
    protector_types: frozenset[str],
) -> RecoveryKeyLocation:
    """Mappt die normalisierten Protector-Types auf eine Recovery-Lage.

    Reihenfolge entspricht "best-praxis-first":
        AD > MS-Account > Numerical-Password > TPM-only > NONE.
    """
    if not protector_types:
        return RecoveryKeyLocation.NONE
    if "ad_account" in protector_types:
        return RecoveryKeyLocation.ACTIVE_DIRECTORY
    if "microsoft_account" in protector_types:
        return RecoveryKeyLocation.MICROSOFT_ACCOUNT
    if "numerical_password" in protector_types:
        return RecoveryKeyLocation.LOCAL_NUMERICAL_ONLY
    if "tpm" in protector_types or "tpm_and_pin" in protector_types:
        return RecoveryKeyLocation.TPM_ONLY
    return RecoveryKeyLocation.UNKNOWN


def _compute_overall_status(
    volumes: list[BitLockerVolumeProbe],
) -> tuple[BitLockerOverallStatus, str]:
    """Aggregat-Status + lesbarer Banner-Text."""
    if not volumes:
        return (
            BitLockerOverallStatus.UNKNOWN,
            "Keine Volumes ermittelt — manuell verifizieren.",
        )
    protected = sum(1 for v in volumes if v.protection_on)
    total = len(volumes)
    if protected == 0:
        return (
            BitLockerOverallStatus.NO_VOLUMES_PROTECTED,
            f"{total} Volumes ohne BitLocker-Schutz.",
        )
    if protected < total:
        return (
            BitLockerOverallStatus.PARTIALLY_PROTECTED,
            f"{protected}/{total} Volumes geschuetzt — Rest manuell pruefen.",
        )
    return (
        BitLockerOverallStatus.FULLY_PROTECTED,
        f"Alle {total} Volumes BitLocker-geschuetzt.",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_bitlocker_status() -> BitLockerReport:
    """Prueft den BitLocker-Status aller Fixed-Volumes.

    Pipeline:
        1. Auf Non-Windows → ``NOT_APPLICABLE``.
        2. PowerShell-Pfad ``Get-BitLockerVolume`` aufrufen.
        3. Wenn der keine Volumes liefert → manage-bde-Fallback.
        4. Wenn beide leer → ``UNKNOWN``.
        5. Sonst aus den Volumes den Overall-Status ableiten.

    Returns:
:class:`BitLockerReport`.
    """
    if platform.system() != "Windows":
        return BitLockerReport(
            status=BitLockerOverallStatus.NOT_APPLICABLE,
            volumes=[],
            source="none",
            message="BitLocker-Check nur unter Windows verfuegbar.",
        )

    volumes, raw_ps = _probe_powershell()
    if volumes:
        status, message = _compute_overall_status(volumes)
        log.info(
            "bitlocker_check source=powershell volumes=%d status=%s",
            len(volumes),
            status.name,
        )
        return BitLockerReport(
            status=status,
            volumes=volumes,
            source="powershell",
            message=message,
            raw_output=raw_ps,
        )

    log.info("bitlocker_check powershell-Pfad leer — Fallback auf manage-bde.")
    volumes_bde, raw_bde = _probe_manage_bde()
    if volumes_bde:
        status, message = _compute_overall_status(volumes_bde)
        log.info(
            "bitlocker_check source=manage-bde volumes=%d status=%s",
            len(volumes_bde),
            status.name,
        )
        return BitLockerReport(
            status=status,
            volumes=volumes_bde,
            source="manage-bde",
            message=message,
            raw_output=raw_bde,
        )

    return BitLockerReport(
        status=BitLockerOverallStatus.UNKNOWN,
        volumes=[],
        source="none",
        message=(
            "BitLocker-Status konnte nicht ermittelt werden "
            "(weder PowerShell-Modul noch manage-bde aufrufbar)."
        ),
        raw_output=raw_ps + "\n---\n" + raw_bde,
    )
