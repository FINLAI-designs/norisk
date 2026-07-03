"""
hardware_fingerprint — Eindeutige Hardware-Kennung für FINLAI

Berechnet einen stabilen Hardware-Fingerprint aus **fünf** Systemmerkmalen
(seit Lizenzsystem-Umbau v1.0):

  1. Windows MachineGuid (Registry)
  2. CPU-Bezeichnung (wmic / PowerShell)
  3. Disk-Seriennummer (wmic / PowerShell)
  4. MAC-Adresse der ersten aktiven NIC (uuid.getnode) ← NEU PHASE-2.1.5
  5. Hostname (socket.gethostname) ← NEU PHASE-2.1.5

Aggregations-Formel (deterministisch, über Neustarts reproduzierbar):

  1. Jede Komponente einzeln SHA-256-hashen → 5 lowercase-Hex-Strings.
  2. Diese 5 Hashes alphabetisch nach Schluessel sortieren.
  3. Konkatenierte Werte (lowercase) ein zweites Mal SHA-256-hashen.

Verwendung / — auf den lokalen Bedarf reduziert): der Lizenz-/
Activation-Cert-Pfad ist entfallen; der Fingerprint dient nur noch der
Audit-Log-User-ID (:mod:`core.audit_log`, R-9) und der Legacy-DEK-Ableitung.

Public API:

*:func:`get_hardware_fingerprint` — Aggregat-Hex-String (64 Zeichen)
*:func:`get_hardware_fingerprint_components` — Dict mit 5 SHA-256-Hashes
  (Einzel-Komponenten für Diagnose-/Quorum-Zwecke)

Wichtig:
    - Kein reiner MAC-Address-Fingerprint (zu instabil bei VMs und USB-Adaptern).
      MAC ist nur **eine** der fuenf Komponenten — Quorum 4-aus-5 (Server-
      side) toleriert HW-Tausch einzelner Komponenten.
    - Jede Komponente hat einen Fallback (``unknown-…`` oder
      ``hostname-{hostname}``), sodass der Fingerprint stets berechnet
      werden kann.
    - Der Fingerprint wird NICHT im Log ausgegeben (Informationsleck-Schutz).
    - Cache-Versionierung: das alte v1-Format (einzelne Hex-Zeile) wird
      automatisch invalidiert und durch v2 (Header-Zeile + Hex) ersetzt.

Abhängigkeiten:
    Standard-Bibliothek: hashlib, socket, subprocess, uuid, winreg (Windows)

Author: Patrick Riederich
Version: 2.0 (5-Komponenten-Schema seit PHASE-2.1.5)
"""

from __future__ import annotations

import hashlib
import re
import socket
import subprocess
import sys
import uuid

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

# Cache-Datei: Speichert den Aggregat-Fingerprint nach erstmaliger Berechnung,
# damit WMI-Ausfaelle den Schluessel nicht aendern.
_FINGERPRINT_CACHE = finlai_dir() / ".hw_fingerprint"

#: Format-Version der Cache-Datei. Bumps bei jeder Aenderung der
#: Aggregations-Formel oder des Komponenten-Sets — alte Caches werden dann
#: nicht mehr akzeptiert (:func:`_load_cached_fingerprint`).
_CACHE_FORMAT_VERSION = "v2"


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------


def get_hardware_fingerprint() -> str:
    """Berechnet den Aggregat-Hardware-Fingerprint des aktuellen Geräts.

    Aggregat ueber 5 Komponenten (siehe Modul-Docstring fuer Formel).
    Genutzt fuer die Audit-Log-User-ID (R-9) und die Legacy-DEK-Ableitung; der Lizenz-/Activation-Cert-Pfad entfiel mit.

    Wird in ``~/.finlai/.hw_fingerprint`` gecacht (v2-Format), damit
    sporadische WMI-Ausfaelle den Fingerprint nicht veraendern. Caches
    aus dem alten 3-Komponenten-Schema (v1, ohne Header-Zeile) werden
    automatisch invalidiert.

    Returns:
        64-stelliger Hexadezimal-SHA-256-Hash als Hardware-ID.

    Example:
        >>> fp = get_hardware_fingerprint
        >>> assert len(fp) == 64
    """
    cached = _load_cached_fingerprint()
    if cached is not None:
        log.debug("Hardware-Fingerprint aus Cache geladen.")
        return cached

    raw_components = _collect_raw_components()
    has_fallback = any(value.startswith("unknown-") for value in raw_components.values())
    components = {key: _hash_component(value) for key, value in raw_components.items()}
    fingerprint = _aggregate_fingerprint(components)

    # Nur cachen wenn KEINE harten Fallback-Werte verwendet wurden.
    # Hostname-basierte Fallbacks (``machine-guid-{host}``) sind
    # einigermassen stabil und werden bewusst NICHT als ``unknown-``
    # markiert — sie zaehlen also nicht als Cache-Verbot.
    if not has_fallback:
        _save_cached_fingerprint(fingerprint)
        log.debug("Hardware-Fingerprint berechnet und gecacht.")
    else:
        log.warning(
            "Hardware-Fingerprint mit Fallback-Werten berechnet — "
            "wird NICHT gecacht (WMI-Aufruf fehlgeschlagen?).",
        )

    return fingerprint


def get_hardware_fingerprint_components() -> dict[str, str]:
    """Gibt die fünf SHA-256-gehashten Hardware-Komponenten zurück.

    Liefert die fuenf Einzel-Komponenten (lowercase-Hex-SHA-256) fuer
    Diagnose-/Quorum-Zwecke. (Der fruehere Server-Revalidierungs-Pfad,
    der sie als Request-Body nutzte, entfiel mit.)

    Pflicht-Schluessel (alphabetisch sortiert):
        ``cpu_name``, ``disk_serial``, ``hostname``, ``mac_address``,
        ``machine_guid``.

    Returns:
        Dict mit genau 5 Eintraegen, jeder Wert ist ein 64-Zeichen-
        Hex-SHA-256-String (lowercase).
    """
    raw = _collect_raw_components()
    return {key: _hash_component(value) for key, value in raw.items()}


# ---------------------------------------------------------------------------
# Aggregations-Formel (server-kompatibel)
# ---------------------------------------------------------------------------


def _hash_component(value: str) -> str:
    """SHA-256 ueber den Roh-Wert, lowercase Hex.

    UTF-8-Encoding erlaubt Unicode in Hostnamen u.a. — der Server
    macht beim Re-Hash dasselbe (siehe Server-cert_service-Tests).
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aggregate_fingerprint(components: dict[str, str]) -> str:
    """Server-kompatible Aggregation: sortiert + lowercase + concat + SHA-256.

    Mirror von:func:`app.services.cert_service.compute_hardware_fingerprint`
    im license-server-Repo. Aenderungen muessen synchron mit der Server-
    Implementierung erfolgen — sonst bricht der Fingerprint-Vergleich.
    """
    sorted_concat = "".join(components[key].lower() for key in sorted(components))
    return hashlib.sha256(sorted_concat.encode("ascii")).hexdigest()


def _collect_raw_components() -> dict[str, str]:
    """Sammelt die fünf Roh-Komponenten **vor** dem Hashing.

    Interne API. Public-Code geht ueber
:func:`get_hardware_fingerprint_components` (gibt die gehashten
    Werte zurueck) bzw.:func:`get_hardware_fingerprint` (gibt das
    Aggregat zurueck).
    """
    return {
        "machine_guid": _get_machine_guid(),
        "cpu_name": _get_cpu_name(),
        "disk_serial": _get_disk_serial(),
        "mac_address": _get_mac_address(),
        "hostname": _get_hostname(),
    }


# ---------------------------------------------------------------------------
# Fingerprint-Cache (Schutz gegen WMI-Ausfälle)
# ---------------------------------------------------------------------------

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_cached_fingerprint() -> str | None:
    """Lädt den gecachten Fingerprint, falls vorhanden, valide und v2.

    Cache-Format v2 (zwei Zeilen):

        v2
        <64-char-hex>

    Caches aus dem alten 3-Komponenten-Schema (v1, einzelne Hex-Zeile
    ohne Header) werden erkannt und invalidiert: Rueckgabe ``None`` →
    der Caller berechnet neu und:func:`_save_cached_fingerprint`
    schreibt das v2-Format.

    Returns:
        64-stelliger Hex-Hash bei gueltigem v2-Cache, sonst ``None``.
    """
    try:
        if not _FINGERPRINT_CACHE.exists():
            return None
        text = _FINGERPRINT_CACHE.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    lines = text.splitlines()

    # v2: Header-Zeile + Hash-Zeile
    if len(lines) >= 2 and lines[0].strip() == _CACHE_FORMAT_VERSION:
        candidate = lines[1].strip()
        if _HEX64_RE.match(candidate):
            return candidate
        log.warning("Fingerprint-Cache v2 hat ungueltigen Hash — wird ignoriert.")
        return None

    # v1 Legacy: einzelne Hex-Zeile (3-Komponenten-Schema, jetzt veraltet)
    if _HEX64_RE.match(text):
        log.info(
            "Fingerprint-Cache v1 erkannt (3-Komponenten-Schema) — "
            "wird auf v2 (5-Komponenten-Schema) migriert.",
        )
        return None  # Caller rechnet neu, save schreibt v2

    log.warning("Fingerprint-Cache hat unbekanntes Format — wird ignoriert.")
    return None


def _save_cached_fingerprint(fingerprint: str) -> None:
    """Speichert den Fingerprint im v2-Format.

    Args:
        fingerprint: 64-stelliger Hex-Hash.
    """
    try:
        _FINGERPRINT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        content = f"{_CACHE_FORMAT_VERSION}\n{fingerprint}\n"
        _FINGERPRINT_CACHE.write_text(content, encoding="utf-8")
        try:
            _FINGERPRINT_CACHE.chmod(0o600)
        except (OSError, NotImplementedError):
            pass
    except OSError as exc:
        log.warning("Fingerprint-Cache nicht schreibbar: %s", exc)


# ---------------------------------------------------------------------------
# Komponenten-Sammlung
# ---------------------------------------------------------------------------


def _get_machine_guid() -> str:
    """Liest die MachineGuid aus der Windows-Registry.

    Der Schlüssel ``HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography``
    enthält die pro Installation eindeutige MachineGuid. Sie ist stabiler
    als MAC-Adressen und ändert sich nur bei einer Neuinstallation des
    Betriebssystems.

    Returns:
        MachineGuid als Zeichenkette, oder Hostname-basierter Fallback bei Fehler.
    """
    if sys.platform != "win32":
        return _get_hostname_fallback("machine-guid")

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).strip()
        finally:
            winreg.CloseKey(key)
    except (OSError, FileNotFoundError, AttributeError):
        log.debug("MachineGuid nicht lesbar — verwende Hostname-Fallback.")
        return _get_hostname_fallback("machine-guid")


def _get_cpu_name() -> str:
    """Liest die CPU-Bezeichnung aus WMI (mit PowerShell-Fallback).

    Reihenfolge: wmic → PowerShell Get-CimInstance.
    ``wmic`` ist ab Windows 11 deprecated und kann fehlen.

    Returns:
        CPU-Bezeichnung als Zeichenkette, oder ``"unknown-cpu"`` bei Fehler.
    """
    if sys.platform != "win32":
        return "unknown-cpu-non-windows"

    name = _run_wmic("cpu", "Name")
    if name:
        return name

    name = _run_powershell("(Get-CimInstance Win32_Processor).Name")
    if name:
        return name

    log.debug("CPU-Bezeichnung nicht ermittelbar — verwende Fallback.")
    return "unknown-cpu"


def _get_disk_serial() -> str:
    """Liest die Seriennummer des primären Laufwerks (mit PowerShell-Fallback).

    Reihenfolge: wmic → PowerShell Get-CimInstance.

    Returns:
        Disk-Seriennummer als Zeichenkette, oder ``"unknown-disk"`` bei Fehler.
    """
    if sys.platform != "win32":
        return "unknown-disk-non-windows"

    serial = _run_wmic("diskdrive", "SerialNumber")
    if serial:
        return serial

    serial = _run_powershell(
        "(Get-CimInstance Win32_DiskDrive | "
        "Where-Object {$_.SerialNumber} | "
        "Select-Object -First 1).SerialNumber"
    )
    if serial:
        return serial

    log.debug("Disk-Seriennummer nicht ermittelbar — verwende Fallback.")
    return "unknown-disk"


def _get_mac_address() -> str:
    """Liest die MAC-Adresse der ersten erkannten Hardware-NIC.

    Verwendet:func:`uuid.getnode` (stdlib, plattformunabhaengig). Wenn
    keine echte MAC ermittelbar ist, liefert ``getnode`` eine Random-MAC
    mit gesetztem Multicast-Bit (LSB des ersten Octets) — diese wird
    erkannt und durch einen Hostname-Fallback ersetzt, damit der
    Fingerprint zwischen Restarts stabil bleibt.

    Returns:
        MAC-Adresse als ``"xx:xx:xx:xx:xx:xx"`` (lowercase), oder
        Hostname-basierter Fallback bei Random-MAC.
    """
    try:
        node = uuid.getnode()
    except OSError:
        return _get_hostname_fallback("mac-address")

    # Multicast-Bit (LSB des ersten Octets) gesetzt -> Random-Fallback aus uuid.
    # Quelle: https://docs.python.org/3/library/uuid.html#uuid.getnode
    if (node >> 40) & 0x01:
        log.debug("uuid.getnode() lieferte Random/Multicast-MAC — Fallback.")
        return _get_hostname_fallback("mac-address")

    return ":".join(f"{(node >> (i * 8)) & 0xFF:02x}" for i in reversed(range(6)))


def _get_hostname() -> str:
    """Liefert den System-Hostname.

    Returns:
        Hostname-String, oder ``"unknown-hostname"`` bei OSError.
    """
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-hostname"


# ---------------------------------------------------------------------------
# Interne Hilfsfunktionen
# ---------------------------------------------------------------------------


def _run_wmic(wmi_class: str, field: str) -> str | None:
    """Führt einen wmic-Aufruf durch und gibt den Wert zurück.

    Args:
        wmi_class: WMI-Klasse (z.B. "cpu", "diskdrive").
        field: Feldname (z.B. "Name", "SerialNumber").

    Returns:
        Wert als String oder None bei Fehler.
    """
    try:
        result = subprocess.run(
            ["wmic", wmi_class, "get", field, "/value"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            prefix = f"{field}="
            if line.startswith(prefix) and len(line) > len(prefix):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _run_powershell(command: str) -> str | None:
    """Führt einen PowerShell-Befehl aus und gibt die erste Ausgabezeile zurück.

    Args:
        command: PowerShell-Befehl (z.B. "(Get-CimInstance Win32_Processor).Name").

    Returns:
        Erste nicht-leere Zeile oder None bei Fehler.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                return line
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _get_hostname_fallback(prefix: str) -> str:
    """Liefert den Hostname als letzten Fallback.

    Args:
        prefix: Präfix für den Rückgabewert, damit verschiedene Fallbacks
                unterscheidbar bleiben.

    Returns:
        ``"<prefix>-<hostname>"`` oder ``"<prefix>-unknown"`` bei Fehler.
    """
    try:
        return f"{prefix}-{socket.gethostname()}"
    except OSError:
        return f"{prefix}-unknown"
