"""core.os_info — Host-OS-Eckdaten (Edition/Version/Build) für tool-übergreifende Anzeige.

Ein selbstständiger, fail-soft Detektor für die Klartext-OS-Angaben, die mehrere
Tools brauchen (Patch-Monitor-Kopfzeile, Audit-Prefill, Cockpit). Bewusst in
``core/`` und **stdlib-only** (``platform`` + ``winreg``) gehalten — so braucht
ein Konsument (z. B. ``patch_monitor``) KEINEN Tool→Tool-Import (
``core/hardware_fingerprint.py``, das Registry/PowerShell ebenfalls direkt in
``core`` liest).

Abgrenzung:
* ``tools.system_scanner`` ``detect_os_info`` liefert eine reichere ``OSInfo``
  (mit ``ComponentStatus``) für den vollen System-Scan — das bleibt dort.
* ``tools.system_tuner`` ``EditionGate`` leitet aus der Edition die Telemetrie-
  Ehrlichkeit ab — anderes Konzept, bleibt dort.
* Dieses Modul liefert nur die **Anzeige-Strings** (kein Status, keine Policy).

Schichtzugehörigkeit: core/ — fail-soft, keine Exceptions nach außen.

Author: Patrick Riederich
Version: 1.0 Phase E, 2026-06-29)
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass

from core.logger import get_logger

log = get_logger(__name__)

#: Registry-Schlüssel mit den Windows-Versions-Eckdaten (read-only).
_CV_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

#: Ab diesem CurrentBuild ist es Windows 11 — die Registry-``ProductName``
#: meldet aber weiterhin "Windows 10" (Microsoft hat den Wert nie aktualisiert).
#: Gleicher Schwellwert wie ``tools.system_tuner.application.edition_gate`` (bewusst
#: dupliziert: anderer Konsument, anderer Rückgabetyp).
_WIN11_MIN_BUILD = 22000


@dataclass(frozen=True, slots=True)
class HostOsInfo:
    """Klartext-OS-Eckdaten für die Anzeige (alle Felder fail-soft, ggf. leer).

    Attributes:
        system: ``platform.system`` — z. B. ``"Windows"``, ``"Linux"``,
            ``"Darwin"``. Nie leer.
        product: Anzeigename inkl. Edition, z. B. ``"Windows 11 Pro"``. Auf
            Windows aus der Registry (mit Win10→Win11-Korrektur), sonst ein
            ``platform``-Fallback.
        display_version: Marketing-Version, z. B. ``"23H2"`` (Windows
            ``DisplayVersion``/``ReleaseId``). Leer wenn unbekannt.
        build: Build-Nummer, z. B. ``"22631"`` (Windows ``CurrentBuild``). Leer
            wenn unbekannt.
        architecture: Prozessor-Architektur, z. B. ``"AMD64"``.
    """

    system: str
    product: str = ""
    display_version: str = ""
    build: str = ""
    architecture: str = ""

    @property
    def anzeige(self) -> str:
        """Einzeiliger Anzeige-String aus den nicht-leeren Feldern.

        Beispiel: ``"Windows 11 Pro · 23H2 · Build 22631 · AMD64"``.

        Returns:
            Mit ``" · "`` verbundene, nicht-leere Teile; mindestens ``system``.
        """
        teile = [self.product or self.system]
        if self.display_version:
            teile.append(self.display_version)
        if self.build:
            teile.append(f"Build {self.build}")
        if self.architecture:
            teile.append(self.architecture)
        return " · ".join(teile)


def _normalize_product(product: str | None, current_build: str | None) -> str:
    """Korrigiert "Windows 10" → "Windows 11", wenn der Build es verrät.

    ``ProductName`` bleibt auf Windows-11-Systemen bei "Windows 10 …" stehen;
    nur ``CurrentBuild >= 22000`` unterscheidet die Generationen zuverlässig.
    Ist der Build unbekannt/nicht parsebar, bleibt ``product`` unverändert
    (fail-soft — keine falsche Korrektur).

    Args:
        product: Roher ``ProductName`` aus der Registry oder ``None``.
        current_build: Roher ``CurrentBuild`` aus der Registry oder ``None``.

    Returns:
        Korrigierter Produktname (leerer String, wenn ``product`` leer war).
    """
    if not product or "windows 10" not in product.lower():
        return product or ""
    try:
        build = int((current_build or "").strip())
    except (ValueError, TypeError):
        return product
    if build >= _WIN11_MIN_BUILD:
        return re.sub(r"(?i)windows 10", "Windows 11", product)
    return product


def _read_windows_registry() -> dict[str, str]:
    """Liest die OS-Eckdaten aus ``HKLM\\…\\CurrentVersion`` (read-only, fail-soft).

    Returns:
        Dict mit den Roh-Strings (``product``/``display_version``/``build``);
        leeres Dict bei jedem Fehler (kein Windows, kein Zugriff, fehlende Keys).
    """
    try:
        import winreg  # noqa: PLC0415 — nur auf Windows verfügbar
    except ImportError:
        return {}

    werte: dict[str, str] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CV_KEY) as key:

            def _get(name: str) -> str:
                try:
                    wert, _ = winreg.QueryValueEx(key, name)
                    return str(wert).strip()
                except OSError:
                    return ""

            product = _get("ProductName")
            build = _get("CurrentBuild")
            werte["product"] = _normalize_product(product, build)
            werte["build"] = build
            # DisplayVersion ist der moderne Marketing-String (z. B. "23H2");
            # ReleaseId ist der ältere Fallback (z. B. "2009").
            werte["display_version"] = _get("DisplayVersion") or _get("ReleaseId")
    except OSError as exc:
        log.debug("Windows-OS-Registry nicht lesbar: %s", type(exc).__name__)
        return {}
    return werte


def detect_host_os_info() -> HostOsInfo:
    """Erhebt die Host-OS-Eckdaten fail-soft (nie Exception nach außen).

    Auf Windows werden Produkt/Edition, Version und Build aus der Registry
    gelesen (mit Win10→Win11-Korrektur); auf anderen Plattformen bzw. bei jedem
    Fehler bleibt es bei den ``platform``-Eckdaten. ``architecture`` und
    ``system`` kommen immer aus ``platform``.

    Returns:
        Ein:class:`HostOsInfo` (Felder ggf. leer, aber nie ``None``).
    """
    system = platform.system() or "Unbekannt"
    architecture = platform.machine()

    if system == "Windows":
        reg = _read_windows_registry()
        product = reg.get("product") or f"Windows {platform.release()}".strip()
        return HostOsInfo(
            system=system,
            product=product,
            display_version=reg.get("display_version", ""),
            build=reg.get("build", "") or platform.version(),
            architecture=architecture,
        )

    # Nicht-Windows: schlanker platform-Fallback (Patch-Monitor ist Windows-
    # zentriert; die Kopfzeile soll dort trotzdem nicht crashen).
    release = platform.release()
    product = f"{system} {release}".strip() if release else system
    return HostOsInfo(
        system=system,
        product=product,
        build=platform.version(),
        architecture=architecture,
    )
