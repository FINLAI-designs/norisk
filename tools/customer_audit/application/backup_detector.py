"""
backup_detector — Optionale Detektion installierter Backup-Software.

Patrick-Direktive: "das muss optional sein. ein-/ausschaltbar
weil nicht jeder diese technologien nutzt." Der Detector wird also nur
ausgefuehrt, wenn der User im Wizard den Schalter explizit aktiviert.
Bei deaktivierter Detection liefert:class:`BackupDetector` eine leere
Liste zurueck und der Wizard zeigt einen Info-Block der die Vorteile
der Backup-Systematik erklaert.

Detektion via Windows-Registry-Uninstall-Keys (HKLM + HKCU). Mac/Linux
liefern eine leere Liste (NoRisk-Hauptplattform ist Windows).

Schichtzugehoerigkeit: application/ — darf domain/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass

from core.logger import get_logger

_log = get_logger(__name__)


#: Map ``Marker-Substring (lower) → BEKANNTE_BACKUP_TOOLS-Anzeigename``.
#: Marker werden gegen ``DisplayName`` aus den Uninstall-Registry-Keys
#: gematcht. Erweitern wenn weitere Tools relevant werden.
_DETECT_PATTERNS: dict[str, str] = {
    "veeam agent": "Veeam Agent",
    "veeam backup": "Veeam Backup & Replication",
    "acronis cyber protect": "Acronis Cyber Protect",
    "acronis true image": "Acronis Cyber Protect",
    "macrium reflect": "Macrium Reflect",
    "windowsbackup": "Windows Backup",
    "aomei backupper": "AOMEI Backupper",
    "easeus todo backup": "EaseUS Todo Backup",
    "backblaze": "Backblaze",
    "synology drive": "Synology Active Backup",
    "synology active backup": "Synology Active Backup",
    "qnap hbs": "QNAP HBS",
    "duplicati": "Duplicati",
    "restic": "Restic",
}

_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3})\b")


@dataclass(frozen=True)
class DetectedBackupTool:
    """Eine einzelne Detection-Treffer.

    Attributes:
        canonical_name: Anzeigename aus:data:`BEKANNTE_BACKUP_TOOLS`
            (z. B. ``"Veeam Agent"``).
        version: Versionsstring falls aus Display-Name oder
            DisplayVersion lesbar (``""`` wenn unbekannt).
        registry_path: Pfad in der Registry, fuer Debugging.
    """

    canonical_name: str
    version: str
    registry_path: str


class BackupDetector:
    """Optionaler Scanner fuer installierte Backup-Software.

    Nur aktiv wenn:meth:`detect` mit ``enabled=True`` aufgerufen wird.
    """

    def detect(self, *, enabled: bool) -> list[DetectedBackupTool]:
        """Listet erkannte Backup-Tools.

        Args:
            enabled: Wenn ``False``, wird gar nichts gescannt und eine
                leere Liste zurueckgegeben. So bleibt das Tool ohne
                User-Consent stumm.

        Returns:
            Liste der Treffer. Eindeutig nach ``canonical_name`` (kein
            Tool taucht mehrfach auf, auch wenn mehrere Registry-Keys
            matchen — wir nehmen den ersten Treffer mit Version).
        """
        if not enabled:
            return []
        if platform.system().lower() != "windows":
            _log.debug("BackupDetector: nicht-Windows-Host, ueberspringe Scan.")
            return []
        try:
            return self._scan_windows()
        except Exception as exc:  # noqa: BLE001 — Scanner darf nie crashen
            _log.warning("BackupDetector-Scan fehlgeschlagen: %s", exc)
            return []

    # ------------------------------------------------------------------

    def _scan_windows(self) -> list[DetectedBackupTool]:
        import winreg  # noqa: PLC0415

        roots = (
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        )
        seen: dict[str, DetectedBackupTool] = {}
        for hive, subkey in roots:
            try:
                key = winreg.OpenKey(hive, subkey)
            except FileNotFoundError:
                continue
            with key:
                for i in range(self._enum_count(key)):
                    try:
                        sub_name = winreg.EnumKey(key, i)
                    except OSError:
                        continue
                    try:
                        with winreg.OpenKey(key, sub_name) as subkey_h:
                            try:
                                display_name = winreg.QueryValueEx(
                                    subkey_h, "DisplayName"
                                )[0]
                            except FileNotFoundError:
                                continue
                            try:
                                display_version = winreg.QueryValueEx(
                                    subkey_h, "DisplayVersion"
                                )[0]
                            except FileNotFoundError:
                                display_version = ""
                    except OSError:
                        continue
                    match = self._match(display_name)
                    if match is None:
                        continue
                    if match in seen:
                        continue
                    version = display_version or self._guess_version(display_name)
                    seen[match] = DetectedBackupTool(
                        canonical_name=match,
                        version=str(version or ""),
                        registry_path=f"{subkey}\\{sub_name}",
                    )
        result = list(seen.values())
        _log.info(
            "BackupDetector: %d Tool(s) erkannt: %s",
            len(result),
            [t.canonical_name for t in result],
        )
        return result

    def _enum_count(self, key) -> int:  # type: ignore[no-untyped-def]
        """Wrapper damit ``range(QueryInfoKey[0])`` testbar bleibt."""
        import winreg  # noqa: PLC0415

        return winreg.QueryInfoKey(key)[0]

    def _match(self, display_name: str) -> str | None:
        name_lower = display_name.lower()
        for marker, canonical in _DETECT_PATTERNS.items():
            if marker in name_lower:
                return canonical
        return None

    def _guess_version(self, display_name: str) -> str:
        m = _VERSION_RE.search(display_name)
        return m.group(1) if m else ""
