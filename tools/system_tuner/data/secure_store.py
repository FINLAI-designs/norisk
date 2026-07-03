"""
secure_store — Admin-only Ablage unter %ProgramData% (A5/A2-Ledger).

Result-Marker, Snapshots und der Single-Use-Token-Ledger duerfen NICHT in einem
user-schreibbaren Verzeichnis liegen (sonst kann ein Non-Admin ein "alles OK"
faelschen, Snapshots loeschen oder den Replay-Schutz aushebeln). Diese
Helfer legen ``%ProgramData%\\NoRisk\\system_tuner`` mit einer **geschuetzten
DACL** an: SYSTEM + Administratoren = Vollzugriff, Users = nur Lesen.

**Fail-closed:** Setzen der DACL/des Owners braucht Admin (SeRestorePrivilege).
Gelingt es nicht (Non-Admin, Nicht-Windows, pywin32 fehlt), liefert
``ensure_secure_dir`` ``False`` und der elevated Apply bricht ab.

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)

_SID_SYSTEM = "S-1-5-18"
_SID_ADMINISTRATORS = "S-1-5-32-544"
_SID_USERS = "S-1-5-32-545"


def secure_dir() -> Path:
    """Pfad der admin-only Ablage (``%ProgramData%\\NoRisk\\system_tuner``)."""
    base = (
        os.environ.get("PROGRAMDATA")
        or os.environ.get("ALLUSERSPROFILE")
        or "C:\\ProgramData"
    )
    return Path(base) / "NoRisk" / "system_tuner"


def _apply_admin_only_dacl(path: Path) -> bool:
    """Setzt Owner=Administratoren + geschuetzte DACL (Admin full, Users read)."""
    import ntsecuritycon  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    system = win32security.ConvertStringSidToSid(_SID_SYSTEM)
    admins = win32security.ConvertStringSidToSid(_SID_ADMINISTRATORS)
    users = win32security.ConvertStringSidToSid(_SID_USERS)

    inherit = (
        win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    )
    full = ntsecuritycon.FILE_ALL_ACCESS
    read_exec = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE

    dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, full, system)
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, full, admins)
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, read_exec, users)

    flags = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION
    )
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, flags, admins, None, dacl, None
    )
    return True


def ensure_secure_dir(path: Path | None = None) -> bool:
    """Legt die admin-only Ablage an + haertet die DACL (fail-closed).

    Returns:
        ``True`` nur, wenn das Verzeichnis existiert UND die admin-only DACL
        gesetzt werden konnte (nur als Admin moeglich). Sonst ``False``.
    """
    if sys.platform != "win32":
        return False
    target = path or secure_dir()
    try:
        target.mkdir(parents=True, exist_ok=True)
        return _apply_admin_only_dacl(target)
    except Exception as exc:  # noqa: BLE001 — Boundary: jeder Fehler = fail-closed
        log.warning("Admin-only Ablage nicht herstellbar (fail-closed): %s", exc)
        return False
