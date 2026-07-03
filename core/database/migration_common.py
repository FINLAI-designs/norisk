"""migration_common — geteilte Konstanten und Helpers fuer die Bestandsdaten-Migration.

 Modul-Aufteilung §3): die zuvor in
``core.database.migrate_to_envelope`` lebende 1335-LoC-Sammlung wurde in
fuenf fokussierte Module gesplittet. Dieses Modul ist die Leaf-Schicht —
keine Abhaengigkeiten zu den anderen Migrations-Modulen, nur generische
Filesystem-/Konstanten-Helper.

Inhalt:

*:data:`_BACKUP_PREFIX` — Datums-Suffix fuer Backup-Verzeichnisse und
  ``secure_store.enc``-Backup-Dateien (siehe §3.2).
*:func:`_atomic_write_bytes` — atomares ``.tmp + fsync + replace``-
  Pattern fuer Bytes-Payloads. Wird vom SecureStore-Pfad genutzt;
  generisch genug, um auch fuer kuenftige State-Files zu greifen.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

#: Praefix fuer Backup-Verzeichnisse + secure_store-Backup-Datei.
#:
#: Layout (siehe §3.2):
#: <db_dir>/<_BACKUP_PREFIX><YYYY-MM-DD>[-HHMMSS]/
#: ~/.finlai/secure_store.enc<_BACKUP_PREFIX><YYYY-MM-DD>[-HHMMSS]
_BACKUP_PREFIX: Final[str] = ".pre-envelope-backup-"


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Schreibt ``payload`` atomar nach ``path`` (.tmp + fsync + replace).

    Selbe Konvention wie ``KeyManager.initialize`` und
:func:`set_state` — kein halb-geschriebener Zustand bei Crash.

    Permissions werden auf 0600 gesetzt (Windows ignoriert es leise).
    """
    tmp_path = path.with_name(path.name + ".tmp")
    try:
        with open(tmp_path, "wb") as fp:
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, path)
    except OSError:
        # Cleanup.tmp falls vorhanden.
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise

    # Permissions 0600 (Windows ignoriert es leise — kein Fehler).
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
