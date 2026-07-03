"""migration_backup — Pre-Migration-Backup fuer DB-Verzeichnis + secure_store.

 Modul-Aufteilung. Liefert die Backup-Funktionen fuer Schritt 3.2
des Bestandsdaten-Migrations-Algorithmus §3.2):

*:class:`BackupResult` — Ergebnis-Dataclass mit Pfad + LoC-Counters.
*:func:`compute_backup_dir_path` — Pure Funktion, liefert den geplanten
  Backup-Pfad (HHMMSS-Eskalation bei Mehrfach-Lauf am selben Tag).
*:func:`pre_migration_backup` — Pflicht-Schritt vor jeder Migration.
  Kopiert alle ``*.db``-Dateien + optional ``secure_store.enc`` in ein
  Tages-Backup-Verzeichnis mit fsync und Groessen-Verifikation.

Privat (nur Modul-intern):

*:func:`_compute_secure_store_backup_path` — Suffix-Ableitung vom
  Backup-Verzeichnis-Namen.
*:func:`_copy_with_verify` — ``shutil.copy2`` + ``fsync`` +
  Groessen-Vergleich.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from core.database.migration_common import _BACKUP_PREFIX
from core.exceptions import FileSystemError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackupResult:
    """Ergebnis eines:func:`pre_migration_backup`-Laufs.

    Attributes:
        backup_dir: Pfad des angelegten DB-Backup-Verzeichnisses.
        db_count: Anzahl der kopierten DB-Dateien.
        secure_store_backup: Pfad der secure_store-Backup-Datei oder
            ``None`` wenn keine Datei zum Sichern angegeben/vorhanden war.
        total_bytes: Summe der kopierten Bytes (DBs + secure_store).
    """

    backup_dir: Path
    db_count: int
    secure_store_backup: Path | None
    total_bytes: int


def compute_backup_dir_path(
    db_dir: Path,
    now: datetime | None = None,
) -> Path:
    """Liefert den Backup-Verzeichnis-Pfad fuer:func:`pre_migration_backup`.

    Strategie §3.2 — Mehrfach-Backup):
        1. Erst-Versuch ``<db_dir>/<prefix><YYYY-MM-DD>``.
        2. Existiert das Tagesverzeichnis bereits (Mehrfach-Lauf am
           selben Tag), eskaliere zu
           ``<db_dir>/<prefix><YYYY-MM-DD>-HHMMSS``.

    Beide Backup-Verzeichnisse bleiben nach einem Mehrfach-Lauf liegen
    — keine Auto-Cleanup. Recovery-Versicherung hat Vorrang vor
    Plattenplatz-Optimierung (siehe §3.2 Mehrfach-Backup-
    Strategie).

    Pure Function — kein Filesystem-Schreibvorgang. Caller (
:func:`pre_migration_backup`) macht ``mkdir(exist_ok=False)``, um
    Race-Conditions auszuschliessen.

    Args:
        db_dir: Verzeichnis, in dem das Backup-Verzeichnis als
            Geschwister-Eintrag angelegt wird.
        now: Optionaler datetime-Anker (UTC). Default
            ``datetime.now(UTC)``. Tests injizieren feste Zeit fuer
            Determinismus.

    Returns:
        Pfad zum geplanten Backup-Verzeichnis. Verzeichnis existiert
        zu diesem Zeitpunkt noch NICHT (oder im Eskalations-Pfad nur
        das Tagesverzeichnis).
    """
    if now is None:
        now = datetime.now(tz=UTC)
    daily = db_dir / f"{_BACKUP_PREFIX}{now.strftime('%Y-%m-%d')}"
    if not daily.exists():
        return daily
    return db_dir / (
        f"{_BACKUP_PREFIX}{now.strftime('%Y-%m-%d-%H%M%S')}"
    )


def _compute_secure_store_backup_path(
    secure_store_path: Path,
    backup_dir: Path,
) -> Path:
    """Liefert den Pfad fuer das secure_store-Backup neben backup_dir.

    Layout §3.2):
        ``~/.finlai/secure_store.enc.pre-envelope-backup-<YYYY-MM-DD>[-HHMMSS]``

    Suffix wird vom backup_dir-Namen abgeleitet, damit DB- und
    SecureStore-Backup denselben Datums-Anker tragen — Forensik kann
    ein zusammengehoeriges Paar ueber identische Suffix-Werte zuordnen.
    """
    suffix = backup_dir.name[len(_BACKUP_PREFIX) :]
    return secure_store_path.with_name(
        f"{secure_store_path.name}{_BACKUP_PREFIX}{suffix}"
    )


def _copy_with_verify(src: Path, dst: Path) -> int:
    """Kopiert ``src`` nach ``dst`` mit ``fsync`` und Groessen-Vergleich.

    ``shutil.copy2`` kopiert Inhalt + Metadaten (mtime, atime). Danach
    wird ``os.fsync`` auf einem frischen ``r+b``-Handle (read+write,
    kein Truncate) ausgefuehrt, um sicherzustellen, dass die Bytes auf
    Disk sind (nicht nur im OS-Buffer). ``r+b`` ist Pflicht — Windows
    ``_commit`` (das ``os.fsync`` auf Windows realisiert) verlangt einen
    Write-mode-Handle, ``rb`` wuerde mit ``OSError [Errno 9] Bad file
    descriptor`` fehlschlagen. Erst nach dem fsync wird die Groesse
    verglichen — bei Mismatch ``RuntimeError``.

    Returns:
        Anzahl der kopierten Bytes (Disk-Groesse von ``dst``).

    Raises:
        OSError: Filesystem-Fehler waehrend Copy oder fsync.
        RuntimeError: Groessen-Mismatch zwischen src und dst nach Copy.
            Die destination-Datei wird in dem Fall NICHT geloescht
            (Forensik-Hilfe).
    """
    shutil.copy2(src, dst)
    with open(dst, "r+b") as fp:
        os.fsync(fp.fileno())
    src_size = src.stat().st_size
    dst_size = dst.stat().st_size
    if src_size != dst_size:
        raise FileSystemError(
            f"Backup-Groessen-Mismatch fuer {src.name}: "
            f"src={src_size} bytes, dst={dst_size} bytes."
        )
    return dst_size


def pre_migration_backup(
    db_dir: Path,
    secure_store_path: Path | None = None,
    now: datetime | None = None,
) -> BackupResult:
    """Legt vollstaendiges Pre-Migration-Backup an §3.2).

    **Pflicht bei JEDEM Migrations-Lauf**, nicht nur dem ersten.
    Plattenplatz-Optimierung hat keinen Vorrang vor Recovery-
    Versicherung (siehe §3.2 Mehrfach-Backup-Strategie).

    Vorgehen:
        1. Backup-Verzeichnis-Pfad berechnen via
:func:`compute_backup_dir_path`. Bei Mehrfach-Lauf am selben
           Tag wird HHMMSS-Suffix verwendet — beide Verzeichnisse
           bleiben liegen.
        2. Backup-Verzeichnis anlegen (``mkdir(exist_ok=False)``) — bei
           Existenz wird ``RuntimeError`` geworfen (Race-Condition-
           Schutz, sollte nach:func:`compute_backup_dir_path` nicht
           passieren).
        3. Alle ``<db_dir>/*.db``-Dateien kopieren via
:func:`_copy_with_verify`. Sub-Verzeichnisse (``.archive``,
           ``.unrecoverable``, andere Backups) werden NICHT mitkopiert —
           der ``glob("*.db")``-Filter trifft nur direkte Datei-Kinder.
        4. Falls ``secure_store_path`` gesetzt UND Datei existiert:
           kopiere zu ``<path>.pre-envelope-backup-<suffix>``.
        5. ``BackupResult`` zurueckgeben — Caller (Migrations-
           Algorithmus in Schritt 3.3) traegt ``backup_dir`` in den
           Migration-State ein.

    Bei Fehler (Copy-Fail, Groessen-Mismatch): ``RuntimeError`` /
    ``OSError`` propagiert. **Migration startet nicht** (Caller-
    Konvention). Bereits kopierte Dateien bleiben im Backup-Verzeichnis
    liegen — bewusst, weil das Verzeichnis als Forensik-Hilfe und
    manuelle Recovery-Quelle dient §3.2).

    Reflexions-Regel-3 (PE-1-Lehre): Existenz-Check vor jedem mkdir.
    Mehrfach-Lauf eskaliert zu HHMMSS-Suffix, kein blindes
    Ueberschreiben.

    Args:
        db_dir: ``~/.finlai/db/<app_id>/`` — App-spezifisches DB-
            Verzeichnis. Caller filtert auf ``app_id`` (z. B.
            ``"norisk"``).
        secure_store_path: Optionaler Pfad zur ``secure_store.enc``-
            Datei. Default ``None`` = kein SecureStorage-Backup.
        now: Optionaler datetime-Anker (UTC). Default
            ``datetime.now(UTC)``.

    Returns:
:class:`BackupResult` mit Backup-Verzeichnis, kopierten DBs
        und optionaler SecureStore-Backup-Datei.

    Raises:
        OSError: db_dir existiert nicht, oder Filesystem-Fehler waehrend
            Kopiervorgang.
        RuntimeError: Backup-Pfad existiert bereits (Race), oder
:func:`_copy_with_verify` meldet Groessen-Mismatch.
    """
    if not db_dir.is_dir():
        raise OSError(
            f"db_dir existiert nicht oder ist kein Verzeichnis: {db_dir}"
        )

    backup_dir = compute_backup_dir_path(db_dir, now=now)
    if backup_dir.exists():
        raise FileSystemError(
            f"Backup-Pfad existiert bereits: {backup_dir}. "
            "Mehrfach-Lauf in derselben Sekunde, oder unerwarteter "
            "State auf Disk. Migration startet nicht."
        )

    backup_dir.mkdir(parents=False, exist_ok=False)

    # DB-Files kopieren — nur direkte ``*.db``, keine Sub-Verzeichnisse.
    db_count = 0
    total_bytes = 0
    for src in sorted(db_dir.glob("*.db")):
        if not src.is_file():
            # Defensive: Falls jemand ein Verzeichnis mit ``.db``-Suffix
            # angelegt hat — ueberspringen.
            continue
        dst = backup_dir / src.name
        bytes_copied = _copy_with_verify(src, dst)
        total_bytes += bytes_copied
        db_count += 1

    # SecureStore-Backup (optional)
    secure_store_backup: Path | None = None
    if secure_store_path is not None and secure_store_path.is_file():
        sb_dst = _compute_secure_store_backup_path(
            secure_store_path, backup_dir
        )
        if sb_dst.exists():
            raise FileSystemError(
                f"secure_store-Backup-Pfad existiert bereits: {sb_dst}"
            )
        bytes_copied = _copy_with_verify(secure_store_path, sb_dst)
        total_bytes += bytes_copied
        secure_store_backup = sb_dst

    log.info(
        "Pre-Migration-Backup abgeschlossen: %d DBs, %d Bytes nach %s. "
        "SecureStore-Backup: %s",
        db_count,
        total_bytes,
        backup_dir,
        secure_store_backup if secure_store_backup else "(kein)",
    )

    return BackupResult(
        backup_dir=backup_dir,
        db_count=db_count,
        secure_store_backup=secure_store_backup,
        total_bytes=total_bytes,
    )
