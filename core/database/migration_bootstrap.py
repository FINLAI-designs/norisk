"""migration_bootstrap — Top-Level-Orchestrator fuer die Bestandsdaten-Migration.

 Modul-Aufteilung. Liefert Schritt 3.5 §3.5):

*:func:`run_bootstrap_migration` — Public-Entrypoint. Wird von
:func:`apps.launch_app` zwischen:meth:`KeyManager.initialize` und
:func:`set_active_key_manager` aufgerufen. Idempotent.
*:func:`_do_run_bootstrap_migration` — innere Migrations-Logik
  (Idempotenz-Check + Stale-State-Warnung + Frische-Installation +
  Backup + DB-Migration + SecureStore-Migration + State-Persistierung).

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from core.database.migration_backup import pre_migration_backup
from core.database.migration_dbs import migrate_all_databases
from core.database.migration_secure_store import (
    SecureStoreMigrationStatus,
    migrate_secure_store,
)
from core.finlai_paths import finlai_dir as resolve_finlai_dir

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

log = logging.getLogger(__name__)


def run_bootstrap_migration(
    key_manager: KeyManager,
    app_id: str,
    *,
    db_root: Path | None = None,
    secure_store_path: Path | None = None,
    finlai_dir: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Top-Level-Bootstrap-Trigger fuer die Bestandsdaten-Migration (Subtask 3.5).

    Wird in:func:`apps.launch_app` zwischen:meth:`KeyManager.initialize`
    und:func:`set_active_key_manager` aufgerufen. Reihenfolge ist
    bewusst: andere Konsumenten duerfen DBs erst oeffnen, wenn die
    Migration durch ist (Modul-State wird erst nach Migration gesetzt).

    Idempotenz:
        - State-File ``migration-state.json`` mit ``completed_at`` ≠
          ``None`` → no-op (Migration bereits abgeschlossen).
        - State-File mit pending DBs → Resume; Caller-Konvention I-2.
        - State-File stale (>24 h ohne completed_at) → log.warning,
          Resume trotzdem (Test-ID I-3).
        - Kein State-File und keine DBs → frische Installation,
          schreibt completed_at-State und kehrt zurueck.

    Migration-Log: ``<finlai_dir>/migration-<YYYY-MM-DD>.log`` (separater
    FileHandler, nur waehrend des Migrations-Laufs aktiv §3.7).

    Args:
        key_manager: aktiver KeyManager (DEK initialisiert/geladen).
        app_id: App-ID (z. B. ``"norisk"``). DBs leben unter
            ``<db_root>/<app_id>/``.
        db_root: Default ``<finlai_dir>/db``. Tests injizieren tmp-Pfade.
        secure_store_path: Default ``<finlai_dir>/secure_store.enc``.
            Wenn die Datei nicht existiert, gilt SecureStore-Status
:attr:`SecureStoreMigrationStatus.ABSENT`.
        finlai_dir: Default ``~/.finlai``. Tests injizieren tmp-Pfade.
        now: datetime-Anker (UTC). Default ``datetime.now(UTC)``.

    Raises:
        OSError: Filesystem-Fehler waehrend Backup oder Schreiben des
            State-Files.
        RuntimeError: Backup-Pfad-Race oder SecureStore-Verifikations-
            Bug. Bootstrap-Caller faengt das mit Recovery-Hinweis.
    """
    if now is None:
        now = datetime.now(tz=UTC)
    if finlai_dir is None:
        finlai_dir = resolve_finlai_dir()
    if db_root is None:
        db_root = finlai_dir / "db"
    if secure_store_path is None:
        secure_store_path = finlai_dir / "secure_store.enc"

    finlai_dir.mkdir(parents=True, exist_ok=True)
    mig_log_path = finlai_dir / f"migration-{now.strftime('%Y-%m-%d')}.log"

    mig_handler = logging.FileHandler(mig_log_path, encoding="utf-8")
    mig_handler.setLevel(logging.INFO)
    # auch dieser persistierende Sibling-Handler sanitisiert (kein Secret/
    # IBAN-Leak), damit ALLE finlai-Logdateien dieselbe Redaction tragen.
    from core.logger import _RedactingFormatter  # noqa: PLC0415

    mig_handler.setFormatter(
        _RedactingFormatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    # Logger-Level temporaer auf INFO ziehen, damit INFO-Records beim
    # FileHandler ankommen. Default-Level eines Modul-Loggers ist
    # WARNING (Python-Default), was unsere INFO-Aufrufe sonst filtert
    # bevor sie die Handler-Kette erreichen.
    saved_level = log.level
    log.setLevel(logging.INFO)
    log.addHandler(mig_handler)
    try:
        _do_run_bootstrap_migration(
            key_manager=key_manager,
            app_id=app_id,
            db_root=db_root,
            secure_store_path=secure_store_path,
            now=now,
        )
    finally:
        log.removeHandler(mig_handler)
        mig_handler.close()
        log.setLevel(saved_level)


def _do_run_bootstrap_migration(
    key_manager: KeyManager,
    app_id: str,
    db_root: Path,
    secure_store_path: Path,
    now: datetime,
) -> None:
    """Innere Migrations-Logik (:func:`run_bootstrap_migration`)."""
    # Lazy import — vermeidet Circular-Import beim Modul-Load.
    from core.database import migration_state  # noqa: PLC0415

    state = migration_state.get_state(app_id)

    # 1. Idempotenz-Check.
    if state is not None and state.get("completed_at") is not None:
        log.info(
            "Migration bereits abgeschlossen (completed_at=%s) — no-op.",
            state["completed_at"],
        )
        return

    # 2. Stale-State-Warnung (Resume trotzdem).
    if state is not None and migration_state.is_state_stale(state):
        log.warning(
            "Migration-State ist stale (>24 h ohne completed_at) — Resume."
        )

    db_dir = db_root / app_id

    # 3. Frische Installation → kein Backup, kein DB-Loop.
    if not db_dir.is_dir():
        # P3-Fix: SecureStore-Status ueber den tatsaechlichen
        # Datei-Stand bestimmen, NICHT pauschal als "absent" setzen. Edge:
        # User loescht den DB-Ordner manuell, aber ``secure_store.enc``
        # bleibt liegen — pauschales "absent" wuerde den Status
        # falsch persistieren und die Migration spaeter nie nachholen.
        if secure_store_path.is_file():
            log.info(
                "Kein DB-Verzeichnis %s, aber secure_store.enc existiert — "
                "asymmetrische Frische-Installation. SecureStore-Migration "
                "wird ausgefuehrt.",
                db_dir,
            )
            ss_status = migrate_secure_store(
                secure_store_path, key_manager, now=now
            )
        else:
            log.info(
                "Kein DB-Verzeichnis %s — frische Installation, kein Backup.",
                db_dir,
            )
            ss_status = SecureStoreMigrationStatus.ABSENT
        fresh_state = {
            "schema_version": 1,
            "started_at": now.isoformat(),
            "completed_at": now.isoformat(),
            "backup_path": None,
            "dbs": {},
            "secure_store": {"status": ss_status.value},
        }
        migration_state.set_state(fresh_state, app_id)
        return

    # 4. Pre-Migration-Backup (Pflicht bei JEDEM Lauf — siehe §3.2).
    backup_result = pre_migration_backup(
        db_dir,
        secure_store_path=secure_store_path
        if secure_store_path.is_file()
        else None,
        now=now,
    )
    log.info(
        "Pre-Migration-Backup: %d DBs nach %s (%d Bytes).",
        backup_result.db_count,
        backup_result.backup_dir,
        backup_result.total_bytes,
    )

    # 5. DB-Migration.
    report = migrate_all_databases(
        db_dir,
        key_manager,
        backup_dir=backup_result.backup_dir,
        state=state,
        now=now,
    )

    # 6. SecureStore-Migration. ``backup_result.secure_store_backup`` wird
    # an ``migrate_secure_store`` durchgereicht, damit kein zweites Backup
    # (HHMMSS-Suffix) angelegt wird Cleanup-Fix.
    if secure_store_path.is_file():
        ss_status = migrate_secure_store(
            secure_store_path,
            key_manager,
            now=now,
            existing_backup_path=backup_result.secure_store_backup,
        )
    else:
        ss_status = SecureStoreMigrationStatus.ABSENT

    report.state["secure_store"] = {"status": ss_status.value}

    # 7. State persisten — markiert Migration als abgeschlossen.
    migration_state.set_state(report.state, app_id)

    log.info(
        "Migration abgeschlossen: %d already, %d migrated, %d unrecoverable, "
        "secure_store=%s.",
        len(report.already_migrated),
        len(report.migrated),
        len(report.unrecoverable),
        ss_status.value,
    )

    # C3: Wrong-Key/DEK-Verlust wird NICHT verschwiegen, sondern als
    # sichtbarer Datenverlust gemeldet (statt Crash beim ersten DB-Open). Die
    # betroffenen DBs liegen verschluesselt in.unrecoverable und werden frisch
    # neu angelegt.
    if report.unrecoverable:
        log.warning(
            "DATENVERLUST bei App '%s': %d DB(s) liessen sich mit dem aktuellen "
            "Schluessel nicht oeffnen (DEK-Verlust/Profilwechsel?) und wurden "
            "nach .unrecoverable verschoben: %s. Frische DBs werden angelegt. "
            "Pruefen Sie %s/.unrecoverable/ und die migration-*.log.",
            app_id,
            len(report.unrecoverable),
            ", ".join(sorted(report.unrecoverable)),
            db_dir,
        )
