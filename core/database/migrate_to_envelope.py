"""migrate_to_envelope — Bestandsdaten-Migration auf Envelope-Encryption (Subtask 3).

 Modul-Aufteilung: dieses Modul war urspruenglich der 1335-LoC-
Sammler fuer den gesamten Subtask-3-Migrations-Code. Mit der Aufteilung
liegt die Logik jetzt in fuenf fokussierten Modulen, dieses Modul ist
ein **Shim** der die Public-API erhaelt:

*:mod:`core.database.migration_common` — Konstanten + Generic-Helpers
  (``_BACKUP_PREFIX``, ``_atomic_write_bytes``).
*:mod:`core.database.migration_backup` — Backup-Algorithmus
  (``BackupResult``, ``compute_backup_dir_path``, ``pre_migration_backup``).
*:mod:`core.database.migration_dbs` — DB-Migration + Quorum-Helper
  (``_can_open_with_key``, ``_rekey_db``, ``legacy_db_key``,
  ``handle_unrecoverable``, ``MigrationReport``, ``migrate_all_databases``).
*:mod:`core.database.migration_secure_store` — SecureStorage-Pfad
  (``SecureStoreMigrationStatus``, ``migrate_secure_store``).
*:mod:`core.database.migration_bootstrap` — Top-Level-Orchestrator
  (``run_bootstrap_migration``).

**Backward-Kompatibilitaet:** Bestehende Importer ``from
core.database.migrate_to_envelope import X`` funktionieren unveraendert,
weil dieses Shim alle Public- und ausgewaehlte Private-Symbole
re-exportiert. Tests, die ueber ``patch.object(mte.shutil,...)`` /
``patch.object(mte.legacy_db_key,...)`` patchen, funktionieren auch
weiter — die ``mte.shutil``-/``mte.legacy_db_key``-Attribute existieren
durch die expliziten Imports unten, und ``migrate_all_databases``
(in:mod:`migration_dbs`) macht einen Late-Lookup via
``migrate_to_envelope.legacy_db_key``, damit Test-Monkeypatches greifen.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur,
kein PySide6-Import — testbar ohne GUI).
"""

from __future__ import annotations

# Modul-Level-Imports fuer Test-Patches via ``mte.<module>.<func>``.
# ``patch.object(mte.shutil, "copy2", side_effect=...)`` erwartet ein
# Modul-Attribut ``shutil`` auf diesem Namespace. Ohne diese Imports
# wuerden die Tests ``AttributeError`` werfen.
import logging
import os  # noqa: F401 — fuer Test-Patches via mte.os
import shutil  # noqa: F401 — fuer Test-Patches via mte.shutil
import warnings  # noqa: F401 — fuer Test-Patches via mte.warnings

# Backup-Pfad
from core.database.migration_backup import (
    BackupResult,
    _compute_secure_store_backup_path,
    _copy_with_verify,
    compute_backup_dir_path,
    pre_migration_backup,
)

# Bootstrap-Orchestrator
from core.database.migration_bootstrap import (
    _do_run_bootstrap_migration,
    run_bootstrap_migration,
)

# Konstanten
from core.database.migration_common import (
    _BACKUP_PREFIX,
    _atomic_write_bytes,
)

# DB-Migrations-Pfad
from core.database.migration_dbs import (
    _UNRECOVERABLE_CONTEXT_SCHEMA_VERSION,
    _UNRECOVERABLE_DIRNAME,
    MigrationReport,
    _can_open_with_key,
    _derive_legacy_integrity_key,
    _ensure_state_skeleton,
    _rekey_db,
    handle_unrecoverable,
    legacy_db_key,
    migrate_all_databases,
)

# SecureStore-Pfad
from core.database.migration_secure_store import (
    SecureStoreMigrationStatus,
    _compute_secure_store_backup_path_for_now,
    _derive_legacy_fernet_key,
    _legacy_secure_store_password,
    _try_decrypt_secure_store,
    migrate_secure_store,
)

log = logging.getLogger(__name__)

__all__ = [
    # Konstanten
    "_BACKUP_PREFIX",
    "_UNRECOVERABLE_CONTEXT_SCHEMA_VERSION",
    "_UNRECOVERABLE_DIRNAME",
    # Backup
    "BackupResult",
    "_compute_secure_store_backup_path",
    "_copy_with_verify",
    "compute_backup_dir_path",
    "pre_migration_backup",
    # DB-Migration
    "MigrationReport",
    "_can_open_with_key",
    "_derive_legacy_integrity_key",
    "_ensure_state_skeleton",
    "_rekey_db",
    "handle_unrecoverable",
    "legacy_db_key",
    "migrate_all_databases",
    # SecureStore
    "SecureStoreMigrationStatus",
    "_atomic_write_bytes",
    "_compute_secure_store_backup_path_for_now",
    "_derive_legacy_fernet_key",
    "_legacy_secure_store_password",
    "_try_decrypt_secure_store",
    "migrate_secure_store",
    # Bootstrap
    "_do_run_bootstrap_migration",
    "run_bootstrap_migration",
]
