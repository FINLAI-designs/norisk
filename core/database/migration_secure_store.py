"""migration_secure_store — SecureStorage-Datei-Migration auf DEK-Pfad.

 Modul-Aufteilung. Liefert die Migrations-Funktionen fuer
Schritt 3.4 §3.4):

*:class:`SecureStoreMigrationStatus` — Status-Enum (ABSENT,
  ALREADY_MIGRATED, MIGRATED, MIGRATED_EMPTY).
*:func:`migrate_secure_store` — Top-Level-Migrations-Funktion. Kann
  einen ``existing_backup_path`` aus:func:`pre_migration_backup`
  uebernehmen oder Standalone laufen Cleanup-Fix).

Privat (nur Modul-intern):

*:func:`_try_decrypt_secure_store` — Versucht eine Datei mit gegebenem
  Fernet-Key zu entschluesseln.
*:func:`_legacy_secure_store_password` — Production-Default fuer das
  Legacy-Password (= Hardware-Fingerprint, Pre-Subtask-2-Pfad).
*:func:`_compute_secure_store_backup_path_for_now` — Standalone-
  Backup-Pfad (mit HHMMSS-Eskalation).
*:func:`_derive_legacy_fernet_key` — Wrapper um den Pre-Subtask-2-
  ``_derive_key`` aus ``encryption.py``.

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import warnings
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from core.database.migration_common import _BACKUP_PREFIX, _atomic_write_bytes
from core.exceptions import CryptoError

if TYPE_CHECKING:
    from collections.abc import Callable

    from core.database.key_manager import KeyManager

log = logging.getLogger(__name__)


class SecureStoreMigrationStatus(StrEnum):
    """Ergebnis von:func:`migrate_secure_store` (Subtask 3 §3.4).

    -:attr:`ABSENT`: ``secure_store.enc`` existiert nicht (Anwender ohne
      gespeicherte API-Keys). Migration ist no-op.
    -:attr:`ALREADY_MIGRATED`: Datei ist bereits mit dem DEK-
      abgeleiteten Fernet-Key verschluesselt. Kein Re-Encrypt noetig.
    -:attr:`MIGRATED`: Legacy-Daten wurden gelesen und mit dem neuen
      Fernet-Key re-verschluesselt. Alle Keys uebernommen.
    -:attr:`MIGRATED_EMPTY`: Legacy-Datei nicht entschluesselbar
      (z. B. nach Hardware-Wechsel ohne Cert-Re-Activation). Neuer
      leerer Store wurde geschrieben — User muss API-Keys neu
      eingeben. Recovery via Backup-Datei moeglich.
    """

    ABSENT = "absent"
    ALREADY_MIGRATED = "already_migrated"
    MIGRATED = "migrated"
    MIGRATED_EMPTY = "migrated_empty"


def _try_decrypt_secure_store(
    path: Path,
    fernet_key_b64: bytes,
) -> dict[str, str] | None:
    """Versucht ``path`` mit gegebenem Fernet-Key zu entschluesseln.

    Wird sowohl fuer den DEK-Pfad (ALREADY_MIGRATED-Detection) als auch
    fuer den Legacy-Pfad genutzt — der Unterschied liegt nur im
    Fernet-Key, nicht in der Decrypt-Logik.

    Args:
        path: Pfad zur ``secure_store.enc``-Datei.
        fernet_key_b64: Fernet-kompatibler 44-ASCII-Char-Schluessel
            (base64url-kodierter 32-Byte-Wert).

    Returns:
        ``dict[str, str]`` bei erfolgreicher Entschluesselung,
        ``None`` bei Read-/Decode-/Decrypt-Fehler.
    """
    from cryptography.fernet import (  # noqa: PLC0415
        Fernet,
        InvalidToken,
    )

    try:
        fernet = Fernet(fernet_key_b64)
        raw = path.read_bytes()
        plaintext = fernet.decrypt(raw)
        data = json.loads(plaintext.decode("utf-8"))
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        InvalidToken,
    ):
        return None
    if not isinstance(data, dict):
        return None
    return {str(k): str(v) for k, v in data.items()}


def _legacy_secure_store_password() -> str:
    """Production-Default fuer den Legacy-SecureStorage-Password.

    Pre-Subtask-2-Pfad: ``_derive_key(get_hardware_fingerprint)``.
    Dieser Helper kapselt den Hardware-Fingerprint-Zugriff, damit Tests
    via ``legacy_password_func``-Argument synthetische Passwords
    injizieren koennen.
    """
    from core.hardware_fingerprint import (  # noqa: PLC0415
        get_hardware_fingerprint,
    )

    return get_hardware_fingerprint()


def migrate_secure_store(
    secure_store_path: Path,
    key_manager: KeyManager,
    *,
    legacy_password_func: Callable[[], str] | None = None,
    now: datetime | None = None,
    existing_backup_path: Path | None = None,
) -> SecureStoreMigrationStatus:
    """Migriert die SecureStorage-Datei auf den DEK-abgeleiteten Fernet-Key.

    Algorithmus §3.5 + Refinement Subtask 3):

    1. Wenn ``secure_store_path`` nicht existiert →:attr:`ABSENT`.
    2. Versuche mit ``derive_secondary_key("secure_storage")``-Fernet-
       Key zu entschluesseln. Erfolg →:attr:`ALREADY_MIGRATED` (no-op,
       Datei bleibt unangetastet).
    3. Backup-Datei sichern: wenn ``existing_backup_path`` uebergeben ist
       (Bootstrap-Pfad mit vorgelagertem:func:`pre_migration_backup`),
       wird DIESER Pfad als Backup angerechnet — kein zweites Backup,
       kein HHMMSS-Suffix-Doppel Cleanup). Andernfalls (Standalone-
       Aufruf) wird der Pfad ueber
:func:`_compute_secure_store_backup_path_for_now` berechnet und
       die Quelle dorthin kopiert.
    4. Versuche mit ``legacy_password_func`` zu entschluesseln. Default:
       ``get_hardware_fingerprint``. Tests injizieren synthetische
       Funktionen.
    5. Schreibe (alte Daten oder leeres dict) mit DEK-Fernet-Key atomar
       (``.tmp`` + ``fsync`` + ``os.replace``).
    6. Verifiziere: alle Keys aus dem Legacy-Read sind in der neuen
       Datei mit DEK-Key lesbar.

    SM-1/SM-2 (alte Daten lesbar + neu mit DEK lesbar): Status
:attr:`MIGRATED` mit verifizierten Keys.
    SM-3 (Backup-Datei vorhanden): unter
    ``<path>.pre-envelope-backup-<date>[-HHMMSS]``.
    SM-4 (Legacy nicht entschluesselbar)::attr:`MIGRATED_EMPTY` —
    neuer leerer Store, alte Datei in Backup-Pfad recoverable.

    Args:
        secure_store_path: Pfad zur ``secure_store.enc``-Datei (typisch
            ``~/.finlai/secure_store.enc``).
        key_manager: aktiver:class:`KeyManager`.
        legacy_password_func: Liefert das Legacy-Password fuer
:func:`core.security.encryption._derive_key`. Default:
:func:`_legacy_secure_store_password`
            (= ``get_hardware_fingerprint``).
        now: Optionaler datetime-Anker fuer den Backup-Suffix.
        existing_backup_path: Pfad eines bereits durchgefuehrten Backups
            (z. B. aus:attr:`BackupResult.secure_store_backup`). Wenn
            angegeben, wird kein zweites Backup angelegt — derselbe Pfad
            taucht im Log als Recovery-Quelle auf. ``None`` bei Standalone-
            Aufruf (Tests, Diagnose-Tool) → Backup wird hier neu erstellt.

    Returns:
:class:`SecureStoreMigrationStatus`.

    Raises:
        RuntimeError: Bei Verifikations-Fail (sollte nicht passieren —
            Indikator fuer Fernet-/Encoding-Bug).
        OSError: Bei Filesystem-Fehler waehrend Backup oder Schreiben.
    """
    if now is None:
        now = datetime.now(tz=UTC)

    if not secure_store_path.is_file():
        return SecureStoreMigrationStatus.ABSENT

    # 1. DEK-Fernet-Key vorbereiten (32 Bytes → base64url 44 ASCII).
    raw_secondary = key_manager.derive_secondary_key("secure_storage")
    new_fernet_key = base64.urlsafe_b64encode(raw_secondary)

    # 2. Already-Migrated-Detection.
    existing = _try_decrypt_secure_store(
        secure_store_path, new_fernet_key
    )
    if existing is not None:
        return SecureStoreMigrationStatus.ALREADY_MIGRATED

    # 3. Backup-Pfad bestimmen + ggf. anlegen.
    if existing_backup_path is not None:
        # Bootstrap-Pfad: pre_migration_backup hat bereits den Backup-
        # Pfad angelegt. Kein zweites Backup, keine Suffix-Eskalation.
        backup_path = existing_backup_path
    else:
        # Standalone-Pfad: berechne Backup-Pfad selbst, kopiere falls noetig.
        backup_path = _compute_secure_store_backup_path_for_now(
            secure_store_path, now
        )
        if not backup_path.exists():
            shutil.copy2(secure_store_path, backup_path)
            # fsync ueber r+b-Handle (Windows-_commit-Pflicht, 
            # _copy_with_verify Doku).
            with open(backup_path, "r+b") as fp:
                os.fsync(fp.fileno())

    # 4. Legacy-Decryption.
    if legacy_password_func is None:
        # Lookup via Shim-Modul, damit Test-Monkeypatches auf
        # ``mte._legacy_secure_store_password`` durchschlagen. Lazy-
        # Import vermeidet Circular-Import beim Modul-Load.
        from core.database import migrate_to_envelope as _mte  # noqa: PLC0415

        legacy_password_func = _mte._legacy_secure_store_password

    legacy_data: dict[str, str] = {}
    legacy_read_succeeded = False
    try:
        password = legacy_password_func()
    except Exception:  # noqa: BLE001 -- legacy func darf alles werfen.
        password = None

    if password is not None:
        legacy_fernet_key = _derive_legacy_fernet_key(password)
        decrypted = _try_decrypt_secure_store(
            secure_store_path, legacy_fernet_key
        )
        if decrypted is not None:
            legacy_data = decrypted
            legacy_read_succeeded = True

    # 5. Neue Datei atomar schreiben.
    payload = json.dumps(legacy_data, ensure_ascii=False).encode("utf-8")
    from cryptography.fernet import Fernet  # noqa: PLC0415

    encrypted = Fernet(new_fernet_key).encrypt(payload)
    _atomic_write_bytes(secure_store_path, encrypted)

    # 6. Verifizieren.
    verify_data = _try_decrypt_secure_store(
        secure_store_path, new_fernet_key
    )
    if verify_data is None:
        raise CryptoError(
            "secure_store-Migration: Verify-Read mit DEK-Key fehlgeschlagen "
            "(neue Datei nicht lesbar). Indikator fuer Fernet-/Encoding-Bug."
        )
    missing_keys = set(legacy_data) - set(verify_data)
    if missing_keys:
        raise CryptoError(
            f"secure_store-Migration: Keys fehlen nach Re-Encrypt: "
            f"{sorted(missing_keys)}"
        )

    log.info(
        "SecureStore-Migration abgeschlossen: %d Keys uebernommen, "
        "Backup: %s.",
        len(legacy_data),
        backup_path,
    )

    # Status-Differenzierung: erfolgreicher Legacy-Read (egal ob leer
    # oder voll) → MIGRATED. Legacy-Read fehlgeschlagen (Password-
    # Exception oder Decrypt-Fail) → MIGRATED_EMPTY.
    if legacy_read_succeeded:
        return SecureStoreMigrationStatus.MIGRATED
    return SecureStoreMigrationStatus.MIGRATED_EMPTY


def _compute_secure_store_backup_path_for_now(
    secure_store_path: Path,
    now: datetime,
) -> Path:
    """Liefert den Backup-Pfad fuer secure_store ohne separates db_dir.

    Komplementaer zum ``backup_dir``-abgeleiteten Pfad in
:mod:`core.database.migration_backup` — hier rechnen wir den
    Suffix aus ``now`` aus, fuer Standalone-:func:`migrate_secure_store`-
    Aufrufe ohne vorherigen:func:`pre_migration_backup`-Lauf.

    Strategie analog ``compute_backup_dir_path``:
        Erst-Versuch ``<path><prefix><YYYY-MM-DD>``, bei Existenz
        Eskalation auf ``<path><prefix><YYYY-MM-DD>-HHMMSS``.
    """
    daily_suffix = now.strftime("%Y-%m-%d")
    daily = secure_store_path.with_name(
        f"{secure_store_path.name}{_BACKUP_PREFIX}{daily_suffix}"
    )
    if not daily.exists():
        return daily
    full_suffix = now.strftime("%Y-%m-%d-%H%M%S")
    return secure_store_path.with_name(
        f"{secure_store_path.name}{_BACKUP_PREFIX}{full_suffix}"
    )


def _derive_legacy_fernet_key(password: str) -> bytes:
    """Wrapper um:func:`core.security.encryption._derive_key`.

    Unterdrueckt den DeprecationWarning lokal — wir wissen, dass der
    Pfad deprecated ist und nutzen ihn bewusst zur Migration.
    """
    from core.security.encryption import _derive_key  # noqa: PLC0415

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return _derive_key(password)
