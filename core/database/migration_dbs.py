"""migration_dbs — DB-Migration auf den DEK-basierten SQLCipher-Schluessel.

 Modul-Aufteilung. Liefert die Migrations-Funktionen fuer
Schritt 3.3 §3.3) plus den dazugehoerigen Legacy-Schluessel-
Ableitungspfad:

*:func:`_can_open_with_key` — kann ``db_path`` mit ``key_hex`` geoeffnet
  werden? Pflicht-Existenz-Guard fuer nicht existente Pfade P3).
*:func:`_rekey_db` — atomarer ``PRAGMA rekey`` unter WAL-Mode.
*:func:`_derive_legacy_integrity_key` — Pre-Subtask-2-PBKDF2-Replikation
  (Migration-only Cleanup-Replikation).
*:func:`legacy_db_key` — Production-Default Legacy-Key-Closure.
*:func:`handle_unrecoverable` — verschiebt nicht migrierbare DBs nach
  ``.unrecoverable/`` mit Forensik-Context.
*:class:`MigrationReport` — aggregiertes Ergebnis von
:func:`migrate_all_databases`.
*:func:`migrate_all_databases` — Top-Level-Orchestrator fuer 3.3.
*:func:`_ensure_state_skeleton` — State-dict-Skeleton (frisch oder
  Resume).

Schichtzugehoerigkeit: ``core/database/`` (Migrations-Infrastruktur).
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import sqlcipher3

from core.database.key_manager import KeyManagerError, MigrationStatus
from core.exceptions import CryptoError, FileSystemError

if TYPE_CHECKING:
    from collections.abc import Callable

    from core.database.key_manager import KeyManager

log = logging.getLogger(__name__)

#: Suffix-Pfad fuer nicht migrierbare DBs (siehe §3.3).
_UNRECOVERABLE_DIRNAME: Final[str] = ".unrecoverable"

#: Schema-Version des ``.context.json``-Forensik-Files in
#::file:`.unrecoverable/`. Bei Schema-Wechsel hochziehen + §3.3
#: nachpflegen.
_UNRECOVERABLE_CONTEXT_SCHEMA_VERSION: Final[int] = 1


def _can_open_with_key(
    db_path: Path, key_hex: str, *, raw_key: bool = False
) -> bool:
    """True wenn ``db_path`` mit ``key_hex`` als SQLCipher-Schluessel oeffnet.

    Nutzt:func:`core.database.encrypted_db._configure_connection` —
    selbe PRAGMA-Sequenz wie die Production-Verbindung. Damit ist die
    Cipher-Konfiguration garantiert konsistent.

    ``raw_key``: Default ``False`` haelt das Legacy-Verhalten
    (String-Key/PBKDF2) fuer die Legacy→DEK-Migration. Der Raw-Key-Discard-
    Schritt (:func:`core.database.migration_rawkey.discard_pre_rawkey_databases`)
    ruft mit ``raw_key=True``, um zu pruefen, ob eine DB schon im Raw-Key-Format
    vorliegt.

    Schluessel-Validierung erfolgt durch ``SELECT count(*) FROM
    sqlite_master`` — SQLCipher prueft beim ersten Statement den HMAC.
    Bei falschem Key wirft sqlcipher3 ``DatabaseError`` mit "file is
    not a database" oder "file is encrypted".

    Args:
        db_path: Pfad zur SQLCipher-DB.
        key_hex: 64-stelliger Hex-String fuer ``PRAGMA key``.

    Returns:
        ``True`` wenn die DB lesbar ist, ``False`` bei jedem
        ``DatabaseError`` oder wenn die Datei gar nicht existiert.

    Note:
        Existenz-Guard ist Pflicht P3-Fix): ``sqlcipher3.connect``
        erzeugt fuer nicht existente Pfade automatisch eine **leere** DB
        und liefert ein ``True`` ohne Schluessel-Pruefung. Production-
        Caller (:func:`migrate_all_databases`) filtern Pfade vorher mit
        ``is_file`` — ohne diesen Guard waere ``_can_open_with_key``
        aber falsch wenn z. B. das Diagnose-Tool eine Liste reiner Stems
        uebergibt. Der Guard schliesst den Vertrag dauerhaft ab.
    """
    if not db_path.is_file():
        return False

    # Lazy-Import, weil encrypted_db transitiv den KeyManager-Modul-State
    # konsumiert — bei Modul-Ladezeit unsicher.
    from core.database.encrypted_db import (  # noqa: PLC0415
        _configure_connection,
    )

    conn: Any = None
    try:
        conn = sqlcipher3.connect(str(db_path))
        _configure_connection(conn, key_hex, raw_key=raw_key)
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlcipher3.DatabaseError:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlcipher3.DatabaseError:
                pass
    return True


def _rekey_db(db_path: Path, old_key_hex: str, new_key_hex: str) -> None:
    """Re-keyed eine SQLCipher-DB von ``old_key_hex`` auf ``new_key_hex``.

    SQLCipher ``PRAGMA rekey`` ist atomar in WAL-Mode — entweder ganz
    oder gar nicht. Caller (:meth:`KeyManager.migrate_legacy_db`) ruft
    diese Funktion erst nach erfolgreichem:func:`_can_open_with_key`-
    Check, damit ein PRAGMA-rekey-Versuch nicht auf einer mit altem
    Schluessel ungelesen-bar gewordenen DB stattfindet.

    Raises:
        sqlcipher3.DatabaseError: Bei Rekey-Fehler. Caller faengt das
            generisch — die DB-Datei bleibt im (alten) konsistenten
            Zustand wegen WAL-Atomizitaet.
    """
    from core.database.encrypted_db import (  # noqa: PLC0415
        _configure_connection,
    )

    conn = sqlcipher3.connect(str(db_path))
    try:
        # Legacy→DEK-Migration liest/schreibt im alten String-Key-Format
        #: Default ist Raw-Key, hier bewusst String-Key).
        _configure_connection(conn, old_key_hex, raw_key=False)
        # Verify lesbar mit altem Key, sonst kein Rekey starten.
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        conn.execute(f'PRAGMA rekey="{new_key_hex}"')
        conn.commit()
    finally:
        conn.close()


def _derive_legacy_integrity_key() -> bytes:
    """Leitet den Pre-Subtask-2-Integritaetsschluessel ab (privat, Migration-only).

    Repliziert byte-identisch die in aus
    ``core/security/encryption.py`` entfernte HW-Fingerprint-PBKDF2-
    Ableitung:

.. code-block:: text

        salt = ~/.finlai/.salt (encryption._get_or_create_salt)
        hw = get_hardware_fingerprint
        out = PBKDF2-HMAC-SHA256(b"integrity:" + hw,
                                  salt=salt, iter=100_000, dklen=32)

    Wird **ausschliesslich** vom Legacy-Migrations-Pfad
    (:func:`legacy_db_key`) gebraucht und ist deshalb bewusst NICHT in
    ``encryption.py`` zurueckgekehrt — die Public-Surface dort ist
    Subtask-2-Stand (KeyManager + DEK), Hardware-Fingerprint-Kopplung
    nur noch hier in der Migration.

    Returns:
        32-Byte-Schluessel.

    Raises:
        RuntimeError: Wenn HW-Fingerprint oder Salt nicht abgeleitet
            werden koennen.
    """
    # Lazy-Import: encryption.py + hardware_fingerprint.py haben jeweils
    # transitive Windows-Subprocess-Abhaengigkeiten — nur laden, wenn die
    # Migration tatsaechlich laeuft.
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.kdf.pbkdf2 import (  # noqa: PLC0415
        PBKDF2HMAC,
    )

    from core.hardware_fingerprint import (  # noqa: PLC0415
        get_hardware_fingerprint,
    )
    from core.security.encryption import (  # noqa: PLC0415
        _get_or_create_salt,
    )

    try:
        hw_id = get_hardware_fingerprint()
        salt = _get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(f"integrity:{hw_id}".encode())
    except Exception as exc:
        msg = "Legacy-Integritaetsschluessel nicht ableitbar."
        raise CryptoError(msg) from exc


def legacy_db_key(db_name: str) -> str:
    """Production-Default fuer den Legacy-DB-Schluessel.

    Repliziert den Pre-Subtask-2-Code-Pfad:

.. code-block:: python

        base_key = _derive_legacy_integrity_key
        db_key = HMAC-SHA256(base_key, f"sqlcipher:v1:{db_name}").hexdigest

    Args:
        db_name: DB-Stem-Name (z. B. ``"network_monitor"``).

    Returns:
        64-stelliger Hex-String fuer ``PRAGMA key``.

    Raises:
        RuntimeError: Wenn:func:`_derive_legacy_integrity_key` keinen
            Schluessel ableiten kann (z. B. fehlendes Salt-File). Der
            KeyManager-Migrations-Pfad faengt das in
:meth:`KeyManager.migrate_legacy_db`.
    """
    integrity_key = _derive_legacy_integrity_key()
    return hmac.new(
        integrity_key,
        f"sqlcipher:v1:{db_name}".encode(),
        hashlib.sha256,
    ).hexdigest()


def handle_unrecoverable(
    db_path: Path,
    db_dir: Path,
    *,
    tried_algorithms: list[str],
    last_error_class: str,
    last_error_message: str,
    backend_type: str | None = None,
    hkdf_salt_version: str = "v1",
    now: datetime | None = None,
) -> Path:
    """Verschiebt eine nicht migrierbare DB nach ``.unrecoverable/``.

    Layout §3.3):

.. code-block:: text

        <db_dir>/.unrecoverable/<db_name>.db
        <db_dir>/.unrecoverable/<db_name>.context.json

    Context-File enthaelt **kein Crypto-Material** — nur Pfad-Metadaten,
    Failure-Reason, Hash der Fehler-Botschaft, Original-Groesse,
    Original-mtime und KeyManager-Backend-Typ. Konvention aus
    §3.3 wortgenau.

    Reflexions-Regel-3 (PE-1-Lehre): wenn das Ziel
    ``<unrec_dir>/<db_name>.db`` bereits existiert (Mehrfach-Migration
    am selben Tag), eskaliere zu ``<db_name>-<YYYYMMDD-HHMMSS>.db``.
    **Niemals silent ueberschreiben.**

    Args:
        db_path: Quell-DB im ``db_dir``. Wird per:func:`shutil.move`
            verschoben.
        db_dir: ``~/.finlai/db/<app_id>/``. ``.unrecoverable/`` wird hier
            angelegt.
        tried_algorithms: Reihenfolge der versuchten Schluessel-
            Algorithmen (Algorithmus-Bezeichner, NICHT Schluessel-
            Material). Beispiel: ``["dek_new", "v2_legacy"]``.
        last_error_class: Klassen-Name der zuletzt aufgetretenen
            Fehler-Exception (z. B. ``"DatabaseEncryptionError"``).
        last_error_message: Fehler-Botschaft. Wird zu SHA-256 gehasht
            in den Context geschrieben — der volle Text wird NICHT
            persistiert (kann ggf. Pfad-Komponenten enthalten).
        backend_type: Optional, KeyManager-Backend-Typ aus
:meth:`KeyManager.get_key_metadata`. Default ``None`` falls
            nicht ermittelbar.
        hkdf_salt_version: HKDF-Salt-Version aus dem KeyManager
            (Default ``"v1"``).
        now: Optionaler datetime-Anker. Default ``datetime.now(UTC)``.

    Returns:
        Pfad zur verschobenen DB-Datei in:file:`.unrecoverable/`.

    Raises:
        RuntimeError: Wenn das Suffix-eskalierte Ziel auch schon
            existiert (Mehrfach-Lauf in derselben Sekunde — extrem
            unwahrscheinlich, aber strict).
        OSError: Filesystem-Fehler waehrend Move/Write.
    """
    if now is None:
        now = datetime.now(tz=UTC)

    unrec_dir = db_dir / _UNRECOVERABLE_DIRNAME
    unrec_dir.mkdir(parents=True, exist_ok=True)

    # Reflexions-Regel-3: existierendes Ziel → HHMMSS-Eskalation.
    target = unrec_dir / db_path.name
    if target.exists():
        suffix = now.strftime("%Y%m%d-%H%M%S")
        target = unrec_dir / f"{db_path.stem}-{suffix}.db"
        if target.exists():
            raise FileSystemError(
                f"Unrecoverable-Pfad existiert bereits: {target}. "
                "Mehrfach-Lauf in derselben Sekunde — Migration "
                "abgebrochen, manueller Eingriff noetig."
            )

    # Original-Metadaten VOR Move erfassen.
    src_stat = db_path.stat()
    original_size = src_stat.st_size
    original_mtime_iso = datetime.fromtimestamp(
        src_stat.st_mtime, tz=UTC
    ).isoformat()

    shutil.move(str(db_path), str(target))

    # Context-File schreiben (kein Crypto-Material!).
    error_hash = hashlib.sha256(
        last_error_message.encode("utf-8")
    ).hexdigest()
    context = {
        "schema_version": _UNRECOVERABLE_CONTEXT_SCHEMA_VERSION,
        "db_name": db_path.stem,
        "moved_at": now.isoformat(),
        "tried_algorithms": tried_algorithms,
        "last_error_class": last_error_class,
        "last_error_hash_sha256": error_hash,
        "original_size_bytes": original_size,
        "original_modified_at": original_mtime_iso,
        "key_manager_metadata": {
            "backend_type": backend_type,
            "hkdf_salt_version": hkdf_salt_version,
        },
    }
    context_path = target.with_suffix(".context.json")
    context_path.write_text(
        json.dumps(context, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.warning(
        "DB %s nach %s verschoben (tried_algorithms=%s, last_error=%s).",
        db_path.name,
        target,
        tried_algorithms,
        last_error_class,
    )

    return target


@dataclass(frozen=True)
class MigrationReport:
    """Aggregiertes Ergebnis von:func:`migrate_all_databases`.

    Attributes:
        state: Finaler State-dict — wird vom Caller atomar via
:func:`core.database.migration_state.set_state` persistiert.
        already_migrated: DB-Stem-Namen, die schon mit DEK
            verschluesselt waren (no-op).
        migrated: DB-Stem-Namen, die frisch migriert wurden.
        unrecoverable: DB-Stem-Namen, die nach:file:`.unrecoverable/`
            verschoben wurden.
    """

    state: dict[str, Any]
    already_migrated: list[str] = field(default_factory=list)
    migrated: list[str] = field(default_factory=list)
    unrecoverable: list[str] = field(default_factory=list)


def migrate_all_databases(
    db_dir: Path,
    key_manager: KeyManager,
    *,
    legacy_key_factories: dict[str, Callable[[str], str]] | None = None,
    backup_dir: Path | None = None,
    state: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> MigrationReport:
    """Migriert alle DBs in ``db_dir`` auf den DEK-basierten Schluessel.

    Top-Level-Orchestrator fuer Schritt 3.3. Pro DB:

    1. Wenn der State fuer diese DB schon ``"migrated"`` zeigt, ueberspringen
       (Idempotenz / Resume — siehe MIGRATION_TEST_PLAN I-1, I-2).
    2. Sonst pro Legacy-Algorithmus
       (Default: ``{"v2_legacy": legacy_db_key}``):
       Closure ``functools.partial(factory, db_name)`` als
       ``old_key_func`` an:meth:`KeyManager.migrate_legacy_db` reichen.
       Bei:attr:`MigrationStatus.ALREADY_MIGRATED` /
:attr:`MigrationStatus.MIGRATED`: State-Update + naechste DB.
    3. Wenn alle Legacy-Versuche scheitern:
:func:`handle_unrecoverable` + State ``"failed_v1_v2"``.

    State-Lifecycle:
        - ``state is None`` → frischer Start, alle DBs initial implizit
          ``pending``.
        - Resume-Modus: nur DBs ohne ``"migrated"``-Status werden
          erneut versucht.

    Args:
        db_dir: ``~/.finlai/db/<app_id>/``.
        key_manager: aktiver KeyManager (DEK initialisiert/geladen).
        legacy_key_factories: dict[algo_name, factory(db_name) →
            hex_key]. Default: ``{"v2_legacy": legacy_db_key}`` —
            **Lookup ueber den ``migrate_to_envelope``-Shim**, damit
            test-monkeypatches ``mte.legacy_db_key`` propagieren.
            Tests koennen alternativ synthetische Factories direkt
            injizieren.
        backup_dir: Pfad vom:func:`pre_migration_backup`-Schritt. Wird
            in den State eingetragen. Wenn ``None``: ``state["backup_path"]``
            unveraendert (oder leer bei frischem Start).
        state: Resume-State oder ``None``.
        now: Optionaler datetime-Anker.

    Returns:
:class:`MigrationReport` mit finalem State und Listen pro
        Status. Caller (Bootstrap) persistiert ``report.state`` via
:func:`core.database.migration_state.set_state`.
    """
    if now is None:
        now = datetime.now(tz=UTC)

    if legacy_key_factories is None:
        # Lookup via Shim-Modul, damit Test-Monkeypatches auf
        # ``mte.legacy_db_key`` durchschlagen. Lazy-Import vermeidet
        # Circular-Import beim Modul-Load.
        from core.database import migrate_to_envelope as _mte  # noqa: PLC0415

        legacy_key_factories = {"v2_legacy": _mte.legacy_db_key}

    state = _ensure_state_skeleton(state, backup_dir, now)

    try:
        backend_type = key_manager.get_key_metadata().get("backend_type")
    except Exception:  # noqa: BLE001 -- Diagnose-Helfer, never fail.
        backend_type = None

    already: list[str] = []
    migrated: list[str] = []
    unrecoverable: list[str] = []

    for db_path in sorted(db_dir.glob("*.db")):
        if not db_path.is_file():
            continue
        db_name = db_path.stem

        prior = state["dbs"].get(db_name, {})
        if prior.get("status") == "migrated":
            # Resume: schon erledigt.
            already.append(db_name)
            continue

        # Per-Algorithmus durchprobieren.
        tried: list[str] = []
        last_error_class = ""
        last_error_message = ""
        result_status = MigrationStatus.FAILED

        for algo_name, factory in legacy_key_factories.items():
            tried.append(algo_name)
            old_key_func = functools.partial(factory, db_name)
            try:
                result_status = key_manager.migrate_legacy_db(
                    db_path, old_key_func
                )
            except KeyManagerError:
                # P3-Fix: ``KeyManagerError`` ist ein systemisches
                # Problem (DEK kaputt, DPAPI-Crash, Backend-Wrap-Fehler).
                # Wenn EIN Aufruf das wirft, werden alle weiteren DBs mit
                # derselben Ursache scheitern und faelschlich nach
                # ``.unrecoverable/`` gerollt. Stattdessen propagieren
                # wir den Fehler an den Bootstrap-Caller (apps/__init__.py),
                # der ihn als harten Bootstrap-Fail behandelt — analog zu
                # einem ``initialize``-Fail.
                log.exception(
                    "KeyManagerError waehrend Migration von %s — "
                    "Migration wird sofort abgebrochen, restliche DBs "
                    "bleiben unangetastet.",
                    db_name,
                )
                state["completed_at"] = None
                raise
            except Exception as exc:  # noqa: BLE001 -- last-resort capture.
                last_error_class = type(exc).__name__
                last_error_message = str(exc)
                result_status = MigrationStatus.FAILED
                continue

            if result_status in (
                MigrationStatus.ALREADY_MIGRATED,
                MigrationStatus.MIGRATED,
            ):
                break
            # FAILED → naechsten Algorithmus probieren.
            last_error_class = "MigrationStatus.FAILED"
            last_error_message = (
                f"migrate_legacy_db returned FAILED for algo={algo_name}"
            )

        if result_status == MigrationStatus.ALREADY_MIGRATED:
            state["dbs"][db_name] = {
                "status": "migrated",
                "old_key_algo": None,
                "migrated_at": now.isoformat(),
                "error": None,
            }
            already.append(db_name)
        elif result_status == MigrationStatus.MIGRATED:
            # Letztes erfolgreich getriedes Algo ist der old_key_algo.
            state["dbs"][db_name] = {
                "status": "migrated",
                "old_key_algo": tried[-1],
                "migrated_at": now.isoformat(),
                "error": None,
            }
            migrated.append(db_name)
        else:
            # Alle Versuche gescheitert → unrecoverable.
            handle_unrecoverable(
                db_path,
                db_dir,
                tried_algorithms=tried,
                last_error_class=last_error_class or "Unknown",
                last_error_message=last_error_message or "no message",
                backend_type=backend_type,
                now=now,
            )
            state["dbs"][db_name] = {
                "status": "failed_v1_v2",
                "old_key_algo": None,
                "migrated_at": None,
                "error": last_error_class or "Unknown",
            }
            unrecoverable.append(db_name)

    state["completed_at"] = now.isoformat()

    log.info(
        "Migration abgeschlossen: %d already, %d migrated, %d unrecoverable.",
        len(already),
        len(migrated),
        len(unrecoverable),
    )

    return MigrationReport(
        state=state,
        already_migrated=already,
        migrated=migrated,
        unrecoverable=unrecoverable,
    )


def _ensure_state_skeleton(
    state: dict[str, Any] | None,
    backup_dir: Path | None,
    now: datetime,
) -> dict[str, Any]:
    """Liefert einen vollstaendigen State-dict (Skeleton) — frisch oder Resume."""
    if state is None:
        return {
            "schema_version": 1,
            "started_at": now.isoformat(),
            "completed_at": None,
            "backup_path": str(backup_dir) if backup_dir else None,
            "dbs": {},
            "secure_store": {"status": "pending"},
        }
    # Resume-Pfad: minimale Felder sicherstellen.
    state.setdefault("schema_version", 1)
    state.setdefault("started_at", now.isoformat())
    state.setdefault("completed_at", None)
    state.setdefault(
        "backup_path", str(backup_dir) if backup_dir else None
    )
    state.setdefault("dbs", {})
    state.setdefault("secure_store", {"status": "pending"})
    return state
