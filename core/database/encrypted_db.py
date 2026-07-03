"""
Verschluesselte SQLite-Datenbankverbindung.

Verwendet ausschliesslich sqlcipher3.
Kein Fallback auf unverschluesseltes sqlite3.
Alle FINLAI-Datenbanken nutzen diese Klasse.

Sicherheitsdesign:
  - AES-256-CBC Vollverschluesselung
  - 4096-Byte Seitengroesse (OWASP-Empfehlung)
  - 256.000 KDF-Iterationen (PBKDF2-HMAC-SHA512)
  - HMAC-SHA512 fuer Seitenintegritaet
  - DB-Schluessel via KeyManager.derive_secondary_key(f"db:<name>")
    aus DEK + DPAPI-KEK abgeleitet (Envelope Encryption)
  - Optionaler db_path ausserhalb ~/.finlai/db (z. B. admin-only %ProgramData%)
  - Kein Klartext-Fallback — niemals!

Schichtzugehoerigkeit: core/ (framework-agnostisch).

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import functools
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import sqlcipher3

from core.database.key_manager_context import get_active_key_manager
from core.finlai_paths import finlai_dir
from core.logger import get_logger

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

logger = get_logger(__name__)

DB_DIR = finlai_dir() / "db"


def _get_db_dir_for_name(db_name: str) -> Path:
    """Bestimmt das Verzeichnis für eine DB-Datei.

    Liest den App-ID-Kontext aus ``core.database.db_context``:
    - Kontext gesetzt → ``DB_DIR/<app_id>/`` (strikte Isolation pro App)
    - Kontext nicht gesetzt → ``DB_DIR/`` (nur für Tests ohne App-Boot)

    Alle Produktivpfade laufen über den gesetzten Kontext — ``apps/__init__.py``
    ruft ``set_db_app_id(config.app_id)`` beim App-Start. Eine Rückfall-
    Heuristik auf ältere Pfade (``DB_DIR/<db_name>.db``) existiert bewusst
    NICHT — sie führte zu App-übergreifender Datenkontamination, wenn mehrere
    Apps auf derselben Maschine installiert waren.

    Args:
        db_name: Name der Datenbank ohne Dateiendung.

    Returns:
        Zielverzeichnis (als Path), in dem ``<db_name>.db`` liegt/angelegt wird.
    """
    from core.database.db_context import get_db_app_id  # noqa: PLC0415

    app_id = get_db_app_id()
    if not app_id:
        return DB_DIR  # kein Kontext gesetzt (nur Tests) → Root-Verzeichnis

    return DB_DIR / app_id


def _resolve_consolidated_db_name(db_name: str) -> str:
    """Bildet konsolidierte Tool-DB-Namen auf die gemeinsame DB ab.

    NUR im echten App-Kontext (Produktion, ``get_db_app_id`` gesetzt) werden
    alle User-Context-Tool-DBs auf:data:`CONSOLIDATED_DB_NAME` gelenkt — EINE
    Datei, EIN abgeleiteter Schluessel (``db:norisk``). Ausgenommen bleiben die
    DB selbst,:data:`SEPARATE_DB_NAMES` (network_monitor / system_tuner_snapshots)
    und:data:`LEGACY_DB_NAMES`.

    In Tests OHNE App-Boot (``get_db_app_id is None``) findet KEINE
    Konsolidierung statt -> jeder Name bleibt seine eigene DB (Test-Isolation).
    Effekt: ``EncryptedDatabase("system_scanner")`` landet in Produktion physisch
    in ``norisk.db`` — Aenderung dieser Funktion/Mengen wirkt auf ALLE
    konsolidierten Tools + Schluessel + Pfad + den Alt-DB-Wipe.
    """
    from core.database.consolidation import (  # noqa: PLC0415
        CONSOLIDATED_DB_NAME,
        LEGACY_DB_NAMES,
        SEPARATE_DB_NAMES,
    )

    if (
        db_name == CONSOLIDATED_DB_NAME
        or db_name in SEPARATE_DB_NAMES
        or db_name in LEGACY_DB_NAMES
    ):
        return db_name

    from core.database.db_context import get_db_app_id  # noqa: PLC0415

    if get_db_app_id() is None:
        return db_name  # Test ohne App-Boot -> keine Konsolidierung
    return CONSOLIDATED_DB_NAME


def purge_consolidated_legacy_dbs() -> int:
    """Loescht vor-konsolidierte Per-Tool-DB-Dateien, Full-Wipe).

    Behaelt im App-DB-Verzeichnis nur die konsolidierte DB + die bewusst
    separaten DBs; loescht alle anderen ``*.db`` (+ ``-wal``/``-shm``) UND die
    PII-tragenden Migrations-Backup-Artefakte (``*.bak``/``*.plaintext_backup``),
    die nicht auf ``.db`` enden und den Wipe sonst ueberleben (Review).
    Daten sind verzichtbar (Pre-Production) -> kein Transfer. Einmalig pro
    Maschine (Sentinel ``.db_consolidation_v1``); zweiter Lauf = No-op.

    Returns:
        Anzahl entfernter Alt-DB-Basisdateien (ohne WAL/SHM; ohne die
        zusaetzlich entfernten Backup-Artefakte, die separat geloggt werden).
    """
    from core.database.consolidation import (  # noqa: PLC0415
        CONSOLIDATED_DB_NAME,
        SEPARATE_DB_NAMES,
    )
    from core.database.db_context import get_db_app_id  # noqa: PLC0415

    # Ohne gesetzten App-Kontext liefert _get_db_dir_for_name das DB_DIR-ROOT —
    # ein Wipe dort waere katastrophal. Der Cleanup laeuft AUSSCHLIESSLICH im
    # App-Verzeichnis (DB_DIR/<app_id>/); ohne Kontext: No-op (Review).
    if get_db_app_id() is None:
        return 0

    db_dir = _get_db_dir_for_name(CONSOLIDATED_DB_NAME)
    if not db_dir.exists():
        return 0
    sentinel = db_dir / ".db_consolidation_v1"
    if sentinel.exists():
        return 0

    keep = {CONSOLIDATED_DB_NAME, *SEPARATE_DB_NAMES}
    removed = 0
    for db_file in db_dir.glob("*.db"):
        if db_file.stem in keep:
            continue
        for p in (
            db_file,
            db_file.with_name(db_file.name + "-wal"),
            db_file.with_name(db_file.name + "-shm"),
        ):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("Alt-DB-Cleanup: %s nicht loeschbar: %s", p, exc)
        removed += 1

    # PII-tragende Migrations-/Backup-Artefakte, die NICHT auf ``.db`` enden und
    # den ``*.db``-Wipe sonst ueberleben Full-Wipe = keine PII-Residuen,
    # Review):
    # ``*.bak`` z.B. ``customer_assessment.db.migrated_to_audit.bak``
    # + ``norisk.db.nis2_tamper_v1.bak`` (Voll-Kopie der
    # konsolidierten DB inkl. PII)
    # ``*.plaintext_backup`` Legacy-Klartext->SQLCipher-Migration
    # Beide werden nur auf VOR-konsolidierten Daten erzeugt (auf frischer
    # norisk.db triggern die Erzeuger nicht) -> hier liegen also ausschliesslich
    # Legacy-Residuen. BEWUSST NICHT erfasst: die verwalteten
    # ``pre_migration_backup``-Verzeichnisse (eigene Retention, Recovery-
    # Mechanismus) — das sind keine stale Residuen.
    backups_removed = 0
    for pattern in ("*.bak", "*.plaintext_backup"):
        for artifact in db_dir.glob(pattern):
            if not artifact.is_file():
                continue
            try:
                artifact.unlink()
                backups_removed += 1
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning(
                    "Alt-DB-Cleanup: Backup %s nicht loeschbar: %s", artifact, exc
                )

    try:
        sentinel.write_text(
            "ADR-037 DB-Konsolidierung (Full-Wipe) ausgefuehrt\n", encoding="utf-8"
        )
    except OSError as exc:
        logger.warning("Alt-DB-Cleanup: Sentinel nicht schreibbar: %s", exc)

    if removed or backups_removed:
        logger.info(
            "ADR-037 Alt-DB-Cleanup: %d Per-Tool-DB(s) + %d PII-Backup-Artefakt(e) "
            "entfernt",
            removed,
            backups_removed,
        )
    return removed


# Einheitliche SQLCipher-Konfiguration fuer alle FINLAI-DBs
_CIPHER_PAGE_SIZE = 4096
_KDF_ITER = 256_000
_HMAC_ALGORITHM = "HMAC_SHA512"
_CIPHER_ALGORITHM = "AES-256-CBC"

# Timeout und Retry-Konfiguration
_DB_LOCK_TIMEOUT_SECONDS = 30  # SQLite wartet bis zu 30s auf gesperrte DB
_MAX_RETRIES = 3  # Anzahl Python-seitiger Wiederholungsversuche
_RETRY_BASE_DELAY = 0.5  # Basiswartezeit zwischen Versuchen in Sekunden


# ---------------------------------------------------------------------------
# Spezifische Ausnahmetypen
# ---------------------------------------------------------------------------


class FinLaiDatabaseError(Exception):
    """Basis-Exception für alle DB-Fehler in FINLAI.

    Ersetzt den generischen ``RuntimeError`` der früheren Implementierung.
    Callers können gezielt ``FinLaiDatabaseError`` fangen.
    """


class DatabaseLockedError(FinLaiDatabaseError):
    """DB temporär gesperrt (database is locked / busy) — Retry möglich.

    Tritt auf wenn ein anderer Prozess oder Thread die DB exklusiv hält.
    Nach einem kurzem Warten kann der Zugriff wiederholt werden.
    """


class DatabaseCorruptError(FinLaiDatabaseError):
    """DB-Datei ist strukturell beschädigt — kein automatischer Retry.

    Tritt auf bei Bit-Flip, partiell geschriebener Datei oder defektem
    Dateisystem. Erfordert Wiederherstellung aus einem Backup.
    """


class DatabaseEncryptionError(FinLaiDatabaseError):
    """Encryption-Schlüssel falsch oder DB nicht mit SQLCipher verschlüsselt.

    Tritt auf wenn der abgeleitete DB-Schlüssel nicht mit dem Schlüssel
    übereinstimmt, mit dem die DB ursprünglich erstellt wurde.
    """


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _is_nonempty_file(path: Path) -> bool:
    """True wenn ``path`` eine existierende, nicht-leere Datei ist."""
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _classify_db_error(
    db_name: str,
    exc: Exception,
    db_path: Path | None = None,
) -> FinLaiDatabaseError:
    """Ordnet eine sqlcipher3-Exception dem passenden FinLai-Typ zu.

    SQLCipher liefert bei einem **falschen Schluessel** dieselbe Meldung
    ("file is not a database") wie bei echter Korruption. Zeigt ``db_path``
    auf eine existierende, nicht-leere Datei, ist ein Schluessel-Mismatch
    (DEK-Verlust, Windows-Profilwechsel) die weit haeufigere Ursache als
    physische Korruption — dann wird:class:`DatabaseEncryptionError` mit
    Recovery-Hinweis geliefert statt eines irrefuehrenden
:class:`DatabaseCorruptError`. Ohne ``db_path`` (Unit-Tests, Aufrufer
    ohne Pfad) bleibt das alte Verhalten erhalten — so steht der Fehler am
    richtigen Ort (Schluessel/Bootstrap) statt faelschlich bei "DB korrupt".

    Args:
        db_name: Name der Datenbank (für die Fehlermeldung).
        exc: Original-Exception aus sqlcipher3.
        db_path: Optionaler Pfad zur DB-Datei — aktiviert die
            Wrong-Key-vs-Korruption-Heuristik.

    Returns:
        Spezifische FinLaiDatabaseError-Instanz.
    """
    msg = str(exc).lower()
    if "locked" in msg or "busy" in msg:
        return DatabaseLockedError(f"DB '{db_name}' gesperrt: {exc}")
    # "malformed" = echte strukturelle Korruption (Bit-Flip, truncated) —
    # hat Vorrang vor der Wrong-Key-Heuristik.
    if "malformed" in msg:
        return DatabaseCorruptError(f"DB '{db_name}' korrupt: {exc}")
    # Wrong-Key: SQLCipher meldet bei falschem Schluessel typischerweise
    # "file is encrypted or is not a database", "file is not a database"
    # oder "hmac check failed" — alle drei sind ein Schluessel-Mismatch,
    # KEINE Korruption. Bei existierender, nicht-leerer Datei (db_path) ist
    # das fast immer DEK-Verlust/Profilwechsel → DatabaseEncryptionError mit
    # Recovery-Hinweis.
    if (
        "file is encrypted" in msg
        or "file is not a database" in msg
        or "hmac check failed" in msg
    ):
        if db_path is not None and _is_nonempty_file(db_path):
            return DatabaseEncryptionError(
                f"DB '{db_name}': Entschlüsselung fehlgeschlagen — der "
                f"abgeleitete Schlüssel passt nicht zur Datei (DEK-Verlust "
                f"oder Windows-Profilwechsel?). Die Datei ist NICHT korrupt: "
                f"{exc}. Recovery: migration-*.log und .unrecoverable/ im "
                f"FINLAI-Datenverzeichnis prüfen."
            )
        # Ohne Pfad-Kontext (Unit-Tests / Aufrufer ohne Pfad): "file is
        # encrypted" → Verschluesselungsfehler; nacktes "file is not a
        # database" → Korruption (Rueckwaerts-Kompat, 2-Argument-Aufruf).
        if "file is encrypted" in msg:
            return DatabaseEncryptionError(
                f"Verschlüsselungsfehler in DB '{db_name}': {exc}"
            )
        return DatabaseCorruptError(f"DB '{db_name}' korrupt: {exc}")
    return FinLaiDatabaseError(f"Datenbankfehler in DB '{db_name}': {exc}")


def with_db_retry(func):
    """Decorator: Wiederholt eine DB-Operation bei ``DatabaseLockedError``.

    Kann auf Repository-Methoden angewendet werden, die besonders häufig
    gleichzeitig von mehreren Threads aufgerufen werden (z.B. Scheduler +
    GUI). Verwendet exponentiellen Backoff zwischen den Versuchen.

    Das Timeout in ``sqlcipher3.connect`` (``_DB_LOCK_TIMEOUT_SECONDS``)
    ist die erste Verteidigungslinie — dieser Decorator ist die zweite.

    Args:
        func: Repository-Methode, die ``with db.connection`` verwendet.

    Returns:
        Wrapped function mit Retry-Logik.

    Example::

        class MyRepository:
            @with_db_retry
            def save(self, obj):
                with self._db.connection as conn:
                    conn.execute("INSERT...")
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except DatabaseLockedError:
                if attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * attempt
                    logger.warning(
                        "DB locked (Versuch %d/%d) — Retry in %.1fs: %s",
                        attempt,
                        _MAX_RETRIES,
                        delay,
                        func.__qualname__,
                    )
                    time.sleep(delay)
                    continue
                raise

    return wrapper


def _derive_db_key(
    db_name: str,
    key_manager: KeyManager | None = None,
) -> str:
    """Leitet einen DB-spezifischen Schluessel ueber den KeyManager ab.

    Jede Datenbank bekommt einen eigenen 256-bit-Sekundaerschluessel via
    HKDF-Domain-Separation aus dem DEK des KeyManager §2.4).
    Kompromittierung einer DB gefaehrdet keine anderen.

    Purpose-String ``f"db:{db_name}"`` trennt DB-Schluessel von anderen
    Sekundaerschluessel-Familien (``"secure_storage"``,
    ``"audit_log_hmac"``,...).

    Hex-Konvertierung an genau dieser Stelle: ``derive_secondary_key``
    liefert 32 ``bytes``, SQLCipher erwartet einen 64-stelligen Hex-
    String fuer ``PRAGMA key="<hex>"`` (:func:`_configure_connection`).

    Args:
        db_name: Name der Datenbank (z.B. ``"accounts"``).
        key_manager: Optionaler expliziter ``KeyManager`` (Constructor-
            Injection §2.5 β-Variante). Wenn ``None`` (Default),
            wird der aktive Manager aus:mod:`core.database.key_manager_context`
            verwendet (Variante A — App-Bootstrap-Pfad).

    Returns:
        64-stelliger Hex-String fuer ``PRAGMA key``.

    Raises:
        RuntimeError: Kein expliziter ``key_manager`` und kein aktiver
            Manager im Modul-State (typisch: ``apps.launch_app`` hat
            ``set_active_key_manager`` nicht aufgerufen).
        KeyManagerNotInitializedError: ``master.key.wrapped`` existiert
            nicht (transitiv via:meth:`KeyManager.derive_secondary_key`).
        KeyManagerCorruptError: DEK nicht entschluesselbar (transitiv).
        KeyManagerPermissionError: DEK-Datei nicht lesbar (transitiv).
    """
    km = key_manager if key_manager is not None else get_active_key_manager()
    derived = km.derive_secondary_key(f"db:{db_name}")
    return derived.hex()


def _configure_connection(conn: Any, key: str, *, raw_key: bool = True) -> None:
    """Konfiguriert eine SQLCipher-Verbindung.

    Muss als ERSTES nach connect aufgerufen werden —
    vor jedem anderen Statement! SQLCipher-Anforderung.

    Einheitliche Cipher-Konfiguration fuer alle FINLAI-DBs:
    AES-256-CBC, 4096-Byte-Seiten, HMAC-SHA512.

    Args:
        conn: sqlcipher3-Verbindung (unmittelbar nach connect).
        key: DB-Schluessel als 64-stelliger Hex-String (32 Byte).
        raw_key: ``True`` (Default) → der Hex wird als ROHER AES-256-
            Schluessel uebergeben (``PRAGMA key="x'<hex>'"``); SQLCipher
            ueberspringt die PBKDF2-Passphrasen-Ableitung (~93 ms → ~2 ms pro
            Open). Kryptografisch unbedenklich: ``key`` ist bereits ein
            256-bit-HKDF-Derivat aus dem DPAPI-DEK — PBKDF2 darauf
            haerte nichts. ``False`` → alter String-Key-Pfad (PBKDF2 ueber
            ``_KDF_ITER``); ausschliesslich fuer die Legacy→DEK-Migration, die
            Bestands-DBs im alten Format lesen/rekey'en muss.
    """
    # PRAGMA key MUSS das allererste Statement sein!
    if raw_key:
        # Raw-Key: Hex direkt als AES-Schluessel, kein PBKDF2.
        conn.execute(f"PRAGMA key=\"x'{key}'\"")
    else:
        # Legacy String-Key: PBKDF2 ueber die Hex-Passphrase.
        conn.execute(f'PRAGMA key="{key}"')

    # Cipher-Konfiguration
    conn.execute(f"PRAGMA cipher_page_size={_CIPHER_PAGE_SIZE}")
    if not raw_key:
        # KDF-Parameter sind nur im String-Key-Pfad relevant — bei Raw-Key
        # gibt es keine Passphrasen-Ableitung (das ist der Perf-Gewinn).
        conn.execute(f"PRAGMA kdf_iter={_KDF_ITER}")
        conn.execute("PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512")
    conn.execute(f"PRAGMA cipher_hmac_algorithm={_HMAC_ALGORITHM}")

    # Performance und Integritaet
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    # busy_timeout: bei Multi-Writer-Zugriff auf EINE konsolidierte DB
    # (GUI + Fleet-Agent) wartet SQLite intern bis 5 s auf das Schreib-Lock,
    # statt sofort "database is locked" zu werfen. BEWUSST 5 s (nicht die 30 s
    # des connect(timeout=)-Defaults, den dieses PRAGMA ueberschreibt): kurze
    # Wartezeit pro Versuch + App-seitiges with_db_retry = schnelles Fail-and-
    # Retry statt langem GUI-Freeze. Unter WAL blockieren Reader ohnehin nie.
    conn.execute("PRAGMA busy_timeout=5000")


class EncryptedDatabase:
    """Verschluesselte SQLite-Datenbank via SQLCipher.

    Verwendet sqlcipher3 fuer AES-256-CBC Vollverschluesselung.
    Der DB-Schluessel wird via ``KeyManager.derive_secondary_key(f"db:<name>")``
    aus dem DEK abgeleitet (Envelope Encryption §2.4). Der DEK
    selbst ist DPAPI-gewrappt an den Windows-User-Login gebunden. Optional kann
    ein expliziter ``db_path`` (ausserhalb ~/.finlai/db, z. B. die admin-only
    %ProgramData%-Snapshot-DB) uebergeben werden — der Schluessel kommt weiter
    aus dem KeyManager (Default-Lookup oder ``key_manager``-Injektion).

    Jede Datenbank hat einen eigenen Schluessel (Domain-Separation via
    HKDF-info).
    Kein Fallback auf Klartext — niemals!

    Beispiel:
        db = EncryptedDatabase("accounts")
        with db.connection as conn:
            rows = conn.execute(
                "SELECT * FROM accounts"
).fetchall
    """

    def __init__(
        self,
        db_name: str,
        *,
        key_manager: KeyManager | None = None,
        db_path: Path | None = None,
    ) -> None:
        """Initialisiert die verschluesselte Datenbank.

        Args:
            db_name: Datenbankname ohne Dateiendung.
                Dateipfad: ~/.finlai/db/<app_id>/<db_name>.db (wenn App-Kontext gesetzt)
                           ~/.finlai/db/<db_name>.db (nur Tests ohne Boot)
            key_manager: Optionaler expliziter ``KeyManager`` fuer
                Constructor-Injection §2.5 β-Variante). Default:
                aktiver Manager aus:mod:`core.database.key_manager_context`.
                Tests koennen einen dedizierten Manager mit
                ``InMemoryDPAPIBackend`` injizieren, ohne den Modul-
                State zu beruehren.
            db_path: Optionaler **expliziter** Dateipfad. Wenn gesetzt, wird die
                app-id-abgeleitete Verzeichnislogik uebersprungen — fuer DBs, die
                NICHT in ``~/.finlai/db`` liegen duerfen (z. B. die admin-only
                ``%ProgramData%``-Snapshot-DB des system_tuner). Default: app-id-
                Verzeichnis.

        Raises:
            RuntimeError: Falls sqlcipher3 nicht importierbar ist, oder
                falls weder ``key_manager`` uebergeben wurde noch ein aktiver
                KeyManager im Modul-State liegt.
        """
        try:
            import sqlcipher3 as _chk  # noqa: F401, PLC0415
        except ImportError as exc:
            from core.exceptions import ConfigurationError  # noqa: PLC0415

            raise ConfigurationError(
                "sqlcipher3 nicht installiert!\n"
                "Bitte ausfuehren:\n"
                "pip install sqlcipher3"
            ) from exc

        if db_path is not None:
            # Expliziter Pfad umgeht die app-id-Verzeichnislogik BEWUSST — und
            # daher AUCH den-Remap: sonst entstuende ein Key/Pfad-
            # Mismatch (db:norisk-Schluessel auf eine Fremddatei). Key + Pfad
            # nutzen konsequent den Original-Namen (Review).
            self._db_name = db_name
            self._db_key = _derive_db_key(db_name, key_manager=key_manager)
            self._db_path = db_path
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info("EncryptedDatabase '%s' bereit: %s", db_name, self._db_path)
        else:
            # konsolidierte Tool-DBs auf die gemeinsame DB lenken (nur
            # im echten App-Kontext; Tests ohne Boot bleiben isoliert).
            resolved_name = _resolve_consolidated_db_name(db_name)
            self._db_name = resolved_name
            self._db_key = _derive_db_key(resolved_name, key_manager=key_manager)
            _resolved_dir = _get_db_dir_for_name(resolved_name)
            _resolved_dir.mkdir(parents=True, exist_ok=True)
            self._db_path = _resolved_dir / f"{resolved_name}.db"
            if resolved_name != db_name:
                logger.info(
                    "EncryptedDatabase '%s' -> konsolidiert '%s': %s",
                    db_name,
                    resolved_name,
                    self._db_path,
                )
            else:
                logger.info(
                    "EncryptedDatabase '%s' bereit: %s", db_name, self._db_path
                )

    @property
    def db_path(self) -> Path:
        """Pfad zur Datenbank-Datei (read-only).

        Nuetzlich fuer Cross-DB-Migrationen, in denen ein Repository
        die Existenz einer alten DB-Datei pruefen muss, bevor es eine
        zweite ``EncryptedDatabase``-Instanz fuer den Lesepfad oeffnet.
        """
        return self._db_path

    @contextmanager
    def connection(self) -> Generator[Any, None, None]:
        """Erstellt eine verschluesselte Datenbankverbindung.

        Automatisches commit bei Erfolg, rollback bei Exception.
        Die Verbindung wird immer geschlossen.

        Setup-Phase (connect + configure + verify) wird bei DB-Lock
        bis zu ``_MAX_RETRIES`` Mal wiederholt. Innerhalb des with-Blocks
        greift das SQLite-interne Timeout (``_DB_LOCK_TIMEOUT_SECONDS``).

        Yields:
            Konfigurierte sqlcipher3-Verbindung.

        Raises:
            DatabaseLockedError: DB nach allen Retry-Versuchen noch gesperrt.
            DatabaseCorruptError: DB-Datei strukturell beschaedigt.
            DatabaseEncryptionError: Falscher Schluessel oder nicht SQLCipher.
            FinLaiDatabaseError: Sonstiger Datenbankfehler.
        """
        conn: Any = None
        for attempt in range(1, _MAX_RETRIES + 1):
            _conn = sqlcipher3.connect(
                str(self._db_path),
                timeout=_DB_LOCK_TIMEOUT_SECONDS,
            )
            try:
                _configure_connection(_conn, self._db_key)
                # Verbindung verifizieren — schlaegt bei falschem Key fehl
                _conn.execute("SELECT count(*) FROM sqlite_master")
                conn = _conn
                break
            except sqlcipher3.DatabaseError as exc:
                _conn.close()
                msg = str(exc).lower()
                if ("locked" in msg or "busy" in msg) and attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * attempt
                    logger.warning(
                        "DB '%s' setup gesperrt (%d/%d) — Retry in %.1fs",
                        self._db_name,
                        attempt,
                        _MAX_RETRIES,
                        delay,
                    )
                    time.sleep(delay)
                else:
                    raise _classify_db_error(
                        self._db_name, exc, self._db_path
                    ) from exc
            except Exception:  # noqa: BLE001 -- Cleanup-Handler: Verbindung schliessen und re-raisen, jede Exception
                _conn.close()
                raise

        try:
            yield conn
            conn.commit()
        except sqlcipher3.DatabaseError as exc:
            conn.rollback()
            logger.error(
                "DB-Fehler in '%s': %s",
                self._db_name,
                exc,
            )
            raise _classify_db_error(
                self._db_name, exc, self._db_path
            ) from exc
        except Exception:  # noqa: BLE001 -- Cleanup-Handler: Rollback und re-raisen, jede Exception
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self, schema_sql: str) -> None:
        """Erstellt das Datenbankschema falls nicht vorhanden.

        Idempotent — kann mehrfach aufgerufen werden wenn
        alle Statements CREATE TABLE IF NOT EXISTS verwenden.

        Args:
            schema_sql: SQL mit CREATE TABLE Statements.
        """
        with self.connection() as conn:
            conn.executescript(schema_sql)
        logger.info("Schema '%s' initialisiert.", self._db_name)

    def migrate_from_plaintext(self, old_db_path: Path) -> None:
        """Migriert eine unverschluesselte sqlite3-Datenbank zu SQLCipher.

        Liest alle Tabellen und Daten aus der alten Datenbank und
        kopiert sie in die verschluesselte Datenbank. Tabellen werden
        nur angelegt wenn sie noch nicht existieren (IF NOT EXISTS).
        Die alte Datei wird nach Abschluss umbenannt — nicht geloescht.

        Args:
            old_db_path: Pfad zur unverschluesselten sqlite3-Datei.
        """
        if not old_db_path.exists():
            logger.debug("Keine alte DB gefunden: %s", old_db_path)
            return

        logger.info(
            "Migriere %s zu verschluesselter DB...",
            old_db_path.name,
        )

        old_conn = sqlite3.connect(str(old_db_path))
        old_conn.row_factory = sqlite3.Row

        try:
            tables = old_conn.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='table' AND sql IS NOT NULL "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()

            with self.connection() as new_conn:
                for table in tables:
                    tname = table["name"]
                    table_sql = table["sql"]

                    # IF NOT EXISTS einfuegen falls noch nicht vorhanden
                    # — damit Migration auch nach init_schema funktioniert
                    if "IF NOT EXISTS" not in table_sql.upper():
                        table_sql = table_sql.replace(
                            "CREATE TABLE ",
                            "CREATE TABLE IF NOT EXISTS ",
                            1,
                        )
                    new_conn.execute(table_sql)

                    rows = old_conn.execute(
                        f"SELECT * FROM {tname}"  # noqa: S608 # nosec B608
                    ).fetchall()

                    if rows:
                        placeholders = ",".join(["?"] * len(rows[0]))
                        new_conn.executemany(
                            f"INSERT INTO {tname} VALUES ({placeholders})",  # noqa: S608 # nosec B608
                            [tuple(r) for r in rows],
                        )
                    logger.info("  %s: %d Zeilen migriert", tname, len(rows))
        finally:
            old_conn.close()

        backup = old_db_path.with_suffix(".db.plaintext_backup")
        old_db_path.rename(backup)
        logger.info("Migration OK. Backup: %s", backup.name)
