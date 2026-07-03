"""
encryption — Verschlüsselte Key-Value-Speicherung für FINLAI (S2).

Verwendet Fernet-symmetrische Verschlüsselung. Der Fernet-Schlüssel
wird seit Subtask 2 via
``KeyManager.derive_secondary_key("secure_storage")`` aus dem DEK
abgeleitet — der DEK selbst ist DPAPI-CurrentUser-gewrappt an den
Windows-User-Login gebunden. Dadurch sind gespeicherte Werte an
das User-Profile auf dieser Maschine gebunden, NICHT mehr an die
Hardware-Konfiguration (Trennung License-Binding ↔ Data
Confidentiality §2.4).

Sicherheitsdesign:
  - HKDF-SHA256 ueber DEK (256 Bit) mit Domain-Separation
    via ``info=f"finlai.purpose.secure_storage"``
  - DEK-Schicht: 256-bit zufaellig + DPAPI-CurrentUser-Wrap
    (:mod:`core.database.key_manager`)
  - Kein API-Key, Token oder Secret wird je im Klartext gespeichert
  - Fernet garantiert authenticated encryption (AES-128-CBC + HMAC-SHA256)

WARNUNG: Wenn ``~/.finlai/master.key.wrapped`` geloescht wird oder
das Windows-User-Profile wechselt, sind alle verschluesselten Daten
unwiederbringlich verloren! Recovery-Pfad: User-bestaetigte Re-Init
via Migration-Flow (Subtask 3).

Bestandsdaten-Migration: Die bisher hardware-fingerprint-gebundenen
SecureStorage-Daten werden in Subtask 3 ueber den Legacy-Pfad
:func:`_derive_key` (DeprecationWarning) gelesen und mit dem neuen
DEK-abgeleiteten Schluessel re-verschluesselt. Die analoge
EncryptedDatabase-Migration nutzt eine Inline-Replikation der
Pre-Subtask-2-PBKDF2-Logik in
:func:`core.database.migrate_to_envelope._derive_legacy_integrity_key`
 Cleanup — die alte Public-Funktion in diesem Modul ist weg).

Abhängigkeit: pip install cryptography>=42.0.0

Author: Patrick Riederich
Version: 2.0 (Subtask 2: KeyManager-Integration)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import shutil
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.database.key_manager_context import get_active_key_manager
from core.finlai_paths import finlai_dir
from core.logger import get_logger

if TYPE_CHECKING:
    from core.database.key_manager import KeyManager

# Type-Alias fuer den Corruption-Observer-Callback. Empfaengt den
# Pfad der korrupten Datei und (falls schon gesichert) den Backup-Pfad.
# ``None`` als Backup-Pfad bedeutet: Corruption beim Read erkannt, Backup
# wurde noch nicht angelegt — passiert erst beim naechsten ``set``.
CorruptionObserver = Callable[[Path, Path | None], None]


class SecureStorageUnavailableError(RuntimeError):
    """Erhoben, wenn SecureStorage fail-closed nicht genutzt werden kann.

    Indikator fuer Sicherheits-relevante Init-Fehler (DPAPI-Drift,
    KeyManager-Korruption, Profile-Wechsel). Abgegrenzt vom ImportError-
    Fall (``cryptography``-Library fehlt), der weiter als weicher Read-
    Only-Mode behandelt wird — Library-Fehlen ist kein Schluessel-Verlust.

    Erfuellt dieirektive "Verschluesselung fail-closed:
    RuntimeError wenn Schluessel fehlt, kein Klartext-Fallback":
    ``set``/``get``/``delete`` werfen diese Exception statt stiller
    False/None/no-op-Returns, damit Lesefehler nach DPAPI-Drift den
    Caller laut anschlagen statt unbemerkt zu maskieren.

    Recovery-Pfad: MainWindow prueft ``SecureStorage.init_error`` nach
    ``get_secure_storage`` und triggert den bestehenden Corruption-
    Recovery-Dialog-Pattern erweitert um Init-Errors).
    """


_log = get_logger(__name__)

_SALT_FILE = finlai_dir() / ".salt"
_STORE_FILE = finlai_dir() / "secure_store.enc"
_KEY_ITERATIONS = 480_000  # OWASP 2024 Empfehlung für PBKDF2-HMAC-SHA256
_lock = threading.Lock()  # Schutz gegen Race-Conditions beim Singleton


# ---------------------------------------------------------------------------
# Interne Hilfsfunktionen
# ---------------------------------------------------------------------------


def _get_or_create_salt() -> bytes:
    """Lädt oder erstellt das kryptografische Salt.

    Das Salt wird einmalig zufällig generiert und nie verändert.
    Verlust des Salt = Verlust aller verschlüsselten Daten.

    Returns:
        32-Byte-Salt.
    """
    try:
        if _SALT_FILE.exists():
            salt = _SALT_FILE.read_bytes()
            if len(salt) == 32:
                return salt
            _log.warning("Salt-Datei hat ungültige Größe — neu erstellen.")

        salt = os.urandom(32)
        _SALT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SALT_FILE.write_bytes(salt)
        # Nur Owner darf lesen (wird auf Windows ignoriert, aber kein Fehler)
        try:
            _SALT_FILE.chmod(0o600)
        except (OSError, NotImplementedError):
            pass
        _log.debug("Neues Salt erstellt.")
        return salt

    except OSError as exc:
        _log.error("Salt-Datei nicht lesbar/schreibbar: %s", exc)
        from core.exceptions import CryptoError  # noqa: PLC0415

        raise CryptoError("Kryptografisches Salt nicht verfügbar.") from exc


def _derive_key(password: str) -> bytes:
    """Leitet einen Fernet-kompatiblen Schluessel aus einem Passwort ab.

    Legacy-Funktion seit Subtask 2: Wird NICHT mehr von
:class:`SecureStorage` genutzt. Bleibt fuer Subtask 3
    (Bestandsdaten-Migration) erhalten — die Migration liest alte
    ``secure_store.enc``-Dateien mit diesem Pfad
    (``_derive_key(get_hardware_fingerprint)``) und re-verschluesselt
    sie mit dem KeyManager-DEK-abgeleiteten Fernet-Key.

    Verwendet PBKDF2-HMAC-SHA256 mit 480.000 Iterationen.

    Args:
        password: Ableitungspasswort (typisch: Hardware-Fingerprint
            der Bestandsdaten).

    Returns:
        Base64url-kodierter 32-Byte-Schluessel fuer Fernet.

    Raises:
        ImportError: Wenn cryptography nicht installiert ist.
    """
    try:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.kdf.pbkdf2 import (
            PBKDF2HMAC,  # noqa: PLC0415
        )
    except ImportError as exc:
        raise ImportError(
            "Das Paket 'cryptography' ist nicht installiert. "
            "Bitte 'pip install cryptography>=42.0.0' ausführen."
        ) from exc

    salt = _get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KEY_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# ---------------------------------------------------------------------------
# SecureStorage
# ---------------------------------------------------------------------------


class SecureStorage:
    """Verschluesselte Key-Value-Speicherung fuer sensible Daten.

    Verschluesselt Werte (API-Keys, Tokens, URLs) mit Fernet symmetrischer
    Verschluesselung. Der Fernet-Schluessel wird seit Subtask 2
    via ``KeyManager.derive_secondary_key("secure_storage")`` aus dem
    DEK abgeleitet — der DEK ist DPAPI-CurrentUser-gewrappt. Werte sind
    damit an das **Windows-User-Profile** gebunden, NICHT mehr an die
    Hardware-Konfiguration (Trennung License/Crypto §2.4).

    Verwendung:
        storage = SecureStorage
        storage.set("nvd_api_key", "mein-key")
        key = storage.get("nvd_api_key")

    Sicherheit:
        - API-Keys werden NIE im Klartext gespeichert
        - Jeder set-Aufruf re-verschluesselt die gesamte Store-Datei
        - Lesefehler geben den Default zurueck (fail-safe)
    """

    def __init__(self, *, key_manager: KeyManager | None = None) -> None:
        """Initialisiert SecureStorage mit DEK-abgeleitetem Fernet-Schluessel.

        Args:
            key_manager: Optionaler expliziter ``KeyManager`` fuer
                Constructor-Injection §2.5 β-Variante). Default:
                aktiver Manager aus:mod:`core.database.key_manager_context`.
                Tests koennen einen dedizierten Manager mit
                ``InMemoryDPAPIBackend`` injizieren, ohne den Modul-
                State zu beruehren.

        Effekt: Bei fehlendem KeyManager (kein Bootstrap, keine Injection),
        bei DPAPI-Fehler (Profile-Wechsel) oder bei fehlender
        ``cryptography``-Library wird ``self._available`` auf ``False``
        gesetzt — kein Crash, keine Klartext-Daten. ``set``/``get``
        pruefen die Verfuegbarkeit und geben sicher fail.
        """
        # Corruption-Observer-Liste. ``_load_all`` ruft die
        # Callbacks beim ersten erkannten Fernet-InvalidToken auf einer
        # nicht-leeren Datei auf — MainWindow nutzt das, um den User
        # ueber einen Recovery-Dialog zu warnen. Per-Instance damit Tests
        # nicht gegeneinander leaken. Idempotent: ``_corruption_reported``
        # verhindert wiederholtes Feuern.
        #
        # ``_last_load_failed`` ist die zentrale Wahrheit zwischen
        # ``_load_all`` und ``set``: bei InvalidToken auf einer nicht-
        # leeren Datei wird das Flag gesetzt, ``set`` triggert dann
        # ``_backup_corrupted_store``. So unterscheiden wir "legitimes
        # leeres Dict" (`{}`) von "Datei nicht entschluesselbar" — das
        # alte ``not data``-Check war ein False-Positive-Forensik
        # 2026-05-12: Subtask-3-Migration hat `{}` geschrieben, das
        # naechste ``set`` hat das faelschlicherweise als Korruption
        # eingestuft + gebackupt).
        self._corruption_observers: list[CorruptionObserver] = []
        self._corruption_reported: bool = False
        self._last_load_failed: bool = False
        #fail-closed: bei Sicherheits-Indikator-Init-Fehler
        # (DPAPI-Drift, KeyManager-Korruption) merken wir den Fehler.
        # ``set``/``get``/``delete`` werfen dann ``SecureStorageUnavailableError``
        # statt stiller False/None/no-op. ImportError-Fall (cryptography
        # fehlt) bleibt soft Read-Only — Library-Fehlen ist kein
        # Schluessel-Verlust.
        self._init_error: Exception | None = None

        try:
            from cryptography.fernet import Fernet  # noqa: PLC0415

            from core.database.key_manager import KeyManagerError  # noqa: PLC0415

            km = key_manager if key_manager is not None else get_active_key_manager()
            # KeyManager liefert 32 rohe Bytes; Fernet erwartet
            # base64url-kodierten 32-Byte-Key (44 ASCII-Zeichen).
            raw_secondary = km.derive_secondary_key("secure_storage")
            fernet_key = base64.urlsafe_b64encode(raw_secondary)
            self._fernet = Fernet(fernet_key)
            self._available = True
            _log.debug("SecureStorage initialisiert (KeyManager-DEK).")
        except ImportError as exc:
            _log.error("SecureStorage nicht verfuegbar: %s", exc)
            self._available = False
        except (OSError, RuntimeError, ValueError, KeyManagerError) as exc:
            _log.error(
                "SecureStorage Init fail-closed (%s) — Security-Pflicht.",
                type(exc).__name__,
            )
            self._available = False
            self._init_error = exc

    # ------------------------------------------------------------------
    # Corruption-Observer-Hook (Recovery-UX)
    # ------------------------------------------------------------------
    def add_corruption_observer(self, callback: CorruptionObserver) -> None:
        """Registriert einen Callback fuer den ersten Corruption-Event.

        ``_load_all`` ruft alle registrierten Observer **einmalig** auf,
        wenn ``secure_store.enc`` existiert + nicht-leer ist, aber Fernet
        die Entschluesselung mit ``InvalidToken`` ablehnt. Typische Ursache:
        DPAPI-Drift zwischen Schreib- und Lesevorgang (THREAT_MODEL R-8 —
        z. B. nach Windows-Update oder User-Profile-Aenderung). Der
        Observer kriegt den Pfad der korrupten Datei und (sofern bereits
        gesichert) den Pfad des ``.bak_*``-Backups — sonst ``None``.

        Effekt: MainWindow registriert hier einen Lambda der ein Qt-Signal
        emittiert (siehe ``core/main_window.py``). Das Signal wird per
        ``QueuedConnection`` auf den GUI-Thread geroutet, der dann den
        Recovery-Dialog oeffnet. Der Hook ist absichtlich Qt-frei — core/
        darf nicht an PySide6 koppeln.

        Args:
            callback: Wird mit ``(corrupted_path, backup_path | None)``
                aufgerufen. Exceptions im Callback werden geloggt und
                geschluckt, damit SecureStorage trotzdem fail-safe bleibt.
        """
        self._corruption_observers.append(callback)

    def _emit_corruption_event(self, backup_path: Path | None) -> None:
        """Feuert die registrierten Observer einmalig.

        Idempotent: nachfolgende Aufrufe sind no-op (``_corruption_reported``-
        Flag). Exceptions in Observers werden geloggt und nicht propagiert —
        ein fehlerhafter Observer darf SecureStorage nicht beeintraechtigen.
        """
        if self._corruption_reported:
            return
        self._corruption_reported = True
        for cb in self._corruption_observers:
            try:
                cb(_STORE_FILE, backup_path)
            except Exception as exc:  # noqa: BLE001 — Observer darf SecureStorage nie crashen
                _log.error(
                    "SecureStorage corruption-observer raised %s — ignoriert.",
                    type(exc).__name__,
                )

    @property
    def is_available(self) -> bool:
        """True wenn SecureStorage einsatzbereit ist."""
        return self._available

    @property
    def init_error(self) -> Exception | None:
        """Init-Error wenn fail-closed wegen Sicherheits-Indikator, sonst None.

        Wird vom MainWindow nach ``get_secure_storage`` geprueft —
        wenn nicht ``None``, triggert das den Recovery-Dialog
-Pattern erweitert um Init-Errors).
        """
        return self._init_error

    def set(self, key: str, value: str) -> bool:
        """Speichert einen Wert verschlüsselt.

        Wenn die bestehende Store-Datei nicht entschlüsselt werden kann
        (z.B. nach Hardware-Fingerprint-Änderung), wird die alte Datei
        gesichert und ein neuer Store erstellt, damit der Wert nicht
        verloren geht.

        Args:
            key: Schlüssel (nur ASCII, kein Leerzeichen).
            value: Zu speichernder Wert (z. B. API-Key).

        Returns:
            True wenn der Wert erfolgreich gespeichert wurde.

        Raises:
            SecureStorageUnavailableError: Wenn ``_init_error`` gesetzt ist
                (DPAPI-Drift, KeyManager-Korruption).flicht:
                fail-closed statt stilles ``return False``.
        """
        if self._init_error is not None:
            raise SecureStorageUnavailableError(
                f"SecureStorage fail-closed wegen Init-Error "
                f"({type(self._init_error).__name__}). Recovery erforderlich."
            ) from self._init_error
        if not self._available:
            _log.warning("SecureStorage nicht verfügbar — Wert nicht gespeichert.")
            return False
        try:
            data = self._load_all()

            # Korruptions-Detection ueber das ``_last_load_failed``-
            # Flag aus ``_load_all`` (gesetzt nur bei tatsaechlichem
            # InvalidToken). Der alte ``not data``-Check war ein False-
            # Positive — ein legitimes ``{}`` im Store (z. B. nach
            # Subtask-3 ``MIGRATED_EMPTY``) wurde dort als korrupt
            # eingestuft und das File unnoetig gebackupt. Forensik-
            # Befund 2026-05-12.
            if self._last_load_failed:
                _log.warning(
                    "Store-Datei nicht entschluesselbar (InvalidToken) — "
                    "Backup erstellen und neu beginnen."
                )
                self._backup_corrupted_store()
                # Flag zuruecksetzen: Backup erledigt + neuer Store
                # wird gleich mit aktuellem Key geschrieben.
                self._last_load_failed = False
                # Wir wissen jetzt: alter Inhalt verloren, kein Merge
                # moeglich. ``data`` ist {} aus _load_all — bleibt {}.

            data[key] = value
            encrypted = self._fernet.encrypt(
                json.dumps(data, ensure_ascii=False).encode("utf-8")
            )
            _STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _STORE_FILE.write_bytes(encrypted)
            try:
                _STORE_FILE.chmod(0o600)
            except (OSError, NotImplementedError):
                pass
            return True
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.error("SecureStorage.set fehlgeschlagen: %s", type(exc).__name__)
            return False

    def _backup_corrupted_store(self) -> None:
        """Sichert eine nicht-entschlüsselbare Store-Datei mit Zeitstempel.

        Nach erfolgreichem Backup werden die Corruption-Observer
        re-emittiert mit dem konkreten Backup-Pfad — selbst wenn die
        Observer schon einmal mit ``backup_path=None`` informiert wurden
        (durch ``_load_all``). Damit kann der Recovery-Dialog den Pfad
        zur Sicherungskopie anzeigen.
        """
        try:
            ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
            backup = _STORE_FILE.with_suffix(f".bak_{ts}")
            shutil.copy2(_STORE_FILE, backup)
            _STORE_FILE.unlink()
            _log.warning("Korrupter Store gesichert als: %s", backup.name)
            # Backup-Pfad nachreichen — Observer wurde ggf.
            # vorher schon ohne Pfad benachrichtigt (Load vor Set).
            # Wir setzen das Flag zurueck, damit der re-emit greift.
            self._corruption_reported = False
            self._emit_corruption_event(backup_path=backup)
        except OSError as exc:
            _log.error("Store-Backup fehlgeschlagen: %s", exc)

    def get(self, key: str, default: str | None = None) -> str | None:
        """Lädt und entschlüsselt einen Wert.

        Args:
            key: Schlüssel.
            default: Rückgabewert wenn Schlüssel nicht vorhanden.

        Returns:
            Entschlüsselter Wert oder default.

        Raises:
            SecureStorageUnavailableError: Wenn ``_init_error`` gesetzt ist
                (DPAPI-Drift, KeyManager-Korruption).flicht:
                fail-closed statt stilles ``return default``.
        """
        if self._init_error is not None:
            raise SecureStorageUnavailableError(
                f"SecureStorage fail-closed wegen Init-Error "
                f"({type(self._init_error).__name__}). Recovery erforderlich."
            ) from self._init_error
        if not self._available:
            return default
        try:
            data = self._load_all()
            return str(data[key]) if key in data else default
        except (OSError, RuntimeError, ValueError, KeyError):
            return default

    def delete(self, key: str) -> None:
        """Löscht einen Schlüssel aus dem Store.

        Args:
            key: Zu löschender Schlüssel.

        Raises:
            SecureStorageUnavailableError: Wenn ``_init_error`` gesetzt ist
                (DPAPI-Drift, KeyManager-Korruption).flicht:
                fail-closed statt stilles no-op.
        """
        if self._init_error is not None:
            raise SecureStorageUnavailableError(
                f"SecureStorage fail-closed wegen Init-Error "
                f"({type(self._init_error).__name__}). Recovery erforderlich."
            ) from self._init_error
        if not self._available:
            return
        try:
            data = self._load_all()
            if key in data:
                del data[key]
                encrypted = self._fernet.encrypt(
                    json.dumps(data, ensure_ascii=False).encode("utf-8")
                )
                _STORE_FILE.write_bytes(encrypted)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.error("SecureStorage.delete fehlgeschlagen: %s", type(exc).__name__)

    def _load_all(self) -> dict[str, Any]:
        """Lädt und entschlüsselt alle gespeicherten Werte.

        Gibt bei Fehlern ein leeres Dict zurück. ``set`` prüft
        zusätzlich, ob ein nicht-leeres Store-File vorhanden war
        und erstellt bei Bedarf ein Backup.

        Cleanup-Sprint 2026-04-29: ``cryptography.fernet.InvalidToken``
        und ``binascii.Error`` werden zusätzlich gefangen — wenn das
        Store-File manipuliert oder kaputt ist, soll ``get`` auf den
        ``default`` zurückfallen statt zu raisen.

        Wenn ``InvalidToken`` auf einer **nicht-leeren** Datei
        fliegt, ist das Symptom fuer DPAPI-Drift (R-8). In dem Fall
        werden die registrierten Corruption-Observer einmalig
        benachrichtigt — MainWindow zeigt dann einen Recovery-Dialog.
        """
        if not _STORE_FILE.exists():
            return {}
        # InvalidToken nur lazy importieren — cryptography ist sonst
        # bereits via Fernet-Init verifiziert; wenn der Import hier
        # scheitert, gibt es ohnehin keinen Fernet, und _available wäre
        # False (siehe set/get-Vorbedingungen).
        from cryptography.fernet import InvalidToken  # noqa: PLC0415

        try:
            raw = _STORE_FILE.read_bytes()
            data = json.loads(self._fernet.decrypt(raw).decode("utf-8"))
            # Erfolgreicher Read — Failure-Flag clearen falls vorher
            # gesetzt (z. B. nach erneutem Bootstrap nach DPAPI-Recovery).
            self._last_load_failed = False
            return data  # type: ignore[no-any-return]
        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            InvalidToken,
            binascii.Error,
        ) as exc:
            _log.warning(
                "SecureStorage Lesen fehlgeschlagen: %s",
                type(exc).__name__,
            )
            # Corruption-Detection — Datei existiert, ist nicht
            # leer, kann aber nicht entschluesselt werden. Das ist das
            # Symptom aus THREAT_MODEL R-8 (DPAPI-Drift). Wir setzen das
            # ``_last_load_failed``-Flag damit ``set`` ein Backup
            # ausloest, und feuern die Corruption-Observer einmalig
            # (Recovery-Dialog).
            if isinstance(exc, InvalidToken):
                try:
                    if _STORE_FILE.exists() and _STORE_FILE.stat().st_size > 0:
                        self._last_load_failed = True
                        self._emit_corruption_event(backup_path=None)
                except OSError:
                    # stat darf nie crashen lassen — fail-safe.
                    pass
            return {}


# ---------------------------------------------------------------------------
# Bot-Integritätsfunktionen (HMAC-SHA256)
# ---------------------------------------------------------------------------
#
# Hinweis: die ehemalige Pre-Subtask-2-HMAC-Schluessel-
# Ableitung (Hardware-Fingerprint-PBKDF2) wurde hier entfernt. Die
# Migration-only-Replikation der Logik lebt jetzt privat in
#:func:`core.database.migrate_to_envelope._derive_legacy_integrity_key` —
# damit ist die Public-Surface dieses Moduls vom Hardware-Fingerprint
# entkoppelt §9 Mess-Punkt erfuellt).


def sign_data(data: dict, key: bytes) -> str:
    """Erstellt eine HMAC-SHA256-Signatur für ein Dictionary.

    Args:
        data: Zu signierende Daten (werden deterministisch serialisiert).
        key: HMAC-Schlüssel (32 Byte).

    Returns:
        Hexadezimale Signatur.
    """
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_data(data: dict, signature: str, key: bytes) -> bool:
    """Prüft eine HMAC-SHA256-Signatur für ein Dictionary.

    Verwendet constant-time comparison (hmac.compare_digest) gegen
    Timing-Angriffe.

    Args:
        data: Die signierten Daten.
        signature: Erwartete hexadezimale Signatur.
        key: HMAC-Schlüssel (32 Byte).

    Returns:
        True wenn die Signatur korrekt ist.
    """
    expected = sign_data(data, key)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Modul-Level Singleton (lazy)
# ---------------------------------------------------------------------------

_instance: SecureStorage | None = None


def get_secure_storage() -> SecureStorage:
    """Gibt die Singleton-Instanz von SecureStorage zurück (thread-safe).

    Returns:
        SecureStorage-Instanz (wird bei erstem Aufruf initialisiert).
    """
    global _instance  # noqa: PLW0603
    if _instance is None:
        with _lock:
            # Double-check nach Lock-Erwerb
            if _instance is None:
                _instance = SecureStorage()
    return _instance
