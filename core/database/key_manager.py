"""key_manager — Envelope-Encryption-Schluesselverwaltung.

Stellt:class:`KeyManager` mit Constructor-Injection bereit (kein
Singleton — siehe §2.5 Architektur-Entscheidung 2026-05-04).
Verwaltet:

* Schicht 1 — DEK (Data Encryption Key, 256 Bit zufaellig generiert).
* Schicht 2 — KEK (Key Encryption Key) ueber DPAPI ``CurrentUser``-Scope,
  via:mod:`core.database.key_manager_platform`.
* Schicht 3 — Sekundaerschluessel via HKDF aus DEK + ``purpose``-Domain-
  Trennung fuer ``SecureStorage`` u. a.

Public-API (final in Schritt 1.x):

*:meth:`KeyManager.initialize` — beim ersten App-Start
*:meth:`KeyManager.load_master_key` — bei jedem Start
*:meth:`KeyManager.derive_secondary_key` — fuer SecureStorage etc.
*:meth:`KeyManager.wipe` — bei Logout/Shutdown
*:meth:`KeyManager.get_key_metadata` — Diagnose, KEINE Schluessel
*:meth:`KeyManager.rotate_master_key` — Stub fuer Post-Beta
*:meth:`KeyManager.migrate_legacy_db` — fuer Subtask 3

**Stand:** Schritt 1.1 — nur Skeleton mit Exception-Hierarchie und
Konstanten. Methoden werfen ``NotImplementedError``, werden in
Schritt 1.2+ gefuellt.

Schichtzugehoerigkeit: ``core/database/`` (Crypto-Infrastruktur, kein
PySide6-Import — testbar ohne GUI).

Author: Patrick Riederich
Version: 0.1 (Subtask 1 Skeleton)
"""

from __future__ import annotations

import contextlib
import os
import secrets
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.exceptions import ValidationError
from core.finlai_paths import finlai_dir

if TYPE_CHECKING:
    from collections.abc import Callable

    from core.database.key_manager_platform import _DPAPIBackend


class MigrationStatus(StrEnum):
    """Ergebnis von:meth:`KeyManager.migrate_legacy_db` (Subtask 3 §3.3).

    Drei Werte trennen drei UI-/State-Pfade:

    -:attr:`ALREADY_MIGRATED`: DB ist bereits mit dem aktuellen DEK
      verschluesselt. Kein Re-Key noetig. Migration-State: ``migrated``,
      ``old_key_algo=null``.
    -:attr:`MIGRATED`: DB wurde mit dem Legacy-Schluessel gelesen und
      via PRAGMA-rekey auf den DEK umgestellt. Migration-State:
      ``migrated``, ``old_key_algo=<algo_name>``.
    -:attr:`FAILED`: Weder DEK noch Legacy-Schluessel hat gepasst.
      Caller (Orchestrator) verschiebt die DB nach
:file:`.unrecoverable/`.

 §2.5 hatte ``-> bool`` als Stub-Signatur skizziert. In der
    konkreten Implementation (Subtask 3) ist eine 3-Werte-Enum
    pragmatischer, weil "schon migriert" und "frisch migriert" beide
    Erfolgs-Pfade sind, aber unterschiedliche State-Eintraege erzeugen
    (``old_key_algo=null`` vs. ``old_key_algo=<algo>``).
    """

    ALREADY_MIGRATED = "already_migrated"
    MIGRATED = "migrated"
    FAILED = "failed"

# ---------------------------------------------------------------------------
# Modul-Konstanten
# ---------------------------------------------------------------------------

#: Pfad zur DPAPI-gewrappten DEK-Datei im User-Profile.
#:
#: Effekt: Bei App-Start liest:meth:`KeyManager.load_master_key` diese
#: Datei via ``win32crypt.CryptUnprotectData``. Loeschen oder Kopieren auf
#: andere Maschine fuehrt zu:class:`KeyManagerCorruptError` (DPAPI-
#: Profile-Bindung — siehe THREAT_MODEL.md R-8).
_MASTER_KEY_FILE: Final[Path] = finlai_dir() / "master.key.wrapped"

#: Laenge des DEK in Bytes (256 Bit).
_DEK_LENGTH_BYTES: Final[int] = 32

#: HKDF-Salt v1 — bewusst hartkodiert und im Repo oeffentlich.
#:
#: Begruendung (fuer Reviewer/Security-Audits):
#: RFC 5869 §3.1 ist explizit — der Salt einer HKDF-Extraktion darf
#: oeffentlich sein. Er schuetzt **nicht** den abgeleiteten Schluessel,
#: sondern ausschliesslich gegen **Multi-Target-Angriffe** (eine pre-
#: computed Salt-Tabelle fuer viele Opfer). Im Single-User-Single-Machine-
#: Szenario von NoRisk hat ein oeffentlicher Salt keinen Sicherheits-
#: nachteil — der DEK ist pro Maschine eindeutig und nur via DPAPI-Wrap
#: persistiert (siehe §2.3 Schicht 2).
#:
#: V1-Suffix ist bewusst — bei Rotation entsteht ``_HKDF_SALT_V2`` daneben
#: und ein Migrations-Pfad muss her (siehe §K-5). Rotation wuerde
#: die Migration aller ``derive_secondary_key``-Verbraucher (heute:
#: ``secure_store.enc``) erzwingen, daher bewusst stabil.
#:
#: Wert wurde einmalig per ``secrets.token_bytes(32)`` generiert.
#: Generator-Skript ist nicht mehr noetig — der Wert ist die Konstante.
_HKDF_SALT_V1: Final[bytes] = bytes.fromhex(
    "5e459f44bb2c9125723149e3a19250609d1021105052f2e6b5c42ce48a85e2d3"
)

#: Schema-Version der Sekundaerschluessel-Ableitung. Wird in
#::meth:`KeyManager.get_key_metadata` exponiert.
_HKDF_SALT_VERSION: Final[str] = "v1"

#: Praefix fuer HKDF ``info``-Parameter. Effekt: Domain-Trennung zwischen
#: KeyManager-Verbrauchern und potenziellen anderen HKDF-Nutzern in FINLAI.
#: Aenderung hier bricht alle bestehenden Sekundaerschluessel.
_HKDF_INFO_PREFIX: Final[str] = "finlai.purpose."


# ---------------------------------------------------------------------------
# Exception-Hierarchie
# ---------------------------------------------------------------------------


class KeyManagerError(Exception):
    """Basis-Exception fuer KeyManager-Fehler.

    Untertypen unterscheiden, ob Recovery-Pfade greifen (Subtask 3
    konsumiert die spezifischen Subtypen).
    """


class KeyManagerNotInitializedError(KeyManagerError):
    """``master.key.wrapped`` existiert noch nicht.

    Erste Aktivierung der Architektur — Subtask 3 triggert die
    Bestandsdaten-Migration. Kein Datenverlust, kein User-sichtbarer
    Fehler.
    """


class KeyManagerCorruptError(KeyManagerError):
    """``master.key.wrapped`` existiert, ist aber via DPAPI nicht entschluesselbar.

    Typische Ursachen: User-Profile-Migration (Domain-Wechsel, neuer
    User-Account), Datei manipuliert, Datei von anderer Maschine kopiert.
    Recovery: User-bestaetigte Re-Initialisierung (siehe §3 +
    THREAT_MODEL.md R-8).
    """


class KeyManagerPermissionError(KeyManagerError):
    """``master.key.wrapped`` existiert, aber Filesystem-Zugriff verweigert.

    Typische Ursachen: ACL-Aenderung, korrupter NTFS-Index, Antivirus-
    Quarantaene. Recovery: User informiert ueber Permission-Fix; KEIN
    Auto-Re-Init (sonst gefaehrlich, falls die Datei doch noch da ist).
    """


# ---------------------------------------------------------------------------
# KeyManager — Skeleton (Schritt 1.1)
# ---------------------------------------------------------------------------


class KeyManager:
    """Envelope-Encryption Key Manager (DPAPI-KEK + DEK).

    **Constructor-Injection-Klasse, kein Singleton** (siehe §2.5
    Architektur-Entscheidung 2026-05-04). Der App-Bootstrap
    (:func:`apps.launch_app`) erzeugt genau eine Instanz und reicht sie
    an alle Konsumenten (``EncryptedDatabase``, ``SecureStorage``,
    Migrations-Code in Subtask 3). Diese Konvention garantiert, dass alle
    Konsumenten denselben Cache teilen, ohne globalen State einzufuehren.

    **Verworfene Alternative Singleton:** Begruendung in §2.5
    (Test-Sauberkeit, kein globaler State, Race-Condition-Akzeptanz —
    App-Bootstrap ist single-threaded vor ``app.exec``).

    Schichten siehe §2.

    Args:
        backend: Optionaler ``_DPAPIBackend``. Default: Auto-Auswahl per
:func:`core.database.key_manager_platform.select_backend`.
            Tests injizieren ``InMemoryDPAPIBackend`` ueber diesen
            Konstruktor.

    Effekt: Der ``backend``-Parameter macht den KeyManager auf Linux/macOS
    test-fixturable — Tests koennen ``InMemoryDPAPIBackend`` injizieren,
    ohne ``win32crypt`` vorauszusetzen.

    Test-Konsequenz: Tests instanziieren ``KeyManager`` direkt mit
    ``backend=InMemoryDPAPIBackend`` und reichen die Instanz an die zu
    testende Komponente. Kein Singleton-Reset zwischen Tests noetig.
    """

    def __init__(self, backend: _DPAPIBackend | None = None) -> None:
        if backend is None:
            from core.database.key_manager_platform import (
                select_backend,  # noqa: PLC0415
            )

            backend = select_backend()
        self._backend: _DPAPIBackend = backend
        # DEK wird in Schritt 1.3 als bytearray initialisiert; jetzt None.
        # Effekt: ``wipe`` (Schritt 1.6) ueberschreibt die bytearray-
        # Slots, danach setzen wir auf None. ``bytes`` waere immutable.
        self._dek: bytearray | None = None

    # ------------------------------------------------------------------
    # Public API — alle in Schritt 1.2+ implementiert
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Beim ersten App-Start: DEK generieren, wrappen, atomar schreiben.

        Idempotent: existiert:data:`_MASTER_KEY_FILE` bereits, wird sie
        NICHT ueberschrieben — stattdessen via Backend-Unwrap auf Lesbarkeit
        geprueft. Bei nicht-lesbarer Datei wird ein
:class:`KeyManagerCorruptError` geworfen, **die Datei bleibt
        unangetastet** (kein Auto-Reset, sonst gefaehrlich falls die
        Datei doch noch zu retten waere — siehe THREAT_MODEL.md R-8
        Recovery-Strategie).

        Atomares Schreiben (siehe §3.3): ``.wrapped.tmp`` +
        ``flush`` + ``os.fsync`` + ``os.replace``. ``os.replace`` ist
        atomar auf Windows + POSIX.

        Effekt: nach erfolgreicher Initialisierung existiert
:data:`_MASTER_KEY_FILE` und ein nachfolgender
:meth:`load_master_key`-Aufruf liefert den DEK. Der RAM-Cache
        wird hier NICHT befuellt — das ist Aufgabe von
        ``load_master_key`` (Schritt 1.3).

        Raises:
            KeyManagerCorruptError: Existierende Datei nicht via Backend-
                Unwrap entschluesselbar (typisch: User-Profile-Wechsel).
            KeyManagerPermissionError: Filesystem-Lese- oder Schreib-
                Zugriff verweigert.
            KeyManagerError: Backend-Wrap fehlgeschlagen (z. B.
                ``CryptProtectData`` ohne interaktiven User-Login).
        """
        if _MASTER_KEY_FILE.exists():
            # Idempotenz-Pfad: pruefe Lesbarkeit, dann no-op.
            try:
                wrapped = _MASTER_KEY_FILE.read_bytes()
            except OSError as exc:
                raise KeyManagerPermissionError(
                    f"master.key.wrapped nicht lesbar: {exc}"
                ) from exc
            try:
                self._backend.unwrap(wrapped)
            except (RuntimeError, NotImplementedError) as exc:
                # Wichtig: Datei NICHT loeschen oder ueberschreiben.
                # Recovery-Pfad muss vom Caller getriggert werden
                # (User-bestaetigte Re-Init via Migration-Flow).
                raise KeyManagerCorruptError(
                    "master.key.wrapped existiert, aber Backend-Unwrap "
                    "fehlgeschlagen. Wahrscheinlich User-Profile-Wechsel "
                    "(siehe THREAT_MODEL.md R-8). Recovery: Migration-"
                    "Flow ueber Subtask 3."
                ) from exc
            return

        # Erste Initialisierung: DEK generieren und wrappen.
        dek = secrets.token_bytes(_DEK_LENGTH_BYTES)
        try:
            wrapped = self._backend.wrap(dek)
        except (RuntimeError, NotImplementedError) as exc:
            # Generierten DEK aus dem Lokal-Frame entfernen.
            # bytes ist immutable, also nur Referenz drop.
            del dek
            raise KeyManagerError(
                f"Backend.wrap fehlgeschlagen: {type(exc).__name__}"
            ) from exc

        # Atomar schreiben.
        _MASTER_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = _MASTER_KEY_FILE.with_name(
            _MASTER_KEY_FILE.name + ".tmp"
        )
        try:
            with open(tmp_path, "wb") as fp:
                fp.write(wrapped)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(tmp_path, _MASTER_KEY_FILE)
        except OSError as exc:
            # Cleanup.tmp falls vorhanden — kein halb-geschriebener
            # Zustand uebrig lassen.
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise KeyManagerPermissionError(
                f"Schreiben von master.key.wrapped fehlgeschlagen: {exc}"
            ) from exc
        finally:
            # DEK-Klartext aus dem lokalen Scope entfernen. bytes ist
            # immutable; wir koennen nur die Referenz droppen, nicht
            # ueberschreiben (Limitation siehe §2.5 wipe-Doc).
            del dek

        # Permissions 0600 (Windows ignoriert es leise — kein Fehler).
        with contextlib.suppress(OSError, NotImplementedError):
            _MASTER_KEY_FILE.chmod(0o600)

    def load_master_key(self) -> bytes:
        """Laedt den DEK aus ``master.key.wrapped``, cached final innerhalb
        dieser Instanz.

        Cache-Verhalten:
            Erster Call: Disk-Read + Backend-Unwrap, in ``self._dek``
                         (bytearray) cachen, ``bytes``-Kopie zurueckgeben.
            Folge-Calls: kein Disk-Read, ``bytes``-Kopie aus Cache.

        Cache-Invalidierung:
            Innerhalb einer KeyManager-Instanz NICHT moeglich. Wenn eine
            andere Komponente ``master.key.wrapped`` zur Laufzeit ersetzt
            (z. B. Migration in Subtask 3), greift dieser Cache auf den
            ALTEN DEK weiter.

            Recovery-Pfad nach File-Replacement:
              1.:meth:`wipe` aufrufen (ueberschreibt Cache-bytearray).
              2. KeyManager-Instanz verwerfen.
              3. Neue Instanz erzeugen, die liest dann frisch von Disk.

            Alternative fuer spaetere Iterationen:
            ``force_reload=True``-Parameter oder mtime-basierte
            Invalidierung. Beides bewusst NICHT in v1 implementiert —
            Mental-Model "Cache ist final" ist einfacher und Tests
            reproduzierbarer.

        Memory-Footprint:
            Jeder Aufruf erzeugt eine 32-Byte-Kopie ueber
            ``bytes(bytearray)``. Bei gelegentlicher DEK-Verwendung
            irrelevant. Falls in Folge-Subtasks ein Hot-Path entsteht,
            der ``load_master_key`` in einer Schleife aufruft (z. B.
            pro DB-Zugriff): bekannte Eigenschaft, kein Bug,
            Mikro-Optimierung waere ein bytearray-View.

        Returns:
            ``bytes``: 256-bit DEK als immutable Kopie. Caller darf nicht
            annehmen, dass weitere Aufrufe denselben Speicher zurueckgeben.
            Niemals loggen, niemals in Strings konkatenieren.

        Raises:
            KeyManagerNotInitializedError: ``master.key.wrapped`` existiert
                nicht. Caller (typisch ``apps/__init__.py``) muss zuerst
:meth:`initialize` aufrufen.
            KeyManagerCorruptError: Datei vorhanden, aber Backend-Unwrap
                fehlgeschlagen (typisch User-Profile-Wechsel — 
                THREAT_MODEL.md R-8).
            KeyManagerPermissionError: Filesystem-Lese-Zugriff verweigert.
        """
        if self._dek is not None:
            # Cache-Hit. bytes(bytearray) erzeugt eine immutable Kopie —
            # damit kann der Caller das Ergebnis nicht versehentlich
            # ueberschreiben oder unsere wipe-Strategie aushebeln.
            return bytes(self._dek)

        if not _MASTER_KEY_FILE.exists():
            raise KeyManagerNotInitializedError(
                "master.key.wrapped existiert nicht. "
                "Vor load_master_key() muss initialize() laufen "
                "(typisch in apps/__init__.py launch_app)."
            )

        try:
            wrapped = _MASTER_KEY_FILE.read_bytes()
        except OSError as exc:
            raise KeyManagerPermissionError(
                f"master.key.wrapped nicht lesbar: {exc}"
            ) from exc

        try:
            dek_bytes = self._backend.unwrap(wrapped)
        except (RuntimeError, NotImplementedError) as exc:
            raise KeyManagerCorruptError(
                "master.key.wrapped existiert, aber Backend-Unwrap "
                "fehlgeschlagen. Wahrscheinlich User-Profile-Wechsel "
                "(siehe THREAT_MODEL.md R-8). Recovery: Migration-"
                "Flow ueber Subtask 3."
            ) from exc

        # In bytearray umpacken — mutable, damit wipe in Schritt 1.5/1.6
        # die Slots ueberschreiben kann. bytes(bytearray) liefert dann
        # eine sichere Kopie an den Caller.
        self._dek = bytearray(dek_bytes)
        return bytes(self._dek)

    def derive_secondary_key(self, purpose: str) -> bytes:
        """Leitet einen 256-bit-Sekundaerschluessel aus dem DEK ab.

        Verwendet HKDF (RFC 5869) mit dem DEK als IKM, festem Salt
:data:`_HKDF_SALT_V1` und einem ``purpose``-spezifischen
        ``info``-Parameter. Damit ist jeder Schluessel an eine Domain
        gebunden:

        - ``derive_secondary_key("secure_storage")`` !=
          ``derive_secondary_key("audit_log_hmac")``
        - ``derive_secondary_key("foo")`` ist deterministisch
          (gleicher DEK + gleiche purpose → byte-identisch)

        Algorithmus:
            HKDF-Extract-and-Expand mit SHA-256, Output-Laenge 32 Byte,
            ``info = "finlai.purpose.<purpose>".encode("utf-8")``.

        Args:
            purpose: Domain-Identifier — nicht-leerer String, kein
                reines Whitespace. Beispiele: ``"secure_storage"``,
                ``"audit_log_hmac"``. Unicode-Strings funktionieren
                (UTF-8-Encoding im info-Param).

        Returns:
            32-Byte Sekundaerschluessel als ``bytes``. Niemals loggen.

        Raises:
            ValueError: ``purpose`` ist leer oder reines Whitespace —
                Domain-Separation waere unterlaufen.
            KeyManagerNotInitializedError: DEK noch nicht via
:meth:`initialize` erzeugt (transitiv via
:meth:`load_master_key`).
            KeyManagerCorruptError: DEK nicht entschluesselbar (transitiv).
            KeyManagerPermissionError: DEK-Datei nicht lesbar (transitiv).
        """
        # Domain-Separation-Garantie: leerer / nur-Whitespace-purpose
        # unterlaeuft die Domain-Separation still — der derived Key
        # waere der "Default-Purpose-Key". HKDF info-Param darf laut
        # RFC 5869 leer sein, aber Caller hat dann fast sicher einen
        # Bug (uninitialized variable, truncated config field, etc.).
        if not purpose or not purpose.strip():
            raise ValidationError(
                "purpose must be a non-empty string for domain separation. "
                "Examples: 'secure_storage', 'audit_log_hmac'."
            )

        # TODO Subtask 6 (Cleanup): Whitelist mit Override-Flag erwaegen.
        # Heute kein Schutz gegen Typos wie 'secure_strorage' (wuerde
        # still einen anderen Schluessel zurueckgeben). In 1.4 bewusst
        # auf Whitelist verzichtet, weil nur eine Purpose ("secure_
        # storage") in v1 geplant ist. Wenn weitere Purposes dazukommen,
        # Pattern fuer Subtask 6:
        # _KNOWN_PURPOSES = frozenset({"secure_storage",...})
        # derive_secondary_key(purpose, allow_unknown=False)
        # Default strict, allow_unknown=True fuer Test-Code/Spaet-Erweiterung.

        # TODO Subtask 6 (Cleanup): Unicode-Normalisierung erwaegen.
        # Annahme: Caller uebergibt NFC-normalisierte Purpose-Strings.
        # Bei Mixed-Normalization (NFC vs. NFD — z. B. "ü" als einzelnes
        # Codepoint vs. "u" + Combining-Diaeresis) wuerden zwei visuell
        # identische Purposes unterschiedliche derived Keys produzieren.
        # Heute kein Schutz, kein Caller in v1 generiert NFD. Bei Bedarf:
        # `purpose = unicodedata.normalize("NFC", purpose)` vor encode.

        dek_bytes = self.load_master_key()
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_HKDF_SALT_V1,
                info=f"{_HKDF_INFO_PREFIX}{purpose}".encode(),
            )
            derived = hkdf.derive(dek_bytes)
        finally:
            # Symbolisches del — immutable bytes koennen in CPython nicht
            # garantiert vom Heap entfernt werden (Refcount + GC-Strategie).
            # Der explizite del entfernt aber die Variable aus dem Function-
            # Scope, was die Lebensdauer auf das fruehestmoegliche Frame-
            # Cleanup verkuerzt. Echte Memory-Sanitization passiert nur in
            # wipe auf dem Cache-bytearray — siehe Schritt 1.5.
            del dek_bytes

        return derived

    def wipe(self) -> None:
        """Ueberschreibt den DEK-Cache mit Nullen und droppt die Referenz.

        Limitations (CPython-spezifisch):
            - bytearray-Slot-Ueberschreibung wirkt — die Cache-Bytes
              werden zu ``0x00``. Caller, die den bytearray-Slot vor
              dem:meth:`wipe`-Aufruf als Referenz halten, sehen die
              Nullen via ``cache_ref[i] == 0``.
            - GC-Timing ist nicht garantiert: das ueberschriebene
              bytearray-Objekt wird irgendwann freigegeben, das exakte
              Wann ist undefiniert.
            - ``bytes``-Kopien, die Caller via:meth:`load_master_key`
              bekommen haben, sind NICHT betroffen — die liegen in
              eigenen Heap-Slots. Das ist beabsichtigt: laufende
              Operationen behalten ihre eigene immutable Kopie.
            - Memory-Pages koennen auf Disk geswappt werden
              (Windows-Hibernation, Linux-Swapfile) — Schutz davor
              waere OS-level (``mlock``/``VirtualLock``), bewusst nicht
              implementiert. Native-Backend via ``sodium_memzero``
              waere die naechste Eskalations-Stufe — siehe K-5.

        Der Schutz ist Best-Effort innerhalb des Python-Prozesses, nicht
        absolut. Fuer staerkere Garantien waere ein Native-Backend oder
        ein TEE/Enclave noetig — out of v1 scope.

        Idempotent: doppelter Aufruf schadet nicht (zweiter Call ist
        no-op, weil ``self._dek`` bereits ``None`` ist).

        Verwendungs-Faelle:
            - bei Logout
            - bei App-Shutdown
            - vor Re-Initialization (neuer DEK)
            - in Migration (Subtask 3): vor force-reload-Pattern
        """
        if self._dek is None:
            return
        # bytearray-Slots ueberschreiben — wirkt, weil bytearray mutable
        # ist. Sequenzielle Iteration statt Slice-Assignment, damit der
        # Optimizer die Schleife nicht wegoptimiert (defensive Codierung).
        for i in range(len(self._dek)):
            self._dek[i] = 0
        self._dek = None

    def get_key_metadata(self) -> dict[str, Any]:
        """Read-only-Diagnose-Metadaten ueber den DEK + Wrap-Datei.

        Wird gebraucht fuer:
            - Diagnose-Tools (Settings-Tab "Crypto-Status").
            - Spaetere Key-Rotation (welche Version ist aktiv?).
            - Forensik nach Migration-Failure (welcher Backend-Typ war
              aktiv? Wann wurde die Datei geschrieben?).

        EXPLIZIT KEINE Schluessel-Daten exponiert. Rueckgabe enthaelt nur
        Metadaten ueber Pfad/Existenz/Groesse/Backend-Typ/Algorithmus-
        Version. Niemals der DEK selbst, niemals abgeleitete Schluessel,
        niemals der gewrappte Bytes-Inhalt.

        Read-only auf Disk-Metadaten + Modul-Konstanten — **kein
        DEK-Zugriff, kein Cache-Befuellen als Seiteneffekt**. Diagnose-
        Werkzeug muss auch in unsicherem Zustand laufen koennen (z. B.
        nach:meth:`wipe`, bei Fehlerdiagnose, bei nicht-initialisiertem
        KeyManager).

        Returns:
            Dict mit den Feldern:

            - ``schema_version`` (str): aktuell ``"1"``. Erweiterung des
              Schemas erhoeht diese Version — Konsumenten koennen daran
              entscheiden, ob sie das Schema kennen oder ein Upgrade
              brauchen. Ein zukuenftiges 10. Feld bricht damit keine
              Konsumenten, die nur die Felder von ``schema_version=="1"``
              kennen — sie sehen einen unerwartet hoeheren Wert und
              koennen klar fail-en statt missverstaendlich Werte zu
              ignorieren.
            - ``wrapped_path`` (str): Pfad der DPAPI-gewrappten Datei.
            - ``wrapped_exists`` (bool): existiert die Datei?
            - ``wrapped_created_at`` (str | None): ISO-8601-UTC-mtime
              der Datei, ``None`` falls Datei fehlt oder Stat-Fehler.
              **Best-effort:** mtime auf POSIX, st_mtime auf Windows.
              Streng genommen letzte Modifikation, nicht Erstellung —
              in der Praxis identisch, weil ``master.key.wrapped`` nach
:meth:`initialize` nicht geaendert wird (ausser
:meth:`rotate_master_key`, derzeit Stub). Feldname bleibt
              ``wrapped_created_at`` aus Abwaertskompatibilitaet.
            - ``wrapped_size_bytes`` (int): Datei-Groesse in Bytes,
              ``0`` falls Datei fehlt.
            - ``backend_type`` (str)::class:`BackendKind`-Wert des
              aktiven Backends (``"windows_dpapi"`` / ``"in_memory"`` /
              ``"macos_keychain"`` / ``"linux_libsecret"``). Stabile
              API, unabhaengig vom Klassen-Namen.
            - ``hkdf_salt_version`` (str)::data:`_HKDF_SALT_VERSION`,
              aktuell ``"v1"``.
            - ``kdf_algorithm`` (str): ``"HKDF-SHA256"`` (festverdrahtet
              gegenueber §2.5).
            - ``key_length_bits`` (int): ``256``.
            - ``rotation_supported`` (bool): aktuell ``False`` (Stub bis
              Post-Beta — siehe §K-5).
        """
        if _MASTER_KEY_FILE.exists():
            try:
                stat = _MASTER_KEY_FILE.stat()
                wrapped_size = stat.st_size
                wrapped_created_at: str | None = datetime.fromtimestamp(
                    stat.st_mtime, tz=UTC
                ).isoformat()
                wrapped_exists = True
            except OSError:
                # Datei zwischen exists und stat weggefallen — extrem
                # unwahrscheinlich, aber wir behandeln es gleich wie
                # "nicht da".
                wrapped_size = 0
                wrapped_created_at = None
                wrapped_exists = False
        else:
            wrapped_size = 0
            wrapped_created_at = None
            wrapped_exists = False

        return {
            "schema_version": "1",
            "wrapped_path": str(_MASTER_KEY_FILE),
            "wrapped_exists": wrapped_exists,
            "wrapped_created_at": wrapped_created_at,
            "wrapped_size_bytes": wrapped_size,
            "backend_type": self._backend.KIND.value,
            "hkdf_salt_version": _HKDF_SALT_VERSION,
            "kdf_algorithm": "HKDF-SHA256",
            "key_length_bits": 256,
            "rotation_supported": False,
        }

    def rotate_master_key(self) -> None:
        """Post-Beta. Stub bleibt ``NotImplementedError``."""
        raise NotImplementedError(
            "KeyManager.rotate_master_key ist Stub fuer Post-Beta (ADR-007 §2.5, K-5)."
        )

    def migrate_legacy_db(
        self,
        db_path: Path,
        old_key_func: Callable[[], str],
    ) -> MigrationStatus:
        """Migriert eine einzelne SQLCipher-DB auf den DEK-basierten Schluessel.

        Vorgehen §3.4 + Refinement Subtask 3):

        1. Versuche die DB mit dem aktuellen DEK-abgeleiteten Schluessel
           zu oeffnen (``derive_secondary_key(f"db:{db_path.stem}")``).
           Erfolg →:attr:`MigrationStatus.ALREADY_MIGRATED` (DB war
           bereits migriert, no-op).
        2. Hole den Legacy-Schluessel via ``old_key_func`` und
           versuche die DB damit zu oeffnen. Erfolg → ``PRAGMA rekey``
           auf den DEK-Schluessel. Verifikation durch erneutes Oeffnen
           mit dem neuen Schluessel. →:attr:`MigrationStatus.MIGRATED`.
        3. Andernfalls (weder DEK noch Legacy lesbar) →
:attr:`MigrationStatus.FAILED`. Caller (Orchestrator)
           kuemmert sich um den:file:`.unrecoverable/`-Move.

        Atomizitaet: ``PRAGMA rekey`` wird von SQLCipher unter WAL-Mode
        in einer einzelnen Transaktion ausgefuehrt — entweder ganz oder
        gar nicht. **Trotzdem** ist Pre-Migration-Backup
        (:func:`core.database.migrate_to_envelope.pre_migration_backup`)
        Pflicht — siehe §3.2: Backup ist Versicherung gegen
        unerwartete Faelle (SQLCipher-Bug, Stromausfall mid-commit,
        Disk-Korruption), nicht nur gegen Migration-Fail.

        Reflexions-Regel-3 (PE-1-Lehre): die DB-Datei selbst wird nur
        ueber ``PRAGMA rekey`` modifiziert. Im FAILED-Pfad bleibt die
        DB unangetastet — der Caller verschiebt sie atomar nach
:file:`.unrecoverable/`.

        Args:
            db_path: Pfad zur SQLCipher-Datenbank.
            old_key_func: Liefert den Legacy-Schluessel als 64-Zeichen-
                Hex-String. Closure typisch ueber den Production-Pfad
                (:func:`migrate_to_envelope.legacy_db_key` mit
                HMAC ueber den Pre-Subtask-2-Integritaetsschluessel) oder
                ueber Test-Fixtures.

        Returns:
:class:`MigrationStatus` — dreiwertig (siehe Klassen-Doc).
        """
        # Lazy-Import: zyklische Abhaengigkeit Encrypted-DB → KeyManager
        # bei Modul-Ladezeit vermeiden.
        from core.database.migrate_to_envelope import (  # noqa: PLC0415
            _can_open_with_key,
            _rekey_db,
        )

        new_key = self.derive_secondary_key(f"db:{db_path.stem}").hex()

        # 1. Schon migriert? Raw-Key = aktueller Stand ODER
        # DEK-String-Key = Zwischenstand vor der Raw-Key-Umstellung. Beides
        # bedeutet „bereits auf dem DEK" — die Legacy-Rekey-Kette darf NICHT
        # laufen (sonst wuerde eine Raw-Key-DB mit String-Key nicht geoeffnet
        # und faelschlich nach.unrecoverable verschoben → Datenverlust, falls
        # migration-state.json je verlorengeht).
        if _can_open_with_key(
            db_path, new_key, raw_key=True
        ) or _can_open_with_key(db_path, new_key, raw_key=False):
            return MigrationStatus.ALREADY_MIGRATED

        # 2. Legacy-Schluessel beschaffen (kann selbst raisen — z. B.
        # KeyManagerError, RuntimeError aus _derive_legacy_integrity_key).
        # In dem Fall ist FAILED korrekt: ohne Legacy-Schluessel kein Recovery.
        try:
            old_key = old_key_func()
        except Exception:  # noqa: BLE001 -- Legacy-Funktion darf alles werfen.
            return MigrationStatus.FAILED

        if not _can_open_with_key(db_path, old_key):
            return MigrationStatus.FAILED

        # 3. Re-key. SQLCipher PRAGMA rekey ist atomar in WAL-Mode.
        try:
            _rekey_db(db_path, old_key, new_key)
        except Exception:  # noqa: BLE001 -- bei Fehler unangetastet lassen.
            return MigrationStatus.FAILED

        # 4. Verify: DB ist jetzt mit DEK-Schluessel lesbar.
        if not _can_open_with_key(db_path, new_key):
            return MigrationStatus.FAILED

        return MigrationStatus.MIGRATED
