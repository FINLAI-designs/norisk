"""core.exceptions — zentrale Exception-Hierarchie fuer NoRisk by FINLAI.

Foundation fuer den **R-Exc-Sprint** (Run 2): pro Tool darf eine
``domain/exceptions.py`` eigene Subklassen ableiten, die strukturiertes
Error-Handling und Audit-Logging ermoeglichen ohne Stdlib-Exceptions
direkt zu nutzen (``RuntimeError`` / ``ValueError`` ohne Kontext sind
ein Code-Quality-Defizit, siehe NoRisk_DECISIONS L23).

Hierarchie (alle erben von ``FinLaiError``, das wiederum von
``Exception`` erbt):

.. code-block:: text

    FinLaiError — Basis fuer alles aus FINLAI-Code
    ├── ConfigurationError — fehlende/ungueltige Settings, ENV-Vars
    ├── ValidationError — Input-/Schema-/Format-Pruefungen
    ├── StorageError — DB-/Datei-/Cache-Operationen
    │ ├── DatabaseError — SQLCipher-spezifisch
    │ └── FileSystemError — Filesystem-IO ohne DB
    ├── NetworkError — HTTP/API/Timeout
    ├── CryptoError — Keys, Signaturen, Encryption
    ├── LicenseError — License-Validierung, Activation
    ├── AuthError — Login/Session/Permissions
    └── ExternalToolError — Subprocess (winget, wmic, PowerShell)

**Bewusste Design-Entscheidungen:**

* **Mehrfach-Vererbung mit Stdlib-Exceptions** Phase-1-Anpassung
  2026-05-07): ``ValidationError`` erbt ``ValueError``, ``CryptoError``
  erbt ``RuntimeError``, ``StorageError`` erbt ``OSError`` etc. Damit
  bleiben bestehende ``except ValueError`` / ``pytest.raises(ValueError)``-
  Tests weiter gruen, waehrend neuer Code die spezifischen Klassen werfen
  kann. Pattern bestaetigt durch ``requests.HTTPError`` (extends both
  ``IOError`` and ``RequestException``) und ``pandas.errors.*``.
  Catchment ``except FinLaiError`` faengt weiter alle Subklassen — die
  semantische Trennung "FINLAI-Problem vs. Bug" bleibt erhalten,
  ``except ValueError`` ist parallel weiter erlaubt.

* **Tool-spezifische Subklassen** leben in
  ``tools/<toolname>/domain/exceptions.py`` und erben von der passenden
  Kategorie hier. Beispiel::

      # tools/cert_monitor/domain/exceptions.py
      from core.exceptions import NetworkError, ValidationError

      class CertMonitorError(NetworkError):
          \"\"\"Basis fuer cert_monitor.\"\"\"

      class CertParseError(ValidationError):
          \"\"\"Cert-Format konnte nicht geparst werden.\"\"\"

* **``raise X from err`` ist Pflicht** (Phase 4: B904-Enforce). Nutzt
  Python's Exception-Chaining, behaelt den Original-Stacktrace.

* **Keine ``__init__``-Boilerplate** in den Basisklassen — Subklassen
  erben den ``Exception.__init__(*args)``-Vertrag. Wer Kontext (z. B.
  betroffene URL, Datei-Pfad) tragen will, definiert das in der
  Subklasse mit ``@dataclass(frozen=True)``-Pattern oder per Slot-Init.

**Wer welche Kategorie nutzt** (Migrations-Heuristik aus
NoRisk_DECISIONS L21-L24):

* ``RuntimeError`` mit ``"<irgendwas> nicht verfuegbar"`` /
  ``"konnte nicht abgerufen werden"`` → ``NetworkError`` /
  ``ExternalToolError`` / ``StorageError`` (Kontext-abhaengig).
* ``RuntimeError`` mit ``"<schluessel> fehlt"`` /
  ``"<config> ungueltig"`` → ``ConfigurationError``.
* ``ValueError`` aus Input-Pruefung → ``ValidationError``.
* ``RuntimeError`` aus Crypto-Modul (key derivation, encryption) →
  ``CryptoError``.

**Skin-Tests** (this module verifies its own contract):
``tests/test_core_exceptions.py``.
"""

from __future__ import annotations


class FinLaiError(Exception):
    """Wurzel der NoRisk-/FINLAI-Exception-Hierarchie.

    Direktes Catching mit ``except FinLaiError`` faengt alles, was im
    Produktiv-Code als kontrolliertes Problem geworfen wurde — im
    Gegensatz zu unkontrollierten Bugs (``AttributeError``,
    ``KeyError``,...). Audit-Logger und Bootstrap-Caller koennen das
    nutzen, um zwischen "erwartetem Fehler" und "Bug" zu unterscheiden.

    Subklassen erweitern die Hierarchie um Domaene-Wissen
    (Konfiguration, Storage, Crypto, Network,...). Tool-spezifische
    Klassen leben in ``tools/<toolname>/domain/exceptions.py``.

    Args:
        *args: An ``Exception.__init__`` weitergereicht. Typisch eine
            menschenlesbare Botschaft.
    """


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------


class ConfigurationError(FinLaiError, RuntimeError):
    """Fehlende, ungueltige oder inkonsistente Settings/ENV-Vars.

    Beispiele:
        * ENV-Var ``LICENSE_SERVER_URL`` ist leer.
        * ``tools.<x>.config`` zeigt auf nicht existenten Pfad.
        * ``--profile=foo`` aber Profil ist nicht definiert.

    NICHT fuer User-Input — das ist:class:`ValidationError`.

    Mehrfach-Vererbung von:class:`RuntimeError` (Stdlib): bestehende
    ``except RuntimeError``-Pfade fangen ConfigurationError weiter,
    Migration ist additiv.
    """


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(FinLaiError, ValueError):
    """User-Input, Schema-, oder Format-Pruefung fehlgeschlagen.

    Beispiele:
        * Lizenzschluessel hat falsches Format.
        * Hochgeladene Datei hat unerwarteten Magic-Number.
        * Pflicht-Feld fehlt im Form-Submit.

    Caller behandelt das typisch mit User-feedback ("bitte korrigieren"),
    nicht mit Crash.

    Mehrfach-Vererbung von:class:`ValueError` (Stdlib): bestehende
    ``except ValueError``-Pfade fangen ValidationError weiter, Migration
    ist additiv.
    """


# ---------------------------------------------------------------------------
# Storage / Datenbank / Filesystem
# ---------------------------------------------------------------------------


class StorageError(FinLaiError, OSError):
    """Generische Storage-Operation (DB oder Filesystem) fehlgeschlagen.

    Use ``DatabaseError`` oder ``FileSystemError`` wenn die Schicht
    eindeutig ist.

    Mehrfach-Vererbung von:class:`OSError` (Stdlib): bestehende
    ``except OSError``-Pfade fangen StorageError und Subklassen weiter,
    Migration ist additiv.
    """


class DatabaseError(StorageError):
    """SQLCipher- oder SQLite-Operation fehlgeschlagen.

    Beispiele:
        * ``PRAGMA key`` mit falschem Schluessel.
        * Schema-Migration scheitert.
        * Verletzung eines UNIQUE-Constraints.

    Erbt transitiv von:class:`OSError` ueber:class:`StorageError`.
    """


class FileSystemError(StorageError):
    """Datei-/Verzeichnis-Operation ohne DB-Beteiligung fehlgeschlagen.

    Beispiele:
        * Backup-Datei kann nicht angelegt werden.
        * Konfig-Datei nicht lesbar.
        * Atomic-Write scheitert (.tmp-Datei verbleibt).

    Erbt transitiv von:class:`OSError` ueber:class:`StorageError`.
    """


# ---------------------------------------------------------------------------
# Network / HTTP / API
# ---------------------------------------------------------------------------


class NetworkError(FinLaiError, OSError):
    """HTTP-, API- oder Timeout-Fehler bei externer Kommunikation.

    Beispiele:
        * License-Server unreachable.
        * NVD-API liefert HTTP 429 mehrfach.
        * DeepL-API antwortet nach Timeout.

    Subprocess-Aufrufe gehoeren zu:class:`ExternalToolError`, NICHT
    hier.

    Mehrfach-Vererbung von:class:`OSError` (Stdlib, weil HTTP/Socket-
    Fehler historisch dort einsortiert sind, vgl. ``ConnectionError``):
    bestehende ``except OSError``-Pfade fangen NetworkError weiter.
    """


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


class CryptoError(FinLaiError, RuntimeError):
    """Verschluesselung, Signatur, Schluessel-Ableitung fehlgeschlagen.

    Beispiele:
        * Ed25519-Verify wirft ``InvalidSignature``.
        * KEK-Wrap/Unwrap schlaegt fehl.
        * HKDF-Salt-Material ist korrupt.

    Per ``SECURITY.md``: niemals Crypto-Schluesselmaterial in
    Exception-Args durchreichen — nur Klassen-Name + generische
    Botschaft.

    Mehrfach-Vererbung von:class:`RuntimeError` (Stdlib): bestehende
    ``except RuntimeError``-Pfade in der Migration-/KeyManager-Schicht
    fangen CryptoError weiter, Migration ist additiv.
    """


# ---------------------------------------------------------------------------
# License
# ---------------------------------------------------------------------------


class LicenseError(FinLaiError, RuntimeError):
    """License-Validierung, Activation oder Re-Validation fehlgeschlagen.

    Beispiele:
        * Activation-Cert nicht parsebar.
        * Hardware-Quorum < 4-aus-5.
        * Lizenzschluessel revoked.

    Cross-Cut zu:class:`NetworkError` (Server-Roundtrip) und
:class:`CryptoError` (Cert-Signature-Verify) — der Caller
    entscheidet die spezifischere Klasse.

    Mehrfach-Vererbung von:class:`RuntimeError` (Stdlib): bestehende
    ``except RuntimeError``-Pfade fangen LicenseError weiter.
    """


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class AuthError(FinLaiError, RuntimeError):
    """Authentifizierung, Session-Management oder Permissions-Fehler.

    Beispiele:
        * Login mit falschem Passwort.
        * Session-Token abgelaufen.
        * User hat nicht die noetige Rolle.

    Mehrfach-Vererbung von:class:`RuntimeError` (Stdlib): bestehende
    ``except RuntimeError``-Pfade fangen AuthError weiter.
    """


# ---------------------------------------------------------------------------
# External Tool / Subprocess
# ---------------------------------------------------------------------------


class ExternalToolError(FinLaiError, RuntimeError):
    """Subprocess (winget, wmic, PowerShell,...) lieferte unerwartetes Ergebnis.

    Beispiele:
        * winget exit-code != 0.
        * PowerShell-Script wirft ScriptHalted.
        * wmic-Output kann nicht geparst werden (Locale-Drift).

    Plattform-spezifische Tools — auf non-Windows-Plattformen liefern
    diese Aufrufe meist ``FileNotFoundError`` (Stdlib), das wird vom
    Caller in einen ``ExternalToolError`` ueberfuehrt.

    Mehrfach-Vererbung von:class:`RuntimeError` (Stdlib): bestehende
    ``except RuntimeError``-Pfade fangen ExternalToolError weiter.
    """


__all__ = [
    "AuthError",
    "ConfigurationError",
    "CryptoError",
    "DatabaseError",
    "ExternalToolError",
    "FileSystemError",
    "FinLaiError",
    "LicenseError",
    "NetworkError",
    "StorageError",
    "ValidationError",
]
