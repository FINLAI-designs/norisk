"""key_manager_platform — Backend-Stubs fuer Envelope-Encryption KEK.

Stellt drei Backends bereit, die das ``_DPAPIBackend``-Protocol implementieren:

* ``WindowsDPAPIBackend`` — produktiv. Nutzt ``win32crypt.CryptProtectData``
  und ``CryptUnprotectData`` mit ``CurrentUser``-Scope (kein
  ``CRYPTPROTECT_LOCAL_MACHINE``-Flag — dadurch ist der gewrappte DEK an
  den Windows-User-Login gebunden).
* ``MacOSKeychainBackend`` — Stub fuer 1.x. Wirft ``NotImplementedError``
  bei jeder Operation.
* ``LinuxLibsecretBackend`` — Stub fuer 1.x. Wirft ``NotImplementedError``.
* ``InMemoryDPAPIBackend`` — Test-only. Wrap/Unwrap = Identity mit
  Header-Praefix. Wird in ``tests/`` ueber Fixtures injiziert, damit Tests
  auf Linux-CI laufen ohne ``win32crypt``.

Auswahl-Logik in:func:`select_backend` ueber ``sys.platform``.

Schichtzugehoerigkeit: ``core/database/`` (Crypto-Infrastruktur).
Schicht: KEK = Key Encryption Key (siehe §2.3).

Author: Patrick Riederich
Version: 1.0 (Subtask 1 Skeleton)
"""

from __future__ import annotations

import sys
from enum import StrEnum
from typing import ClassVar, Final, Protocol

from core.exceptions import CryptoError

# ---------------------------------------------------------------------------
# Backend-Kind-Enum (stabile Identifier, unabhaengig vom Klassen-Namen)
# ---------------------------------------------------------------------------


class BackendKind(StrEnum):
    """Stabile Identifier fuer Backend-Typen — unabhaengig vom
    Klassen-Namen.

    Wird in:meth:`KeyManager.get_key_metadata` exponiert. Damit ist
    der Diagnose-Output stabile API: wenn ``WindowsDPAPIBackend`` in
    Zukunft umbenannt wird (z. B. zu ``Win32DPAPIBackend``), bleibt der
    Diagnose-Output unveraendert. Logs, Health-Checks und Migrations-
    Skripte koennen sich auf diese Enum-Werte verlassen.

    Werte sind ``snake_case``-Strings (StrEnum-konform fuer JSON-
    Serialisierung). Erweiterbar ohne Breaking Change — neue Backends
    fuegen einen neuen Enum-Wert hinzu.
    """

    WINDOWS_DPAPI = "windows_dpapi"
    MACOS_KEYCHAIN = "macos_keychain"
    LINUX_LIBSECRET = "linux_libsecret"
    IN_MEMORY = "in_memory"

# ---------------------------------------------------------------------------
# Backend-Protocol
# ---------------------------------------------------------------------------


class _DPAPIBackend(Protocol):
    """Protocol fuer KEK-Backends (Wrap/Unwrap des DEK).

    Effekt: Das gewählte Backend definiert, an welche Identität der
    gewrappte DEK gebunden ist. ``WindowsDPAPIBackend`` bindet an den
    Windows-User-Login (DPAPI ``CurrentUser``-Scope) — daraus folgt
    Residualrisiko R-8 in THREAT_MODEL.md (Profile-Migration bricht den
    Wrap). ``InMemoryDPAPIBackend`` ist Test-only und schuetzt nichts.

    Jedes Backend deklariert seinen:class:`BackendKind` als
    ``KIND``-Class-Attribut. Das ist die stabile API fuer Diagnose-
    Tools.
    """

    KIND: ClassVar[BackendKind]

    def wrap(self, plaintext: bytes) -> bytes:
        """Verschluesselt ``plaintext`` mit dem KEK; gibt Wrapped-Bytes zurueck."""

    def unwrap(self, ciphertext: bytes) -> bytes:
        """Entschluesselt Wrapped-Bytes; gibt ``plaintext`` zurueck."""


# ---------------------------------------------------------------------------
# Production-Backend — Windows DPAPI
# ---------------------------------------------------------------------------


class WindowsDPAPIBackend:
    """Windows DPAPI ``CurrentUser``-Scope ueber ``pywin32.win32crypt``.

    Effekt: ``wrap`` ruft ``CryptProtectData`` ohne
    ``CRYPTPROTECT_LOCAL_MACHINE`` (Default ist ``CurrentUser``) — der
    gewrappte DEK ist an den aktuellen Windows-User-Login gebunden. Andere
    User auf derselben Maschine, anderes User-Profil nach Domain-Wechsel
    oder kopiertes ``master.key.wrapped`` auf einer Fremd-Maschine: kein
    ``unwrap``. Das ist die Schutz-Eigenschaft, nicht der Bug.

    Optionale ``description``-Parameter werden NICHT genutzt — sie wuerden
    in ``CryptProtectData`` als Klartext-Annotation persistiert und ein
    Information-Leak ueber den Verwendungszweck schaffen.
    """

    KIND: ClassVar[BackendKind] = BackendKind.WINDOWS_DPAPI

    def wrap(self, plaintext: bytes) -> bytes:
        """Wrappt ``plaintext`` mit DPAPI. Gibt opaque Bytes zurueck.

        Raises:
            RuntimeError: Wenn ``CryptProtectData`` fehlschlaegt
                (z. B. fehlender User-Context, kein interaktiver Login).
        """
        # Lazy-Import damit Tests auf Nicht-Windows-Plattformen das Modul
        # importieren koennen, ohne pywin32 vorauszusetzen.
        import win32crypt  # noqa: PLC0415

        try:
            # CryptProtectData liefert direkt EncryptedBytes (kein Tuple).
            # CryptUnprotectData liefert (Description, DecryptedBytes) —
            # Asymmetrie der pywin32-API.
            ciphertext = win32crypt.CryptProtectData(
                plaintext,
                None,  # Description: bewusst leer (siehe Klassen-Docstring)
                None,  # OptionalEntropy: nicht genutzt
                None,  # Reserved
                None,  # PromptStruct
                0,     # Flags: 0 = CurrentUser-Scope
            )
        except Exception as exc:
            raise CryptoError(
                f"DPAPI CryptProtectData fehlgeschlagen: {type(exc).__name__}"
            ) from exc
        return bytes(ciphertext)

    def unwrap(self, ciphertext: bytes) -> bytes:
        """Entwrapt DPAPI-Bytes. Gibt ``plaintext`` zurueck.

        Raises:
            RuntimeError: Wenn ``CryptUnprotectData`` fehlschlaegt
                (z. B. anderer User-Login, manipulierte Bytes,
                Profile-Migration).
        """
        import win32crypt  # noqa: PLC0415

        try:
            _description, plaintext = win32crypt.CryptUnprotectData(
                ciphertext,
                None,  # OptionalEntropy
                None,  # Reserved
                None,  # PromptStruct
                0,     # Flags
            )
        except Exception as exc:
            raise CryptoError(
                f"DPAPI CryptUnprotectData fehlgeschlagen: {type(exc).__name__}"
            ) from exc
        return bytes(plaintext)


# ---------------------------------------------------------------------------
# Cross-Platform-Stubs (1.x)
# ---------------------------------------------------------------------------


class MacOSKeychainBackend:
    """Stub fuer macOS Keychain Services. NICHT in 1.0 implementiert.

    Effekt: Wenn NoRisk fuer macOS gebaut wird, muss diese Klasse mit
    ``security``-CLI-Wrapper oder ``keyring``-Library gefuellt werden.
    Eskalations-Trigger fuer Residualrisiko R-10: sobald Beta fuer macOS
    geplant wird, erhoeht sich R-10 von P4 auf P2/P3.
    """

    KIND: ClassVar[BackendKind] = BackendKind.MACOS_KEYCHAIN

    def wrap(self, plaintext: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError(
            "macOS-Backend ist fuer 1.x geplant. NoRisk Beta ist Windows-only."
        )

    def unwrap(self, ciphertext: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError(
            "macOS-Backend ist fuer 1.x geplant. NoRisk Beta ist Windows-only."
        )


class LinuxLibsecretBackend:
    """Stub fuer Linux libsecret/D-Bus. NICHT in 1.0 implementiert."""

    KIND: ClassVar[BackendKind] = BackendKind.LINUX_LIBSECRET

    def wrap(self, plaintext: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError(
            "Linux-Backend ist fuer 1.x geplant. NoRisk Beta ist Windows-only."
        )

    def unwrap(self, ciphertext: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError(
            "Linux-Backend ist fuer 1.x geplant. NoRisk Beta ist Windows-only."
        )


# ---------------------------------------------------------------------------
# Test-Backend — In-Memory
# ---------------------------------------------------------------------------


_INMEMORY_HEADER: Final[bytes] = b"FAKE_DPAPI_HEADER:"


class InMemoryDPAPIBackend:
    """In-Memory-Stub fuer Tests. Wrap/Unwrap = Identity + Header-Praefix.

    Effekt: Test-Code kann ``KeyManager`` ohne ``pywin32``-Dependency und
    plattformunabhaengig verifizieren. Kein echtes Crypto, nur ein
    syntaktisches Wrap-Format.

    NIEMALS in Production verwenden — der "gewrappte" DEK liegt im Klartext
    auf Disk (nur mit Praefix versehen).
    """

    KIND: ClassVar[BackendKind] = BackendKind.IN_MEMORY

    def wrap(self, plaintext: bytes) -> bytes:
        return _INMEMORY_HEADER + plaintext

    def unwrap(self, ciphertext: bytes) -> bytes:
        if not ciphertext.startswith(_INMEMORY_HEADER):
            raise CryptoError(
                "InMemoryDPAPIBackend.unwrap: Header-Praefix fehlt — "
                "ciphertext stammt von anderem Backend?"
            )
        return ciphertext[len(_INMEMORY_HEADER):]


# ---------------------------------------------------------------------------
# Backend-Auswahl
# ---------------------------------------------------------------------------


def select_backend() -> _DPAPIBackend:
    """Waehlt das passende Backend nach ``sys.platform``.

    Effekt: Auf Windows wird ``WindowsDPAPIBackend`` zurueckgegeben (echter
    KEK-Schutz). Auf macOS / Linux wird der jeweilige Stub gewaehlt — der
    bei Wrap/Unwrap ``NotImplementedError`` wirft.

    Tests injizieren ``InMemoryDPAPIBackend`` explizit ueber den
    ``KeyManager(backend=...)``-Konstruktor und umgehen damit
    ``select_backend``.

    Raises:
        RuntimeError: Wenn ``sys.platform`` nicht erkannt wird (z. B.
            Cygwin, BSD).
    """
    if sys.platform == "win32":
        return WindowsDPAPIBackend()
    if sys.platform == "darwin":
        return MacOSKeychainBackend()
    if sys.platform.startswith("linux"):
        return LinuxLibsecretBackend()
    raise CryptoError(
        f"Kein DPAPI-Backend fuer Platform '{sys.platform}' verfuegbar."
    )
