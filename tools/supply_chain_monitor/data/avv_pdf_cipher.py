"""
avv_pdf_cipher — At-Rest-Verschluesselung der AVV-PDFs.

Die AVV-PDF-Bytes liegen NICHT in der DB (Direktive 2026-05-15), sondern als
eigene Datei unter ``~/.finlai/avv/<vendor_id>/<uuid>.pdf.enc``. Diese Datei ist
mit Fernet (AES-128-CBC + HMAC-SHA256, authenticated) verschluesselt; der
Schluessel wird via ``KeyManager.derive_secondary_key("supply_chain:avv_pdf")``
aus dem DPAPI-CurrentUser-gebundenen DEK abgeleitet — gleiches Muster wie
:class:`core.security.encryption.SecureStorage`.

Fail-closed: fehlt der KeyManager/DEK, wirft die Konstruktion
:class:`AvvPdfCipherError` — kein Klartext-Fallback.

Schichtzugehoerigkeit: data/ — darf core/ importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from core.database.key_manager_context import get_active_key_manager
from core.logger import get_logger

_log = get_logger(__name__)

#: HKDF-Purpose des AVV-PDF-Schluessels — Domain-Trennung gegen andere
#: ``derive_secondary_key``-Verbraucher (z. B. ``"secure_storage"``).
_AVV_PDF_PURPOSE = "supply_chain:avv_pdf"

#: Datei-Suffix der verschluesselten AVV-PDFs (Klartext-Vorversion hatte ".pdf").
ENCRYPTED_SUFFIX = ".pdf.enc"


class AvvPdfCipherError(RuntimeError):
    """Basis-Fehler der AVV-PDF-Verschluesselung (fail-closed)."""


class AvvPdfDecryptError(AvvPdfCipherError):
    """Entschluesselung fehlgeschlagen — falscher Schluessel oder kein AVV-Ciphertext.

    Tritt u. a. auf, wenn eine Klartext-PDF aus der unverschluesselten
    Vorversion geoeffnet wird Pre-Prod-Wipe: kein Migrationspfad).
    """


class AvvPdfCipher:
    """Fernet-basierte At-Rest-Verschluesselung fuer AVV-PDFs."""

    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    @classmethod
    def from_active_key_manager(cls) -> AvvPdfCipher:
        """Baut den Cipher aus dem aktiven, DPAPI-gebundenen DEK (fail-closed).

        Returns:
            Einsatzbereiter:class:`AvvPdfCipher`.

        Raises:
            AvvPdfCipherError: Wenn kein aktiver KeyManager/DEK verfuegbar ist.
        """
        try:
            raw = get_active_key_manager().derive_secondary_key(_AVV_PDF_PURPOSE)
        except Exception as exc:  # noqa: BLE001 — fail-closed an der Crypto-Grenze
            raise AvvPdfCipherError(
                "AVV-Verschluesselung nicht verfuegbar (kein Schluessel)."
            ) from exc
        # derive_secondary_key liefert 32 ROHE Bytes; Fernet erwartet url-safe
        # base64 — identisch zu SecureStorage (core/security/encryption.py).
        return cls(base64.urlsafe_b64encode(raw))

    def encrypt_file(self, source: Path, target: Path) -> None:
        """Verschluesselt ``source`` (Klartext-PDF) nach ``target`` (Ciphertext).

        Args:
            source: Pfad zur Klartext-PDF.
            target: Zielpfad fuer den Ciphertext (``.pdf.enc``).
        """
        target.write_bytes(self._fernet.encrypt(source.read_bytes()))

    def decrypt_file(self, source: Path, target: Path) -> None:
        """Entschluesselt ``source`` (Ciphertext) nach ``target`` (Klartext-PDF).

        Args:
            source: Pfad zum Ciphertext (``.pdf.enc``).
            target: Zielpfad fuer die entschluesselte PDF.

        Raises:
            AvvPdfDecryptError: Wenn ``source`` kein gueltiger AVV-Ciphertext ist
                (falscher Schluessel oder altes Klartext-Format).
        """
        try:
            plain = self._fernet.decrypt(source.read_bytes())
        except InvalidToken as exc:
            raise AvvPdfDecryptError(
                f"AVV-PDF nicht entschluesselbar: {source}"
            ) from exc
        target.write_bytes(plain)
