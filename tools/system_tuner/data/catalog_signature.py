"""
catalog_signature — Ed25519-Signatur-Gate fuer den Tweak-Katalog (R3).

Fail-closed: nur bei gueltiger Signatur darf (spaeter) angewandt werden; ohne/
ungueltige Signatur bleibt das Tool im Scan-Modus (eingebetteter Public-Key,
``InvalidSignature``).

Signatur wird ueber den **normalisierten** Katalog-Inhalt gebildet (CRLF→LF),
damit sie unabhaengig vom Checkout-Line-Ending stabil ist.

Signing-Key: Public-Key unten eingebettet; der **private** Key liegt ausserhalb
des Repos (Prod-Key seit B2-Rotation 2026-06-18, B2-Empfehlung: verschluesselt/
offline) und wird NIE committet. Re-Signieren via ``sign_tuner_catalog.py``
(keygen/sign/verify) bei Katalog-Aenderung.

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.logger import get_logger

log = get_logger(__name__)

#: Prod-Signing-Public-Key (Raw 32B, base64). B2-Rotation 2026-06-18: vom
#: Vor-Release-Dev-Key auf den Prod-Key rotiert. Der zugehoerige PRIVATE-Key
#: liegt ausserhalb des Repos (B2-Empfehlung: verschluesselt/offline) und wird
#: NIE committet. Re-Signieren bei Katalog-Aenderung via ``sign_tuner_catalog.py``.
_PUBLIC_KEY_B64 = "obnB3CxxOpwR+bSxOFF7zTp9hdDQntDcL0PwyGbnTPQ="


def _normalize(path: Path) -> bytes:
    """Liest den Katalog als CRLF-normalisierte UTF-8-Bytes (stabil)."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")


def _load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(public_key_b64)
    if len(raw) != 32:
        raise ValueError(f"Ungueltige Public-Key-Laenge: {len(raw)} (erwartet 32)")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_catalog(
    catalog_path: Path,
    signature_path: Path,
    *,
    public_key_b64: str = _PUBLIC_KEY_B64,
) -> bool:
    """Fail-closed: ``True`` nur bei gueltiger Ed25519-Signatur des Katalogs.

    Jeder Fehler (fehlende Datei, Format, ungueltige Signatur) → ``False``.
    """
    try:
        if not catalog_path.is_file() or not signature_path.is_file():
            return False
        data = _normalize(catalog_path)
        signature = base64.b64decode(
            signature_path.read_text(encoding="utf-8").strip()
        )
        _load_public_key(public_key_b64).verify(signature, data)
    except (InvalidSignature, ValueError, OSError) as exc:
        log.warning("Katalog-Signatur ungueltig/fehlt (%s): %s", catalog_path.name, exc)
        return False
    return True


def sign_catalog(catalog_path: Path, private_key_b64: str) -> str:
    """Signiert den Katalog (Dev/CI) und gibt die base64-Signatur zurueck."""
    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key_b64)
    )
    return base64.b64encode(private_key.sign(_normalize(catalog_path))).decode()
