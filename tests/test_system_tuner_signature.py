"""
test_system_tuner_signature — Ed25519-Katalog-Signatur-Gate (R3, Phase 2b).

Verifiziert das fail-closed Verify-Gate: gebuendelter Katalog + Signatur valide
(eingebetteter Prod-Public-Key seit B2-Rotation 2026-06-18); Tamper/fehlende
Signatur -> False; Sign/Verify-Roundtrip mit Ephemeral-Key; CRLF-Robustheit
(normalisiert).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.system_tuner.application.catalog_loader import (
    default_catalog_path,
    default_signature_path,
    verify_bundled_catalog,
)
from tools.system_tuner.data.catalog_signature import sign_catalog, verify_catalog


def _ephemeral_keys() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    return priv_b64, pub_b64


class TestBundledCatalog:
    def test_bundled_catalog_signature_valid(self):
        assert verify_bundled_catalog() is True

    def test_verify_catalog_direct(self):
        assert verify_catalog(default_catalog_path(), default_signature_path()) is True

    def test_missing_signature_is_false(self, tmp_path: Path):
        cat = tmp_path / "catalog.yaml"
        cat.write_text("catalog_version: '1.0'\n", encoding="utf-8")
        assert verify_catalog(cat, tmp_path / "nope.sig") is False

    def test_tampered_catalog_is_false(self, tmp_path: Path):
        # Echte Signatur, aber veraenderter Inhalt -> ungueltig
        tampered = tmp_path / "catalog_v1.yaml"
        original = default_catalog_path().read_text(encoding="utf-8")
        tampered.write_text(original + "\n# tampered\n", encoding="utf-8")
        assert verify_catalog(tampered, default_signature_path()) is False


class TestRoundtrip:
    def test_sign_then_verify(self, tmp_path: Path):
        priv_b64, pub_b64 = _ephemeral_keys()
        cat = tmp_path / "c.yaml"
        cat.write_text("catalog_version: '1.0'\ntweaks: []\n", encoding="utf-8")
        sig = tmp_path / "c.yaml.sig"
        sig.write_text(sign_catalog(cat, priv_b64), encoding="utf-8")
        assert verify_catalog(cat, sig, public_key_b64=pub_b64) is True

    def test_wrong_key_is_false(self, tmp_path: Path):
        priv_b64, _ = _ephemeral_keys()
        _, other_pub = _ephemeral_keys()
        cat = tmp_path / "c.yaml"
        cat.write_text("x: 1\n", encoding="utf-8")
        sig = tmp_path / "c.yaml.sig"
        sig.write_text(sign_catalog(cat, priv_b64), encoding="utf-8")
        assert verify_catalog(cat, sig, public_key_b64=other_pub) is False

    def test_crlf_normalization(self, tmp_path: Path):
        priv_b64, pub_b64 = _ephemeral_keys()
        content = "catalog_version: '1.0'\ntweaks: []\n"
        lf = tmp_path / "lf.yaml"
        lf.write_bytes(content.encode("utf-8"))
        sig = tmp_path / "lf.yaml.sig"
        sig.write_text(sign_catalog(lf, priv_b64), encoding="utf-8")
        # Gleicher Inhalt mit CRLF muss gegen dieselbe Signatur verifizieren
        crlf = tmp_path / "crlf.yaml"
        crlf.write_bytes(content.replace("\n", "\r\n").encode("utf-8"))
        assert verify_catalog(crlf, sig, public_key_b64=pub_b64) is True
