"""
test_system_tuner_apply_gates — Plan-Binding (R5) + Consent-Gate (R7).

Pure/IO-arme Tests der elevated-Apply-Sicherheits-Primitive.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from tools.system_tuner.application.apply_plan import bind_plan, verify_plan
from tools.system_tuner.application.consent_gate import (
    CURRENT_EULA_VERSION,
    ConsentGate,
)

_SECRET = b"0123456789abcdef0123456789abcdef"
_SIG = "catalog-signature-xyz"


def _bound() -> dict:
    return bind_plan(
        "tok-1", ["TW-A", "TW-B"], _SIG, secret=_SECRET
    ).to_dict()


class TestPlanBinding:
    def test_roundtrip(self):
        ids = verify_plan(_bound(), secret=_SECRET, expected_catalog_sig=_SIG)
        assert ids == ["TW-A", "TW-B"]

    def test_order_independent_hmac(self):
        # gleiche IDs in anderer Reihenfolge -> selbe Bindung gueltig
        payload = bind_plan("t", ["B", "A"], _SIG, secret=_SECRET).to_dict()
        assert verify_plan(payload, secret=_SECRET, expected_catalog_sig=_SIG) == [
            "B",
            "A",
        ]

    def test_tampered_ids_rejected(self):
        payload = _bound()
        payload["tweak_ids"] = ["TW-A", "TW-EVIL"]
        assert verify_plan(payload, secret=_SECRET, expected_catalog_sig=_SIG) is None

    def test_wrong_secret_rejected(self):
        assert (
            verify_plan(_bound(), secret=b"x" * 32, expected_catalog_sig=_SIG) is None
        )

    def test_used_token_rejected(self):
        assert (
            verify_plan(
                _bound(),
                secret=_SECRET,
                expected_catalog_sig=_SIG,
                used_tokens=frozenset({"tok-1"}),
            )
            is None
        )

    def test_wrong_catalog_sig_rejected(self):
        assert (
            verify_plan(_bound(), secret=_SECRET, expected_catalog_sig="other") is None
        )

    def test_schema_defect_rejected(self):
        assert verify_plan({"token": "x"}, secret=_SECRET, expected_catalog_sig=_SIG) is None


class TestConsentGate:
    def test_no_consent_initially(self, tmp_path: Path):
        gate = ConsentGate(tmp_path / "consent.json")
        assert gate.has_consent() is False

    def test_record_then_has_consent(self, tmp_path: Path):
        gate = ConsentGate(tmp_path / "consent.json")
        gate.record_consent(recorded_at="2026-06-17T00:00:00")
        assert gate.has_consent() is True

    def test_version_mismatch_requires_reconsent(self, tmp_path: Path):
        gate = ConsentGate(tmp_path / "consent.json")
        gate.record_consent(recorded_at="2026-06-17T00:00:00", eula_version="0.9")
        assert gate.has_consent(CURRENT_EULA_VERSION) is False
