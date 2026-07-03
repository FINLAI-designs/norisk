"""
test_system_tuner_elevated — Trust-Boundary-Orchestrator (R5/R6/R7).

Mock-getestete elevated-Apply-Logik: Sign-off-Gate, Signatur-Gate, Plan-Binding,
Katalog-Re-Resolve, Restore-Point fail-closed, Anwendung via Engine.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.system_tuner.application.apply_plan import bind_plan
from tools.system_tuner.application.catalog_loader import load_catalog_from_mapping
from tools.system_tuner.application.elevated_apply import run_elevated_apply
from tools.system_tuner.data.mock_tweak_probe import MockTweakProbe
from tools.system_tuner.data.snapshot_repository import InMemorySnapshotRepo
from tools.system_tuner.domain.entities import Tweak
from tools.system_tuner.domain.enums import TweakStatus

_SECRET = b"0123456789abcdef0123456789abcdef"
_SIG = "catalog-sig-1"


@pytest.fixture(autouse=True)
def _enable_apply(monkeypatch):
    """A1: run_elevated_apply verlangt jetzt die autoritative Modul-Konstante
    APPLY_ENABLED=True. Diese Tests simulieren den Post-Sign-off-Zustand und
    pruefen die ANDEREN Gates (Signatur/Plan-Binding/Re-Resolve/Restore-Point)."""
    monkeypatch.setattr(
        "tools.system_tuner.application.elevated_apply.APPLY_ENABLED", True
    )
_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"


def _reg_tweak(tweak_id: str = "TW-R") -> Tweak:
    return load_catalog_from_mapping(
        {
            "catalog_version": "1.0",
            "tweaks": [
                {
                    "id": tweak_id,
                    "title_de": "T",
                    "category": "telemetry",
                    "risk_tier": "T1_safe",
                    "recommend": "standard",
                    "rationale_de": "x",
                    "docs_url": "https://learn.microsoft.com/x",
                    "compliance_relevance": ["Unterstuetzt DSGVO Art. 32 (TOM)"],
                    "provenance": {"source": "MS"},
                    "change": {
                        "op": "registry_set",
                        "hive": "HKLM",
                        "key": _KEY,
                        "value_name": "AllowTelemetry",
                        "value_type": "REG_DWORD",
                        "desired": 1,
                    },
                    "verify": {"expect_value": 1},
                    "revert": {"kind": "restore_prior"},
                }
            ],
        }
    )[0]


def _payload(ids: list[str], token: str = "tok-1") -> dict:
    return bind_plan(token, ids, _SIG, secret=_SECRET).to_dict()


def _run(payload: dict, **kw: Any):
    defaults: dict[str, Any] = {
        "secret": _SECRET,
        "expected_catalog_sig": _SIG,
        "signature_ok": True,
        "apply_enabled": True,
    }
    defaults.update(kw)
    return run_elevated_apply(
        payload,
        [_reg_tweak()],
        MockTweakProbe(),
        InMemorySnapshotRepo(),
        **defaults,
    )


class TestGates:
    def test_sign_off_gate_closed_rejects(self):
        result = _run(_payload(["TW-R"]), apply_enabled=False)
        assert result.results == ()

    def test_invalid_signature_rejects(self):
        assert _run(_payload(["TW-R"]), signature_ok=False).results == ()

    def test_tampered_plan_rejects(self):
        payload = _payload(["TW-R"])
        payload["hmac"] = "deadbeef"
        assert _run(payload).results == ()

    def test_uncatalogued_id_rejects(self):
        assert _run(_payload(["TW-UNKNOWN"])).results == ()

    def test_used_token_rejects(self):
        assert _run(_payload(["TW-R"]), used_tokens=frozenset({"tok-1"})).results == ()

    def test_wrong_expected_sig_rejects(self):
        assert _run(_payload(["TW-R"]), expected_catalog_sig="other").results == ()

    def test_module_signoff_gate_authoritative(self, monkeypatch):
        # A1: Selbst mit apply_enabled=True rejectet das Modul-Gate, solange die
        # Konstante APPLY_ENABLED=False ist (argv/--allow-apply genuegt NICHT).
        monkeypatch.setattr(
            "tools.system_tuner.application.elevated_apply.APPLY_ENABLED", False
        )
        assert _run(_payload(["TW-R"])).results == ()


class TestApply:
    def test_valid_plan_applies(self):
        probe = MockTweakProbe()
        result = run_elevated_apply(
            _payload(["TW-R"]),
            [_reg_tweak()],
            probe,
            InMemorySnapshotRepo(),
            secret=_SECRET,
            expected_catalog_sig=_SIG,
            signature_ok=True,
            apply_enabled=True,
        )
        assert result.results[0].status is TweakStatus.SUCCESS
        assert probe.read_registry_value("HKLM", _KEY, "AllowTelemetry") == "1"

    def test_restore_point_failure_blocks(self):
        result = _run(_payload(["TW-R"]), restore_point=lambda: False)
        assert result.results[0].status is TweakStatus.BLOCKED

    def test_restore_point_success_proceeds(self):
        result = _run(_payload(["TW-R"]), restore_point=lambda: True)
        assert result.results[0].status is TweakStatus.SUCCESS
