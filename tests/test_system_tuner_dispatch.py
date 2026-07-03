"""
test_system_tuner_dispatch — A1 (voll): Dev/Smoke-Flag-Gating im Entry-Dispatch.

Stellt sicher, dass `_run_system_tuner_apply_cli` die Dev/Smoke-Flags
(`--allow-apply`/`--skip-restore-point`/`--allow-untrusted-path`/`--catalog`)
in Produktion (frozen) bzw. ohne Env-Opt-in HART ignoriert und nur im non-frozen
Dev-Build mit `NORISK_SYSTEM_TUNER_DEV=1` honoriert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import sys

from apps import norisk_app

_DEV_ENV = "NORISK_SYSTEM_TUNER_DEV"
_ARGV = [
    "--system-tuner-apply",
    "--plan",
    "p.json",
    "--catalog",
    "evil.yaml",
    "--allow-apply",
    "--skip-restore-point",
    "--allow-untrusted-path",
]


def _capture(monkeypatch):
    calls: dict = {}

    def _fake(**kwargs):
        calls.update(kwargs)
        return 0

    monkeypatch.setattr(
        "tools.system_tuner.application.elevated_round_trip.run_apply_entry", _fake
    )
    return calls


def test_no_flag_returns_none():
    assert norisk_app._run_system_tuner_apply_cli(["--other"]) is None


def test_frozen_ignores_dev_flags(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv(_DEV_ENV, "1")  # selbst mit Env: frozen gewinnt
    norisk_app._run_system_tuner_apply_cli(_ARGV)
    assert calls["allow_apply"] is False
    assert calls["skip_restore_point"] is False
    assert calls["allow_untrusted_path"] is False
    assert calls["catalog_path"] is None  # Fremdkatalog ignoriert


def test_non_frozen_without_env_ignores(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.delenv(_DEV_ENV, raising=False)
    norisk_app._run_system_tuner_apply_cli(_ARGV)
    assert calls["allow_apply"] is False
    assert calls["allow_untrusted_path"] is False
    assert calls["catalog_path"] is None


def test_dev_build_with_optin_honors(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setenv(_DEV_ENV, "1")
    norisk_app._run_system_tuner_apply_cli(_ARGV)
    assert calls["allow_apply"] is True
    assert calls["skip_restore_point"] is True
    assert calls["allow_untrusted_path"] is True
    assert str(calls["catalog_path"]) == "evil.yaml"
