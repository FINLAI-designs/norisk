"""Tests fuer den elevierten Recheck-Entry ``_run_recheck_hardening_cli`` (D6).

Prueft, dass JEDER Fehlerpfad einen signierten Reject-Marker schreibt (statt
still ohne Marker zu enden -> 90 s GUI-Timeout) und der Erfolgsfall ein
ok-Outcome liefert. Probe + is_admin werden gemockt (kein echtes UAC/Windows).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from apps import norisk_app

from core.security.severity import Severity
from tools.system_scanner.application.hardening_recheck import (
    read_and_consume_recheck_result,
)
from tools.system_scanner.domain.entities import HardeningCheck, OSInfo, ScanResult
from tools.system_scanner.domain.enums import OSPlatform, RecheckReason

_SCANNER = "tools.system_scanner.application.windows_hardening_scanner.run_hardening_baseline_scan"


def _scan() -> ScanResult:
    return ScanResult(
        scan_id="s1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=[
            HardeningCheck("SH-001", "SH-001", True, Severity.HIGH, measurable=True)
        ],
    )


def _argv(home: Path, nonce: str = "n1") -> list[str]:
    return [
        "norisk", "--recheck-hardening",
        "--finlai-home", str(home),
        "--recheck-nonce", nonce,
    ]


@pytest.fixture(autouse=True)
def _reset_home() -> Iterator[None]:
    from core.finlai_paths import set_finlai_home

    yield
    set_finlai_home(None)


@pytest.fixture
def _admin(monkeypatch) -> None:
    monkeypatch.setattr("core.elevation.is_admin", lambda: True)


def _read(home: Path):
    return read_and_consume_recheck_result(expected_nonce="n1", home=home)


def test_success_writes_ok_marker(tmp_path, monkeypatch, _admin) -> None:
    monkeypatch.setattr(_SCANNER, lambda: _scan())
    assert norisk_app._run_recheck_hardening_cli(_argv(tmp_path)) == 0
    out = _read(tmp_path)
    assert out is not None and out.ok
    assert out.scan is not None


def test_scan_none_writes_probe_unavailable(tmp_path, monkeypatch, _admin) -> None:
    monkeypatch.setattr(_SCANNER, lambda: None)
    assert norisk_app._run_recheck_hardening_cli(_argv(tmp_path)) == 0
    out = _read(tmp_path)
    assert out is not None and not out.ok
    assert out.reason is RecheckReason.PROBE_UNAVAILABLE


def test_scan_exception_writes_scan_failed(tmp_path, monkeypatch, _admin) -> None:
    def _boom() -> ScanResult:
        raise RuntimeError("probe kaputt")

    monkeypatch.setattr(_SCANNER, _boom)
    assert norisk_app._run_recheck_hardening_cli(_argv(tmp_path)) == 0
    out = _read(tmp_path)
    assert out is not None and not out.ok
    assert out.reason is RecheckReason.SCAN_FAILED


def test_not_admin_writes_reject(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("core.elevation.is_admin", lambda: False)
    assert norisk_app._run_recheck_hardening_cli(_argv(tmp_path)) == 0
    out = _read(tmp_path)
    assert out is not None and not out.ok
    assert out.reason is RecheckReason.NOT_ADMIN


def test_non_recheck_argv_returns_none(tmp_path) -> None:
    # Kein --recheck-hardening -> Dispatch gibt None zurueck (anderer Handler dran).
    assert norisk_app._run_recheck_hardening_cli(["norisk"]) is None
