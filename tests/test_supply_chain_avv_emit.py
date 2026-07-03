"""
test_supply_chain_avv_emit-ii.

Tests fuer:meth:`AvvService.emit_renewal_findings` mit Mock-Emitter.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.storytelling.ki_todo_emitter import KiTodoEmitter
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.data.avv_repository import AvvRepository


class _RecordingEmitter(KiTodoEmitter):
    """Test-Double: zeichnet alle emit-Calls auf statt zu schicken."""

    def __init__(self) -> None:
        super().__init__()
        self.emitted: list[list] = []

    def emit(self, findings: Iterable) -> None:  # type: ignore[override]
        self.emitted.append(list(findings))


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


def _make_pdf(path: Path) -> Path:
    path.write_bytes(b"X" * 64)
    return path


@pytest.fixture
def emitter() -> _RecordingEmitter:
    return _RecordingEmitter()


@pytest.fixture
def service(tmp_path: Path, emitter: _RecordingEmitter) -> AvvService:
    return AvvService(
        repository=AvvRepository(db=_InMemoryDB()),
        storage_root=tmp_path,
        ki_todo_emitter=emitter,
    )


def _upload(service: AvvService, tmp_path: Path, days_until: int, sha_char: str) -> None:
    pdf = _make_pdf(tmp_path / f"{sha_char}.pdf")
    now = datetime.now(UTC)
    service.upload_avv(
        vendor_id=1,
        source_path=pdf,
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=days_until),
    )


def test_emit_renewal_findings_schickt_actionable_eintraege(
    service: AvvService,
    emitter: _RecordingEmitter,
    tmp_path: Path,
) -> None:
    _upload(service, tmp_path, days_until=400, sha_char="a")  # OK
    _upload(service, tmp_path, days_until=45, sha_char="b")  # EXPIRING_SOON
    _upload(service, tmp_path, days_until=-3, sha_char="c")  # OVERDUE

    count = service.emit_renewal_findings()
    # OK wird gefiltert, also 2 Findings.
    assert count == 2
    assert len(emitter.emitted) == 1
    findings = emitter.emitted[0]
    types = {f.finding_type for f in findings}
    assert types == {"avv_renewal_soon", "avv_renewal_overdue"}


def test_emit_renewal_ohne_actionable_macht_keinen_emit_call(
    service: AvvService,
    emitter: _RecordingEmitter,
    tmp_path: Path,
) -> None:
    _upload(service, tmp_path, days_until=400, sha_char="a")  # OK
    count = service.emit_renewal_findings()
    assert count == 0
    assert emitter.emitted == []


def test_emit_renewal_haengt_vendor_name_lookup_durch(
    service: AvvService,
    emitter: _RecordingEmitter,
    tmp_path: Path,
) -> None:
    _upload(service, tmp_path, days_until=10, sha_char="a")
    service.emit_renewal_findings(vendor_name_lookup={1: "Microsoft"})
    assert emitter.emitted[0][0].subject == "Microsoft"
