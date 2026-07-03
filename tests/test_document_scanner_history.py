"""
test_document_scanner_history.

Tests fuer:class:`HistoryRepository`. Wir umgehen die echte
EncryptedDatabase via eines In-Memory-SQLite-Mocks — der Repository-
Vertrag (add / list_recent / delete / clear) soll auch ohne SQLCipher
funktionieren.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from tools.document_scanner.data.history_repository import HistoryRepository
from tools.document_scanner.domain.models import (
    DocumentScanResult,
    QuarantineEntry,
    ScanVerdict,
)


class _FakeConnContext:
    """Wrapper damit eine sqlite3.Connection als context-manager-fluss
    der ``EncryptedDatabase.connection``-API folgt."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    """Minimaler EncryptedDatabase-Stub fuer Tests."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


def _make_result(name: str = "datei.pdf", verdict: ScanVerdict = ScanVerdict.SAFE):
    entry = QuarantineEntry(
        uuid=uuid4(),
        original_name=name,
        quarantine_dir=Path("/tmp/x"),
        stored_path=Path("/tmp/x/datei.pdf"),
        sha256="a" * 64,
        size_bytes=1234,
        created_at=datetime.now(UTC),
    )
    return DocumentScanResult(
        entry=entry,
        verdict=verdict,
        risk_score=20 if verdict is ScanVerdict.SUSPICIOUS else 0,
        magika_label="pdf",
        type_match=True,
        threats=[],
        validation_report=None,
        duration_ms=12.3,
        scanned_at=datetime.now(UTC),
    )


@pytest.fixture
def repo():
    return HistoryRepository(db=_InMemoryDB())


def test_schema_wird_initialisiert(repo: HistoryRepository) -> None:
    assert repo.list_recent() == []


def test_add_und_list_recent(repo: HistoryRepository) -> None:
    rid1 = repo.add(_make_result("a.pdf", ScanVerdict.SAFE))
    rid2 = repo.add(_make_result("b.docx", ScanVerdict.SUSPICIOUS))

    rows = repo.list_recent()
    assert len(rows) == 2
    ids = {r.id for r in rows}
    assert ids == {rid1, rid2}
    names = {r.original_name for r in rows}
    assert names == {"a.pdf", "b.docx"}


def test_list_recent_ordnung_neueste_zuerst(repo: HistoryRepository) -> None:
    # Reihenfolge erzwingen: kuenstliche Timestamps
    import time

    repo.add(_make_result("alt.pdf"))
    time.sleep(0.01)
    repo.add(_make_result("neu.pdf"))

    rows = repo.list_recent()
    assert rows[0].original_name == "neu.pdf"
    assert rows[1].original_name == "alt.pdf"


def test_delete(repo: HistoryRepository) -> None:
    rid = repo.add(_make_result())
    repo.delete(rid)
    assert repo.list_recent() == []


def test_clear(repo: HistoryRepository) -> None:
    for i in range(5):
        repo.add(_make_result(f"f_{i}.pdf"))
    removed = repo.clear()
    assert removed == 5
    assert repo.list_recent() == []


def test_threat_codes_roundtrip(repo: HistoryRepository) -> None:
    """``threat_codes`` werden als JSON gespeichert und beim Lesen geparst."""
    from dataclasses import dataclass

    @dataclass
    class _T:
        code: str

    result = _make_result()
    object.__setattr__(  # bypass frozen
        result,
        "threats",
        [_T("YARA_NoRisk_PS_Empire_Stager"), _T("SCRIPT_OBFUSCATION")],
    )
    repo.add(result)
    rows = repo.list_recent()
    assert rows[0].threat_codes == [
        "YARA_NoRisk_PS_Empire_Stager",
        "SCRIPT_OBFUSCATION",
    ]
