"""
test_awareness_tracker_csv_template — Muster-CSV-Vorlage + Roundtrip.

Tests fuer die herunterladbare CSV-Vorlage des Awareness-Trackers
(``build_template_csv``): der exportierte Header MUSS exakt dem vom
``csv_importer`` akzeptierten Schema entsprechen, und die mitgelieferten
Beispielzeilen MUESSEN fehlerfrei durch den jeweiligen Importer laufen
(Roundtrip Vorlage -> Importer).

Author: Patrick Riederich
"""

from __future__ import annotations

import csv
import io
import sqlite3

import pytest

from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.application.csv_importer import (
    EMPLOYEE_HEADER,
    TRAINING_HEADER,
    import_employees_from_csv,
    import_trainings_from_csv,
)
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.gui.csv_import_dialog import (
    CsvImportMode,
    build_template_csv,
)


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
        self._conn.execute("PRAGMA foreign_keys = ON")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def service() -> AwarenessService:
    repo = AwarenessRepository(db=_InMemoryDB())
    return AwarenessService(repository=repo)


def _read_rows(csv_text: str) -> tuple[list[str], list[list[str]]]:
    """Liest Header + Datenzeilen aus dem Vorlage-CSV-String."""
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert rows, "Vorlage darf nicht leer sein."
    return rows[0], rows[1:]


# ---------------------------------------------------------------------------
# Header-Korrektheit (= Importer-Schema)
# ---------------------------------------------------------------------------


class TestTemplateHeader:
    def test_employee_header_matches_importer(self) -> None:
        header, _rows = _read_rows(build_template_csv(CsvImportMode.EMPLOYEES))
        assert tuple(header) == EMPLOYEE_HEADER

    def test_training_header_matches_importer(self) -> None:
        header, _rows = _read_rows(build_template_csv(CsvImportMode.TRAININGS))
        assert tuple(header) == TRAINING_HEADER

    def test_employee_template_has_example_rows(self) -> None:
        _header, rows = _read_rows(build_template_csv(CsvImportMode.EMPLOYEES))
        assert len(rows) >= 1
        # Jede Beispielzeile hat genau so viele Spalten wie der Header.
        for row in rows:
            assert len(row) == len(EMPLOYEE_HEADER)

    def test_training_template_has_example_rows(self) -> None:
        _header, rows = _read_rows(build_template_csv(CsvImportMode.TRAININGS))
        assert len(rows) >= 1
        for row in rows:
            assert len(row) == len(TRAINING_HEADER)


# ---------------------------------------------------------------------------
# Roundtrip: Vorlage -> Importer (fehlerfrei)
# ---------------------------------------------------------------------------


class TestTemplateRoundtrip:
    def test_employee_template_imports_without_errors(
        self, service: AwarenessService
    ) -> None:
        csv_text = build_template_csv(CsvImportMode.EMPLOYEES)
        result = import_employees_from_csv(csv_text, service)
        assert not result.errors, f"Unerwartete Fehler: {result.errors}"
        assert result.added_count >= 1
        assert len(service.list_employees()) == result.added_count

    def test_training_template_imports_without_errors(
        self, service: AwarenessService
    ) -> None:
        # Erst Mitarbeiter-Vorlage importieren (Patrick-Direktive: erst
        # Mitarbeiter, dann Schulungen) — die Schulungs-Beispielzeilen
        # referenzieren genau diese Personen.
        emp_csv = build_template_csv(CsvImportMode.EMPLOYEES)
        emp_result = import_employees_from_csv(emp_csv, service)
        assert not emp_result.errors

        train_csv = build_template_csv(CsvImportMode.TRAININGS)
        result = import_trainings_from_csv(train_csv, service)
        assert not result.errors, f"Unerwartete Fehler: {result.errors}"
        assert result.added_count >= 1
        assert len(service.list_trainings()) == result.added_count

    def test_full_roundtrip_through_file(
        self, service: AwarenessService, tmp_path
    ) -> None:
        # Echter Datei-Roundtrip: schreibe die Vorlage so, wie die GUI sie
        # schreibt (utf-8, kein BOM), und lese sie so ein, wie der Import-
        # Dialog liest (encoding="utf-8"). Das deckt das BOM-Risiko ab:
        # waere ein BOM dabei, bliebe es am ersten Header haengen und der
        # Import schluege fehl.
        target = tmp_path / "mitarbeiter_vorlage.csv"
        target.write_text(
            build_template_csv(CsvImportMode.EMPLOYEES), encoding="utf-8"
        )
        decoded = target.read_text(encoding="utf-8")
        result = import_employees_from_csv(decoded, service)
        assert not result.errors
        assert result.added_count >= 1
        # Erstes Feld muss exakt "full_name" sein (kein BOM-Praefix).
        assert decoded.splitlines()[0].split(",")[0] == "full_name"
