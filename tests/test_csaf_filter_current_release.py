"""
test_csaf_filter_current_release — Regression fuer den days-Filter
im Advisory-Monitor follow-up, 2026-05-14).

Patrick-Smoke 2026-05-14: Advisory-Monitor zeigte Advisories aus 2020,
2021, 2022 auch wenn "7 Tage" / "30 Tage" gewaehlt war. Ursache:
``AdvisoryRepository.list_advisories(days=N)`` filterte auf
``fetched_at`` (Download-Zeitstempel) statt ``current_release``
(Veroeffentlichungs-Datum). Beim initialen Bulk-Download stempelt der
Service alle Advisories mit ``fetched_at=now``, der Filter laesst dann
alle durch.

Nach dem Fix: ``current_release >= cutoff`` — alte Advisories werden
zuverlaessig ausgefiltert.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from tools.csaf_advisor.data.advisory_repository_impl import AdvisoryRepository


def _make_advisory_row(
    *,
    advisory_id: str,
    current_release: str,
    fetched_at: str,
    severity: str = "high",
) -> tuple:
    """Baut eine DB-Row-Tupel im Format das _row_to_advisory erwartet."""
    # Schema-Spaltenreihenfolge: id, title, publisher, tracking_id,
    # tracking_version, initial_release, current_release, severity,
    # cvss_score, cve_ids, affected_products, summary, source_url,
    # raw_json, fetched_at
    return (
        advisory_id,  # id
        "Test-Title",  # title
        "BSI",  # publisher
        f"BSI-{advisory_id}",  # tracking_id
        "1",  # tracking_version
        current_release,  # initial_release
        current_release,  # current_release
        severity,  # severity
        7.5,  # cvss_score
        "[]",  # cve_ids (JSON)
        "[]",  # affected_products (JSON)
        "",  # summary
        "",  # source_url
        "",  # raw_json
        fetched_at,  # fetched_at
    )


class TestDaysFilterUsesCurrentRelease:
    """Regression: ``days``-Filter prueft ``current_release`` nicht ``fetched_at``."""

    def _run_with_rows(
        self, rows: list[tuple], days: int | None
    ) -> tuple[list, list[object]]:
        """Fuehrt list_advisories(days=N) gegen einen In-Memory-Cursor aus
        und liefert (Ergebnis-Liste, Query-Params) zurueck."""
        with patch(
            "tools.csaf_advisor.data.advisory_repository_impl.EncryptedDatabase"
        ) as mock_db_cls:
            captured_query: list[str] = []
            captured_params: list[list[object]] = []

            def execute(query: str, params: list[object] = None):  # noqa: ANN001
                captured_query.append(query)
                if params is not None:
                    captured_params.append(params)
                # SELECT-Resultset: liefere ``rows`` wenn die Query
                # ``FROM csaf_advisories`` enthaelt, sonst leeren Cursor.
                cursor = MagicMock()
                if "FROM csaf_advisories" in query and "COUNT" not in query:
                    cursor.fetchall.return_value = rows
                else:
                    cursor.fetchall.return_value = []
                cursor.fetchone.return_value = None
                return cursor

            conn = MagicMock()
            conn.execute = execute
            mock_db_cls.return_value.connection.return_value.__enter__.return_value = conn

            repo = AdvisoryRepository()
            result = repo.list_advisories(days=days)
            return result, captured_params[-1] if captured_params else []

    def test_days_filter_verwendet_current_release_in_query(self) -> None:
        """Die SQL-Query muss ``current_release >=`` enthalten, nicht
        ``fetched_at >=``."""
        with patch(
            "tools.csaf_advisor.data.advisory_repository_impl.EncryptedDatabase"
        ) as mock_db_cls:
            captured_queries: list[str] = []
            conn = MagicMock()

            def execute(query: str, params=None):  # noqa: ANN001
                captured_queries.append(query)
                cursor = MagicMock()
                cursor.fetchall.return_value = []
                cursor.fetchone.return_value = None
                return cursor

            conn.execute = execute
            mock_db_cls.return_value.connection.return_value.__enter__.return_value = conn

            repo = AdvisoryRepository()
            repo.list_advisories(days=30)

            list_query = next(
                q for q in captured_queries
                if "FROM csaf_advisories" in q and "COUNT" not in q
            )
            assert "current_release >= ?" in list_query
            assert "fetched_at >= ?" not in list_query

    def test_days_filter_blockiert_alte_advisories(self) -> None:
        """Advisory von 2020 mit fetched_at=heute darf den 30-Tage-Filter
        NICHT passieren — auch wenn fetched_at frisch ist."""
        heute = datetime.now(UTC).isoformat()
        vor_5_jahren = (datetime.now(UTC) - timedelta(days=5 * 365)).isoformat()

        # SQL muss schon im Repository den 2020er-Eintrag rausfiltern —
        # wir testen das hier auf SQL-Statement-Level mit einem echten
        # In-Memory-SQLite, weil String-Vergleich plattform-abhängig ist.
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE csaf_advisories (
                id TEXT PRIMARY KEY,
                title TEXT, publisher TEXT, tracking_id TEXT,
                tracking_version TEXT, initial_release TEXT,
                current_release TEXT, severity TEXT, cvss_score REAL,
                cve_ids TEXT, affected_products TEXT, summary TEXT,
                source_url TEXT, raw_json TEXT, fetched_at TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO csaf_advisories VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                _make_advisory_row(
                    advisory_id="alt-2020",
                    current_release=vor_5_jahren,
                    fetched_at=heute,
                ),
                _make_advisory_row(
                    advisory_id="neu-heute",
                    current_release=heute,
                    fetched_at=heute,
                ),
            ],
        )

        # 30-Tage-Cutoff
        cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        rows = conn.execute(
            "SELECT id FROM csaf_advisories WHERE current_release >= ?",
            (cutoff,),
        ).fetchall()
        ids = [r[0] for r in rows]
        conn.close()
        assert "neu-heute" in ids
        assert "alt-2020" not in ids

    def test_days_filter_alte_fetched_at_query_haette_alle_durchgelassen(self) -> None:
        """Dokumentiert den alten Bug: Filter auf ``fetched_at`` haette
        beide Advisories durchgelassen (beide haben fetched_at=heute)."""
        heute = datetime.now(UTC).isoformat()
        vor_5_jahren = (datetime.now(UTC) - timedelta(days=5 * 365)).isoformat()

        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE csaf_advisories (
                id TEXT PRIMARY KEY,
                title TEXT, publisher TEXT, tracking_id TEXT,
                tracking_version TEXT, initial_release TEXT,
                current_release TEXT, severity TEXT, cvss_score REAL,
                cve_ids TEXT, affected_products TEXT, summary TEXT,
                source_url TEXT, raw_json TEXT, fetched_at TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO csaf_advisories VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                _make_advisory_row(
                    advisory_id="alt-2020",
                    current_release=vor_5_jahren,
                    fetched_at=heute,
                ),
                _make_advisory_row(
                    advisory_id="neu-heute",
                    current_release=heute,
                    fetched_at=heute,
                ),
            ],
        )

        cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        # Alter Bug-Pfad — beide Eintraege haben fetched_at=heute,
        # also liefert der falsche Filter beide zurueck.
        rows = conn.execute(
            "SELECT id FROM csaf_advisories WHERE fetched_at >= ?",
            (cutoff,),
        ).fetchall()
        ids = sorted(r[0] for r in rows)
        conn.close()
        assert ids == ["alt-2020", "neu-heute"], (
            "Wenn dieser Test fehlschlaegt, hat sich das Bug-Pattern "
            "geaendert — die Doku oben anpassen."
        )

    def test_days_none_kein_zeitfilter(self) -> None:
        """``days=None`` setzt keinen Cutoff — alle Advisories werden
        zurueckgegeben."""
        with patch(
            "tools.csaf_advisor.data.advisory_repository_impl.EncryptedDatabase"
        ) as mock_db_cls:
            captured_queries: list[str] = []
            conn = MagicMock()

            def execute(query: str, params=None):  # noqa: ANN001
                captured_queries.append(query)
                cursor = MagicMock()
                cursor.fetchall.return_value = []
                cursor.fetchone.return_value = None
                return cursor

            conn.execute = execute
            mock_db_cls.return_value.connection.return_value.__enter__.return_value = conn

            repo = AdvisoryRepository()
            repo.list_advisories(days=None)

            list_query = next(
                q for q in captured_queries
                if "FROM csaf_advisories" in q and "COUNT" not in q
            )
            # ``current_release`` kommt im ORDER BY immer vor — wir testen
            # spezifisch dass kein Zeit-Cutoff (``>= ?``) gesetzt wurde.
            assert "current_release >= ?" not in list_query
            assert "fetched_at >= ?" not in list_query
            assert "WHERE" not in list_query


@pytest.fixture(autouse=True)
def _no_disk_io(monkeypatch, tmp_path):
    monkeypatch.setenv("FINLAI_DB_DIR", str(tmp_path))
    yield
