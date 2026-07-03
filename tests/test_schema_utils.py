"""tests/test_schema_utils — Identifier-Guard fuer den additiven Schema-Helfer.

Deckt:func:`core.database.schema_utils.ensure_column` und den fail-closed
Identifier-Guard:func:`_require_identifier` ab. Nutzt eine stdlib-
``sqlite3``-In-Memory-DB — ``ensure_column`` braucht nur PRAGMA/ALTER, kein
SQLCipher; so bleibt der Test schnell und headless.
"""

from __future__ import annotations

import sqlite3

import pytest

from core.database.schema_utils import _require_identifier, ensure_column


class TestRequireIdentifier:
    def test_gueltige_identifier_kein_raise(self):
        _require_identifier("subject_id", "Spalten")
        _require_identifier("system_profiles", "Tabellen")
        _require_identifier("_intern", "Spalten")

    def test_injection_versuch_raises(self):
        with pytest.raises(ValueError, match="Ungueltiger"):
            _require_identifier("t; DROP TABLE y", "Tabellen")

    def test_klammer_und_kommentar_raises(self):
        with pytest.raises(ValueError):
            _require_identifier("c) ; DROP TABLE t --", "Spalten")

    def test_leerstring_raises(self):
        with pytest.raises(ValueError):
            _require_identifier("", "Spalten")

    def test_fuehrende_ziffer_raises(self):
        with pytest.raises(ValueError):
            _require_identifier("1col", "Spalten")

    def test_nicht_string_raises(self):
        with pytest.raises(ValueError):
            _require_identifier(None, "Spalten")  # type: ignore[arg-type]


class TestEnsureColumnGuard:
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (id INTEGER)")
        return conn

    def test_fuegt_spalte_additiv_hinzu(self):
        conn = self._conn()
        assert ensure_column(conn, "t", "neu", "TEXT DEFAULT ''") is True
        cols = {row[1] for row in conn.execute("PRAGMA table_info(t)")}
        assert "neu" in cols

    def test_idempotent(self):
        conn = self._conn()
        ensure_column(conn, "t", "neu", "TEXT DEFAULT ''")
        assert ensure_column(conn, "t", "neu", "TEXT DEFAULT ''") is False

    def test_boeser_table_identifier_raises(self):
        conn = self._conn()
        with pytest.raises(ValueError):
            ensure_column(conn, "t; DROP TABLE t", "neu", "TEXT")

    def test_boeser_column_identifier_raises(self):
        conn = self._conn()
        with pytest.raises(ValueError):
            ensure_column(conn, "t", "neu) ; DROP TABLE t --", "TEXT")


class TestEchteAufruferIdentifierGueltig:
    """Smoke-Auflage): die Identifier ALLER 5 Produktiv-Aufrufer von
    ``ensure_column`` muessen den Guard passieren — sonst braeche der Guard eine
    legitime Migration. Werte gespiegelt aus den Repositories (Stand 2026-06-09).
    """

    _ECHTE_IDENTIFIER = {
        "customer_audits": [
            "subject_id",
            "version",
            "supersedes_audit_id",
            "root_audit_id",
            "is_latest",
        ],
        "hardening_scores": ["subject_id"],
        "org_assessments": ["subject_id"],
        "scores": ["subject_id"],
        "system_profiles": [
            "branche",
            "groesse",
            "fte",
            "umsatz_eur",
            "bilanzsumme_eur",
            "sektor_key",
            "nis2_anhang",
            "rolle",
            "segment",
            "hat_eigene_website",
            "hat_eigene_api",
            "ist_entwickler",
            "hat_server_infrastruktur",
        ],
    }

    def test_alle_echten_identifier_passieren_guard(self):
        for tabelle, spalten in self._ECHTE_IDENTIFIER.items():
            _require_identifier(tabelle, "Tabellen")  # darf nicht werfen
            for spalte in spalten:
                _require_identifier(spalte, "Spalten")
