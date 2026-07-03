"""test_security_scoring_subject_id_migration — Regression: Pre--Bestands-DB.

Reproduziert den Live-Befund vom 2026-06-07: auf einer **vor** angelegten
``security_scoring``-DB (Tabellen ``scores``/``org_assessments``/
``hardening_scores`` OHNE ``subject_id``) brach die Repo-Initialisierung mit
``no such column: subject_id`` ab — das Security-Scoring-Tool ließ sich nicht
öffnen und der Startup-Subjekt-Backfill wurde übersprungen.

Ursache war die Reihenfolge im Konstruktor: ``executescript(_SCHEMA)`` enthielt
ein ``CREATE INDEX... ON <tabelle>(subject_id)``, das VOR der additiven
``ensure_column``-Migration lief. Auf einer Bestands-DB ist das
``CREATE TABLE IF NOT EXISTS`` ein No-op, sodass die Index-Zeile auf eine noch
fehlende Spalte traf. Fresh DBs (CI) waren grün, weil ``CREATE TABLE`` dort die
Spalte gleich mitanlegt — klassischer „grün im Test, rot beim Bestandskunden".

Diese Tests legen die alten Tabellen explizit OHNE ``subject_id`` an (so wie sie
in der echten Bestands-DB introspiziert wurden) und verifizieren, dass der Init
heute fehlerfrei durchläuft und Spalte + subject-Index ergänzt werden.

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die DB pro Test.

Author: Patrick Riederich
Version: 1.0 (Fix security_scoring subject_id-Index-Reihenfolge, 2026-06-07)
"""

from __future__ import annotations

from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from tools.security_scoring.application.subject_backfill import run_subject_backfill
from tools.security_scoring.data.hardening_score_repository import (
    HardeningScoreRepository,
)
from tools.security_scoring.data.org_assessment_repository import (
    OrgAssessmentRepository,
)
from tools.security_scoring.data.score_repository import ScoreRepository

_DB = "security_scoring"

# Alt-DDL exakt wie in der echten Pre--DB introspiziert (ohne subject_id,
# ohne subject-Index). Eine Bestandszeile beweist, dass die additive Spalte den
# Default '' bekommt, ohne vorhandene Daten zu verlieren.
_PRE_T294_SCORES = """
CREATE TABLE scores (
    score_id     TEXT PRIMARY KEY,
    target_name  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    overall      REAL NOT NULL,
    grade        TEXT NOT NULL,
    data_json    TEXT NOT NULL
);
CREATE INDEX idx_scores_target_ts ON scores(target_name, timestamp DESC);
"""

_PRE_T294_ORG = """
CREATE TABLE org_assessments (
    audit_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    data_json  TEXT NOT NULL
);
CREATE INDEX idx_org_assessments_ts ON org_assessments(timestamp DESC);
"""

_PRE_T294_HARDENING = """
CREATE TABLE hardening_scores (
    score_id      TEXT PRIMARY KEY,
    target_name   TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    overall       REAL NOT NULL,
    raw_weighted  REAL NOT NULL,
    stage_label   TEXT NOT NULL,
    data_json     TEXT NOT NULL
);
CREATE INDEX idx_h_scores_target_ts ON hardening_scores(target_name, timestamp DESC);
"""


def _seed_pre_t294_db() -> None:
    """Legt die drei Tabellen im Pre--Schema an (je eine Bestandszeile)."""
    db = EncryptedDatabase(_DB)
    with db.connection() as conn:
        conn.executescript(_PRE_T294_SCORES)
        conn.executescript(_PRE_T294_ORG)
        conn.executescript(_PRE_T294_HARDENING)
        conn.execute(
            "INSERT INTO scores (score_id, target_name, timestamp, overall, grade, "
            "data_json) VALUES ('s1', 'Mein System', '2026-06-01T00:00:00+00:00', "
            "80.0, 'B', '{}')"
        )
        conn.execute(
            "INSERT INTO org_assessments (audit_id, timestamp, data_json) "
            "VALUES ('a1', '2026-06-01T00:00:00+00:00', '{}')"
        )
        conn.execute(
            "INSERT INTO hardening_scores (score_id, target_name, timestamp, overall, "
            "raw_weighted, stage_label, data_json) VALUES ('h1', 'Mein System', "
            "'2026-06-01T00:00:00+00:00', 72.0, 72.0, 'X', '{}')"
        )


def _columns(table: str) -> set[str]:
    db = EncryptedDatabase(_DB)
    with db.connection() as conn:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _index_names() -> set[str]:
    db = EncryptedDatabase(_DB)
    with db.connection() as conn:
        return {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }


# ---------------------------------------------------------------------------
# Repo-Init auf Bestands-DB (der eigentliche Regressionsbeweis)
# ---------------------------------------------------------------------------


class TestRepoInitOnPreT294Db:
    def test_score_repository_init_does_not_raise_and_migrates(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _seed_pre_t294_db()

            ScoreRepository()  # Vor dem Fix: no such column: subject_id

            assert "subject_id" in _columns("scores")
            assert "idx_scores_subject" in _index_names()
            db = EncryptedDatabase(_DB)
            with db.connection() as conn:
                val = conn.execute("SELECT subject_id FROM scores").fetchone()[0]
            assert val == ""  # Bestandszeile bekam den additiven Default

    def test_org_assessment_repository_init_does_not_raise_and_migrates(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _seed_pre_t294_db()

            OrgAssessmentRepository()

            assert "subject_id" in _columns("org_assessments")
            assert "idx_org_assessments_subject" in _index_names()

    def test_hardening_score_repository_init_does_not_raise_and_migrates(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _seed_pre_t294_db()

            HardeningScoreRepository()

            assert "subject_id" in _columns("hardening_scores")
            assert "idx_h_scores_subject" in _index_names()


# ---------------------------------------------------------------------------
# End-to-End: Startup-Backfill auf Bestands-DB (der Startup-Log-Pfad)
# ---------------------------------------------------------------------------


class TestSubjectBackfillOnPreT294Db:
    def test_backfill_runs_instead_of_being_skipped(self, tmp_path):
        """run_subject_backfill darf auf einer Bestands-DB nicht mehr crashen.

        Genau dieser Pfad lief am 2026-06-07 in `` Subjekt-Backfill
        uebersprungen: FinLaiDatabaseError``. Nach dem Fix läuft er durch und
        liefert Statistik statt einer Exception, und die Bestandszeilen sind
        einem Subjekt zugeordnet.
        """
        with patch.object(edb, "DB_DIR", tmp_path):
            _seed_pre_t294_db()

            stats = run_subject_backfill()

            assert stats.get("skipped") is not True
            db = EncryptedDatabase(_DB)
            with db.connection() as conn:
                sid = conn.execute(
                    "SELECT subject_id FROM scores WHERE score_id = 's1'"
                ).fetchone()[0]
            assert sid  # Self-Target → eigenes Subjekt, nicht mehr leer
