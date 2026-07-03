"""test_hardening_retention_subject — Retention auf subject_id-Key, T5).

Verifiziert den Retention-Re-Key aus: Tages-Dedup + N-Tage-Cap der
``hardening_scores`` arbeiten auf ``COALESCE(NULLIF(subject_id,''), target_name)``
statt hart auf ``target_name``:

    * Dedup keyt auf das Subjekt — auch wenn der ``target_name`` zwischen zwei
      Speicherungen wechselt (Subjekt umbenannt), bleibt EIN Eintrag/Tag.
    * Cap keyt auf das Subjekt (N jüngste Tage pro Subjekt).
    * Legacy-Fallback: ohne ``subject_id`` (leer) verhält sich die Retention
      exakt wie vorher (Key = ``target_name``).
    * Gemischter Bestand (eine Zeile mit, eine ohne ``subject_id``) bricht
      NICHT und kollabiert nicht fälschlich.

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from tools.security_scoring.data import hardening_score_repository as hsr_mod
from tools.security_scoring.data.hardening_score_repository import (
    HardeningScoreRepository,
)
from tools.security_scoring.domain.hardening_score import HardeningScoreResult
from tools.security_scoring.domain.hardening_stages import score_to_stage


def _result(overall: float) -> HardeningScoreResult:
    return HardeningScoreResult(
        overall_score=overall,
        stage=score_to_stage(overall),
        category_scores=(),
        missing_categories=(),
        hard_cap_events=(),
        raw_weighted_score=overall,
    )


def _count_total() -> int:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM hardening_scores").fetchone()[0]


def _overall_for_subject(subject_id: str) -> list[float]:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT overall FROM hardening_scores WHERE subject_id = ? "
            "ORDER BY timestamp DESC",
            (subject_id,),
        ).fetchall()
    return [r[0] for r in rows]


class TestRetentionSubjectKey:
    def test_dedup_by_subject_same_day_latest_wins(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "Sys", _result(60.0),
                timestamp="2026-06-01T08:00:00+00:00", subject_id="subj-1",
            )
            repo.save_score(
                "Sys", _result(72.0),
                timestamp="2026-06-01T20:00:00+00:00", subject_id="subj-1",
            )
            # Ein Eintrag pro Subjekt/Tag — der spätere (72) gewinnt.
            assert _overall_for_subject("subj-1") == [72.0]

    def test_dedup_keyed_by_subject_not_target_name(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            # Subjekt umbenannt zwischen den Speicherungen (target wechselt),
            # subject_id bleibt stabil → trotzdem Dedup auf einen Tageseintrag.
            repo.save_score(
                "Alter Name", _result(60.0),
                timestamp="2026-06-01T08:00:00+00:00", subject_id="subj-1",
            )
            repo.save_score(
                "Neuer Name", _result(72.0),
                timestamp="2026-06-01T20:00:00+00:00", subject_id="subj-1",
            )
            assert _overall_for_subject("subj-1") == [72.0]
            assert _count_total() == 1

    def test_cap_per_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path), patch.object(
            hsr_mod, "_RETENTION_DAYS", 3
        ):
            repo = HardeningScoreRepository()
            for day in range(1, 6):  # 5 verschiedene Tage
                repo.save_score(
                    "Sys", _result(50.0 + day),
                    timestamp=f"2026-06-0{day}T08:00:00+00:00",
                    subject_id="subj-1",
                )
            # Cap = 3 → nur die 3 jüngsten Tage bleiben.
            assert _count_total() == 3
            assert _overall_for_subject("subj-1") == [55.0, 54.0, 53.0]

    def test_legacy_fallback_dedup_by_target_when_subject_empty(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            # Kein subject_id → Key fällt auf target_name zurück (Alt-Verhalten).
            repo.save_score(
                "Sys", _result(60.0), timestamp="2026-06-01T08:00:00+00:00"
            )
            repo.save_score(
                "Sys", _result(72.0), timestamp="2026-06-01T20:00:00+00:00"
            )
            assert _count_total() == 1

    def test_mixed_bestand_does_not_collapse_or_crash(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            # Alt-Zeile ohne subject_id (Key = "Sys")...
            repo.save_score(
                "Sys", _result(60.0), timestamp="2026-06-01T08:00:00+00:00"
            )
            #... und neue Zeile mit subject_id (Key = "subj-1"), gleicher Tag.
            repo.save_score(
                "Sys", _result(72.0),
                timestamp="2026-06-01T20:00:00+00:00", subject_id="subj-1",
            )
            # Verschiedene Retention-Keys → beide überleben (transienter Zustand
            # bis der Backfill die Alt-Zeile mit subject_id versieht). Kein Crash.
            assert _count_total() == 2
