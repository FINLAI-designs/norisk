"""test_scoring_service_subject — Subjekt-Auflösung im ScoringService.

Roundtrip-Tests (Memory-Regel: je Step ≥1 E2E):
    * berechne_score mit injiziertem SubjectStore → ``subject_id`` landet im
      SecurityScore UND in der ``scores``-Tabelle (DB-Roundtrip).
    * Ohne SubjectStore (Default) bleibt ``subject_id`` leer (fail-soft, inert).
    * compute_hardening_score reicht die ``subject_id`` an die Hardening-
      History durch (Retention-Key).

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die DB; der
SubjectStore wird als Duck-typed Fake injiziert (kein SQLCipher nötig).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from core.security_subject.models import Subject, SubjectKind
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.data.score_repository import ScoreRepository


class _FakeStore:
    """Minimaler SubjectStore-Fake (Duck-Typing gegen den core-Port)."""

    def __init__(self, subject_id: str = "self-xyz") -> None:
        self._sid = subject_id
        self.calls: list[str] = []

    def ensure_self_subject(self, name: str) -> Subject:
        self.calls.append(name)
        return Subject(subject_id=self._sid, kind=SubjectKind.EIGENES, name=name)


def _hardening_subject_ids() -> list[str]:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        rows = conn.execute("SELECT subject_id FROM hardening_scores").fetchall()
    return [r[0] for r in rows]


class TestScoringServiceSubject:
    def test_berechne_score_persists_subject_id(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            service = ScoringService(score_repo=repo, subject_store=_FakeStore("self-1"))
            score = service.berechne_score("Mein System")

            assert score.subject_id == "self-1"
            loaded = repo.lade_letzte_scores("Mein System", 1)
            assert loaded and loaded[0].subject_id == "self-1"

    def test_berechne_score_without_store_is_empty(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            score = ScoringService(score_repo=repo).berechne_score("Andere")
            assert score.subject_id == ""
            loaded = repo.lade_letzte_scores("Andere", 1)
            assert loaded and loaded[0].subject_id == ""

    def test_compute_hardening_score_passes_subject_id(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            service = ScoringService(subject_store=_FakeStore("self-2"))
            service.compute_hardening_score(target_name="Mein System")
            assert _hardening_subject_ids() == ["self-2"]
