"""test_subject_backfill — Tests für den Subjekt-Backfill der security_scoring-DB.

Deckt die Migrations-Fixtures aus dem Migrations-Test-Plan (security_scoring-Seite):
    * T1 Idempotenz: zweiter Lauf ist No-op (Marker), keine Doppel-Subjekte.
    * T2 Self/Org: Org-Assessment + Self-Target → eigenes Subjekt.
    * T4 Target-Mapping: distinkte Nicht-Self-Targets → je ein Kunden-Subjekt.
    * T7 Leer: leere DB → nur Singleton ensured, kein Crash.

Verifikation per direktem DB-Read (subject_id-Spalte) — testet den
Migrations-SQL-Pfad unabhängig von der Domain-Konstruktion.

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die DB pro Test.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from tools.security_scoring.application.subject_backfill import (
    SubjectBackfillInconsistentError,
    _assert_backfill_consistent,
    run_subject_backfill,
)
from tools.security_scoring.application.subject_store import (
    create_default_subject_store,
)
from tools.security_scoring.data.hardening_score_repository import (
    HardeningScoreRepository,
)
from tools.security_scoring.data.org_assessment_repository import (
    OrgAssessmentRepository,
)
from tools.security_scoring.data.score_repository import ScoreRepository

_SELF = "Mein System"


def _seed_org(audit_id: str) -> None:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO org_assessments (audit_id, timestamp, data_json) "
            "VALUES (?, ?, '{}')",
            (audit_id, "2026-06-01T00:00:00+00:00"),
        )


def _seed_score(target: str, score_id: str) -> None:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO scores (score_id, target_name, timestamp, overall, grade, "
            "data_json) VALUES (?, ?, ?, 80.0, 'B', '{}')",
            (score_id, target, "2026-06-01T00:00:00+00:00"),
        )


def _seed_hardening(target: str, score_id: str) -> None:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO hardening_scores (score_id, target_name, timestamp, overall, "
            "raw_weighted, stage_label, data_json) VALUES (?, ?, ?, 72.0, 72.0, 'X', '{}')",
            (score_id, target, "2026-06-01T00:00:00+00:00"),
        )


def _col_map(table: str, key_col: str) -> dict[str, str]:
    db = EncryptedDatabase("security_scoring")
    with db.connection() as conn:
        rows = conn.execute(f"SELECT {key_col}, subject_id FROM {table}").fetchall()
    return {r[0]: r[1] for r in rows}


def _ensure_schema() -> None:
    # Repos anlegen erzeugt Tabellen + subject_id-Spalte.
    OrgAssessmentRepository()
    ScoreRepository()
    HardeningScoreRepository()


# ---------------------------------------------------------------------------


class TestBackfill:
    def test_t7_empty_db_only_ensures_self(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            stats = run_subject_backfill(default_self_name=_SELF)
            assert stats == {
                "org": 0,
                "score_targets": 0,
                "hardening_targets": 0,
                "skipped_empty_targets": 0,
            }
            store = create_default_subject_store()
            assert store is not None
            assert store.get_self() is not None
            assert len(store.list_all()) == 1  # nur Singleton

    def test_t2_org_and_self_target_link_to_self(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_org("org-1")
            _seed_hardening(_SELF, "h-1")
            run_subject_backfill(default_self_name=_SELF)

            store = create_default_subject_store()
            self_id = store.get_self().subject_id
            assert _col_map("org_assessments", "audit_id")["org-1"] == self_id
            assert _col_map("hardening_scores", "score_id")["h-1"] == self_id

    def test_t4_distinct_client_targets_get_own_subjects(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_score(_SELF, "s-self")
            _seed_score("Kunde A GmbH", "s-a")
            _seed_score("Kunde B AG", "s-b")
            run_subject_backfill(default_self_name=_SELF)

            store = create_default_subject_store()
            self_id = store.get_self().subject_id
            scores = _col_map("scores", "score_id")
            assert scores["s-self"] == self_id
            assert scores["s-a"] != self_id and scores["s-a"] != ""
            assert scores["s-b"] != self_id and scores["s-b"] != ""
            assert scores["s-a"] != scores["s-b"]
            # 1 eigenes + 2 Kunden
            assert len(store.list_all()) == 3

    def test_t1_idempotent_second_run_is_noop(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_score("Kunde A GmbH", "s-a")
            first = run_subject_backfill(default_self_name=_SELF)
            assert first.get("skipped") is not True
            store = create_default_subject_store()
            count_after_first = len(store.list_all())

            second = run_subject_backfill(default_self_name=_SELF)
            assert second == {"skipped": True}
            assert len(create_default_subject_store().list_all()) == count_after_first

    # ---: Konsistenz-Assertion ---------------------------------------

    def _repos(self):
        return (
            OrgAssessmentRepository(),
            ScoreRepository(),
            HardeningScoreRepository(),
        )

    def test_assertion_raises_on_unlinked_org(self, tmp_path):
        import pytest

        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_org("o1")  # eligibel, ohne subject_id
            with pytest.raises(SubjectBackfillInconsistentError):
                _assert_backfill_consistent(*self._repos())

    def test_assertion_raises_on_unlinked_score_target(self, tmp_path):
        import pytest

        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_score("Acme GmbH", "s1")  # benennbares Ziel, ohne subject_id
            with pytest.raises(SubjectBackfillInconsistentError):
                _assert_backfill_consistent(*self._repos())

    def test_assertion_ignores_empty_target(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_score("", "s_empty")  # leeres Ziel -> nicht eligibel
            _assert_backfill_consistent(*self._repos())  # darf NICHT werfen

    def test_backfill_surfaces_skipped_empty_targets(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            _seed_score("", "s_empty")
            stats = run_subject_backfill(default_self_name=_SELF)
            assert stats["skipped_empty_targets"] >= 1

    # ---: Orphan-Cleanup (delete_subject_if_unreferenced) -------------

    def _seed_score_with_subject(self, target: str, score_id: str, sid: str) -> None:
        db = EncryptedDatabase("security_scoring")
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO scores (score_id, target_name, timestamp, overall, "
                "grade, data_json, subject_id) VALUES (?, ?, ?, 80.0, 'B', '{}', ?)",
                (score_id, target, "2026-06-01T00:00:00+00:00", sid),
            )

    def test_delete_unreferenced_removes_customer_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Acme GmbH")
            assert store.delete_subject_if_unreferenced(subject.subject_id) is True
            assert store.get(subject.subject_id) is None

    def test_delete_unreferenced_keeps_subject_with_score(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Beta AG")
            self._seed_score_with_subject("Beta AG", "s1", subject.subject_id)
            assert store.delete_subject_if_unreferenced(subject.subject_id) is False
            assert store.get(subject.subject_id) is not None

    def test_delete_unreferenced_keeps_subject_by_name_fallback(self, tmp_path):
        """Alt-Score ohne subject_id, aber gleicher target_name -> Subjekt bleibt."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Gamma KG")
            self._seed_score_with_subject("Gamma KG", "s1", "")  # subject_id leer
            assert store.delete_subject_if_unreferenced(subject.subject_id) is False
            assert store.get(subject.subject_id) is not None

    def test_delete_unreferenced_never_deletes_self(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            self_subject = store.ensure_self_subject(_SELF)
            assert (
                store.delete_subject_if_unreferenced(self_subject.subject_id) is False
            )
            assert store.get_self() is not None

    def test_delete_unreferenced_unknown_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            assert store.delete_subject_if_unreferenced("nope") is False
            assert store.delete_subject_if_unreferenced("") is False

    def test_delete_blocked_when_customer_avv_exists(self, tmp_path):
        """ E4: Kunde mit aufbewahrungspflichtigem Kunden-AVV bleibt.

        Cross-DB-Block ueber den core-Resolver ``create_avv_reference_check``:
        solange ein Kunden-AVV das Subjekt referenziert, blockiert
        ``delete_subject_if_unreferenced`` die Loeschung (keine Kaskade).
        """
        from datetime import UTC, datetime, timedelta

        from tools.supply_chain_monitor.data.customer_avv_repository import (
            CustomerAvvRepository,
        )
        from tools.supply_chain_monitor.domain.models import CustomerAvvDocument

        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Delta GmbH")

            repo = CustomerAvvRepository()
            now = datetime.now(UTC)
            repo.add(
                CustomerAvvDocument(
                    id=None,
                    subject_id=subject.subject_id,
                    file_path="/tmp/x.pdf.enc",
                    sha256="a" * 64,
                    size_bytes=10,
                    original_filename="x.pdf",
                    valid_from=now,
                    valid_until=now + timedelta(days=365),
                )
            )

            # AVV vorhanden -> Loeschung blockiert, Subjekt bleibt.
            assert store.delete_subject_if_unreferenced(subject.subject_id) is False
            assert store.get(subject.subject_id) is not None

            # AVV entfernt -> keine Referenz mehr -> Loeschung gelingt.
            avvs = repo.list_for_customer(subject.subject_id)
            assert avvs[0].id is not None
            assert repo.delete(avvs[0].id) is True
            assert store.delete_subject_if_unreferenced(subject.subject_id) is True
            assert store.get(subject.subject_id) is None

    def test_delete_blocked_when_customer_subprocessor_link_exists(self, tmp_path):
        """H (Live-Test 2026-07-01): Kunde mit Subunternehmer-Verknuepfung bleibt.

        Analog zum AVV-Block E4): solange eine
        ``customer_subprocessors``-Verknuepfung das Subjekt referenziert,
        blockiert ``delete_subject_if_unreferenced`` die Loeschung — sonst
        verwaisen die Links mit toter ``subject_id`` (Composite-Referenz-Check).
        """
        from tools.supply_chain_monitor.data.subprocessor_repository import (
            SubprocessorRepository,
        )
        from tools.supply_chain_monitor.domain.models import (
            Subprocessor,
            VendorCategory,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Epsilon GmbH")

            repo = SubprocessorRepository()
            sub_id = repo.add(
                Subprocessor(
                    id=None, name="AWS", country="US", category=VendorCategory.CLOUD
                )
            )
            link_id = repo.link_customer(subject.subject_id, sub_id, role="Storage")

            # Verknuepfung vorhanden -> Loeschung blockiert, Subjekt bleibt.
            assert store.delete_subject_if_unreferenced(subject.subject_id) is False
            assert store.get(subject.subject_id) is not None

            # Verknuepfung entfernt -> keine Referenz mehr -> Loeschung gelingt.
            assert repo.unlink_customer(link_id) is True
            assert store.delete_subject_if_unreferenced(subject.subject_id) is True
            assert store.get(subject.subject_id) is None
