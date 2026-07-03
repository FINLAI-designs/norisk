"""test_audit_subject_backfill — Tests für den Subjekt-Backfill der customer_audit-DB.

Deckt die Migrations-Fixtures aus dem Migrations-Test-Plan (customer_audit-Seite,
§2 Schritt 4):
    * T1 Idempotenz: zweiter Lauf ist No-op (Marker), keine Doppel-Subjekte.
    * T3 Dedup: zwei Kunden-Audits mit gleichem ``firmenname`` → ein Kunden-Subjekt.
    * T7 Leer: leere DB → kein Crash, Zähler 0.
    * Self-Audit → eigenes Subjekt; Stammdaten (branche/groesse) ins Subjekt gezogen.
    * Roundtrip: ``set_subject_id`` hält Spalte UND ``result_json``-Blob konsistent.

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert beide DBs
(customer_audit + security_scoring) pro Test.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from tools.customer_audit.application.subject_backfill import (
    AuditBackfillInconsistentError,
    _assert_audit_backfill_consistent,
    run_audit_subject_backfill,
)
from tools.customer_audit.data.customer_audit_repository import (
    CustomerAuditRepository,
)
from tools.security_scoring.application.subject_store import (
    create_default_subject_store,
)

_SELF = "Mein System"


def _seed_audit(
    audit_id: str,
    firmenname: str,
    mode: str,
    *,
    branche: str = "Sonstige",
    groesse: str = "1-10",
) -> None:
    """Schreibt eine customer_audits-Zeile OHNE subject_id (Pre--Bestand)."""
    result = {
        "audit_id": audit_id,
        "audit_mode": mode,
        "customer_data": {
            "firmenname": firmenname,
            "branche": branche,
            "unternehmensgroesse": groesse,
            "ansprechpartner_name": "Kontaktperson",
        },
    }
    db = EncryptedDatabase("customer_audit")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO customer_audits (audit_id, firmenname, created_at, "
            "overall_score, risk_level, result_json, subject_id) "
            "VALUES (?, ?, ?, 0.0, 'Mittel', ?, '')",
            (audit_id, firmenname, "2026-06-01T00:00:00+00:00", json.dumps(result)),
        )


def _audit_subject_map() -> dict[str, str]:
    db = EncryptedDatabase("customer_audit")
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT audit_id, subject_id FROM customer_audits"
        ).fetchall()
    return {r[0]: r[1] for r in rows}


def _ensure_schema() -> CustomerAuditRepository:
    # Repo-Init legt customer_audits + audit_migration_log + subject_id an.
    return CustomerAuditRepository()


class TestAuditSubjectBackfill:
    def test_t7_empty_db_no_crash(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            store = create_default_subject_store()
            stats = run_audit_subject_backfill(store=store, repo=repo)
            assert stats == {
                "self_audits": 0,
                "client_audits": 0,
                "skipped_no_name": 0,
            }

    def test_self_audit_links_to_self_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("self-1", "Meine Firma GmbH", "self")
            store = create_default_subject_store()
            run_audit_subject_backfill(store=store, repo=repo)

            self_subject = store.get_self()
            assert self_subject is not None
            assert _audit_subject_map()["self-1"] == self_subject.subject_id

    def test_t3_two_customer_audits_same_firma_dedup(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("a1", "Acme GmbH", "customer", branche="IT", groesse="11-50")
            _seed_audit("a2", "Acme GmbH", "customer", branche="IT", groesse="11-50")
            store = create_default_subject_store()
            stats = run_audit_subject_backfill(store=store, repo=repo)

            mapping = _audit_subject_map()
            assert mapping["a1"] == mapping["a2"]
            assert mapping["a1"] != ""
            # Genau EIN Kunden-Subjekt für beide Audits.
            assert stats == {
                "self_audits": 0,
                "client_audits": 2,
                "skipped_no_name": 0,
            }
            assert len(store.list_all()) == 1
            # Stammdaten wurden ins Subjekt gezogen.
            subject = store.get(mapping["a1"])
            assert subject.branche == "IT"
            assert subject.groesse == "11-50"

    def test_assertion_raises_on_unlinked_eligible_audit(self, tmp_path):
        """: eligibles Audit (Firmenname) ohne subject_id -> Assertion wirft."""
        import pytest

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("c1", "Acme GmbH", "customer")  # bleibt unverknuepft
            with pytest.raises(AuditBackfillInconsistentError):
                _assert_audit_backfill_consistent(repo)

    def test_assertion_ignores_audit_without_firmenname(self, tmp_path):
        """: Kunden-Audit OHNE Firmenname ist nicht eligibel -> kein Wurf."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("c2", "", "customer")  # ohne Identitaet -> nicht eligibel
            _assert_audit_backfill_consistent(repo)  # darf NICHT werfen

    def test_backfill_surfaces_skipped_no_name(self, tmp_path):
        """: Audits ohne Firmenname werden gezaehlt (nicht still uebersprungen)."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("c3", "", "customer")
            store = create_default_subject_store()
            stats = run_audit_subject_backfill(store=store, repo=repo)
            assert stats["skipped_no_name"] == 1
            assert stats["client_audits"] == 0

    # ---: DSGVO Art.17 Orphan-Cleanup beim Loeschen -------------------

    def test_count_for_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("a1", "Acme GmbH", "customer")
            _seed_audit("a2", "Acme GmbH", "customer")
            repo.set_subject_id("a1", "subj-1")
            repo.set_subject_id("a2", "subj-1")
            assert repo.count_for_subject("subj-1") == 2
            assert repo.count_for_subject("other") == 0
            assert repo.count_for_subject("") == 0

    def test_delete_removes_orphaned_customer_subject(self, tmp_path):
        """Letztes Audit eines Kunden OHNE Scores geloescht -> Subjekt-PII weg."""
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Acme GmbH")
            _seed_audit("a1", "Acme GmbH", "customer")
            repo.set_subject_id("a1", subject.subject_id)

            assert LoadAuditUseCase(repo, subject_store=store).delete("a1") is True
            assert store.get(subject.subject_id) is None  # verwaist -> entfernt

    def test_delete_keeps_subject_with_other_audit(self, tmp_path):
        """Kunde hat noch ein zweites Audit -> Subjekt bleibt."""
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Acme GmbH")
            for aid in ("a1", "a2"):
                _seed_audit(aid, "Acme GmbH", "customer")
                repo.set_subject_id(aid, subject.subject_id)

            LoadAuditUseCase(repo, subject_store=store).delete("a1")
            assert store.get(subject.subject_id) is not None  # a2 haelt es

    def test_delete_keeps_subject_with_scores(self, tmp_path):
        """Kunde hat Scores -> Subjekt bleibt trotz Audit-Loeschung."""
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )
        from tools.security_scoring.data.score_repository import ScoreRepository

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            store = create_default_subject_store()
            subject = store.find_or_create_client("Acme GmbH")
            _seed_audit("a1", "Acme GmbH", "customer")
            repo.set_subject_id("a1", subject.subject_id)
            ScoreRepository()  # scores-Tabelle anlegen
            sdb = EncryptedDatabase("security_scoring")
            with sdb.connection() as conn:
                conn.execute(
                    "INSERT INTO scores (score_id, target_name, timestamp, "
                    "overall, grade, data_json, subject_id) "
                    "VALUES ('s1', 'Acme GmbH', '2026-06-01T00:00:00+00:00', "
                    "80.0, 'B', '{}', ?)",
                    (subject.subject_id,),
                )

            LoadAuditUseCase(repo, subject_store=store).delete("a1")
            assert store.get(subject.subject_id) is not None  # Score haelt es

    def test_delete_without_subject_store_no_crash(self, tmp_path):
        """Ohne injizierten SubjectStore: Loeschen funktioniert, kein Cleanup."""
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("a1", "Acme GmbH", "customer")
            assert LoadAuditUseCase(repo).delete("a1") is True

    def test_t1_idempotent_second_run_is_noop(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("a1", "Beta AG", "customer")
            store = create_default_subject_store()
            first = run_audit_subject_backfill(store=store, repo=repo)
            assert first.get("skipped") is not True
            count_after_first = len(store.list_all())

            second = run_audit_subject_backfill(store=store, repo=repo)
            assert second == {"skipped": True}
            assert len(store.list_all()) == count_after_first

    def test_roundtrip_column_and_blob_consistent(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = _ensure_schema()
            _seed_audit("a1", "Gamma GmbH", "customer")
            store = create_default_subject_store()
            run_audit_subject_backfill(store=store, repo=repo)

            sid = _audit_subject_map()["a1"]
            # Blob-Konsistenz: load_by_id liest subject_id aus result_json.
            loaded = repo.load_by_id("a1")
            assert loaded is not None
            assert loaded.subject_id == sid
