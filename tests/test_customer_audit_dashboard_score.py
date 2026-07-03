"""test_customer_audit_dashboard_score — Kunden-Audit-Score im Dashboard-Folge).

Non-GUI-Abdeckung des Surfacings von Kunden-Audit-Scores (Empty-State für
Kunden-Subjekte abgelöst):

    * Repository ``latest_summary_by_subject``: liefert das jüngste Audit eines
      Subjekts + Gesamtanzahl; ``None`` für leeren/unbekannten ``subject_id``
      (parametrisiert, kein ``result_json``-Deserialize).
    * Aggregator ``customer_audit_loader``: nur bei explizit gewähltem
      ``subject_id`` aufgerufen, fail-soft bei Loader-Fehler, füllt
      ``DashboardData.customer_audit``; Default-Pfad bleibt ``None``.
    * Cross-Tool-Read-E2E §5.7): der ``tool.py``-Loader liest ein per
      ``subject_id`` verknüpftes Audit und adaptiert es zum Dashboard-DTO
      (dict→``CustomerAuditSummary``) — kein customer_audit-Domain-Typ im
      Aggregator.

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die
customer_audit-DB pro Test (analog test_audit_subject_backfill).

Author: Patrick Riederich
Version: 1.0-Folge)
"""

from __future__ import annotations

import json
from unittest.mock import patch

from core.database import encrypted_db as edb
from core.database.encrypted_db import EncryptedDatabase
from tools.customer_audit.data.customer_audit_repository import (
    CustomerAuditRepository,
)
from tools.norisk_dashboard.application.dashboard_aggregator import (
    DashboardAggregator,
)
from tools.norisk_dashboard.domain.models import CustomerAuditSummary, TimeRange


def _seed_audit(
    audit_id: str,
    firmenname: str,
    subject_id: str,
    created_at: str,
    *,
    score: float = 50.0,
    risk: str = "Mittel",
) -> None:
    """Schreibt eine customer_audits-Zeile direkt (mit subject_id)."""
    result = {
        "audit_id": audit_id,
        "audit_mode": "customer",
        "subject_id": subject_id,
        "customer_data": {"firmenname": firmenname},
    }
    db = EncryptedDatabase("customer_audit")
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO customer_audits (audit_id, firmenname, created_at, "
            "overall_score, risk_level, result_json, subject_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (audit_id, firmenname, created_at, score, risk, json.dumps(result), subject_id),
        )


class TestLatestSummaryBySubject:
    def test_empty_param_returns_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            assert repo.latest_summary_by_subject("") is None

    def test_unknown_subject_returns_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            _seed_audit("a1", "Acme GmbH", "s1", "2026-06-01T10:00:00+00:00")
            assert repo.latest_summary_by_subject("ghost") is None

    def test_returns_latest_and_count(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            _seed_audit(
                "a1", "Acme GmbH", "s1", "2026-05-01T10:00:00+00:00",
                score=40.0, risk="Hoch",
            )
            _seed_audit(
                "a2", "Acme GmbH", "s1", "2026-06-01T10:00:00+00:00",
                score=72.0, risk="Mittel",
            )
            _seed_audit("b1", "Beta AG", "s2", "2026-06-02T10:00:00+00:00", score=90.0)

            summary = repo.latest_summary_by_subject("s1")
            assert summary is not None
            assert summary["audit_id"] == "a2"  # jüngstes created_at
            assert summary["overall_score"] == 72.0
            assert summary["risk_level"] == "Mittel"
            assert summary["firmenname"] == "Acme GmbH"
            assert summary["audit_count"] == 2  # nur s1, nicht b1

    def test_default_empty_subject_rows_not_matched(self, tmp_path):
        # Bestands-Audits ohne subject_id (Default '') dürfen nie als Treffer
        # eines echten Subjekts auftauchen.
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            _seed_audit("a1", "Alt-Audit", "", "2026-06-01T10:00:00+00:00")
            assert repo.latest_summary_by_subject("s1") is None


class TestAggregatorCustomerAudit:
    def _summary(self) -> CustomerAuditSummary:
        return CustomerAuditSummary(
            subject_id="s1", firmenname="Acme", overall_score=72.0, risk_level="Mittel"
        )

    def test_loader_called_with_subject_id(self):
        seen: list[str] = []
        summary = self._summary()
        agg = DashboardAggregator(
            customer_audit_loader=lambda sid: (seen.append(sid) or summary)
        )
        data = agg.aggregate(TimeRange.WEEK, target_name="Acme", subject_id="s1")
        assert seen == ["s1"]
        assert data.customer_audit is summary

    def test_not_called_without_subject(self):
        seen: list[str] = []
        agg = DashboardAggregator(
            customer_audit_loader=lambda sid: seen.append(sid)
        )
        data = agg.aggregate(TimeRange.WEEK)
        assert seen == []
        assert data.customer_audit is None

    def test_loader_failure_is_fail_soft(self):
        def _boom(_sid):
            raise RuntimeError("Repo weg")

        agg = DashboardAggregator(customer_audit_loader=_boom)
        data = agg.aggregate(TimeRange.WEEK, subject_id="s1")
        assert data.customer_audit is None

    def test_no_loader_leaves_field_none(self):
        agg = DashboardAggregator()
        data = agg.aggregate(TimeRange.WEEK, subject_id="s1")
        assert data.customer_audit is None


class TestCustomerAuditLoaderE2E:
    """Cross-Tool-Read: der norisk_dashboard-Loader liest ein customer_audit
    über den geteilten ``subject_id`` und liefert das Dashboard-DTO."""

    def test_loader_reads_audit_as_dto(self, tmp_path):
        from tools.norisk_dashboard.tool import _build_customer_audit_loader

        with patch.object(edb, "DB_DIR", tmp_path):
            CustomerAuditRepository()  # Schema anlegen
            _seed_audit(
                "a1", "Acme GmbH", "s1", "2026-06-01T10:00:00+00:00",
                score=72.0, risk="Mittel",
            )
            loader = _build_customer_audit_loader()
            dto = loader("s1")
            assert isinstance(dto, CustomerAuditSummary)
            assert dto.firmenname == "Acme GmbH"
            assert dto.overall_score == 72.0
            assert dto.risk_level == "Mittel"
            assert dto.audit_id == "a1"
            assert dto.audit_count == 1
            assert dto.created_at is not None
            # Unbekanntes Subjekt → None (Empty-State).
            assert loader("ghost") is None


class TestAggregatorSelfAudit:
    """ Phase 4): das SELF-Audit wird IMMER geladen (argumentloser
    Loader) — unabhängig vom Subjekt-Selektor. Speist ``DashboardData.self_audit``
    für die „Selbsteinschätzung (Audit)"-Kachel des Einstiegs-Cockpits."""

    def _summary(self) -> CustomerAuditSummary:
        return CustomerAuditSummary(
            subject_id="self",
            firmenname="Mein System",
            overall_score=64.0,
            risk_level="Mittel",
        )

    def test_loader_called_and_fills_self_audit(self):
        calls: list[int] = []
        summary = self._summary()
        agg = DashboardAggregator(
            self_audit_loader=lambda: (calls.append(1) or summary)
        )
        data = agg.aggregate(TimeRange.WEEK)
        assert calls == [1]
        assert data.self_audit is summary

    def test_loaded_even_when_subject_selected(self):
        # Anders als customer_audit (subjekt-gegated) ist self_audit IMMER SELF.
        summary = self._summary()
        agg = DashboardAggregator(self_audit_loader=lambda: summary)
        data = agg.aggregate(TimeRange.WEEK, target_name="Acme", subject_id="s1")
        assert data.self_audit is summary
        #... und das ist NICHT das Kunden-Audit (getrennte Felder).
        assert data.customer_audit is None

    def test_loader_failure_is_fail_soft(self):
        def _boom():
            raise RuntimeError("Subject-Store weg")

        agg = DashboardAggregator(self_audit_loader=_boom)
        data = agg.aggregate(TimeRange.WEEK)
        assert data.self_audit is None

    def test_no_loader_leaves_field_none(self):
        agg = DashboardAggregator()
        data = agg.aggregate(TimeRange.WEEK)
        assert data.self_audit is None


class TestSelfAuditLoaderE2E:
    """Cross-Tool-Read: der argumentlose SELF-Loader löst das eigene
    Subjekt über den core-Resolver (``get_self``) auf und liest dessen jüngstes
    Audit aus dem ``CustomerAuditRepository`` — adaptiert zum Dashboard-DTO."""

    def test_loader_reads_self_audit_as_dto(self, tmp_path):
        from core.security_subject.resolver import create_subject_store
        from tools.norisk_dashboard.tool import _build_self_audit_loader

        with patch.object(edb, "DB_DIR", tmp_path):
            CustomerAuditRepository()  # Schema anlegen
            store = create_subject_store()
            assert store is not None
            self_subject = store.ensure_self_subject("Mein System")
            _seed_audit(
                "sa1", "Mein System", self_subject.subject_id,
                "2026-06-27T10:00:00+00:00", score=64.0, risk="Mittel",
            )
            dto = _build_self_audit_loader()()
            assert isinstance(dto, CustomerAuditSummary)
            assert dto.subject_id == self_subject.subject_id
            assert dto.overall_score == 64.0
            assert dto.risk_level == "Mittel"
            assert dto.audit_id == "sa1"
            assert dto.created_at is not None

    def test_no_self_subject_returns_none(self, tmp_path):
        from tools.norisk_dashboard.tool import _build_self_audit_loader

        with patch.object(edb, "DB_DIR", tmp_path):
            CustomerAuditRepository()  # Schema, aber kein Self-Subjekt angelegt
            assert _build_self_audit_loader()() is None
