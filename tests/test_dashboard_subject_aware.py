"""test_dashboard_subject_aware — Subjekt-bewusster Dashboard-Aggregator, T6/T8).

Non-GUI-Tests des ``DashboardAggregator`` für den Subjekt-Selektor:
    * subjects liefert die (subject_id, Anzeigename)-Paare bzw. [] fail-soft.
    * T8: ein per subject_id geladener Score erscheint im Snapshot (shared
      Identität — ein Kunden-Audit-Subjekt wird im Dashboard sichtbar).
    * T6: ein Subjekt ohne Scores (Orphan) → Empty-State, kein Crash.
    * subject_id ohne Loader → Fallback auf den target_name-Pfad (inert).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.norisk_dashboard.application.dashboard_aggregator import (
    DashboardAggregator,
)
from tools.norisk_dashboard.domain.models import TimeRange


class _Score:
    """Minimaler duck-typed SecurityScore für den Aggregator."""

    def __init__(self, overall: float) -> None:
        self.overall_score = overall
        self.timestamp = "2026-06-03T10:00:00+00:00"
        self.components: list = []


class TestSubjectsList:
    def test_empty_without_loader(self):
        assert DashboardAggregator().subjects() == []

    def test_returns_loader_options(self):
        agg = DashboardAggregator(
            subjects_loader=lambda: [("s1", "Acme GmbH"), ("self-1", "Mein System")]
        )
        assert agg.subjects() == [("s1", "Acme GmbH"), ("self-1", "Mein System")]

    def test_loader_failure_is_fail_soft(self):
        def _boom() -> list:
            raise RuntimeError("Store weg")

        assert DashboardAggregator(subjects_loader=_boom).subjects() == []


class TestSubjectAwareAggregate:
    def test_t8_subject_score_loaded_by_id(self):
        # Ein Kunden-Audit-Subjekt ("s1") taucht mit seinem Score im Dashboard auf.
        agg = DashboardAggregator(
            subject_score_loader=lambda sid: [_Score(88.0)] if sid == "s1" else []
        )
        data = agg.aggregate(TimeRange.WEEK, target_name="Acme GmbH", subject_id="s1")
        assert data.score.current == 88.0
        assert data.score.target == "Acme GmbH"

    def test_t6_orphan_subject_empty_state(self):
        # Subjekt ohne Scores → Empty-State (current None), kein Crash.
        agg = DashboardAggregator(subject_score_loader=lambda _sid: [])
        data = agg.aggregate(
            TimeRange.WEEK, target_name="Unbekanntes Subjekt", subject_id="ghost"
        )
        assert data.score.current is None
        assert data.score.target == "Unbekanntes Subjekt"
        assert data.breakdown == []
        assert data.trend == []

    def test_subject_id_without_loader_falls_back_to_target(self):
        # subject_id gesetzt, aber kein subject_score_loader → target_name-Pfad.
        agg = DashboardAggregator(score_loader=lambda _t: [_Score(70.0)])
        data = agg.aggregate(TimeRange.WEEK, target_name="X", subject_id="s1")
        assert data.score.current == 70.0

    def test_default_path_unchanged(self):
        # Ohne subject_id bleibt alles beim target_name-Pfad.
        agg = DashboardAggregator(score_loader=lambda _t: [_Score(55.0)])
        data = agg.aggregate(TimeRange.WEEK)
        assert data.score.current == 55.0
        assert data.score.target == "Allgemein"


class TestSubjectHandoverE2E:
    """T8: Ein über den Audit-Pfad angelegtes Kunden-Subjekt (Step 4) wird im
    Dashboard-Selektor sichtbar — derselbe kanonische Store, tool-übergreifend."""

    def test_t8_customer_subject_appears_in_dashboard(self, tmp_path):
        from unittest.mock import patch

        from core.database import encrypted_db as edb
        from tools.security_scoring.application.subject_store import (
            create_default_subject_store,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            # Genau das tut der Audit-Save (Step 4) bzw. der Audit-Backfill.
            store.find_or_create_client("Acme GmbH")

            # subjects_loader wie in norisk_dashboard/tool.py verdrahtet.
            agg = DashboardAggregator(
                subjects_loader=lambda: [
                    (s.subject_id, s.display_name) for s in store.list_all()
                ]
            )
            labels = [label for _sid, label in agg.subjects()]
            assert any("Acme GmbH" in lbl for lbl in labels)
