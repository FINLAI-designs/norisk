"""
test_hardening_score_repository — Phase-4d Persistenz-Tests.

Pattern wie ``test_security_scoring.TestScoreRepository``:
``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die Encrypted-
Database auf ein tmp_path-Verzeichnis pro Test.

Deckt:
    * save_score + get_last_two_scores (Trend-Quelle).
    * get_last_two_scores liefert None bei < 2 Eintraegen.
    * load_history sortiert neueste zuerst.
    * list_targets sortiert + deduped.
    * delete_target.
    * JSON-Persistenz enthaelt Cap-Events + Category-Breakdown.
    * load_latest_result rehydriert voll: None bei leer, Voll-Treue
      ueber den DB-Roundtrip, global- vs. target-spezifisch juengster Eintrag.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.database import encrypted_db as edb
from tools.security_scoring.data.hardening_score_repository import (
    HardeningScoreRepository,
)
from tools.security_scoring.domain.hardening_caps import HardCapEvent
from tools.security_scoring.domain.hardening_categories import HardeningCategory
from tools.security_scoring.domain.hardening_score import (
    CategoryScore,
    HardeningScoreResult,
)
from tools.security_scoring.domain.hardening_stages import score_to_stage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    overall: float,
    *,
    raw: float | None = None,
    category_scores: tuple[CategoryScore, ...] = (),
    hard_cap_events: tuple[HardCapEvent, ...] = (),
) -> HardeningScoreResult:
    return HardeningScoreResult(
        overall_score=overall,
        stage=score_to_stage(overall),
        category_scores=category_scores,
        missing_categories=(),
        hard_cap_events=hard_cap_events,
        raw_weighted_score=overall if raw is None else raw,
    )


# ---------------------------------------------------------------------------
# save_score + get_last_two_scores
# ---------------------------------------------------------------------------


class TestSaveAndTrend:
    def test_save_single_then_get_last_two_returns_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score("Workstation-1", _result(72.0))
            assert repo.get_last_two_scores("Workstation-1") is None

    def test_save_two_then_trend_returns_previous_current(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "Workstation-1",
                _result(60.0),
                timestamp="2026-01-01T00:00:00+00:00",
            )
            repo.save_score(
                "Workstation-1",
                _result(75.0),
                timestamp="2026-02-01T00:00:00+00:00",
            )
            trend = repo.get_last_two_scores("Workstation-1")
        assert trend == (60.0, 75.0)

    def test_get_last_two_only_returns_target_specific(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "Workstation-1",
                _result(60.0),
                timestamp="2026-01-01T00:00:00+00:00",
            )
            repo.save_score(
                "Workstation-2",
                _result(90.0),
                timestamp="2026-01-01T00:01:00+00:00",
            )
            repo.save_score(
                "Workstation-1",
                _result(70.0),
                timestamp="2026-02-01T00:00:00+00:00",
            )
            trend = repo.get_last_two_scores("Workstation-1")
        assert trend == (60.0, 70.0)

    def test_get_last_two_uses_latest_two_only(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            for i, score in enumerate([50.0, 60.0, 70.0, 80.0]):
                repo.save_score(
                    "X",
                    _result(score),
                    timestamp=f"2026-0{i+1}-01T00:00:00+00:00",
                )
            trend = repo.get_last_two_scores("X")
        # juengste zwei: April (80) + Maerz (70) → (70.0, 80.0)
        assert trend == (70.0, 80.0)


# ---------------------------------------------------------------------------
# load_history
# ---------------------------------------------------------------------------


class TestLoadHistory:
    def test_history_newest_first(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "X", _result(60.0), timestamp="2026-01-01T00:00:00+00:00"
            )
            repo.save_score(
                "X", _result(70.0), timestamp="2026-02-01T00:00:00+00:00"
            )
            history = repo.load_history("X")
        assert [score for _ts, score in history] == [70.0, 60.0]

    def test_history_limit(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            for i in range(5):
                repo.save_score(
                    "X",
                    _result(50.0 + i),
                    timestamp=f"2026-0{i+1}-01T00:00:00+00:00",
                )
            history = repo.load_history("X", limit=3)
        assert len(history) == 3

    def test_history_empty_target(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            assert repo.load_history("Unbekannt") == []


# ---------------------------------------------------------------------------
# list_targets + delete_target
# ---------------------------------------------------------------------------


class TestTargets:
    def test_list_targets_sorted_unique(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score("Beta", _result(70.0))
            repo.save_score("Alpha", _result(80.0))
            repo.save_score("Alpha", _result(85.0))
            assert repo.list_targets() == ["Alpha", "Beta"]

    def test_delete_target_removes_entries(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            # Verschiedene Tage, damit der Tages-Dedup sie nicht
            # zusammenfasst — zwei eigenstaendige Eintraege.
            repo.save_score(
                "X", _result(70.0), timestamp="2026-01-01T00:00:00+00:00"
            )
            repo.save_score(
                "X", _result(75.0), timestamp="2026-01-02T00:00:00+00:00"
            )
            count = repo.delete_target("X")
            assert count == 2
            assert repo.load_history("X") == []


# ---------------------------------------------------------------------------
# JSON-Persistenz
# ---------------------------------------------------------------------------


class TestJsonPersistence:
    def test_data_json_contains_caps_and_categories(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            result = _result(
                overall=50.0,
                raw=85.0,
                category_scores=(
                    CategoryScore(
                        category=HardeningCategory.CVE_PATCH,
                        score=88.0,
                        weight=0.30,
                        components_count=2,
                    ),
                ),
                hard_cap_events=(
                    HardCapEvent(
                        label="RDP ohne MFA",
                        cap_value=50,
                        triggered_by="SH-003",
                        details="NLA aus",
                    ),
                ),
            )
            sid = repo.save_score("X", result)
            # data_json direkt prüfen
            with repo._db.connection() as conn:
                row = conn.execute(
                    "SELECT data_json FROM hardening_scores WHERE score_id = ?",
                    (sid,),
                ).fetchone()
        assert row is not None
        payload = json.loads(row[0])
        assert payload["overall_score"] == pytest.approx(50.0)
        assert payload["raw_weighted_score"] == pytest.approx(85.0)
        assert payload["stage_label"] == "At Risk"
        cats = {cs["category"]: cs for cs in payload["category_scores"]}
        assert cats[HardeningCategory.CVE_PATCH.value]["score"] == 88.0
        cap = payload["hard_cap_events"][0]
        assert cap["triggered_by"] == "SH-003"
        assert cap["cap_value"] == 50

    def test_score_id_is_returned(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            sid = repo.save_score("X", _result(72.0))
            assert isinstance(sid, str)
            assert len(sid) >= 16  # uuid.hex


# ---------------------------------------------------------------------------
# load_latest_result — Rehydration
# ---------------------------------------------------------------------------


class TestLoadLatestResult:
    def test_returns_none_when_empty(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            assert repo.load_latest_result() is None

    def test_roundtrip_preserves_all_fields(self, tmp_path):
        """Save → load_latest_result rekonstruiert das Result voll-identisch.

        Frozen-Dataclass-Gleichheit (==) beweist Feld-fuer-Feld-Treue inkl.
        Stage, Kategorie-Breakdown, fehlende Kategorien und Hard-Cap-Events.
        """
        original = HardeningScoreResult(
            overall_score=50.0,
            stage=score_to_stage(50.0),
            category_scores=(
                CategoryScore(
                    category=HardeningCategory.CVE_PATCH,
                    score=88.0,
                    weight=0.30,
                    components_count=2,
                ),
                CategoryScore(
                    category=HardeningCategory.NETWORK,
                    score=60.0,
                    weight=0.20,
                    components_count=1,
                ),
            ),
            missing_categories=(HardeningCategory.SYSTEM_HARDENING,),
            hard_cap_events=(
                HardCapEvent(
                    label="RDP ohne MFA",
                    cap_value=50,
                    triggered_by="SH-003",
                    details="NLA aus",
                ),
            ),
            raw_weighted_score=85.0,
        )
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score("Workstation-1", original)
            loaded = repo.load_latest_result()
        assert loaded is not None
        assert loaded.stage.label == "At Risk"
        assert loaded.raw_weighted_score == pytest.approx(85.0)
        # Gezielte Feld-Asserts lokalisieren einen Rehydrate-Bruch besser
        # als der reine ==-Vergleich (der nur "ungleich" meldet).
        assert loaded.missing_categories == (HardeningCategory.SYSTEM_HARDENING,)
        assert len(loaded.category_scores) == 2
        assert loaded.category_scores[0].category == HardeningCategory.CVE_PATCH
        assert loaded.hard_cap_events[0].cap_value == 50
        assert loaded.hard_cap_events[0].triggered_by == "SH-003"
        # Voll-Treue: frozen dataclasses vergleichen feldweise.
        assert loaded == original

    def test_default_picks_globally_freshest(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "A", _result(60.0), timestamp="2026-01-01T00:00:00+00:00"
            )
            repo.save_score(
                "B", _result(90.0), timestamp="2026-03-01T00:00:00+00:00"
            )
            repo.save_score(
                "A", _result(70.0), timestamp="2026-02-01T00:00:00+00:00"
            )
            latest = repo.load_latest_result()
        assert latest is not None
        # B (Maerz) ist der global juengste Eintrag.
        assert latest.overall_score == pytest.approx(90.0)

    def test_target_filter_picks_that_targets_freshest(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "A", _result(60.0), timestamp="2026-01-01T00:00:00+00:00"
            )
            repo.save_score(
                "B", _result(90.0), timestamp="2026-03-01T00:00:00+00:00"
            )
            repo.save_score(
                "A", _result(70.0), timestamp="2026-02-01T00:00:00+00:00"
            )
            latest = repo.load_latest_result(target_name="A")
        assert latest is not None
        # Innerhalb A ist Februar (70) juenger als Januar (60).
        assert latest.overall_score == pytest.approx(70.0)


# ---------------------------------------------------------------------------
# Retention: Tages-Dedup + Cap
# ---------------------------------------------------------------------------

_RETENTION_PATH = (
    "tools.security_scoring.data.hardening_score_repository._RETENTION_DAYS"
)


class TestRetentionT308:
    def test_dedup_per_day_keeps_newest(self, tmp_path):
        """Zwei Berechnungen am selben Tag → ein Eintrag (neuester gewinnt)."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "X", _result(60.0), timestamp="2026-01-01T08:00:00+00:00"
            )
            repo.save_score(
                "X", _result(72.0), timestamp="2026-01-01T20:00:00+00:00"
            )
            history = repo.load_history("X", limit=100)
            latest = repo.load_latest_result(target_name="X")
        assert len(history) == 1
        assert history[0][1] == pytest.approx(72.0)
        assert latest is not None
        assert latest.overall_score == pytest.approx(72.0)

    def test_dedup_default_timestamp_same_day(self, tmp_path):
        """Produktivpfad: zwei Saves OHNE timestamp am selben Tag → ein Eintrag.

        scoring_service ruft save_score immer ohne ``timestamp`` (→ _now_iso),
        also greift der Dedup auf dem heutigen UTC-Tag.
        """
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score("X", _result(60.0))
            repo.save_score("X", _result(72.0))
            history = repo.load_history("X", limit=100)
        assert len(history) == 1
        assert history[0][1] == pytest.approx(72.0)

    def test_distinct_days_kept_separately(self, tmp_path):
        """Verschiedene Tage bleiben eigenstaendige Eintraege."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = HardeningScoreRepository()
            repo.save_score(
                "X", _result(60.0), timestamp="2026-01-01T08:00:00+00:00"
            )
            repo.save_score(
                "X", _result(72.0), timestamp="2026-01-02T08:00:00+00:00"
            )
            history = repo.load_history("X", limit=100)
        assert len(history) == 2

    def test_cap_keeps_last_n_days(self, tmp_path):
        """Cap: nur die juengsten _RETENTION_DAYS Tage bleiben."""
        with patch.object(edb, "DB_DIR", tmp_path), patch(_RETENTION_PATH, 3):
            repo = HardeningScoreRepository()
            for i in range(1, 6):  # 5 verschiedene Tage
                repo.save_score(
                    "X",
                    _result(50.0 + i),
                    timestamp=f"2026-01-0{i}T00:00:00+00:00",
                )
            history = repo.load_history("X", limit=100)
        # Nur die 3 juengsten Tage (03/04/05), neueste zuerst.
        scores = [score for _ts, score in history]
        assert scores == [55.0, 54.0, 53.0]

    def test_retention_isolated_per_target(self, tmp_path):
        """Dedup + Cap wirken nur auf das jeweilige Target."""
        with patch.object(edb, "DB_DIR", tmp_path), patch(_RETENTION_PATH, 2):
            repo = HardeningScoreRepository()
            for i in range(1, 4):  # A: 3 Tage → Cap auf 2
                repo.save_score(
                    "A",
                    _result(50.0 + i),
                    timestamp=f"2026-01-0{i}T00:00:00+00:00",
                )
            repo.save_score(
                "B", _result(80.0), timestamp="2026-01-01T00:00:00+00:00"
            )
            a_hist = repo.load_history("A", limit=100)
            b_hist = repo.load_history("B", limit=100)
        assert len(a_hist) == 2  # A auf 2 gecappt
        assert len(b_hist) == 1  # B unberuehrt
