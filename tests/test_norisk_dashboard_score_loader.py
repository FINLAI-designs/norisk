"""tests/test_norisk_dashboard_score_loader — Bugfix-Tests fuer den
Score-Loader-Fallback im NoRisk-Dashboard.

Hintergrund: Das Dashboard fragt den ``ScoreRepository``
mit dem Default ``target_name="Allgemein"`` ab, das Security-Scoring
persistiert aber unter ``"Mein System"`` (oder einem frei vergebenen
Kunden-Target). Vor dem Fix lieferte der Loader leer zurueck und der
Score-Halbkreis blieb leer. Der Fix ist im Loader implementiert:
faellt zurueck auf das Target mit dem juengsten Score, wenn das
angefragte Target keine Daten hat.

Schichtzugehoerigkeit: tests/ — keine GUI-Imports, nur ``tool.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import core.database.encrypted_db as edb
from tools.norisk_dashboard.tool import _build_score_loader, _pick_freshest_target
from tools.security_scoring.data.score_repository import ScoreRepository
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore
from tools.security_scoring.domain.scoring_engine import (
    DEFAULT_WEIGHTS,
    score_to_grade,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_score(
    target: str,
    overall: float = 72.0,
    minutes_ago: int = 0,
) -> SecurityScore:
    """Baut einen SecurityScore mit kontrollierbarem Timestamp."""
    ts = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    return SecurityScore(
        id=str(uuid.uuid4()),
        target_name=target,
        timestamp=ts.isoformat(),
        overall_score=overall,
        grade=score_to_grade(overall),
        components=[
            ScoreComponent(
                name="API Security",
                score=overall,
                weight=DEFAULT_WEIGHTS["api_security"],
                findings_critical=0,
                findings_high=0,
                last_scan="2026-04-30T10:00:00+00:00",
                source_tool="api_security",
            )
        ],
        summary="Test",
    )


# ---------------------------------------------------------------------------
# Loader: Direkter Treffer
# ---------------------------------------------------------------------------


def test_loader_liefert_scores_bei_direktem_target_treffer(tmp_path):
    """Wenn das angefragte Target Daten hat, kommt es direkt zurueck."""
    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        repo.speichere_score(_make_score("Mein System", overall=88.0))

        loader = _build_score_loader()
        result = loader("Mein System")

    assert len(result) == 1
    assert result[0].target_name == "Mein System"
    assert result[0].overall_score == 88.0


# ---------------------------------------------------------------------------
# Loader: Fallback bei Mismatch (zentrales Bug-Szenario)
# ---------------------------------------------------------------------------


def test_loader_fallback_bei_target_mismatch(tmp_path):
    """Bug-Szenario: Dashboard fragt 'Allgemein', DB hat nur 'Mein System'.

    Vor dem Fix kam ``[]`` zurueck und der Score-Halbkreis blieb leer.
    Nach dem Fix faellt der Loader auf das Target mit Daten zurueck.
    """
    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        repo.speichere_score(_make_score("Mein System", overall=66.0))

        loader = _build_score_loader()
        result = loader("Allgemein")  # exakt der Default des Dashboards

    assert len(result) == 1
    assert result[0].target_name == "Mein System"
    assert result[0].overall_score == 66.0


def test_loader_fallback_picks_freshest_target(tmp_path):
    """Fallback-Logik: Bei mehreren Targets gewinnt das mit dem
    juengsten Score-Eintrag."""
    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        # Alpha AG hat einen alten Score, Beta GmbH einen frischen.
        repo.speichere_score(
            _make_score("Alpha AG", overall=50.0, minutes_ago=120)
        )
        repo.speichere_score(
            _make_score("Beta GmbH", overall=85.0, minutes_ago=1)
        )

        loader = _build_score_loader()
        result = loader("Allgemein")

    assert len(result) >= 1
    # Beta GmbH ist juenger -> Loader gibt Beta zurueck.
    assert result[0].target_name == "Beta GmbH"
    assert result[0].overall_score == 85.0


# ---------------------------------------------------------------------------
# Loader: Empty-DB
# ---------------------------------------------------------------------------


def test_loader_leere_db_liefert_leere_liste(tmp_path):
    """Komplett leere DB -> Loader liefert ``[]``, kein Crash."""
    with patch.object(edb, "DB_DIR", tmp_path):
        loader = _build_score_loader()
        result = loader("Allgemein")

    assert result == []


# ---------------------------------------------------------------------------
# _pick_freshest_target
# ---------------------------------------------------------------------------


def test_pick_freshest_target_ueberspringt_excluded_target(tmp_path):
    """``exclude`` wird beim Fallback nicht erneut abgefragt."""
    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        repo.speichere_score(_make_score("Allgemein", overall=10.0))
        repo.speichere_score(
            _make_score("Mein System", overall=88.0, minutes_ago=0)
        )

        result = _pick_freshest_target(repo, exclude="Allgemein")

    assert result == "Mein System"


def test_pick_freshest_target_leere_db_liefert_none(tmp_path):
    """Leere DB -> kein Target gefunden."""
    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        result = _pick_freshest_target(repo, exclude="Allgemein")

    assert result is None


# ---------------------------------------------------------------------------
# tz-Mismatch (Folge-Bug nach erstem Fallback-Fix)
# ---------------------------------------------------------------------------


def test_aggregator_crasht_nicht_bei_utc_aware_score_timestamps(tmp_path):
    """Regression: Score-Timestamps sind UTC-aware (``datetime.now(UTC)``);
    ``DashboardAggregator._trend_from_history`` vergleicht mit einem
    naiven ``datetime.now``-Cutoff. Vor dem Fix krachte das mit
    ``TypeError: can't compare offset-naive and offset-aware datetimes``,
    sobald der Loader-Fallback echte UTC-Daten lieferte."""
    from tools.norisk_dashboard.application.dashboard_aggregator import (
        DashboardAggregator,
    )
    from tools.norisk_dashboard.domain.models import TimeRange

    with patch.object(edb, "DB_DIR", tmp_path):
        repo = ScoreRepository()
        repo.speichere_score(_make_score("Mein System", overall=72.0))

        loader = _build_score_loader()
        aggregator = DashboardAggregator(score_loader=loader)
        # Darf nicht crashen — vor dem Fix TypeError im Trend-Vergleich.
        data = aggregator.aggregate(TimeRange.WEEK)

    # Zusatz-Sanity: Score wurde via Fallback gefunden, Trend
    # enthaelt mindestens den frisch gespeicherten Punkt.
    assert data.score.current == 72.0
    assert len(data.trend) >= 1


# ---------------------------------------------------------------------------
# _memoized — Perf-Tier-2 (Repo/Service einmal bauen, ueber Refreshes teilen)
# ---------------------------------------------------------------------------


class TestMemoized:
    def test_caches_first_non_none_result(self):
        from tools.norisk_dashboard.tool import _memoized

        calls = {"n": 0}

        def factory():
            calls["n"] += 1
            return object()

        get = _memoized(factory)
        first = get()
        second = get()
        assert first is second  # gleiche Instanz wiederverwendet
        assert calls["n"] == 1  # factory nur EINMAL gebaut

    def test_none_is_not_cached_and_retries(self):
        from tools.norisk_dashboard.tool import _memoized

        results = [None, None, "ok"]
        calls = {"n": 0}

        def factory():
            r = results[calls["n"]]
            calls["n"] += 1
            return r

        get = _memoized(factory)
        assert get() is None  # 1. Versuch None -> nicht gecacht
        assert get() is None  # 2. Versuch erneut None
        assert get() == "ok"  # 3. Versuch liefert Wert
        assert get() == "ok"  # ab jetzt gecacht
        assert calls["n"] == 3  # nach dem Treffer kein erneuter Bau

    def test_exception_is_not_cached(self):
        import pytest

        from tools.norisk_dashboard.tool import _memoized

        state = {"fail": True}

        def factory():
            if state["fail"]:
                raise RuntimeError("boom")
            return "ok"

        get = _memoized(factory)
        with pytest.raises(RuntimeError):
            get()  # Exception propagiert (Loader-try/except faengt sie real)
        state["fail"] = False
        assert get() == "ok"  # nach Exception erneuter Bau moeglich
