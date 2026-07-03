"""
test_evergreen_provider — Tests fuer die "Was tun?"-Evergreens.

Deckt:
    *:func:`get_evergreens` — Limit, Default-Count, Task-Validitaet.
    *:func:`is_evergreen` — Marker-Erkennung via Source + ID-Praefix.
    * ****::class:`EvergreenGatingContext` + Predicates pro
      Template (Vollscan / Patch / Hardening / CSAF / Tech-Stack).
    * Backwards-Compat: ``get_evergreens(limit)`` ohne ``ctx`` liefert
      weiterhin alle Templates ungefiltert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tools.mainpage.application.evergreen_provider import (
    EVERGREEN_SOURCE,
    EvergreenGatingContext,
    get_evergreens,
    is_evergreen,
)
from tools.mainpage.domain.models import Task

_VALID_URGENCIES = frozenset({"quick", "mittel", "langfrist"})


class TestGetEvergreens:
    def test_limit_3_returns_3_tasks(self) -> None:
        result = get_evergreens(3)
        assert len(result) == 3
        assert all(isinstance(t, Task) for t in result)

    def test_limit_0_returns_empty(self) -> None:
        assert get_evergreens(0) == []

    def test_negative_limit_returns_empty(self) -> None:
        assert get_evergreens(-5) == []

    def test_limit_larger_than_template_count_returns_all(self) -> None:
        result = get_evergreens(100)
        # Wir haben aktuell 5 Templates — Limit groesser als Pool gibt
        # alles zurueck, keine Duplikate.
        ids = [t.id for t in result]
        assert len(ids) == len(set(ids))
        assert len(result) >= 3  # mindestens die 3 von Patrick

    def test_all_have_evergreen_source(self) -> None:
        for t in get_evergreens(10):
            assert t.source == EVERGREEN_SOURCE

    def test_all_have_synthetic_id_prefix(self) -> None:
        for t in get_evergreens(10):
            assert t.id.startswith("evergreen:")

    def test_all_have_valid_urgency(self) -> None:
        for t in get_evergreens(10):
            assert t.urgency in _VALID_URGENCIES, (
                f"Urgency '{t.urgency}' nicht in {_VALID_URGENCIES}"
            )

    def test_all_have_description_action_split(self) -> None:
        """Description muss dem Storytelling-Pattern
        ``explanation\\n\\naction`` folgen — sonst rendert _HeroCard
        die Action nicht im Sub-Text."""
        for t in get_evergreens(10):
            assert "\n\n" in t.description, (
                f"Task '{t.title}' hat keine Explanation/Action-Trennung"
            )

    def test_all_have_status_open(self) -> None:
        """Evergreens sind immer 'open' — sie werden nie persistiert,
        also kein in_progress/done."""
        for t in get_evergreens(10):
            assert t.status == "open"

    def test_patrick_required_three_evergreens_present(self) -> None:
        """Patrick-Vorschlag aus: drei konkrete Evergreens muessen
        in der Default-Liste sein."""
        titles = [t.title for t in get_evergreens(10)]
        assert "Hardening-Score pruefen" in titles
        assert "Patch-Inventar aktualisieren" in titles
        assert "Regelmaessigen Vollscan starten" in titles


class TestIsEvergreen:
    def test_evergreen_task_detected(self) -> None:
        evg = get_evergreens(1)[0]
        assert is_evergreen(evg) is True

    def test_normal_auto_task_not_evergreen(self) -> None:
        t = Task(id="real-uuid", title="x", source="auto")
        assert is_evergreen(t) is False

    def test_manual_task_not_evergreen(self) -> None:
        t = Task(id="other-uuid", title="x", source="manual")
        assert is_evergreen(t) is False

    def test_id_prefix_alone_is_sufficient(self) -> None:
        """Falls in Zukunft jemand eine Evergreen-Task mit anderer
        Source baut, faengt die ID-Praefix-Pruefung sie ab."""
        t = Task(id="evergreen:custom", title="x", source="auto")
        assert is_evergreen(t) is True


class TestStableContent:
    def test_each_call_returns_same_content(self) -> None:
        """Provider liefert deterministisch — gleicher Order, gleiche Inhalte."""
        first = get_evergreens(3)
        second = get_evergreens(3)
        assert [t.id for t in first] == [t.id for t in second]
        assert [t.title for t in first] == [t.title for t in second]


# ---------------------------------------------------------------------------
# Dynamic Gating Context + Predicates
# ---------------------------------------------------------------------------


def _ctx(
    *,
    days_since_system_scan: float | None = None,
    days_since_patch: float | None = None,
    days_since_csaf: float | None = None,
    days_since_techstack: float | None = None,
    hardening_score: float | None = None,
) -> EvergreenGatingContext:
    """Helper: baut einen Gating-Context mit 'Tage seit'-Eingaben."""
    now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)

    def _then(days: float | None) -> datetime | None:
        return None if days is None else now - timedelta(days=days)

    return EvergreenGatingContext(
        last_system_scan=_then(days_since_system_scan),
        last_patch_scan=_then(days_since_patch),
        last_csaf_check=_then(days_since_csaf),
        last_techstack_change=_then(days_since_techstack),
        hardening_score=hardening_score,
        now=now,
    )


def _slug(task: Task) -> str:
    """Helper: extrahiert den Template-Slug aus ``id``."""
    return task.id.removeprefix("evergreen:")


class TestBackwardsCompat:
    def test_no_ctx_returns_all_templates(self) -> None:
        """``get_evergreens(limit)`` ohne ctx liefert alles ungefiltert."""
        result = get_evergreens(10)
        # 5 Templates-Stand)
        assert len(result) == 5


class TestGatingContext:
    def test_days_since_none_returns_none(self) -> None:
        ctx = EvergreenGatingContext()
        assert ctx.days_since(None) is None

    def test_days_since_returns_float_difference(self) -> None:
        now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
        then = now - timedelta(days=10)
        ctx = EvergreenGatingContext(now=now)
        days = ctx.days_since(then)
        assert days is not None
        assert 9.99 < days < 10.01

    def test_default_now_uses_current_time(self) -> None:
        """Default-Factory liefert datetime.now(UTC)."""
        before = datetime.now(tz=UTC)
        ctx = EvergreenGatingContext()
        after = datetime.now(tz=UTC)
        assert before <= ctx.now <= after


class TestFullScanPredicate:
    def test_never_scanned_shows_template(self) -> None:
        ctx = _ctx(days_since_system_scan=None)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "full_scan" in slugs

    def test_recent_scan_hides_template(self) -> None:
        """Scan < 30 Tage her → keine Erinnerung."""
        ctx = _ctx(days_since_system_scan=5)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "full_scan" not in slugs

    def test_old_scan_shows_template(self) -> None:
        """Scan > 30 Tage her → wieder zeigen."""
        ctx = _ctx(days_since_system_scan=45)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "full_scan" in slugs

    def test_exact_30_days_does_not_show(self) -> None:
        """Boundary: 30 Tage = noch frisch, 30.01 = zeigen."""
        ctx_30 = _ctx(days_since_system_scan=30.0)
        slugs_30 = [_slug(t) for t in get_evergreens(10, ctx_30)]
        assert "full_scan" not in slugs_30


class TestPatchRefreshPredicate:
    def test_never_scanned_shows_template(self) -> None:
        ctx = _ctx(days_since_patch=None)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "patch_inventory_refresh" in slugs

    def test_recent_patch_scan_hides(self) -> None:
        """Patch-Scan < 7 Tage her → kein Refresh-Hinweis."""
        ctx = _ctx(days_since_patch=3)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "patch_inventory_refresh" not in slugs

    def test_week_old_patch_scan_shows(self) -> None:
        ctx = _ctx(days_since_patch=10)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "patch_inventory_refresh" in slugs


class TestHardeningPredicate:
    def test_no_score_shows_template(self) -> None:
        """Frische Installation ohne Score → Hardening-Hinweis."""
        ctx = _ctx(hardening_score=None)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "hardening_score_check" in slugs

    def test_low_score_shows_template(self) -> None:
        ctx = _ctx(hardening_score=50.0)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "hardening_score_check" in slugs

    def test_high_score_hides_template(self) -> None:
        ctx = _ctx(hardening_score=92.0)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "hardening_score_check" not in slugs

    def test_boundary_score_80_hides(self) -> None:
        ctx = _ctx(hardening_score=80.0)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "hardening_score_check" not in slugs


class TestCsafPredicate:
    def test_old_csaf_shows(self) -> None:
        ctx = _ctx(days_since_csaf=10)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "csaf_advisories_review" in slugs

    def test_recent_csaf_hides(self) -> None:
        ctx = _ctx(days_since_csaf=3)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "csaf_advisories_review" not in slugs


class TestTechstackPredicate:
    def test_no_techstack_change_shows_template(self) -> None:
        """Default: Tech-Stack-Aenderung unbekannt → zeigen."""
        ctx = _ctx(days_since_techstack=None)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "techstack_review" in slugs

    def test_recent_techstack_change_hides(self) -> None:
        ctx = _ctx(days_since_techstack=30)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "techstack_review" not in slugs

    def test_old_techstack_change_shows(self) -> None:
        ctx = _ctx(days_since_techstack=120)
        slugs = [_slug(t) for t in get_evergreens(10, ctx)]
        assert "techstack_review" in slugs


class TestComboCases:
    def test_fully_compliant_system_returns_empty(self) -> None:
        """Alles aktuell + Score hoch → keine Evergreens noetig."""
        ctx = _ctx(
            days_since_system_scan=5,
            days_since_patch=3,
            days_since_csaf=2,
            days_since_techstack=30,
            hardening_score=95.0,
        )
        result = get_evergreens(5, ctx)
        assert result == []

    def test_partial_compliant_system_filters(self) -> None:
        """Nur Patch ueberfaellig → Patch-Hinweis erscheint."""
        ctx = _ctx(
            days_since_system_scan=10,  # < 30 Tage, frisch
            days_since_patch=14,  # > 7 Tage, ueberfaellig
            days_since_csaf=3,  # frisch
            days_since_techstack=30,  # frisch
            hardening_score=85.0,  # ueber Schwelle
        )
        slugs = [_slug(t) for t in get_evergreens(5, ctx)]
        assert slugs == ["patch_inventory_refresh"]

    def test_limit_clips_after_filtering(self) -> None:
        """Bei mehr passenden Templates als ``limit`` werden die ersten
        ``limit`` geliefert (Reihenfolge bleibt erhalten)."""
        ctx = _ctx()  # Frische Installation — alles passt
        result = get_evergreens(2, ctx)
        assert len(result) == 2
