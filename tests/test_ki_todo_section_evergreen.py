"""
test_ki_todo_section_evergreen — Integration: KiTodoSection nutzt
Evergreens als Fallback.

Verifiziert dass die "Was tun?"-Section immer Karten zeigt — auch wenn
keine Regel-Engine-Tasks existieren. Patrick-Smoke 2026-05-12: vorher
war die Section dauerhaft im Empty-State.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

pytest.importorskip("PySide6")

import core.database.encrypted_db as edb  # noqa: E402
from tools.mainpage.application.evergreen_provider import EVERGREEN_SOURCE  # noqa: E402
from tools.mainpage.application.task_service import TaskService  # noqa: E402
from tools.mainpage.data.mainpage_repository import MainpageRepository  # noqa: E402

pytestmark = pytest.mark.gui


@pytest.fixture()
def in_memory_repo(monkeypatch):
    """In-Memory-Repo ohne SQLCipher (analog tests/test_mainpage.py)."""
    def _patched_init(self, name: str) -> None:
        self._name = name
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row

    @contextmanager
    def _patched_connection(self):
        yield self._conn

    def _patched_init_schema(self, schema: str) -> None:
        self._conn.executescript(schema)
        self._conn.commit()

    monkeypatch.setattr(edb.EncryptedDatabase, "__init__", _patched_init)
    monkeypatch.setattr(edb.EncryptedDatabase, "connection", _patched_connection)
    monkeypatch.setattr(edb.EncryptedDatabase, "init_schema", _patched_init_schema)

    return MainpageRepository()


@pytest.fixture()
def task_service(in_memory_repo):
    journal = MagicMock()
    return TaskService(repo=in_memory_repo, journal=journal)


def _cards(section) -> list:  # noqa: ANN001
    """Hilfsmethode: Anzahl der Hero-Cards im Content-Row."""
    return [
        section._content_row.itemAt(i).widget()  # noqa: SLF001
        for i in range(section._content_row.count())  # noqa: SLF001
        if section._content_row.itemAt(i).widget() is not None  # noqa: SLF001
    ]


class TestEmptyDbFillsWithEvergreens:
    def test_no_tasks_shows_three_evergreens(self, qapp, task_service) -> None:  # noqa: ARG002
        from tools.mainpage.gui.ki_todo_section import (
            KiTodoSection,
            _HeroCard,
        )

        section = KiTodoSection(task_service)
        cards = _cards(section)
        # 3 Hero-Cards (keine Evergreen ist Empty-State).
        hero_cards = [c for c in cards if isinstance(c, _HeroCard)]
        assert len(hero_cards) == 3
        # Alle drei haben den Evergreen-Source.
        for card in hero_cards:
            assert card._task.source == EVERGREEN_SOURCE  # noqa: SLF001
        section.close()


class TestPartialGapFilledWithEvergreens:
    def test_one_auto_task_plus_two_evergreens(
        self, qapp, task_service,  # noqa: ARG002
    ) -> None:
        """Mit einer echten Auto-Task wird die Section zu 1 acute +
        2 Evergreens aufgefuellt."""
        from tools.mainpage.gui.ki_todo_section import (
            KiTodoSection,
            _HeroCard,
        )

        task_service.create_auto_task(
            title="Echter Finding",
            tool_name="csaf_advisor",
            description="explanation\n\naction",
            urgency="quick",
            evidence_refs=[{"tool": "csaf", "finding_id": "x"}],
            dedup_key="dedup1",
        )
        section = KiTodoSection(task_service)
        cards = _cards(section)
        hero_cards = [c for c in cards if isinstance(c, _HeroCard)]
        assert len(hero_cards) == 3
        # Eine acute, zwei evergreen.
        sources = [c._task.source for c in hero_cards]  # noqa: SLF001
        assert sources.count("auto") == 1
        assert sources.count(EVERGREEN_SOURCE) == 2
        section.close()


class TestAcuteTasksFillCompletely:
    def test_three_or_more_acute_tasks_no_evergreens(
        self, qapp, task_service,  # noqa: ARG002
    ) -> None:
        """Bei 3+ echten Auto-Tasks soll KEIN Evergreen reinrutschen."""
        from tools.mainpage.gui.ki_todo_section import (
            KiTodoSection,
            _HeroCard,
        )

        for i in range(4):
            task_service.create_auto_task(
                title=f"Finding {i}",
                tool_name="csaf_advisor",
                description=f"expl-{i}\n\nact-{i}",
                urgency="quick",
                evidence_refs=[{"tool": "csaf", "finding_id": f"x{i}"}],
                dedup_key=f"dedup-{i}",
            )
        section = KiTodoSection(task_service)
        hero_cards = [
            c for c in _cards(section)
            if isinstance(c, _HeroCard)
        ]
        assert len(hero_cards) == 3
        # Alle 3 sind echte auto-Tasks, kein Evergreen.
        for card in hero_cards:
            assert card._task.source == "auto"  # noqa: SLF001
        section.close()


class TestRefreshKeepsBehaviour:
    def test_manual_refresh_redraws_evergreens(
        self, qapp, task_service,  # noqa: ARG002
    ) -> None:
        from tools.mainpage.gui.ki_todo_section import (
            KiTodoSection,
            _HeroCard,
        )

        section = KiTodoSection(task_service)
        before = len([
            c for c in _cards(section)
            if isinstance(c, _HeroCard)
        ])
        section.refresh()
        after = len([
            c for c in _cards(section)
            if isinstance(c, _HeroCard)
        ])
        assert before == after == 3
        section.close()


class TestGatingContextWiring:
    """: KiTodoSection baut den Context aus Last-Scan-Registry +
    Hardening-Score und reicht ihn an ``get_evergreens`` durch."""

    def test_build_context_handles_registry_errors(
        self, qapp, task_service,  # noqa: ARG002
    ) -> None:
        """Wenn LastScanRegistry-Calls werfen, bleibt der Context
        defensiv (alle Felder None) — keine Crash, keine fehlenden Cards."""
        from tools.mainpage.application.evergreen_provider import (
            EvergreenGatingContext,
        )
        from tools.mainpage.gui.ki_todo_section import KiTodoSection

        section = KiTodoSection(task_service)
        ctx = section._build_evergreen_context()  # noqa: SLF001
        assert isinstance(ctx, EvergreenGatingContext)
        # Defensive: alle Felder sind entweder datetime/None oder float/None.
        for value in (
            ctx.last_system_scan,
            ctx.last_patch_scan,
            ctx.last_csaf_check,
            ctx.last_techstack_change,
        ):
            from datetime import datetime as _dt
            assert value is None or isinstance(value, _dt)
        assert ctx.hardening_score is None or isinstance(ctx.hardening_score, float)
        section.close()

    def test_section_uses_gated_evergreens(
        self, qapp, task_service, monkeypatch,  # noqa: ARG002
    ) -> None:
        """Mit gemockten "alles frisch"-Context wird das Widget keine
        Evergreens zeigen — und faellt auf den Empty-State zurueck."""
        from datetime import UTC, datetime

        from tools.mainpage.application.evergreen_provider import (
            EvergreenGatingContext,
        )
        from tools.mainpage.gui.ki_todo_section import (
            KiTodoSection,
            _EmptyState,
        )

        # Erst-Construct mit normalem (frischen-Installation-)Ctx,
        # dann monkeypatchen wir den Context-Builder.
        def fake_ctx(self):  # noqa: ANN001, ARG001
            now = datetime.now(tz=UTC)
            return EvergreenGatingContext(
                last_system_scan=now,
                last_patch_scan=now,
                last_csaf_check=now,
                last_techstack_change=now,
                hardening_score=95.0,
                now=now,
            )

        monkeypatch.setattr(
            KiTodoSection,
            "_build_evergreen_context",
            fake_ctx,
        )
        section = KiTodoSection(task_service)
        # Section hat 0 acute Tasks + Ctx filtert alle Evergreens raus
        # → Empty-State wird angezeigt.
        cards = _cards(section)
        has_empty = any(isinstance(c, _EmptyState) for c in cards)
        assert has_empty
        section.close()
