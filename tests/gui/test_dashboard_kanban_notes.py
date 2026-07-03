"""GUI-Tests für die Kanban+Notes-Migration ins NoRisk-Dashboard
(Sprint S4a).

Pure Widget-Tests — Mainpage-Services werden mit isoliertem ``DB_DIR``
gebaut, damit kein Mainpage-DB-Schreibzugriff nach ``~/.finlai/`` geht.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository
from tools.mainpage.gui.journal_widget import JournalWidget
from tools.mainpage.gui.taskboard_widget import TaskboardWidget
from tools.norisk_dashboard.gui.section_kanban import KanbanSection
from tools.norisk_dashboard.gui.section_notes import NotesSection

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_context():
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    """Patcht ``DB_DIR`` auf einen ``tmp_path``."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


@pytest.fixture
def services(isolated_db_dir: Path, app):  # noqa: ARG001
    """Frische TaskService + JournalService mit isolierter DB."""
    repo = MainpageRepository()
    journal = JournalService(repo)
    tasks = TaskService(repo, journal)
    return tasks, journal


# ---------------------------------------------------------------------------
# KanbanSection
# ---------------------------------------------------------------------------


def test_kanban_section_embeddet_taskboard_widget(services, qtbot):
    """``KanbanSection`` enthält ein ``TaskboardWidget``."""
    tasks, _ = services
    section = KanbanSection(tasks)
    qtbot.add_widget(section)
    boards = section.findChildren(TaskboardWidget)
    assert len(boards) == 1


def test_kanban_section_refresh_kein_crash(services, qtbot):
    """``refresh`` delegiert an die interne ``_refresh``-Methode."""
    tasks, _ = services
    section = KanbanSection(tasks)
    qtbot.add_widget(section)
    section.refresh()  # darf nicht crashen


def test_kanban_section_refresh_swallows_inner_error(services, qtbot):
    """Wenn ``_board._refresh`` failt, blubbert die Exception nicht hoch."""
    tasks, _ = services
    section = KanbanSection(tasks)
    qtbot.add_widget(section)
    with patch.object(
        section._board, "_refresh", side_effect=RuntimeError("boom")  # noqa: SLF001
    ):
        section.refresh()  # soll defensive sein


# ---------------------------------------------------------------------------
# NotesSection
# ---------------------------------------------------------------------------


def test_notes_section_embeddet_journal_widget(services, qtbot):
    _, journal = services
    section = NotesSection(journal)
    qtbot.add_widget(section)
    journals = section.findChildren(JournalWidget)
    assert len(journals) == 1


def test_notes_section_refresh_kein_crash(services, qtbot):
    _, journal = services
    section = NotesSection(journal)
    qtbot.add_widget(section)
    section.refresh()


def test_notes_section_refresh_swallows_inner_error(services, qtbot):
    _, journal = services
    section = NotesSection(journal)
    qtbot.add_widget(section)
    with patch.object(
        section._journal, "refresh", side_effect=RuntimeError("boom")  # noqa: SLF001
    ):
        section.refresh()


# ---------------------------------------------------------------------------
# Dashboard-Wiring: Sektionen nur wenn Services gesetzt
# ---------------------------------------------------------------------------


def test_dashboard_ohne_services_zeigt_kanban_notes_nicht(
    isolated_db_dir: Path,  # noqa: ARG001 -- isolieren reicht
    app,  # noqa: ARG001
    qtbot,
):
    """Backwards-Compat: Dashboard ohne ``task_service``/``journal_service``
    legt die zwei neuen Sektionen NICHT an."""
    from tools.norisk_dashboard.gui.dashboard_widget import (
        NoRiskDashboardWidget,
    )

    widget = NoRiskDashboardWidget()
    qtbot.add_widget(widget)
    assert widget._kanban_section is None  # noqa: SLF001
    assert widget._notes_section is None  # noqa: SLF001


def test_dashboard_mit_services_baut_beide_sektionen(
    services, qtbot
):
    """Mit ``task_service`` + ``journal_service`` werden Kanban + Notes
    als Akkordeon-Sektionen angelegt.

    Cockpit-Perf A: Beide sind lazy-on-expand. Die Akkordeon-Huelle existiert
    sofort, das Inner-Widget (DB-Read im ctor) entsteht erst beim Aufklappen.
    """
    from tools.norisk_dashboard.gui.dashboard_widget import (
        NoRiskDashboardWidget,
    )

    tasks, journal = services
    widget = NoRiskDashboardWidget(
        task_service=tasks, journal_service=journal
    )
    qtbot.add_widget(widget)
    # Akkordeon-Huellen sind sofort da; Inner noch nicht gebaut (lazy).
    assert widget._section_kanban is not None  # noqa: SLF001
    assert widget._section_notes is not None  # noqa: SLF001
    assert widget._kanban_section is None  # noqa: SLF001
    assert widget._notes_section is None  # noqa: SLF001

    # Aufklappen materialisiert die Inner-Widgets genau einmal.
    widget._section_kanban.set_expanded(True)  # noqa: SLF001
    widget._section_notes.set_expanded(True)  # noqa: SLF001
    assert isinstance(widget._kanban_section, KanbanSection)  # noqa: SLF001
    assert isinstance(widget._notes_section, NotesSection)  # noqa: SLF001


def test_dashboard_apply_ruft_refresh_der_neuen_sektionen(
    services, qtbot
):
    """``_apply`` triggert die Refreshes der bereits aufgeklappten Sektionen.

    Cockpit-Perf A: Erst nach dem Aufklappen existiert das Inner-Widget — dann
    nimmt ``_apply`` es ueber den None-Guard mit (zugeklappt = uebersprungen).
    """
    from tools.norisk_dashboard.gui.dashboard_widget import (
        NoRiskDashboardWidget,
    )

    tasks, journal = services
    widget = NoRiskDashboardWidget(
        task_service=tasks, journal_service=journal
    )
    qtbot.add_widget(widget)
    # Beide Sektionen aufklappen → Inner-Widgets entstehen.
    widget._section_kanban.set_expanded(True)  # noqa: SLF001
    widget._section_notes.set_expanded(True)  # noqa: SLF001

    with (
        patch.object(widget._kanban_section, "refresh") as kan_refresh,  # noqa: SLF001
        patch.object(widget._notes_section, "refresh") as note_refresh,  # noqa: SLF001
    ):
        widget.refresh()
    assert kan_refresh.called
    assert note_refresh.called
