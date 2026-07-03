"""GUI-Tests fuer die Cockpit-3c-Widget-Komposition Vision B).

Das ``NoRiskDashboardWidget`` nimmt die einzigartigen Home-Bestandteile auf:
Begruessungs-Zeile, Schnellstart-Leiste, Phishing-Radar-Banner,
Aufgaben-Snippet (Empfohlen & Dringend) und Aktivitaeten-Sektion.

Pure Widget-Tests — Mainpage-Services werden mit isoliertem ``DB_DIR``
gebaut, damit kein Mainpage-DB-Schreibzugriff nach ``~/.finlai/`` geht.

Author: Patrick Riederich
Version: 1.0 3c)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.quickstart_service import QuickstartService
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository
from tools.mainpage.gui.activity_widget import ActivityWidget
from tools.mainpage.gui.ki_todo_section import KiTodoSection
from tools.mainpage.gui.phishing_radar_banner import PhishingRadarBanner
from tools.mainpage.gui.quickstart_widget import QuickstartWidget
from tools.mainpage.gui.task_snippet_widget import TaskSnippetWidget
from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

pytestmark = pytest.mark.gui

# 3c: die Anrede ist jetzt tageszeit-abhaengig (Morgen/Tag/Abend/Nacht),
# darum gegen alle vier moeglichen Praefixe pruefen statt gegen "Guten Tag".
_GREETINGS = ("Guten Morgen", "Guten Tag", "Guten Abend", "Gute Nacht")


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
    """Frische Task-/Journal-/Quickstart-Services mit isolierter DB."""
    repo = MainpageRepository()
    journal = JournalService(repo)
    tasks = TaskService(repo, journal)
    quickstart = QuickstartService(repo)
    return tasks, journal, quickstart


# ---------------------------------------------------------------------------
# Komposition: neue Sektionen existieren bei vollem Service-Satz
# ---------------------------------------------------------------------------


def test_cockpit_baut_alle_neuen_home_widgets(services, qtbot):
    """Mit allen Services existieren Begruessung, Schnellstart, Phishing,
    Aufgaben-Snippet und Aktivitaeten als Sub-Widgets."""
    tasks, journal, quickstart = services
    widget = NoRiskDashboardWidget(
        task_service=tasks,
        journal_service=journal,
        quickstart_service=quickstart,
    )
    qtbot.add_widget(widget)

    # Begruessungs-Label oben im Content (tageszeit-abhaengige Anrede).
    assert widget._greeting_label is not None  # noqa: SLF001
    assert widget._greeting_label.text().startswith(_GREETINGS)  # noqa: SLF001

    # Schnellstart-Leiste (Quickstart-Service da → gebaut).
    assert isinstance(widget._quickstart_widget, QuickstartWidget)  # noqa: SLF001
    # Aufgaben-Snippet (Task-Service da → gebaut).
    assert isinstance(widget._task_snippet_widget, TaskSnippetWidget)  # noqa: SLF001
    # Phishing-Banner (immer gebaut, auch ohne VM).
    assert isinstance(widget._phishing_radar, PhishingRadarBanner)  # noqa: SLF001
    # „FINLAI empfiehlt" (KiTodoSection) — Task-Service da → gebaut (eager).
    assert isinstance(widget._ki_todo_section_widget, KiTodoSection)  # noqa: SLF001

    # Akkordeon-Sektionen vorhanden.
    assert getattr(widget, "_section_task_snippet", None) is not None
    assert getattr(widget, "_section_activity", None) is not None
    assert getattr(widget, "_section_ki_todo", None) is not None

    # Cockpit-Perf A: „Letzte Aktivitäten" ist lazy — Inner noch None, bis die
    # zugeklappte Sektion aufgeklappt wird; danach das ActivityWidget.
    assert widget._activity_widget is None  # noqa: SLF001
    widget._section_activity.set_expanded(True)  # noqa: SLF001
    assert isinstance(widget._activity_widget, ActivityWidget)  # noqa: SLF001


def test_cockpit_ki_todo_section_position(services, qtbot):
    """KiTodoSection sitzt zwischen Completeness-Banner und Task-Snippet.

    „FINLAI empfiehlt" (kuratiert) gehoert laut Refactoring-Plan hoch — direkt
    nach der Completeness/Coverage-Sektion und VOR „Empfohlen & Dringend"
    (Board-Top-N). Position wird ueber die Reihenfolge im Content-Layout
    geprueft.
    """
    tasks, journal, quickstart = services
    widget = NoRiskDashboardWidget(
        task_service=tasks,
        journal_service=journal,
        quickstart_service=quickstart,
    )
    qtbot.add_widget(widget)

    # Eltern-Layout der drei betroffenen Sektionen (gemeinsamer Content-Container).
    layout = widget._completeness_banner.parentWidget().layout()  # noqa: SLF001
    order = [layout.itemAt(i).widget() for i in range(layout.count())]

    idx_completeness = order.index(widget._completeness_banner)  # noqa: SLF001
    idx_ki_todo = order.index(widget._section_ki_todo)  # noqa: SLF001
    idx_task_snippet = order.index(widget._section_task_snippet)  # noqa: SLF001

    assert idx_completeness < idx_ki_todo < idx_task_snippet


def test_cockpit_ki_todo_section_fehlt_ohne_task_service(
    isolated_db_dir: Path,  # noqa: ARG001 -- isolieren reicht
    app,  # noqa: ARG001
    qtbot,
):
    """Ohne TaskService wird die KiTodoSection nicht gebaut (Backwards-Compat)."""
    widget = NoRiskDashboardWidget()
    qtbot.add_widget(widget)

    assert widget._ki_todo_section_widget is None  # noqa: SLF001
    assert getattr(widget, "_section_ki_todo", None) is None


def test_cockpit_phishing_und_activity_auch_ohne_services(
    isolated_db_dir: Path,  # noqa: ARG001 -- isolieren reicht
    app,  # noqa: ARG001
    qtbot,
):
    """Backwards-Compat: ohne jeden Service baut das Cockpit weiterhin
    (Phishing + Aktivitaeten kommen, Quickstart + Task-Snippet bleiben weg)."""
    widget = NoRiskDashboardWidget()
    qtbot.add_widget(widget)

    # Service-gegatete Widgets fehlen.
    assert widget._quickstart_widget is None  # noqa: SLF001
    assert widget._task_snippet_widget is None  # noqa: SLF001
    # Phishing-Banner ist service-frei und eager (sofort sichtbar).
    assert isinstance(widget._phishing_radar, PhishingRadarBanner)  # noqa: SLF001
    # Cockpit-Perf A: „Letzte Aktivitäten" ist lazy — erst nach Aufklappen da.
    assert widget._activity_widget is None  # noqa: SLF001
    widget._section_activity.set_expanded(True)  # noqa: SLF001
    assert isinstance(widget._activity_widget, ActivityWidget)  # noqa: SLF001
    # Begruessung ist immer da.
    assert widget._greeting_label.text().startswith(_GREETINGS)  # noqa: SLF001


# ---------------------------------------------------------------------------
# fail-soft: ein Refresh-Fehler eines Sub-Widgets blubbert nicht hoch
# ---------------------------------------------------------------------------


def test_cockpit_refresh_swallows_subwidget_error(services, qtbot):
    """Ein erzwungener Refresh-Fehler eines Home-Sub-Widgets darf den
    Cockpit-Refresh nicht reissen — die uebrigen Refreshes laufen weiter."""
    tasks, journal, quickstart = services
    widget = NoRiskDashboardWidget(
        task_service=tasks,
        journal_service=journal,
        quickstart_service=quickstart,
    )
    qtbot.add_widget(widget)
    # Cockpit-Perf A: Activity ist lazy — aufklappen, damit es im Refresh-Lauf
    # (``_light_home_widgets``) mitgenommen wird.
    widget._section_activity.set_expanded(True)  # noqa: SLF001

    with (
        patch.object(
            widget._phishing_radar,  # noqa: SLF001
            "refresh",
            side_effect=RuntimeError("boom"),
        ),
        patch.object(
            widget._activity_widget, "refresh"  # noqa: SLF001
        ) as activity_refresh,
    ):
        # Darf NICHT hochblubbern trotz boom im Phishing-Refresh.
        widget.refresh()

    # Das nachfolgende Widget wurde trotz Fehler im vorherigen refresht.
    assert activity_refresh.called


def test_cockpit_apply_refresht_neue_home_widgets(services, qtbot):
    """``refresh`` (→ ``_apply``) triggert die Refreshes der neuen Widgets."""
    tasks, journal, quickstart = services
    widget = NoRiskDashboardWidget(
        task_service=tasks,
        journal_service=journal,
        quickstart_service=quickstart,
    )
    qtbot.add_widget(widget)
    # Cockpit-Perf A: Activity ist lazy — aufklappen, damit es im Apply-Refresh
    # mitgenommen wird.
    widget._section_activity.set_expanded(True)  # noqa: SLF001

    with (
        patch.object(widget._quickstart_widget, "refresh") as qs_refresh,  # noqa: SLF001
        patch.object(widget._task_snippet_widget, "refresh") as ts_refresh,  # noqa: SLF001
        patch.object(widget._phishing_radar, "refresh") as ph_refresh,  # noqa: SLF001
        patch.object(widget._activity_widget, "refresh") as ac_refresh,  # noqa: SLF001
        patch.object(widget._ki_todo_section_widget, "refresh") as kt_refresh,  # noqa: SLF001
    ):
        widget.refresh()

    assert qs_refresh.called
    assert ts_refresh.called
    assert ph_refresh.called
    assert ac_refresh.called
    assert kt_refresh.called


def test_cockpit_light_refresh_runs_without_aggregator(services, qtbot):
    """Der leichte 60s-Takt refresht NUR die Home-Widgets, nicht den Aggregator.

    ``_refresh_light_home_widgets`` darf KEIN ``aggregate`` (schwerer Cross-
    Tool-Scan) ausloesen — nur die leichten Widget-``refresh``."""
    tasks, journal, quickstart = services
    widget = NoRiskDashboardWidget(
        task_service=tasks,
        journal_service=journal,
        quickstart_service=quickstart,
    )
    qtbot.add_widget(widget)
    # Cockpit-Perf A: Activity ist lazy — aufklappen, damit der leichte Takt es
    # mitnimmt.
    widget._section_activity.set_expanded(True)  # noqa: SLF001

    with (
        patch.object(widget._aggregator, "aggregate") as agg,  # noqa: SLF001
        patch.object(widget._ki_todo_section_widget, "refresh") as kt_refresh,  # noqa: SLF001
        patch.object(widget._activity_widget, "refresh") as ac_refresh,  # noqa: SLF001
    ):
        widget._refresh_light_home_widgets()  # noqa: SLF001

    assert kt_refresh.called
    assert ac_refresh.called
    assert not agg.called
