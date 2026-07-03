"""GUI-Tests für das Homescreen-Interim AP3, Option A).

Lockt ein:
* TaskSnippetWidget — Prioritäts-Sortierung, Spalten-Zähler, Board-Link,
  Kappung pro Spalte.
* ActivityWidget — Höhendeckel ~200px, 5 Einträge, aktivierter
  „Alle anzeigen"-Button.
* QuickstartWidget — einzeilige Leiste (fix 80px, kein 130px-Kasten).

Headless via pytest-qt (offscreen); Services gemockt.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from tools.mainpage.domain.models import Task
from tools.mainpage.gui.activity_widget import (
    _MAX_WIDGET_HOEHE,
    ActivityDialog,
    ActivityWidget,
)
from tools.mainpage.gui.quickstart_widget import QuickstartWidget
from tools.mainpage.gui.task_snippet_widget import (
    _MAX_PRO_SPALTE,
    TaskSnippetWidget,
    _sortiert,
)

pytestmark = pytest.mark.gui


def _task(title: str, priority: str = "normal", status: str = "open") -> Task:
    return Task(id=str(uuid4()), title=title, priority=priority, status=status)


# ---------------------------------------------------------------------------
# TaskSnippetWidget
# ---------------------------------------------------------------------------


@pytest.fixture
def snippet(qtbot, app):  # noqa: ARG001
    """Aufgaben-Snippet mit gemocktem TaskService."""
    service = MagicMock()
    service.get_board_data.return_value = {
        "open": [
            _task("Normale Aufgabe"),
            _task("Dringende Aufgabe", priority="high"),
        ],
        "in_progress": [_task("Laufende Aufgabe", status="in_progress")],
        "done_today": [],
    }
    w = TaskSnippetWidget(service)
    qtbot.add_widget(w)
    return w


def test_snippet_sortiert_high_zuerst():
    """_sortiert stellt high-Prioritäten an den Anfang."""
    tasks = [_task("b"), _task("a", priority="high"), _task("c", priority="low")]
    result = _sortiert(tasks)
    assert [t.priority for t in result] == ["high", "normal", "low"]


def test_snippet_zeigt_spalten_zaehler(snippet):
    """Spaltenköpfe tragen die Task-Anzahl."""
    texte = _alle_label_texte(snippet)
    assert "Offen (2)" in texte
    assert "In Arbeit (1)" in texte


def test_snippet_board_link_emittiert_signal(snippet, qtbot):
    """Der Board-Link feuert board_requested."""
    with qtbot.waitSignal(snippet.board_requested, timeout=1000):
        snippet._btn_board.click()  # noqa: SLF001


def test_snippet_kappt_pro_spalte(qtbot, app):  # noqa: ARG001
    """Mehr als _MAX_PRO_SPALTE Tasks → Zähler-Zeile statt Endlos-Liste."""
    service = MagicMock()
    service.get_board_data.return_value = {
        "open": [_task(f"Aufgabe {i}") for i in range(_MAX_PRO_SPALTE + 4)],
        "in_progress": [],
        "done_today": [],
    }
    w = TaskSnippetWidget(service)
    qtbot.add_widget(w)
    texte = _alle_label_texte(w)
    assert "+ 4 weitere im Board" in texte


def test_snippet_robust_bei_service_fehler(qtbot, app):  # noqa: ARG001
    """Ein Service-Fehler crasht den Homescreen nicht."""
    service = MagicMock()
    service.get_board_data.side_effect = RuntimeError("kaputt")
    w = TaskSnippetWidget(service)
    qtbot.add_widget(w)
    texte = _alle_label_texte(w)
    assert "Offen (0)" in texte


# ---------------------------------------------------------------------------
# ActivityWidget
# ---------------------------------------------------------------------------


@pytest.fixture
def isoliertes_audit_dir(monkeypatch, tmp_path):
    """Isoliert die Tests vom echten ~/.finlai/audit des Hosts."""
    monkeypatch.setattr(
        "tools.mainpage.gui.activity_widget._AUDIT_DIR", tmp_path
    )
    return tmp_path


def test_activity_widget_ist_gedeckelt(qtbot, app, isoliertes_audit_dir):  # noqa: ARG001
    """Aktivitäten können den Homescreen-Restraum nie wieder fressen."""
    w = ActivityWidget()
    qtbot.add_widget(w)
    assert w.maximumHeight() == _MAX_WIDGET_HOEHE
    assert w.minimumHeight() == 120


def test_activity_alle_anzeigen_aktiv(qtbot, app, isoliertes_audit_dir):  # noqa: ARG001
    """Der frühere Platzhalter-Button ist jetzt aktiviert (E4)."""
    w = ActivityWidget()
    qtbot.add_widget(w)
    assert w._btn_all.isEnabled()  # noqa: SLF001


def test_activity_dialog_konstruktion(qtbot, app, isoliertes_audit_dir):  # noqa: ARG001
    """Die Vollansicht baut sich headless auf — auch ohne Audit-Daten."""
    dlg = ActivityDialog()
    qtbot.add_widget(dlg)
    assert dlg.windowTitle() == "Alle Aktivitäten"
    assert dlg.isModal()
    texte = _alle_label_texte(dlg)
    assert "Noch keine Einträge im Audit-Log." in texte
    assert "Keine Aktivitäten vorhanden." in texte


def test_activity_zeilen_rendern_plaintext(qtbot, app, isoliertes_audit_dir):  # noqa: ARG001
    """Untrusted Audit-Werte werden nie als Auto-RichText gerendert (R22)."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel

    from tools.mainpage.gui.activity_widget import _build_activity_row

    row = _build_activity_row(
        {
            "timestamp": "2026-06-11T12:00:00",
            "tool": "<img src=x>",
            "action": "LOGIN_FAILED",
            "details": {"user": "<img src=//evil/x>"},
        }
    )
    qtbot.add_widget(row)
    for lbl in row.findChildren(QLabel):
        assert lbl.textFormat() == Qt.TextFormat.PlainText


# ---------------------------------------------------------------------------
# QuickstartWidget (Leiste)
# ---------------------------------------------------------------------------


def test_quickstart_ist_einzeilige_leiste(qtbot, app):  # noqa: ARG001
    """Option A: fixe 80px-Leiste in der Header-Zone, kein 130px-Kasten."""
    service = MagicMock()
    service.load_recent_tools.return_value = []
    w = QuickstartWidget(service)
    qtbot.add_widget(w)
    assert w.minimumHeight() == 80
    assert w.maximumHeight() == 80


# ---------------------------------------------------------------------------
# Board-Sprung (F-1): #section-Fragment + Sektions-Aufklappen
# ---------------------------------------------------------------------------


def test_tool_leitet_section_fragment_als_kwarg(qtbot, app):  # noqa: ARG001
    """'norisk:dashboard#kanban' wird zu navigate_to(key, section='kanban')."""
    from PySide6.QtWidgets import QWidget

    from tools.mainpage.tool import MainpageTool

    calls: dict = {}

    class _FakeWindow(QWidget):
        def navigate_to(self, key, **kwargs):  # noqa: ANN001, ANN003
            calls["key"] = key
            calls["kwargs"] = kwargs

    fake = _FakeWindow()
    qtbot.add_widget(fake)
    fake.show()

    MainpageTool()._on_tool_requested("norisk:dashboard#kanban")  # noqa: SLF001
    assert calls == {"key": "norisk:dashboard", "kwargs": {"section": "kanban"}}


def test_dashboard_section_set_expanded(qtbot, app):  # noqa: ARG001
    """set_expanded öffnet/schließt die Akkordeon-Sektion idempotent."""
    from tools.norisk_dashboard.gui._section import _DashboardSection

    s = _DashboardSection("Test", expanded=False)
    qtbot.add_widget(s)
    s.set_expanded(True)
    assert s.is_expanded()
    s.set_expanded(True)
    assert s.is_expanded()
    s.set_expanded(False)
    assert not s.is_expanded()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alle_label_texte(widget) -> list[str]:
    """Sammelt alle QLabel-Texte unterhalb eines Widgets."""
    from PySide6.QtWidgets import QLabel

    return [lbl.text() for lbl in widget.findChildren(QLabel)]
