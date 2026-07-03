"""GUI-Tests für den Aufgabenlog-Dialog.

Stub-Service liefert eine fixe Historie; geprüft werden Zeilen,
Status-Labels, Quelle-Spalte und der clientseitige Filter.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.mainpage.domain.models import Task
from tools.mainpage.gui.task_log_dialog import TaskLogDialog

pytestmark = pytest.mark.gui


def _history() -> list[Task]:
    return [
        Task(
            id="t-auto",
            title="Wireshark: Version 4.8.6 verfuegbar",
            status="done",
            source="auto",
            source_tool="patch_monitor",
            done_at="2026-06-11T08:00:00+00:00",
            done_note="Automatisch erledigt — Update installiert",
        ),
        Task(
            id="t-manual",
            title="Backup pruefen",
            status="done",
            done_at="2026-06-10T09:00:00+00:00",
        ),
        Task(
            id="t-dismissed",
            title="ONLYOFFICE: Version 9.4.0 verfuegbar",
            status="dismissed",
            source="auto",
            source_tool="patch_monitor",
            updated_at="2026-06-09T10:00:00+00:00",
            dismissed_reason="betrifft uns nicht",
        ),
    ]


def _dialog(qtbot, tasks: list[Task]) -> TaskLogDialog:
    svc = MagicMock()
    svc.get_task_log.return_value = tasks
    dlg = TaskLogDialog(svc)
    qtbot.add_widget(dlg)
    return dlg


def _column_values(dlg: TaskLogDialog, col: int) -> list[str]:
    table = dlg._table  # noqa: SLF001
    return [table.item(row, col).text() for row in range(table.rowCount())]


def test_zeigt_alle_eintraege_mit_status_labels(qtbot, app):  # noqa: ARG001
    """Alle Historien-Tasks erscheinen mit korrektem Status-Label."""
    dlg = _dialog(qtbot, _history())
    assert dlg._table.rowCount() == 3  # noqa: SLF001
    status_col = _column_values(dlg, 2)
    assert "Automatisch erledigt" in status_col
    assert "Erledigt" in status_col
    assert "Abgelehnt" in status_col


def test_quelle_unterscheidet_ki_und_manuell(qtbot, app):  # noqa: ARG001
    """Quelle-Spalte: 'KI — <tool>' für Auto-Tasks, sonst 'Manuell'."""
    dlg = _dialog(qtbot, _history())
    quellen = _column_values(dlg, 3)
    assert "KI — patch_monitor" in quellen
    assert "Manuell" in quellen


def test_notiz_zeigt_done_note_oder_begruendung(qtbot, app):  # noqa: ARG001
    """Notiz-Spalte: done_note bei Auto-Erledigt, Begründung bei Abgelehnt."""
    dlg = _dialog(qtbot, _history())
    notizen = _column_values(dlg, 4)
    assert "Automatisch erledigt — Update installiert" in notizen
    assert "betrifft uns nicht" in notizen


def test_filter_abgelehnt_zeigt_nur_dismissed(qtbot, app):  # noqa: ARG001
    """Filter 'Abgelehnt' reduziert auf dismissed-Einträge."""
    dlg = _dialog(qtbot, _history())
    dlg._filter_box.setCurrentText("Abgelehnt")  # noqa: SLF001
    assert dlg._table.rowCount() == 1  # noqa: SLF001
    assert _column_values(dlg, 2) == ["Abgelehnt"]


def test_filter_automatisch_erledigt(qtbot, app):  # noqa: ARG001
    """Filter 'Automatisch erledigt' trennt Auto- von Manuell-Erledigt."""
    dlg = _dialog(qtbot, _history())
    dlg._filter_box.setCurrentText("Automatisch erledigt")  # noqa: SLF001
    assert dlg._table.rowCount() == 1  # noqa: SLF001
    titles = _column_values(dlg, 1)
    assert titles == ["Wireshark: Version 4.8.6 verfuegbar"]


def test_service_fehler_crasht_nicht(qtbot, app):  # noqa: ARG001
    """Service-Exception → leerer Log statt Crash."""
    svc = MagicMock()
    svc.get_task_log.side_effect = OSError("db weg")
    dlg = TaskLogDialog(svc)
    qtbot.add_widget(dlg)
    assert dlg._table.rowCount() == 0  # noqa: SLF001
