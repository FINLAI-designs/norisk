"""GUI-Tests für das Taskboard-Karten-Rework.

Deckt ab:
  - Hauptaktion je Status ("In Arbeit" / "Erledigt" / "Wieder öffnen")
  - Hauptaktions-Klick ruft die korrekte Service-Methode + Refresh
  - "⋯"-Menü: Status-Radios, Bearbeiten, Ablehnen, Löschen;
    KI-Feedback nur auf Auto-Tasks
  - DnD-Regression: Drop auf in_progress/done refresht das Board
  - TaskFormDialog / DismissTaskDialog Formular-Werte
  - Neue QSS-Factories (card_menu_button_qss / menu_qss) — R26-States

GUI-Tests verwenden die ``app``-Fixture aus:mod:`tests.gui.conftest`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.widgets import button_styles
from tools.mainpage.domain.models import Task
from tools.mainpage.gui.task_dialogs import DismissTaskDialog, TaskFormDialog
from tools.mainpage.gui.taskboard_widget import _Column, _TaskCard

pytestmark = pytest.mark.gui


def _task(status: str = "open", source: str = "manual", **kwargs) -> Task:
    defaults = {
        "id": "task-1",
        "title": "Wireshark: Version 4.8.6 verfuegbar",
        "status": status,
        "source": source,
    }
    defaults.update(kwargs)
    return Task(**defaults)


def _card(qtbot, task: Task, svc=None, on_refresh=None) -> _TaskCard:
    card = _TaskCard(task, svc or MagicMock(), on_refresh or (lambda: None))
    qtbot.add_widget(card)
    return card


def _menu_texts(card: _TaskCard) -> list[str]:
    return [a.text() for a in card._menu.actions() if a.text()]  # noqa: SLF001


# ---------------------------------------------------------------------------
# Hauptaktion je Status
# ---------------------------------------------------------------------------


def test_hauptaktion_open_ist_in_arbeit(qtbot, app):  # noqa: ARG001
    """Offene Karte: Hauptaktion heißt 'In Arbeit' und startet die Aufgabe."""
    svc = MagicMock()
    refreshed = []
    card = _card(qtbot, _task("open"), svc, lambda: refreshed.append(1))

    assert card._main_btn.text() == "In Arbeit"  # noqa: SLF001
    card._main_btn.click()  # noqa: SLF001
    svc.move_to_in_progress.assert_called_once_with("task-1")
    assert refreshed


def test_hauptaktion_in_progress_ist_erledigt(qtbot, app):  # noqa: ARG001
    """Karte in Arbeit: Hauptaktion heißt 'Erledigt' und schließt die Aufgabe."""
    svc = MagicMock()
    refreshed = []
    card = _card(qtbot, _task("in_progress"), svc, lambda: refreshed.append(1))

    assert card._main_btn.text() == "Erledigt"  # noqa: SLF001
    card._main_btn.click()  # noqa: SLF001
    svc.complete_task.assert_called_once_with("task-1")
    assert refreshed


def test_hauptaktion_done_ist_wieder_oeffnen(qtbot, app):  # noqa: ARG001
    """Erledigte Karte: Hauptaktion 'Wieder öffnen' (Outline-Stil) reopent."""
    svc = MagicMock()
    refreshed = []
    card = _card(qtbot, _task("done"), svc, lambda: refreshed.append(1))

    assert card._main_btn.text() == "Wieder öffnen"  # noqa: SLF001
    card._main_btn.click()  # noqa: SLF001
    svc.reopen_task.assert_called_once_with("task-1")
    assert refreshed


# ---------------------------------------------------------------------------
# "⋯"-Menü
# ---------------------------------------------------------------------------


def test_menu_enthaelt_status_und_verwaltungsaktionen(qtbot, app):  # noqa: ARG001
    """Manuelle Karte: Status-Radios + Bearbeiten/Ablehnen/Löschen, KEIN Feedback."""
    card = _card(qtbot, _task("open", source="manual"))
    texts = _menu_texts(card)

    for expected in (
        "Offen",
        "In Arbeit",
        "Erledigt",
        "Bearbeiten…",
        "Aufgabe ablehnen…",
        "Löschen…",
    ):
        assert expected in texts
    assert "Hilfreich" not in texts
    assert "Nicht hilfreich" not in texts


def test_menu_ki_karte_hat_feedback_aktionen(qtbot, app):  # noqa: ARG001
    """KI-Karte (source=auto): zusätzlich Hilfreich/Nicht hilfreich."""
    card = _card(qtbot, _task("open", source="auto"))
    texts = _menu_texts(card)
    assert "Hilfreich" in texts
    assert "Nicht hilfreich" in texts


def test_menu_aktueller_status_ist_markiert_und_deaktiviert(qtbot, app):  # noqa: ARG001
    """Der aktuelle Status ist als Radio gecheckt + nicht klickbar."""
    card = _card(qtbot, _task("in_progress"))
    by_text = {a.text(): a for a in card._menu.actions()}  # noqa: SLF001

    assert by_text["In Arbeit"].isChecked()
    assert not by_text["In Arbeit"].isEnabled()
    assert by_text["Offen"].isEnabled()
    assert by_text["Erledigt"].isEnabled()


def test_menu_status_radio_ruft_service(qtbot, app):  # noqa: ARG001
    """Status-Radio 'Erledigt' auf offener Karte ruft complete_task + Refresh."""
    svc = MagicMock()
    refreshed = []
    card = _card(qtbot, _task("open"), svc, lambda: refreshed.append(1))
    by_text = {a.text(): a for a in card._menu.actions()}  # noqa: SLF001

    by_text["Erledigt"].trigger()
    svc.complete_task.assert_called_once_with("task-1")
    assert refreshed


def test_menu_ablehnen_ruft_dismiss_mit_begruendung(
    qtbot, app, monkeypatch  # noqa: ARG001
):
    """'Aufgabe ablehnen…' öffnet den Dialog und reicht die Begründung durch."""
    from PySide6.QtWidgets import QDialog

    from tools.mainpage.gui import taskboard_widget as tw

    class _FakeDismissDialog:
        def __init__(self, parent=None):  # noqa: ARG002
            self.reason = "betrifft uns nicht"

        def exec(self):
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(tw, "DismissTaskDialog", _FakeDismissDialog)
    svc = MagicMock()
    refreshed = []
    card = _card(qtbot, _task("open"), svc, lambda: refreshed.append(1))
    by_text = {a.text(): a for a in card._menu.actions()}  # noqa: SLF001

    by_text["Aufgabe ablehnen…"].trigger()
    svc.dismiss_task.assert_called_once_with(
        "task-1", reason="betrifft uns nicht"
    )
    assert refreshed


def test_menu_loeschen_erst_nach_bestaetigung(qtbot, app, monkeypatch):  # noqa: ARG001
    """'Löschen…' löscht NUR nach bestätigtem Confirm-Dialog."""
    from PySide6.QtWidgets import QDialog

    from tools.mainpage.gui import taskboard_widget as tw

    class _Rejecting:
        def __init__(self, *args, **kwargs):  # noqa: ARG002
            pass

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr(tw, "FinlaiConfirmDialog", _Rejecting)
    svc = MagicMock()
    card = _card(qtbot, _task("open"), svc)
    by_text = {a.text(): a for a in card._menu.actions()}  # noqa: SLF001

    by_text["Löschen…"].trigger()
    svc.delete_task.assert_not_called()


# ---------------------------------------------------------------------------
# DnD-Regression: jeder Drop-Zweig refresht
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("column_status", "service_method"),
    [
        ("in_progress", "move_to_in_progress"),
        ("done", "complete_task"),
        ("open", "reopen_task"),
    ],
)
def test_drop_ruft_service_und_refresh(
    qtbot, app, column_status, service_method  # noqa: ARG001
):
    """Drop auf jede Spalte ruft die Service-Methode UND refresht das Board.

    Regression: vorher refreshte nur der "open"-Zweig — Karten sprangen
    nach dem Drop optisch in die alte Spalte zurück.
    """
    column = _Column("SPALTE", "#ffffff", column_status)
    qtbot.add_widget(column)
    svc = MagicMock()
    start_status = "done" if column_status != "done" else "open"
    svc.get_task.return_value = _task(start_status)
    refreshed = []
    column._svc = svc  # noqa: SLF001
    column._on_refresh = lambda: refreshed.append(1)  # noqa: SLF001

    column._on_task_dropped("task-1")  # noqa: SLF001

    getattr(svc, service_method).assert_called_once_with("task-1")
    assert refreshed


def test_drop_auf_gleiche_spalte_ist_noop(qtbot, app):  # noqa: ARG001
    """Drop auf die Spalte mit identischem Status ändert nichts."""
    column = _Column("OFFEN", "#ffffff", "open")
    qtbot.add_widget(column)
    svc = MagicMock()
    svc.get_task.return_value = _task("open")
    refreshed = []
    column._svc = svc  # noqa: SLF001
    column._on_refresh = lambda: refreshed.append(1)  # noqa: SLF001

    column._on_task_dropped("task-1")  # noqa: SLF001

    svc.reopen_task.assert_not_called()
    assert not refreshed


# ---------------------------------------------------------------------------
# Dialoge
# ---------------------------------------------------------------------------


def test_taskformdialog_neu_liefert_formularwerte(qtbot, app):  # noqa: ARG001
    """Neu-Modus: Eingaben kommen über die Properties zurück."""
    dlg = TaskFormDialog()
    qtbot.add_widget(dlg)

    dlg.title_edit.setText("  Neue Aufgabe  ")
    dlg.desc_edit.setPlainText("Beschreibung")
    dlg.cat_box.setCurrentText("klient")
    dlg.klient_edit.setText("Muster GmbH")
    dlg.prio_box.setCurrentText("high")

    assert dlg.task_title == "Neue Aufgabe"
    assert dlg.task_desc == "Beschreibung"
    assert dlg.task_category == "klient"
    assert dlg.task_klient == "Muster GmbH"
    assert dlg.task_priority == "high"


def test_taskformdialog_edit_vorbefuellt(qtbot, app):  # noqa: ARG001
    """Edit-Modus: Felder sind mit der bestehenden Aufgabe vorbefüllt."""
    task = _task(
        "open",
        title="Bestehender Titel",
        description="Alte Beschreibung",
        category="tool",
        klient="Kunde",
        priority="low",
    )
    dlg = TaskFormDialog(task)
    qtbot.add_widget(dlg)

    assert dlg.task_title == "Bestehender Titel"
    assert dlg.task_desc == "Alte Beschreibung"
    assert dlg.task_category == "tool"
    assert dlg.task_klient == "Kunde"
    assert dlg.task_priority == "low"
    assert dlg.windowTitle() == "Aufgabe bearbeiten"


def test_taskformdialog_speichern_braucht_titel(qtbot, app):  # noqa: ARG001
    """Speichern ist ohne Titel deaktiviert und mit Titel aktiv."""
    dlg = TaskFormDialog()
    qtbot.add_widget(dlg)

    assert not dlg.btn_save.isEnabled()
    dlg.title_edit.setText("Titel da")
    assert dlg.btn_save.isEnabled()
    dlg.title_edit.setText("   ")
    assert not dlg.btn_save.isEnabled()


def test_taskformdialog_ki_task_titel_readonly(qtbot, app):  # noqa: ARG001
    """KI-Tasks: Titel/Beschreibung read-only (Reconciliation rendert sie).

    Review-P1: User-Edits an Maschinen-Feldern würden beim
    nächsten Scan still überschrieben — deshalb gar nicht erst zulassen.
    """
    task = _task("open", source="auto", title="KI-Titel")
    dlg = TaskFormDialog(task)
    qtbot.add_widget(dlg)

    assert dlg.title_edit.isReadOnly()
    assert dlg.desc_edit.isReadOnly()
    # Kategorie/Klient/Priorität bleiben editierbar.
    assert dlg.cat_box.isEnabled()
    assert dlg.klient_edit.isReadOnly() is False


def test_taskformdialog_manuelle_task_voll_editierbar(qtbot, app):  # noqa: ARG001
    """Manuelle Tasks: alle Felder editierbar."""
    dlg = TaskFormDialog(_task("open", source="manual"))
    qtbot.add_widget(dlg)
    assert not dlg.title_edit.isReadOnly()
    assert not dlg.desc_edit.isReadOnly()


def test_dismissdialog_liefert_begruendung(qtbot, app):  # noqa: ARG001
    """DismissTaskDialog gibt die getrimmte Begründung zurück."""
    dlg = DismissTaskDialog()
    qtbot.add_widget(dlg)
    dlg.reason_edit.setText("  doppelt erfasst  ")
    assert dlg.reason == "doppelt erfasst"


# ---------------------------------------------------------------------------
# Neue QSS-Factories (R26)
# ---------------------------------------------------------------------------


def test_card_menu_button_qss_hat_alle_states(app):  # noqa: ARG001
    """QToolButton-Factory: alle 4 States mit color+background+border."""
    qss = button_styles.card_menu_button_qss()
    for state in (":hover", ":pressed", ":disabled"):
        assert f"QToolButton{state}" in qss
    # Jeder State-Block setzt die drei Eigenschaften gemeinsam (R26).
    assert qss.count("background-color:") >= 4
    assert qss.count("border:") >= 4
    # Nativer Menü-Pfeil ist unterdrückt.
    assert "menu-indicator" in qss


def test_menu_qss_styled_items_und_separator(app):  # noqa: ARG001
    """QMenu-Factory: Item-States + Separator sind definiert."""
    qss = button_styles.menu_qss()
    assert "QMenu::item:selected" in qss
    assert "QMenu::item:disabled" in qss
    assert "QMenu::separator" in qss
