"""Tests fuer den c2 KI-Todo-Anleitungs-Dialog + Karten-Klick."""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPushButton

from tools.mainpage.domain.models import Task
from tools.mainpage.gui.ki_todo_anleitung_dialog import (
    KiTodoAnleitungDialog,
    _guides_fuer_task,
)
from tools.mainpage.gui.ki_todo_section import _HeroCard

pytestmark = pytest.mark.gui


def _task(title: str, *, description: str = "", source_tool: str = "") -> Task:
    return Task(
        id="t1", title=title, description=description, source_tool=source_tool
    )


def test_guides_fuer_backup_task():
    guides = _guides_fuer_task(_task("Regelmäßige Datensicherung (Backup) einrichten"))
    assert any(g.key == "backup_321" for g in guides)


def test_guides_fallback_bei_keinem_thema():
    # Kein Schlagwort-Treffer -> Grundschutz-Fallback (nie ohne Leitfaden).
    guides = _guides_fuer_task(_task("Generischer Hinweis ohne Schlagwort qwertz"))
    assert guides
    assert guides[0].key == "grundschutz_kmu"


def test_dialog_baut_mit_guide_und_schliessen_button(app, qtbot):  # noqa: ARG001
    dlg = KiTodoAnleitungDialog(
        _task("Backup einrichten", description="Sichere deine Daten regelmäßig.")
    )
    qtbot.addWidget(dlg)
    btn_texte = [b.text() for b in dlg.findChildren(QPushButton)]
    assert any("öffnen" in t for t in btn_texte)  # mind. ein Leitfaden-Button
    assert any("Schließen" in t for t in btn_texte)


def test_dialog_zeigt_disclaimer_und_assistent_hinweis(app, qtbot):  # noqa: ARG001
    dlg = KiTodoAnleitungDialog(_task("Backup einrichten"))
    qtbot.addWidget(dlg)
    texte = " ".join(lbl.text() for lbl in dlg.findChildren(QLabel))
    assert "lokale KI" in texte  # Disclaimer
    assert "F1" in texte  # Assistent-Hinweis


def test_dialog_titel_ist_plaintext(app, qtbot):  # noqa: ARG001
    # Untrusted KI-Titel duerfen nie als RichText rendern (R22).
    dlg = KiTodoAnleitungDialog(_task("<b>Fett</b> & Co"))
    qtbot.addWidget(dlg)
    plain = [
        lbl
        for lbl in dlg.findChildren(QLabel)
        if lbl.textFormat() == Qt.TextFormat.PlainText and "<b>" in lbl.text()
    ]
    assert plain, "Titel mit RichText-Markup muss als PlainText gerendert sein"


def test_herocard_emittiert_clicked_mit_task(app, qtbot):  # noqa: ARG001
    card = _HeroCard(_task("Backup einrichten"))
    qtbot.addWidget(card)
    with qtbot.waitSignal(card.clicked, timeout=500) as blocker:
        qtbot.mouseClick(card, Qt.MouseButton.LeftButton)
    assert blocker.args[0].title == "Backup einrichten"
