"""Tests für ``tools.mainpage.gui.ki_todo_section`` und _TaskCard-Erweiterungen
(Sprint S2b).

Deckt ab:
  - ``KiTodoSection`` mit Empty-State (keine Auto-Tasks)
  - ``KiTodoSection`` rendert die Top-3 KI-Todos sortiert nach Urgency
  - ``_HeroCard`` zeigt Urgency-Badge + Action-Snippet
  - ``_TaskCard`` mit Auto-Task: KI-Marker + Urgency-Badge sichtbar
  - ``TaskService.record_feedback`` schreibt Audit-Log-Eintrag
  - Feedback-Menü-Aktionen deaktivieren sich nach dem ersten Klick

GUI-Tests verwenden die ``app``-Fixture aus:mod:`tests.gui.conftest`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.ki_todo_service import compute_dedup_key
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository
from tools.mainpage.domain.models import Task
from tools.mainpage.gui.ki_todo_section import (
    _MAX_HERO_CARDS,
    KiTodoSection,
    _HeroCard,
)
from tools.mainpage.gui.taskboard_widget import _TaskCard

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_context():
    """Setzt den App-Kontext der DB-Schicht zwischen Tests zurück."""
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    """Patcht ``DB_DIR`` auf ein temporäres Verzeichnis."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


@pytest.fixture
def task_service(isolated_db_dir: Path, app) -> TaskService:  # noqa: ARG001
    """Frischer TaskService mit isolierter DB."""
    repo = MainpageRepository()
    journal = JournalService(repo)
    return TaskService(repo, journal)


@pytest.fixture
def no_evergreens(monkeypatch: pytest.MonkeyPatch):
    """Schaltet den Evergreen-Fallback ab.

    Diese Tests prüfen ausschließlich die Auto-Task-Auswahl der Section. Der
    Evergreen-Lückenfüller hat eigene Integrationstests
    (``tests/test_ki_todo_section_evergreen.py``) — hier würde er nur die
    Soll-Anzahl der Hero-Karten verfälschen.
    """
    monkeypatch.setattr(
        "tools.mainpage.gui.ki_todo_section.get_evergreens",
        lambda *_args, **_kwargs: [],
    )


def _create_auto_task(
    svc: TaskService,
    *,
    urgency: str,
    title: str = "TLS-Zertifikat fuer example.com laeuft in 5 Tagen ab",
    evidence_id: str = "cert-1",
    description: str = (
        "Das Zertifikat laeuft am 2026-05-04 aus, in 5 Tagen.\n\n"
        "Jetzt erneuern (Let's Encrypt mit certbot: ca. 5 Min)."
    ),
) -> Task:
    """Helfer: erzeugt eine KI-Todo mit gegebener Urgency."""
    return svc.create_auto_task(
        title=title,
        tool_name="cert_monitor",
        description=description,
        urgency=urgency,
        evidence_refs=[
            {"tool": "cert_monitor", "finding_id": evidence_id}
        ],
        dedup_key=compute_dedup_key(
            "cert_monitor", "cert_expiring", evidence_id
        ),
    )


# ---------------------------------------------------------------------------
# KiTodoSection: Empty-State
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("no_evergreens")
def test_section_zeigt_empty_state_wenn_keine_auto_tasks(
    task_service: TaskService, qtbot
):
    """Ohne KI-Tasks rendert die Section den Empty-State."""
    # Sicherheits-Check: ggf. eine manuelle Task einbringen, die NICHT
    # in der Section auftauchen darf.
    task_service.create_task("Manuelle Aufgabe", priority="normal")
    section = KiTodoSection(task_service)
    qtbot.add_widget(section)
    section.refresh()

    # Empty-State ist ein QFrame ohne _HeroCard-Inhalt.
    hero_cards = section.findChildren(_HeroCard)
    assert hero_cards == []


# ---------------------------------------------------------------------------
# KiTodoSection: Sortierung + Top-N
# ---------------------------------------------------------------------------


def test_section_zeigt_top_3_sortiert_nach_urgency(
    task_service: TaskService, qtbot
):
    """Quick > Mittel > Langfrist; manuelle Tasks werden ignoriert."""
    _create_auto_task(task_service, urgency="langfrist", evidence_id="e1")
    _create_auto_task(task_service, urgency="mittel", evidence_id="e2")
    _create_auto_task(task_service, urgency="quick", evidence_id="e3")
    task_service.create_task("nicht-KI-Task")  # darf nicht erscheinen

    section = KiTodoSection(task_service)
    qtbot.add_widget(section)

    hero_cards = section.findChildren(_HeroCard)
    assert len(hero_cards) == 3
    # Reihenfolge: quick zuerst.
    assert hero_cards[0]._task.urgency == "quick"  # noqa: SLF001
    assert hero_cards[1]._task.urgency == "mittel"  # noqa: SLF001
    assert hero_cards[2]._task.urgency == "langfrist"  # noqa: SLF001


@pytest.mark.usefixtures("no_evergreens")
def test_deferred_initial_refresh_populates_after_event_loop(
    task_service: TaskService, qtbot
):
    """Perf: defer_initial_refresh=True baut die Karten erst nach dem ersten
    Event-Loop-Tick (Cockpit-Startup ~46 ms gespart) — synchron leer, danach da.
    """
    _create_auto_task(task_service, urgency="quick", evidence_id="e1")
    section = KiTodoSection(task_service, defer_initial_refresh=True)
    qtbot.add_widget(section)
    # Synchron noch keine Karten (refresh ist auf QTimer(0) verschoben).
    assert section.findChildren(_HeroCard) == []
    # Nach dem Event-Loop-Durchlauf fuellt sich die Sektion.
    qtbot.waitUntil(
        lambda: len(section.findChildren(_HeroCard)) == 1, timeout=2000
    )


def test_section_kappt_bei_max_hero_cards(
    task_service: TaskService, qtbot
):
    """Mehr als ``_MAX_HERO_CARDS`` Auto-Tasks → Section zeigt nur die ersten 3."""
    for i in range(5):
        _create_auto_task(task_service, urgency="quick", evidence_id=f"e{i}")
    section = KiTodoSection(task_service)
    qtbot.add_widget(section)

    hero_cards = section.findChildren(_HeroCard)
    assert len(hero_cards) == _MAX_HERO_CARDS


@pytest.mark.usefixtures("no_evergreens")
def test_section_ignoriert_done_tasks(task_service: TaskService, qtbot):
    """Erledigte KI-Tasks erscheinen nicht in 'Was tun?'."""
    task = _create_auto_task(task_service, urgency="quick", evidence_id="e1")
    task_service.complete_task(task.id)

    section = KiTodoSection(task_service)
    qtbot.add_widget(section)

    assert section.findChildren(_HeroCard) == []


@pytest.mark.usefixtures("no_evergreens")
def test_hero_card_zeigt_action_snippet(task_service: TaskService, qtbot):
    """``_HeroCard`` extrahiert den Action-Teil (zweiter Absatz) aus der Description."""
    _create_auto_task(
        task_service,
        urgency="quick",
        description="Erklaerung erste Zeile.\n\nKonkrete Aktion zweite Zeile.",
    )
    section = KiTodoSection(task_service)
    qtbot.add_widget(section)
    hero_cards = section.findChildren(_HeroCard)
    assert len(hero_cards) == 1
    # Action-Snippet ist als QLabel mit dem Text vorhanden.
    found = any(
        "Konkrete Aktion zweite Zeile" in lbl.text()
        for lbl in hero_cards[0].findChildren(type(hero_cards[0]).__base__)  # noqa: SLF001
        for cls in [type(lbl)]  # noqa: B007 -- robust gegen Qt-Typ-Hierarchie
        if hasattr(lbl, "text")
    ) or any(
        "Konkrete Aktion zweite Zeile" in w.text()
        for w in hero_cards[0].findChildren(object)
        if hasattr(w, "text") and callable(getattr(w, "text", None))
    )
    assert found


# ---------------------------------------------------------------------------
# _TaskCard mit Auto-Task
# ---------------------------------------------------------------------------


def test_taskcard_auto_zeigt_ki_marker_und_urgency_badge(
    task_service: TaskService, qtbot
):
    """KI-Tasks bekommen ``KI``-Marker + Urgency-Badge im Top-Row."""
    task = _create_auto_task(task_service, urgency="quick")
    card = _TaskCard(task, task_service, on_refresh=lambda: None)
    qtbot.add_widget(card)

    labels = card.findChildren(object)
    texts = [
        w.text()
        for w in labels
        if hasattr(w, "text") and callable(getattr(w, "text", None))
    ]
    assert "KI" in texts
    assert "QUICK" in texts


def test_taskcard_manuell_keine_ki_decoration(
    task_service: TaskService, qtbot
):
    """Manuelle Tasks haben weder KI-Marker noch Urgency-Badge."""
    task = task_service.create_task("manuell", priority="normal")
    card = _TaskCard(task, task_service, on_refresh=lambda: None)
    qtbot.add_widget(card)

    texts = [
        w.text()
        for w in card.findChildren(object)
        if hasattr(w, "text") and callable(getattr(w, "text", None))
    ]
    assert "KI" not in texts
    assert "QUICK" not in texts
    assert "WOCHE" not in texts
    assert "LANGFRIST" not in texts


def test_taskcard_feedback_aktionen_deaktivieren_nach_klick(
    task_service: TaskService, qtbot, monkeypatch: pytest.MonkeyPatch
):
    """Beide Feedback-Menü-Aktionen werden nach einem Klick disabled.

    Vorher waren das eigene 24px-Buttons auf der Karte; seit leben
    "Hilfreich"/"Nicht hilfreich" im "⋯"-Menü der Karte.
    """
    # ``record_feedback`` greift auf AuditLogger zu — wir patchen die
    # ``log_action``-Methode, damit der Test keine Datei schreibt.
    from core import audit_log as _audit_module

    captured: list[tuple[str, dict | None, str | None]] = []

    def _fake_log_action(self, action, details=None, tool=None):  # noqa: ANN001, ARG001
        captured.append((action, details, tool))

    monkeypatch.setattr(_audit_module.AuditLogger, "log_action", _fake_log_action)

    task = _create_auto_task(task_service, urgency="quick")
    card = _TaskCard(task, task_service, on_refresh=lambda: None)
    qtbot.add_widget(card)

    assert card._act_helpful.isEnabled()  # noqa: SLF001
    assert card._act_unhelpful.isEnabled()  # noqa: SLF001

    card._act_helpful.trigger()  # noqa: SLF001
    assert not card._act_helpful.isEnabled()  # noqa: SLF001
    assert not card._act_unhelpful.isEnabled()  # noqa: SLF001
    assert len(captured) == 1
    assert captured[0][0] == "KI_TODO_FEEDBACK"
    assert captured[0][1]["helpful"] is True


def test_taskcard_done_keine_feedback_aktionen(
    task_service: TaskService, qtbot
):
    """Erledigte KI-Tasks haben keine Feedback-Aktionen im Menü (zu spät)."""
    task = _create_auto_task(task_service, urgency="quick")
    task_service.complete_task(task.id)
    # Re-load to get the updated task.
    task = task_service.get_task(task.id)
    assert task is not None

    card = _TaskCard(task, task_service, on_refresh=lambda: None)
    qtbot.add_widget(card)
    assert not hasattr(card, "_act_helpful")


# ---------------------------------------------------------------------------
# TaskService.record_feedback
# ---------------------------------------------------------------------------


def test_record_feedback_schreibt_audit_eintrag(
    task_service: TaskService, isolated_db_dir: Path, monkeypatch: pytest.MonkeyPatch
):
    """``record_feedback`` schreibt einen ``KI_TODO_FEEDBACK``-Eintrag ins Audit-File."""
    # Audit-Verzeichnis auf tmp_path lenken.
    audit_dir = isolated_db_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("core.audit_log._AUDIT_DIR", audit_dir)

    task = _create_auto_task(task_service, urgency="quick")
    task_service.record_feedback(task.id, helpful=False)

    month = datetime.now().strftime("%Y%m")
    log_file = audit_dir / f"audit_{month}.log"
    assert log_file.exists()
    raw_lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    feedback_entries = [
        json.loads(ln) for ln in raw_lines if "KI_TODO_FEEDBACK" in ln
    ]
    assert len(feedback_entries) == 1
    entry = feedback_entries[0]
    assert entry["action"] == "KI_TODO_FEEDBACK"
    assert entry["details"]["task_id"] == task.id
    assert entry["details"]["helpful"] is False
    assert entry["details"]["urgency"] == "quick"


def test_record_feedback_unbekannte_task_loggt_trotzdem(
    task_service: TaskService, isolated_db_dir: Path, monkeypatch: pytest.MonkeyPatch
):
    """Audit-Trail bleibt lückenlos — auch wenn die Task bereits gelöscht wurde."""
    audit_dir = isolated_db_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("core.audit_log._AUDIT_DIR", audit_dir)

    task_service.record_feedback("nicht-existierende-id", helpful=True)

    month = datetime.now().strftime("%Y%m")
    log_file = audit_dir / f"audit_{month}.log"
    raw = log_file.read_text(encoding="utf-8").strip()
    assert "KI_TODO_FEEDBACK" in raw
    assert "nicht-existierende-id" in raw
    # Speichert weniger Felder als bei Hit, aber Datensatz existiert.


# ---------------------------------------------------------------------------
# Sicherheits-Check: Auto-Refresh + Smoke
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("no_evergreens")
def test_section_refresh_idempotent(task_service: TaskService, qtbot):
    """Mehrfacher Refresh ohne neue Tasks behält denselben Zustand."""
    _create_auto_task(task_service, urgency="quick", evidence_id="x")
    section = KiTodoSection(task_service)
    qtbot.add_widget(section)
    section.refresh()
    section.refresh()
    section.refresh()
    assert len(section.findChildren(_HeroCard)) == 1


def _all_widget_texts(widget) -> list[str]:  # noqa: ANN001 -- Test-Helfer
    """Sammelt den Text aller Children, die eine ``text``-Methode haben."""
    return [
        w.text()
        for w in widget.findChildren(object)
        if hasattr(w, "text") and callable(getattr(w, "text", None))
    ]


# Suppress the ARG001/unused-import noise from the GUI fixture chain —
# pytest's auto-use fixtures fight with import-only references.
_ = os
