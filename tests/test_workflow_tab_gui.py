"""test_workflow_tab_gui — Der Cockpit-Workflow-Tab, Phase 3, GUI).

Baut echte Qt-Widgets -> ``@pytest.mark.gui``. Deckt ab: Laden pro Subjekt,
Phasen-Rendering, Status-Aenderung (Persistenz + Fortschritt), Reset,
Hinweiszustand ohne Subjekt und die „Zum Tool"-Weiterleitung der Karte.
"""

from __future__ import annotations

import sqlite3

import pytest

from core.security_subject.models import Subject, SubjectKind
from tools.norisk_dashboard.application.workflow_service import (
    WorkflowService,
    WorkflowStepView,
)
from tools.norisk_dashboard.data.workflow_progress_repository import (
    WorkflowProgressRepository,
)
from tools.norisk_dashboard.domain.workflow_definition import step_by_key
from tools.norisk_dashboard.domain.workflow_models import WorkflowStepStatus
from tools.norisk_dashboard.gui._workflow_step_card import WorkflowStepCard
from tools.norisk_dashboard.gui.section_workflow import WorkflowTabWidget


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


def _service() -> WorkflowService:
    return WorkflowService(WorkflowProgressRepository(db=_InMemoryDB()))


def _self_subject() -> Subject:
    return Subject(subject_id="self-1", kind=SubjectKind.EIGENES, name="Mein System")


def _kunde() -> Subject:
    return Subject(subject_id="kunde-1", kind=SubjectKind.KUNDE, name="Muster GmbH")


@pytest.mark.gui
class TestWorkflowTab:
    def test_laden_zeigt_phasen(self, qapp) -> None:
        svc = _service()
        tab = WorkflowTabWidget(svc)
        tab.load(_self_subject())
        assert tab._body.count() > 0  # Phasen-Sektionen gerendert
        assert "Eigenes System" in tab._subject_label.text()

    def test_kunde_und_self_unterschiedlich(self, qapp) -> None:
        svc = _service()
        tab = WorkflowTabWidget(svc)
        tab.load(_kunde())
        assert "Kunde" in tab._subject_label.text()

    def test_ohne_subjekt_hinweiszustand(self, qapp) -> None:
        tab = WorkflowTabWidget(_service())
        tab.load(None)
        # isVisible waere ohne gezeigtes Fenster immer False -> isHidden prueft
        # das explizit gesetzte Sichtbar-Flag (headless-tauglich).
        assert not tab._empty_label.isHidden()

    def test_ohne_service_hinweiszustand(self, qapp) -> None:
        tab = WorkflowTabWidget(None)
        tab.load(_self_subject())
        # isVisible waere ohne gezeigtes Fenster immer False -> isHidden prueft
        # das explizit gesetzte Sichtbar-Flag (headless-tauglich).
        assert not tab._empty_label.isHidden()

    def test_status_aenderung_persistiert_und_aktualisiert(self, qapp) -> None:
        svc = _service()
        tab = WorkflowTabWidget(svc)
        subject = _self_subject()
        tab.load(subject)
        tab._on_status_changed("self_scan_system", "erledigt")
        # Persistenz ist synchron; der Reload laeuft verzoegert -> direkt anstossen.
        tab._reload()
        view = svc.get_view(subject)
        assert view.summary.done == 1
        assert "1 von" in tab._percent_label.text()

    def test_reset_leert(self, qapp) -> None:
        svc = _service()
        subject = _self_subject()
        svc.set_status(subject.subject_id, "self_scan_system", "erledigt")
        tab = WorkflowTabWidget(svc)
        tab.load(subject)
        svc.reset(subject.subject_id)
        tab._reload()
        assert svc.get_view(subject).summary.done == 0


@pytest.mark.gui
class TestWorkflowStepCard:
    def _view(self) -> WorkflowStepView:
        step = step_by_key("self_scan_system")
        assert step is not None
        return WorkflowStepView(step=step, status=WorkflowStepStatus.OFFEN, note="")

    def test_navigate_signal(self, qapp) -> None:
        card = WorkflowStepCard(self._view(), number=1)
        received: list[str] = []
        card.navigate.connect(received.append)
        # „Zum Tool →"-Button finden und klicken.
        from PySide6.QtWidgets import QPushButton

        goto = next(
            b
            for b in card.findChildren(QPushButton)
            if b.text().startswith("Zum Tool")
        )
        goto.click()
        assert received == ["system_scanner"]

    def test_status_changed_signal(self, qapp) -> None:
        card = WorkflowStepCard(self._view(), number=1)
        received: list[tuple[str, str]] = []
        card.status_changed.connect(lambda k, s: received.append((k, s)))
        # Die Menue-Aktionen der Status-Buttons durchgehen und „erledigt" ausloesen.
        from PySide6.QtWidgets import QToolButton

        btn = card.findChild(QToolButton)
        assert btn is not None
        actions = {a.data(): a for a in btn.menu().actions()}
        actions["erledigt"].trigger()
        assert received == [("self_scan_system", "erledigt")]
