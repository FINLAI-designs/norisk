"""test_security_assessment_container — Bewerten-Container-Widget.

Prüft das lazy Tab-Verhalten, die Deeplink-Tab-Vorauswahl, die Cross-Tab-
Signal-Verdrahtung (Audit→NIS2) und die idempotente shutdown-Weiterreichung des
``SecurityAssessmentWidget``. Stub-Factories umgehen die echten Sub-Tool-Services.
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QTabWidget, QWidget

from tools.security_assessment.gui.security_assessment_widget import (
    SecurityAssessmentWidget,
)

pytestmark = pytest.mark.gui


class _StubTab(QWidget):
    """Einfaches Sub-Tab-Widget, das Builds + shutdown mitzählt."""

    _built_count = 0

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        type(self)._built_count += 1
        self.shutdown_calls = 0

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class _AuditStub(_StubTab):
    """Audit-Stub mit ``nis2_requested``-Signal (wie das echte Audit-Widget)."""

    nis2_requested = Signal()


def _specs(factories: dict | None = None) -> list:
    """Baut tab_specs in der echten Reihenfolge mit Stub-Factories."""
    factories = factories or {}
    default = lambda parent=None: _StubTab(parent)  # noqa: E731
    return [
        ("audit", "customer_audit", "Security-Audit", "Security-Audit",
         factories.get("audit", lambda parent=None: _AuditStub(parent))),
        ("score", "security_scoring", "Security-Score", "Security-Score",
         factories.get("score", default)),
        ("awareness", "awareness_tracker", "Awareness-Tracker", "Awareness-Tracker",
         factories.get("awareness", default)),
        ("nis2", "customer_audit", "NIS2-Vorfälle", "NIS2-Vorfälle",
         factories.get("nis2", default)),
    ]


def test_vier_tabs_in_reihenfolge(qtbot) -> None:
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    tabs = widget.findChild(QTabWidget)
    assert tabs.count() == 4
    assert [tabs.tabText(i) for i in range(4)] == [
        "Security-Audit",
        "Security-Score",
        "Awareness-Tracker",
        "NIS2-Vorfälle",
    ]


def test_nur_erster_tab_eager_gebaut(qtbot) -> None:
    """Lazy: beim Öffnen ist nur Tab 0 gebaut, die anderen sind Platzhalter."""
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    assert set(widget._built.keys()) == {0}  # noqa: SLF001


def test_apply_navigation_baut_und_waehlt_subtab(qtbot) -> None:
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    widget.apply_navigation(tab="nis2")
    tabs = widget.findChild(QTabWidget)
    assert tabs.currentIndex() == 3
    assert 3 in widget._built  # lazy gebaut beim Wechsel # noqa: SLF001


def test_apply_navigation_unbekannter_tab_ist_noop(qtbot) -> None:
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    widget.apply_navigation(tab="bogus")
    tabs = widget.findChild(QTabWidget)
    assert tabs.currentIndex() == 0


def test_factory_fehler_zeigt_platzhalter_kein_crash(qtbot) -> None:
    def _raise(parent=None):  # noqa: ANN001, ANN202, ARG001
        raise RuntimeError("score-service-fail")

    widget = SecurityAssessmentWidget(_specs({"score": _raise}))
    qtbot.add_widget(widget)
    tabs = widget.findChild(QTabWidget)
    # Auf den fehlerhaften Tab wechseln -> Platzhalter, kein Crash.
    widget.apply_navigation(tab="score")
    assert tabs.currentIndex() == 1
    assert tabs.count() == 4


def test_audit_nis2_signal_springt_auf_nis2_tab(qtbot) -> None:
    """Der Audit-Tab-Button (``nis2_requested``) springt auf den NIS2-Tab."""
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    audit_widget = widget._built[0]  # noqa: SLF001
    assert isinstance(audit_widget, _AuditStub)
    audit_widget.nis2_requested.emit()
    tabs = widget.findChild(QTabWidget)
    assert tabs.currentIndex() == 3


def test_shutdown_reicht_durch_und_ist_idempotent(qtbot) -> None:
    widget = SecurityAssessmentWidget(_specs())
    qtbot.add_widget(widget)
    # Alle Tabs bauen, damit shutdown sie alle erreicht.
    for tab in ("score", "awareness", "nis2"):
        widget.apply_navigation(tab=tab)
    built = list(widget._built.values())  # noqa: SLF001
    assert len(built) == 4
    widget.shutdown()
    widget.shutdown()  # idempotent
    assert all(w.shutdown_calls == 1 for w in built)
