"""Tests für die Tab-Integration TechStack ↔ CSAF-Advisor.

Deckt ab:
  - ``CsafAdvisorWidget`` rendert zwei Tabs ("Tech-Stack" + "Advisories").
  -: Der frühere read-only „Inventar"-Tab wird durch das echte
    Tech-Stack-Tool ersetzt (voller Editor), via injizierter Factory. Der
    eigenständige Sidebar-Eintrag „Tech-Stack" entfällt — es gibt damit genau
    EINEN Tech-Stack-Editor (D4-Invariante bleibt erfüllt).
  - Factory-Fehler/None → Fallback-Hinweis; der Advisories-Tab bleibt nutzbar.
  - ``set_cve_filter`` wechselt automatisch in den Advisories-Tab und delegiert.
  - ``shutdown`` reicht den Teardown an die Sub-Tabs durch (idempotent).
  - 'techstack' ist kein eigenes Deeplink-/Nav-Ziel mehr (Router-Alias).
  - Standalone-TechStackWidget-API bleibt unangetastet (Regression).

Author: Patrick Riederich
Version: 3.0 — Tech-Stack-Tool ersetzt Inventar-Tab)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QTabWidget, QWidget

from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.gui.csaf_advisor_widget import (
    CsafAdvisorWidget,
    _AdvisoriesPanel,
)

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# Fixtures / Helfer
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_advisory_service():
    """Ein Mock-AdvisoryService — verhindert echten DB-Zugriff."""
    svc = MagicMock(spec=AdvisoryService)
    svc.list_advisories.return_value = []
    svc.list_matches.return_value = []
    svc.advisory_count.return_value = 0
    svc.get_advisory.return_value = None
    return svc


class _StubTechstack(QWidget):
    """Schlankes Stub-Tech-Stack-Widget (umgeht den DashboardService-Stack)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.shutdown_calls = 0

    def shutdown(self) -> None:
        self.shutdown_calls += 1


def _stub_factory(parent: QWidget | None = None) -> QWidget:
    return _StubTechstack(parent)


def _make(service, factory=_stub_factory) -> CsafAdvisorWidget:
    return CsafAdvisorWidget(service, techstack_factory=factory)


# ---------------------------------------------------------------------------
# Tab-Struktur
# ---------------------------------------------------------------------------


def test_widget_hat_zwei_tabs_techstack_und_advisories(qtbot, fake_advisory_service):
    """``CsafAdvisorWidget`` rendert genau die zwei dokumentierten Tabs."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    tabs = widget.findChild(QTabWidget)
    assert tabs is not None
    assert tabs.count() == 2
    assert tabs.tabText(0) == "Tech-Stack"
    assert tabs.tabText(1) == "Advisories"


def test_techstack_tab_ist_injiziertes_widget(qtbot, fake_advisory_service):
    """Tab 1 ist das via Factory injizierte (echte) Tech-Stack-Widget."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    assert isinstance(widget._techstack_widget, _StubTechstack)  # noqa: SLF001
    tabs = widget.findChild(QTabWidget)
    assert tabs.widget(0) is widget._techstack_widget  # noqa: SLF001


def test_advisories_tab_ist_advisories_panel(qtbot, fake_advisory_service):
    """Tab 2 enthält tatsächlich ein ``_AdvisoriesPanel``."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    assert isinstance(widget._advisories_panel, _AdvisoriesPanel)  # noqa: SLF001
    tabs = widget.findChild(QTabWidget)
    assert tabs.widget(1) is widget._advisories_panel  # noqa: SLF001


# ---------------------------------------------------------------------------
# Fallback-Pfade: Factory fehlt oder schlägt fehl
# ---------------------------------------------------------------------------


def test_fallback_bei_factory_fehler(qtbot, fake_advisory_service):
    """Wirft die Factory, wird der Tech-Stack-Tab durch einen Hinweis-Block
    ersetzt — der Advisories-Tab bleibt funktional."""

    def _raise(parent=None):  # noqa: ANN001, ANN202, ARG001
        raise RuntimeError("nvd-init-fail")

    widget = _make(fake_advisory_service, factory=_raise)
    qtbot.add_widget(widget)
    assert widget._techstack_widget is None  # noqa: SLF001
    tabs = widget.findChild(QTabWidget)
    assert tabs.count() == 2
    assert tabs.tabText(0) == "Tech-Stack"
    assert isinstance(widget._advisories_panel, _AdvisoriesPanel)  # noqa: SLF001


def test_fallback_bei_factory_none(qtbot, fake_advisory_service):
    """Ohne Factory (``None``) zeigt der Tab einen Hinweis statt zu crashen."""
    widget = CsafAdvisorWidget(fake_advisory_service, techstack_factory=None)
    qtbot.add_widget(widget)
    assert widget._techstack_widget is None  # noqa: SLF001
    tabs = widget.findChild(QTabWidget)
    assert tabs.count() == 2


# ---------------------------------------------------------------------------
# shutdown: reicht an Sub-Tabs durch (idempotent)
# ---------------------------------------------------------------------------


def test_shutdown_reicht_an_subtabs_durch_idempotent(qtbot, fake_advisory_service):
    """``shutdown`` ruft ``shutdown`` des Tech-Stack-Tabs genau einmal."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    ts = widget._techstack_widget  # noqa: SLF001
    widget.shutdown()
    widget.shutdown()  # zweiter Aufruf = No-op (Idempotenz-Guard)
    assert ts.shutdown_calls == 1


# ---------------------------------------------------------------------------
# set_cve_filter: aktiviert Advisories-Tab + delegiert Filter
# ---------------------------------------------------------------------------


def test_set_cve_filter_wechselt_in_advisories_tab(qtbot, fake_advisory_service):
    """``set_cve_filter`` aktiviert automatisch den Advisories-Tab."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    tabs = widget.findChild(QTabWidget)
    tabs.setCurrentIndex(0)  # explizit auf Tech-Stack starten

    widget.set_cve_filter("CVE-2026-0042")

    assert tabs.currentIndex() == 1  # Advisories
    assert widget._cve_id_filter == "CVE-2026-0042"  # noqa: SLF001


def test_set_cve_filter_leerstring_hebt_filter_auf(qtbot, fake_advisory_service):
    """Leerer String + Whitespace-only setzen den Filter auf ``None``."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    widget.set_cve_filter("CVE-X")
    widget.set_cve_filter("   ")
    assert widget._cve_id_filter is None  # noqa: SLF001
    widget.set_cve_filter("CVE-X")
    widget.set_cve_filter("")
    assert widget._cve_id_filter is None  # noqa: SLF001


def test_set_cve_filter_delegiert_an_panel(qtbot, fake_advisory_service):
    """Die Filter-Anwendung wird an ``_AdvisoriesPanel.set_cve_filter`` delegiert."""
    widget = _make(fake_advisory_service)
    qtbot.add_widget(widget)
    panel = widget._advisories_panel  # noqa: SLF001
    with patch.object(panel, "set_cve_filter") as panel_setter:
        widget.set_cve_filter("CVE-2026-0001")
    panel_setter.assert_called_once_with("CVE-2026-0001")


# ---------------------------------------------------------------------------
# techstack ist kein eigenes Deeplink-/Nav-Ziel mehr (Router-Alias)
# ---------------------------------------------------------------------------


def test_techstack_kein_eigenes_deeplink_ziel_mehr():
    """: 'techstack' ist kein eigenes Tool mehr — der Router-Alias biegt
    navigate('techstack') auf den Advisory-Monitor um."""
    from core.deeplink_registry import DEEPLINK_TARGETS
    from core.navigation_mixin import _TOOL_ALIASES

    assert "techstack" not in DEEPLINK_TARGETS
    assert _TOOL_ALIASES["techstack"][0] == "csaf_advisor"


# ---------------------------------------------------------------------------
# TechStackWidget.stack_changed direkt (Standalone-Regression, unverändert)
# ---------------------------------------------------------------------------


def test_techstack_widget_emittiert_stack_changed_bei_add(qtbot, monkeypatch):
    """``TechStackWidget._eintrag_hinzufuegen`` emittiert das Signal."""
    from tools.techstack.gui.techstack_widget import TechStackWidget

    fake_service = MagicMock()
    fake_service.techstack_laden.return_value = []
    fake_service.techstack_anzahl.return_value = 0
    fake_service.nvd_aktiv.return_value = False

    widget = TechStackWidget(fake_service)
    qtbot.add_widget(widget)

    received: list[None] = []
    widget.stack_changed.connect(lambda: received.append(None))
    widget._input_name.setText("OpenSSL")  # noqa: SLF001
    widget._input_version.setText("1.1.1")  # noqa: SLF001
    widget._eintrag_hinzufuegen()  # noqa: SLF001
    assert len(received) == 1
    fake_service.techstack_hinzufuegen.assert_called_once()


def test_techstack_widget_emittiert_stack_changed_bei_starter(qtbot):
    """``_starter_stack_laden`` emittiert das Signal nach dem Bulk-Import."""
    from tools.techstack.gui.techstack_widget import TechStackWidget

    fake_service = MagicMock()
    fake_service.techstack_laden.return_value = []
    fake_service.techstack_anzahl.return_value = 0
    fake_service.nvd_aktiv.return_value = False

    widget = TechStackWidget(fake_service)
    qtbot.add_widget(widget)

    received: list[None] = []
    widget.stack_changed.connect(lambda: received.append(None))
    widget._starter_stack_laden()  # noqa: SLF001
    assert len(received) == 1
