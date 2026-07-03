"""GUI-Tests fuer die EINE Cockpit-Landing-Seite 3c 1b Vision B).

Deckt zwei Invarianten ab, nachdem Welcome-Page und „Mein Status" verschmolzen
wurden:

(i) ``DockMixin._build_home`` baut das **Cockpit** (``NoRiskDashboardWidget``)
     als Welcome-Dock — nicht mehr das mainpage-„Home" — mit Titel „Cockpit".
(ii) Navigation „home" UND „norisk:dashboard" zeigen DASSELBE Welcome-Dock; es
     entsteht KEIN zweites Dashboard-Dock (``norisk:dashboard`` ist nicht in
     ``_docks``). Cockpit-Deeplinks finden das Cockpit-Widget weiterhin.

Headless via pytest-qt (offscreen). ``_build_home`` und die Navigations-Slots
werden als unbound Mixin-Methoden gegen einen minimalen Stub gefahren — wie
``test_dock_floating_restore`` / ``test_navigate_to_kwargs`` — ohne den schweren
echten MainWindow-/Mainpage-DB-Stack.

Author: Patrick Riederich
Version: 1.0 3c 1b)
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QMainWindow

from core.dock_mixin import _COCKPIT_TOOL_NAME, DockMixin
from core.navigation_mixin import NavigationMixin
from core.widgets.error_placeholder import ErrorPlaceholderWidget
from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget
from tools.norisk_dashboard.tool import NoRiskDashboardTool

pytestmark = pytest.mark.gui


class _CockpitTool:
    """Minimaler Tool-Stub: baut das Cockpit OHNE Services (kein DB-Zugriff)."""

    def create_widget(self, parent=None):  # noqa: ANN001, ANN201
        return NoRiskDashboardWidget(parent=parent)


class _CrashingCockpitTool:
    """Tool-Stub, dessen Cockpit-Bau eine Exception wirft (simuliert einen
    fehlerhaften Sektion-Ctor beim eager App-Start)."""

    def create_widget(self, parent=None):  # noqa: ANN001, ANN201
        raise RuntimeError("Sektion-Ctor explodiert beim Cockpit-Bau")


class _Host(DockMixin, NavigationMixin):
    """Stub mit genau den Feldern/Methoden, die _build_home + Navigation brauchen."""

    def __init__(self, qtbot, with_cockpit: bool = True, tool=None):  # noqa: ANN001
        self._inner_main = QMainWindow()
        qtbot.add_widget(self._inner_main)
        # _tool_map ist nach Tool-NAME gekeyt — das Cockpit liegt unter
        # "Übersicht" (BaseTool.name des norisk_dashboard-Tools).
        if tool is not None:
            self._tool_map = {"Übersicht": tool}
        elif with_cockpit:
            self._tool_map = {"Übersicht": _CockpitTool()}
        else:
            self._tool_map = {}
        self._docks: dict = {}
        self._navigated: list[str] = []

    # Vom _build_home verdrahtet (Cockpit traegt navigate/open_with_filter):
    def _on_sidebar_navigate(self, key):  # noqa: ANN001, ANN201
        self._navigated.append(key)

    def _on_dashboard_open_with_filter(self, key, payload):  # noqa: ANN001, ANN201
        self._navigated.append((key, payload))

    # tool_activated wird nur connectet, wenn das Widget set_last_used hat —
    # das Cockpit hat es nicht, daher reicht ein Platzhalter.
    class _Sig:
        def connect(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN201
            pass

    tool_activated = _Sig()


# ---------------------------------------------------------------------------
# (i) _build_home zeigt das Cockpit
# ---------------------------------------------------------------------------


def test_build_home_welcome_dock_ist_cockpit(qtbot, app):  # noqa: ARG001
    host = _Host(qtbot)
    DockMixin._build_home(host, session=None)

    assert host._welcome_dock is not None
    assert host._welcome_dock.objectName() == "dock_welcome"
    assert isinstance(host._welcome_dock.widget(), NoRiskDashboardWidget)
    assert host._welcome_dock.windowTitle() == "Cockpit"


def test_build_home_fallback_ohne_cockpit_tool(qtbot, app):  # noqa: ARG001
    """Ohne Cockpit-Tool im _tool_map bleibt der Placeholder (fail-soft)."""
    host = _Host(qtbot, with_cockpit=False)
    DockMixin._build_home(host, session=None)

    assert host._welcome_dock is not None
    # Kein NoRiskDashboardWidget, aber ein gueltiges Welcome-Dock-Widget.
    assert not isinstance(host._welcome_dock.widget(), NoRiskDashboardWidget)
    assert host._welcome_dock.widget() is not None


# ---------------------------------------------------------------------------
# (ii) home + norisk:dashboard zeigen DASSELBE Dock (kein zweites Dashboard-Dock)
# ---------------------------------------------------------------------------


def test_home_und_dashboard_zeigen_dasselbe_dock(qtbot, app):  # noqa: ARG001
    host = _Host(qtbot)
    DockMixin._build_home(host, session=None)
    welcome = host._welcome_dock

    # Beide Keys routen aufs Welcome-Dock — kein eigenes norisk:dashboard-Dock.
    NavigationMixin._on_sidebar_navigate(host, "home")
    NavigationMixin._on_sidebar_navigate(host, "norisk:dashboard")

    assert "norisk:dashboard" not in host._docks
    # Deeplink-Lookup liefert fuer beide Keys das Cockpit-Widget (apply_navigation
    # erreichbar) — und es ist dasselbe Widget.
    w_home = NavigationMixin._get_active_widget_for(host, "home")
    w_dash = NavigationMixin._get_active_widget_for(host, "norisk:dashboard")
    assert w_home is welcome.widget()
    assert w_dash is welcome.widget()
    assert isinstance(w_dash, NoRiskDashboardWidget)


# ---------------------------------------------------------------------------
# (iii) P1-1: ein Cockpit-Bau-Crash darf die App nicht am Start hindern
# ---------------------------------------------------------------------------


def test_build_home_fallback_bei_cockpit_bau_exception(qtbot, app):  # noqa: ARG001
    """Wirft der Cockpit-Bau (eager, beim App-Start), faengt ``_build_home`` die
    Exception ab und setzt einen ErrorPlaceholder — das Welcome-Dock entsteht
    trotzdem, die App startet (kein Crash hochblubbern)."""
    host = _Host(qtbot, tool=_CrashingCockpitTool())

    # Darf NICHT werfen — sonst startet die ganze App nicht.
    DockMixin._build_home(host, session=None)

    assert host._welcome_dock is not None
    assert host._welcome_dock.objectName() == "dock_welcome"
    # Fallback ist der ErrorPlaceholder (gleiche Klasse wie der lazy Pfad).
    assert isinstance(host._welcome_dock.widget(), ErrorPlaceholderWidget)
    assert not isinstance(host._welcome_dock.widget(), NoRiskDashboardWidget)


# ---------------------------------------------------------------------------
# (iv) P2 Drift-Guard: _COCKPIT_TOOL_NAME == NoRiskDashboardTool.name
# ---------------------------------------------------------------------------


def test_cockpit_tool_name_drift_guard():
    """``_COCKPIT_TOOL_NAME`` (dock_mixin) MUSS dem realen Tool-Namen
    (``NoRiskDashboardTool.name``) entsprechen.

    Driftet einer der beiden (Umbenennung der Sidebar-Bezeichnung), faende
    ``_build_home`` das Cockpit nicht mehr im ``_tool_map`` und das Welcome-
    Dock fiele still auf den Placeholder zurueck — UND der ``_ALWAYS_ACCESSIBLE``-
    Eintrag in core/auth/session.py griffe ins Leere."""
    assert NoRiskDashboardTool.name == _COCKPIT_TOOL_NAME
