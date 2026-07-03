"""
test_sidebar — Tests für die Sidebar-Navigation.

Prüft Erstellung, Filter-Funktion und Such-Verhalten
des SidebarWidget.

Hinweis: SidebarWidget verwendet intern _all_groups und
_all_nav_items (nicht _groups / _all_items).
"""

import pytest

from core.auth.session import Session
from core.sidebar import SidebarWidget
from core.ui_settings import UISettings

pytestmark = pytest.mark.gui


class TestSidebar:
    """Testet die Sidebar-Navigation."""

    @pytest.fixture
    def sidebar(self, qtbot, app):
        """Erstellt Sidebar für Tests."""
        session = Session()
        settings = UISettings.load()
        widget = SidebarWidget([], session, settings)
        qtbot.addWidget(widget)
        widget.show()
        return widget

    def test_sidebar_erstellt(self, sidebar):
        """Sidebar kann erstellt werden."""
        assert sidebar is not None

    def test_filter_leer_zeigt_alles(self, sidebar):
        """Leerer Filter zeigt alle Gruppen (nicht explizit ausgeblendet)."""
        sidebar.filter_items("")
        # Keine Gruppe darf explizit versteckt sein
        for group in sidebar._all_groups:
            assert not group.isHidden()

    def test_filter_findet_patch_monitor(self, sidebar):
        """Suche 'patch' findet den Patch-Monitor: 'buchprüfung' war ein
        stale FINANCE-Leftover — in NoRisk nicht vorhanden, Test war dauerhaft rot)."""
        sidebar.filter_items("patch")
        not_hidden = [item for item in sidebar._all_nav_items if not item.isHidden()]
        assert len(not_hidden) >= 1

    def test_filter_findet_tool_ascii(self, sidebar):
        """Suche 'einstellungen' findet das Einstellungen-Tool."""
        sidebar.filter_items("einstellungen")
        not_hidden = [item for item in sidebar._all_nav_items if not item.isHidden()]
        assert len(not_hidden) >= 1

    def test_filter_ohne_treffer(self, sidebar):
        """Unbekannter Begriff → alle Items ausgeblendet."""
        sidebar.filter_items("xyzunbekannt123")
        not_hidden = [item for item in sidebar._all_nav_items if not item.isHidden()]
        assert len(not_hidden) == 0

    def test_filter_case_insensitiv(self, sidebar):
        """Filter ist case-insensitiv."""
        sidebar.filter_items("EINSTELLUNGEN")
        count_upper = sum(1 for item in sidebar._all_nav_items if not item.isHidden())
        sidebar.filter_items("einstellungen")
        count_lower = sum(1 for item in sidebar._all_nav_items if not item.isHidden())
        assert count_upper == count_lower

    def test_filter_reset_zeigt_alles(self, sidebar):
        """Nach Suche zeigt leerer Filter wieder alle Gruppen."""
        sidebar.filter_items("buchprüfung")
        sidebar.filter_items("")
        for group in sidebar._all_groups:
            assert not group.isHidden()
