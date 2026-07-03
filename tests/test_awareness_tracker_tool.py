"""
test_awareness_tracker_tool.

Tests fuer die Tool-Plugin-Wiring (Sidebar-Item, AppConfig, NAV-Map,
License-Feature). Analog ``test_supply_chain_tool``.
"""

from __future__ import annotations

from core.base_tool import BaseTool
from tools.awareness_tracker.tool import AwarenessTrackerTool


def test_awareness_tracker_tool_ist_basetool_subklasse() -> None:
    tool = AwarenessTrackerTool()
    assert isinstance(tool, BaseTool)
    assert tool.name == "Awareness-Tracker"
    assert tool.icon == "school"
    assert tool.feature_name == "awareness_tracker"


def test_tool_modul_in_app_config() -> None:
    """``tools.awareness_tracker.tool`` muss in der NoRisk-AppConfig stehen."""
    from apps.app_config import NORISK_CONFIG  # noqa: PLC0415

    assert "tools.awareness_tracker.tool" in NORISK_CONFIG.tool_modules


def test_awareness_ist_subtab_des_bewerten_containers() -> None:
    """: Der Bereich „Bewerten" enthaelt nur den Container
    ``security_assessment``; Awareness ist dessen dritter Sub-Tab (kein eigener
    Sidebar-tool_key mehr)."""
    from apps.app_config import NORISK_CONFIG  # noqa: PLC0415

    from tools.security_assessment.tool import _build_tab_specs  # noqa: PLC0415

    bewerten_group = next(
        (g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "bewerten"),
        None,
    )
    assert bewerten_group is not None
    assert "security_assessment" in bewerten_group["tool_keys"]
    assert "awareness_tracker" not in bewerten_group["tool_keys"]
    assert "awareness" in [spec[0] for spec in _build_tab_specs()]


def test_awareness_kein_eigenes_dock_mehr() -> None:
    """: awareness_tracker hat kein eigenes Dock mehr (kein _NAV_TOOL_MAP-
    Eintrag) — es ist ein Sub-Tab des Bewerten-Containers. Das Tool-Modul bleibt
    aber registriert (Container-Factory + Build-Spec)."""
    from apps.app_config import NORISK_CONFIG  # noqa: PLC0415

    from core.main_window import MainWindow  # noqa: PLC0415

    keys = [entry[0] for entry in MainWindow._NAV_TOOL_MAP]  # noqa: SLF001
    assert "awareness_tracker" not in keys
    assert "security_assessment" in keys
    assert "tools.awareness_tracker.tool" in NORISK_CONFIG.tool_modules


def test_awareness_kein_sidebar_item_mehr() -> None:
    """: ``awareness_tracker`` ist kein SidebarItem mehr — der Bereich
    „Bewerten" hat nur noch den Container-Eintrag."""
    from core.sidebar_config import BEWERTEN_GROUP_CONFIG  # noqa: PLC0415

    keys = [item.key for item in BEWERTEN_GROUP_CONFIG.items]
    assert "awareness_tracker" not in keys
    assert "security_assessment" in keys


