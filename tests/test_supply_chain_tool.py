"""
test_supply_chain_tool.

Tests fuer die Tool-Plugin-Wiring (Sidebar-Item, AppConfig, NAV-Map,
License-Feature). Analog ``test_document_scanner_widget.test_tool_*``.
"""

from __future__ import annotations

from core.base_tool import BaseTool
from tools.supply_chain_monitor.tool import SupplyChainMonitorTool


def test_supply_chain_tool_ist_basetool_subklasse() -> None:
    tool = SupplyChainMonitorTool()
    assert isinstance(tool, BaseTool)
    assert tool.name == "Supply-Chain-Monitor"
    assert tool.icon == "hub"
    assert tool.feature_name == "supply_chain_monitor"


def test_tool_modul_in_app_config() -> None:
    """``tools.supply_chain_monitor.tool`` muss in der NoRisk-AppConfig stehen."""
    from apps.app_config import NORISK_CONFIG  # noqa: PLC0415

    assert "tools.supply_chain_monitor.tool" in NORISK_CONFIG.tool_modules


def test_tool_in_ueberwachen_gruppe() -> None:
    """Der Sidebar-Eintrag muss in der Überwachen-Gruppe liegen, Phase 3)."""
    from apps.app_config import NORISK_CONFIG  # noqa: PLC0415

    ueberwachen_group = next(
        (g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "ueberwachen"),
        None,
    )
    assert ueberwachen_group is not None
    assert "supply_chain_monitor" in ueberwachen_group["tool_keys"]


def test_tool_registration_im_nav_map() -> None:
    """supply_chain_monitor muss in MainWindow._NAV_TOOL_MAP eingetragen sein."""
    from core.main_window import MainWindow  # noqa: PLC0415

    keys = [entry[0] for entry in MainWindow._NAV_TOOL_MAP]  # noqa: SLF001
    assert "supply_chain_monitor" in keys


def test_sidebar_item_in_sidebar_config() -> None:
    """``supply_chain_monitor`` muss als SidebarItem in der Überwachen-Gruppe stehen."""
    from core.sidebar_config import UEBERWACHEN_GROUP_CONFIG  # noqa: PLC0415

    keys = [item.key for item in UEBERWACHEN_GROUP_CONFIG.items]
    assert "supply_chain_monitor" in keys

    item = next(
        i for i in UEBERWACHEN_GROUP_CONFIG.items if i.key == "supply_chain_monitor"
    )
    assert item.license_feature == "supply_chain_monitor"
    assert item.icon == "hub"


