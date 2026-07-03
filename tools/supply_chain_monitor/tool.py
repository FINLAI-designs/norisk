"""tool —:class:`SupplyChainMonitorTool` Plugin-Definition.

Registriert den Supply-Chain-Monitor in der NoRisk-ToolRegistry.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.base_tool import BaseTool


class SupplyChainMonitorTool(BaseTool):
    """Plugin-Definition fuer den Supply-Chain-Monitor.

    Attributes:
        name: ``"Supply-Chain-Monitor"`` — Sidebar-Label.
        icon: Material-Symbol ``"hub"``.
        feature_name: Lizenz-Feature-Key ``supply_chain_monitor``.
    """

    name = "Supply-Chain-Monitor"
    icon = "hub"
    feature_name = "supply_chain_monitor"

    def create_widget(self, parent=None):
        """Erstellt das Widget und initialisiert die Service-Schicht.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
:class:`SupplyChainWidget`-Instanz.
        """
        from tools.supply_chain_monitor.application.vendor_service import (  # noqa: PLC0415
            VendorService,
        )
        from tools.supply_chain_monitor.gui.supply_chain_widget import (  # noqa: PLC0415
            SupplyChainWidget,
        )

        widget = SupplyChainWidget(service=VendorService(), parent=parent)
        widget.setMinimumSize(720, 480)
        return widget
