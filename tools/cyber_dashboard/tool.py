"""
cyber_dashboard.tool — CyberDashboardTool Plugin-Definition.

Registriert das Cyberrisiko-Dashboard in der FINLAI ToolRegistry.
Das CyberDashboardWidget wird als Haupt-Widget bereitgestellt.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool
from tools.cyber_dashboard.gui.dashboard_widget import CyberDashboardWidget


class CyberDashboardTool(BaseTool):
    """Plugin-Definition für das Cyberrisiko-Dashboard.

    Erbt von BaseTool und liefert das CyberDashboardWidget.

    Sidebar-Label "Lagebild" — geschärft per Sprint S0c (Tool-Merger M3),
    damit "Übersicht (eigene Org)" und "Lagebild (die Welt)" auf einen Blick
    unterscheidbar sind.

    Attributes:
        name (str): Sidebar-Anzeigename — ``"Lagebild"``.
        icon (str): Google-Material-Symbol — ``"shield"``.
    """

    name = "Lagebild"
    icon = "shield"
    feature_name = "cyber_dashboard"

    def create_widget(self, parent=None) -> CyberDashboardWidget:
        """Erstellt und gibt eine neue CyberDashboardWidget-Instanz zurück.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            CyberDashboardWidget: Die initialisierte Dashboard-Ansicht.
        """
        widget = CyberDashboardWidget(parent)
        widget.setMinimumSize(900, 600)
        return widget
