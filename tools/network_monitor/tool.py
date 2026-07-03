"""network_monitor.tool — NetworkMonitorTool Plugin-Definition.

Registriert den Netzwerkmonitor in der FINLAI ToolRegistry. Im Single-Tenant-
OSS-Build sind alle Anteile frei — kein Free/Pro-Gating mehr.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.base_tool import BaseTool


class NetworkMonitorTool(BaseTool):
    """Plugin-Definition für den Netzwerkmonitor.

    Attributes:
        name: ``"Netzwerkmonitor"``.
        icon: Material Symbol ``"monitor_heart"``.
        feature_name: Leer → immer aktiv.
    """

    name = "Netzwerkmonitor"
    icon = "monitor_heart"
    feature_name = ""  # immer aktiv (kein Lizenz-Gate)

    def create_widget(self, parent=None):  # noqa: ANN001
        """Erstellt das NetworkMonitorWidget mit passendem Repository.

        kein Lizenz-Gate mehr — die History-Repositories
        werden immer eingebaut (fail-open, falls KeyManager/DB fehlt). Die
        Konstruktion liegt in ``MonitorService.build_history_repositories``
        (Application-Schicht, geteilt mit dem eingebetteten Live-Tab im
        Netzwerk-Scanner).
        """
        from tools.network_monitor.application.monitor_service import (
            MonitorService,
        )
        from tools.network_monitor.gui.network_monitor_widget import (
            NetworkMonitorWidget,
        )

        repository, traffic_repo = MonitorService.build_history_repositories()

        widget = NetworkMonitorWidget(
            parent=parent,
            repository=repository,
            process_traffic_repo=traffic_repo,
        )
        widget.setMinimumSize(900, 600)
        return widget
