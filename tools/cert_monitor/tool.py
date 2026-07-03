"""tool — CertMonitorTool Plugin-Definition.

Registriert den SSL/TLS-Zertifikats-Monitor in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.base_tool import BaseTool


class CertMonitorTool(BaseTool):
    """Plugin-Definition für den Zertifikats-Monitor.

    Attributes:
        name (str): ``"Zertifikats-Monitor"``.
        icon (str): ``"verified_user"`` (Google Material Symbol).
        feature_name (str): ``"cert_monitor"``.
    """

    name = "Zertifikats-Monitor"
    icon = "verified_user"
    feature_name = "cert_monitor"

    def create_widget(self, parent=None):
        """Erstellt das CertMonitorWidget mit vollständigem Service-Stack.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            CertMonitorWidget.
        """
        from tools.cert_monitor.application.cert_monitor_service import (  # noqa: PLC0415
            CertMonitorService,
        )
        from tools.cert_monitor.data.cert_repository import (
            CertRepository,  # noqa: PLC0415
        )
        from tools.cert_monitor.data.cert_scanner import CertScanner  # noqa: PLC0415
        from tools.cert_monitor.gui.cert_monitor_widget import (  # noqa: PLC0415
            CertMonitorWidget,
        )

        service = CertMonitorService(
            scanner=CertScanner(),
            repo=CertRepository(),
        )
        widget = CertMonitorWidget(service=service, parent=parent)
        widget.setMinimumSize(800, 550)
        return widget
