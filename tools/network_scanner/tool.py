"""
network_scanner.tool — NetworkScannerTool Plugin-Definition.

Registriert den Netzwerk-Scanner in der FINLAI ToolRegistry.
Baut den vollständigen Service-Stack auf (DI).

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool
from tools.network_scanner.gui.network_scanner_widget import NetworkScannerWidget


class NetworkScannerTool(BaseTool):
    """Plugin-Definition für den Netzwerk-Scanner.

    Attributes:
        name (str): ``"Netzwerk-Scanner"``.
        icon (str): ``"🌐"``.
        feature_name (str): ``"network_scanner"``.
    """

    name = "Netzwerk-Scanner"
    icon = "wifi_find"
    feature_name = "network_scanner"

    def create_widget(self, parent=None) -> NetworkScannerWidget:
        """Erstellt das NetworkScannerWidget mit vollständigem Service-Stack.

        Baut SocketScanner + NmapScanner + ScanRepository → NetworkService.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            NetworkScannerWidget: Die initialisierte Scanner-Ansicht.
        """
        from tools.network_scanner.application.network_service import NetworkService
        from tools.network_scanner.data.nmap_scanner import NmapScanner
        from tools.network_scanner.data.scan_repository import ScanRepository
        from tools.network_scanner.data.socket_scanner import SocketScanner

        service = NetworkService(
            scanner=SocketScanner(),
            repo=ScanRepository(),
            nmap_scanner=NmapScanner(),
        )
        widget = NetworkScannerWidget(service=service, parent=parent)
        widget.setMinimumSize(900, 600)
        return widget
