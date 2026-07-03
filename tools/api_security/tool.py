"""
api_security.tool — ApiSecurityTool Plugin-Definition.

Registriert den API Security Analyzer in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.1
"""

from core.base_tool import BaseTool
from tools.api_security.gui.api_security_widget import ApiSecurityWidget


class ApiSecurityTool(BaseTool):
    """Plugin-Definition fuer den API Security Analyzer.

    Attributes:
        name (str): ``"API Security Analyzer"``.
        icon (str): ``"🔍"``.
    """

    name = "API Security Analyzer"
    icon = "api"
    feature_name = "api_security"

    def create_widget(self, parent=None) -> ApiSecurityWidget:
        """Erstellt eine neue ApiSecurityWidget-Instanz mit Repository-DI.

        Baut den vollstaendigen Service-Stack auf:
        HttpScanner + ReportAdapter + ScanRepository → ScannerService.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            ApiSecurityWidget: Die initialisierte Scanner-Ansicht.
        """
        from tools.api_security.application.scanner_service import ScannerService
        from tools.api_security.data.http_scanner import HttpScanner
        from tools.api_security.data.report_adapter import ReportAdapter
        from tools.api_security.data.scan_repository import ScanRepository

        service = ScannerService(
            scanner=HttpScanner(verify_ssl=True),
            reporter=ReportAdapter(),
            scan_repo=ScanRepository(),
        )
        widget = ApiSecurityWidget(service=service, parent=parent)
        widget.setMinimumSize(900, 600)
        return widget
