"""
system_scanner.tool — SystemScannerTool Plugin-Definition.

Registriert den System-Scanner in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool


class SystemScannerTool(BaseTool):
    """Plugin-Definition für den lokalen System-Scanner.

    Attributes:
        name (str): ``"Scan starten"``.
        icon (str): ``"security"``.
        feature_name (str): ``"system_scanner"``.
    """

    name = "Scan starten"
    icon = "security"
    feature_name = "system_scanner"

    def create_widget(self, parent=None):
        """Erstellt das SystemScannerWidget mit vollständigem Service-Stack.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            SystemScannerWidget: Die initialisierte Scanner-Ansicht.
        """
        from tools.system_scanner.application.manual_entry_service import (
            ManualEntryService,
        )
        from tools.system_scanner.application.scan_history_use_case import (
            ScanHistoryUseCase,
        )
        from tools.system_scanner.application.scan_use_case import ScanUseCase
        from tools.system_scanner.data.platform_scanner import PlatformScanner
        from tools.system_scanner.data.scanner_repository import ScanRepository
        from tools.system_scanner.gui.scanner_widget import SystemScannerWidget

        scanner = PlatformScanner()
        repository = ScanRepository()
        scan_use_case = ScanUseCase(scanner=scanner, repository=repository)
        history_use_case = ScanHistoryUseCase(repository=repository)
        manual_service = ManualEntryService()

        widget = SystemScannerWidget(
            scan_use_case=scan_use_case,
            history_use_case=history_use_case,
            manual_entry_service=manual_service,
            parent=parent,
        )
        widget.setMinimumSize(700, 500)
        return widget
