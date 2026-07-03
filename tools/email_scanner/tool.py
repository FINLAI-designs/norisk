"""tool — EmailScannerTool Plugin-Definition.

Registriert den E-Mail-Anhang-Scanner in der NoRisk-ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.base_tool import BaseTool


class EmailScannerTool(BaseTool):
    """Plugin-Definition für den E-Mail-Anhang-Scanner.

    Attributes:
        name (str): ``"E-Mail-Anhang-Scanner"``.
        icon (str): Material-Symbol ``"mark_email_unread"``.
        feature_name (str): ``"email_attachment_scanner"``.
    """

    name = "E-Mail-Anhang-Scanner"
    icon = "mark_email_unread"
    feature_name = "email_attachment_scanner"

    def create_widget(self, parent=None):
        """Baut Service (mit Repository) + GUI-Widget.

 (RUN2-GUI): Service haelt das Repository — die GUI sieht
        nur noch den Service.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            EmailScannerWidget-Instanz.
        """
        from tools.email_scanner.application.scan_service import (  # noqa: PLC0415
            EmailScannerService,
        )
        from tools.email_scanner.data.repository import (  # noqa: PLC0415
            EmailScannerRepository,
        )
        from tools.email_scanner.gui.email_scanner_widget import (  # noqa: PLC0415
            EmailScannerWidget,
        )

        service = EmailScannerService(repository=EmailScannerRepository())
        widget = EmailScannerWidget(service=service, parent=parent)
        widget.setMinimumSize(900, 600)
        return widget
