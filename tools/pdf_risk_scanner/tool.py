"""tool — PdfRiskScannerTool Plugin-Definition.

Registriert den PDF-Risk-Scanner in der NoRisk-ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.base_tool import BaseTool


class PdfRiskScannerTool(BaseTool):
    """Plugin-Definition für den PDF-Risk-Scanner.

    Attributes:
        name (str): ``"PDF Risk Scanner"``.
        icon (str): Material-Symbol ``"picture_as_pdf"``.
        feature_name (str): ``"pdf_risk_scanner"``.
    """

    name = "PDF Risk Scanner"
    icon = "picture_as_pdf"
    feature_name = "pdf_risk_scanner"

    def create_widget(self, parent=None):
        """Baut den Service-Stack und gibt das GUI-Widget zurück.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            PdfRiskScannerWidget-Instanz.
        """
        from tools.pdf_risk_scanner.application.scan_service import (  # noqa: PLC0415
            PdfScanService,
        )
        from tools.pdf_risk_scanner.gui.pdf_risk_scanner_widget import (  # noqa: PLC0415
            PdfRiskScannerWidget,
        )

        widget = PdfRiskScannerWidget(service=PdfScanService(), parent=parent)
        widget.setMinimumSize(800, 550)
        return widget
