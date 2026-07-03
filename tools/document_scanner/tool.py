"""tool — DocumentScannerTool Plugin-Definition.

Registriert den Document-Scanner in der NoRisk-ToolRegistry.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.base_tool import BaseTool


class DocumentScannerTool(BaseTool):
    """Plugin-Definition fuer den Document Scanner.

    Attributes:
        name: ``"Dokument-Scanner"``.
        icon: Material-Symbol ``"description"``.
        feature_name: Lizenz-Feature-Key (Reservierung, Iter 4
            aktiviert die Lizenz-Gate-Logik).
    """

    name = "Dokument-Scanner"
    icon = "description"
    feature_name = "document_scanner"

    def create_widget(self, parent=None):
        """Erstellt das Widget und initialisiert die Service-Schicht.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
:class:`DocumentScannerWidget`-Instanz.
        """
        from tools.document_scanner.application.scanner_service import (  # noqa: PLC0415
            DocumentScannerService,
        )
        from tools.document_scanner.gui.document_scanner_widget import (  # noqa: PLC0415
            DocumentScannerWidget,
        )

        widget = DocumentScannerWidget(service=DocumentScannerService(), parent=parent)
        widget.setMinimumSize(720, 480)
        return widget
