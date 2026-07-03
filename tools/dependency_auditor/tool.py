"""
dependency_auditor.tool — DependencyAuditorTool Plugin-Definition.

Registriert den Dependency-Auditor in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool
from tools.dependency_auditor.gui.dependency_auditor_widget import (
    DependencyAuditorWidget,
)


class DependencyAuditorTool(BaseTool):
    """Plugin-Definition fuer den Dependency-Auditor.

    Attributes:
        name (str): ``"Dependency-Auditor"``.
        icon (str): ``"🔒"``.
        feature_name (str): ``"dependency_auditor"``.
    """

    name = "Dependency-Auditor"
    icon = "inventory_2"
    feature_name = "dependency_auditor"

    def create_widget(self, parent=None) -> DependencyAuditorWidget:
        """Erstellt eine neue DependencyAuditorWidget-Instanz mit DI.

        Baut den vollstaendigen Service-Stack auf:
        PyPIAdvisoryClient → AuditService.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            DependencyAuditorWidget: Die initialisierte Auditor-Ansicht.
        """
        from tools.dependency_auditor.application.audit_service import (
            create_default_audit_service,
        )

        service = create_default_audit_service()
        widget = DependencyAuditorWidget(service=service, parent=parent)
        widget.setMinimumSize(800, 600)
        return widget
