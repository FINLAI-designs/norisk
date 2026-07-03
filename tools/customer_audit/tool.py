"""
customer_assessment.tool — CustomerAuditTool Plugin-Definition.

Registriert das Kunden-Assessment in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool


class CustomerAuditTool(BaseTool):
    """Plugin-Definition für das Kunden-Assessment.

    Attributes:
        name (str): ``"Kunden-Assessment"``.
        icon (str): ``"assignment_ind"``.
        feature_name (str): ``"customer_audit"``.
    """

    name = "Security-Audit"
    icon = "verified_user"
    feature_name = "customer_audit"

    def create_widget(self, parent=None):
        """Erstellt das CustomerAuditWidget mit vollständigem Service-Stack.

 (RUN2-GUI): Repository wird in der application-Schicht
        gebuendelt, die GUI bekommt nur das Service-Buendel.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            CustomerAuditWidget: Die initialisierte Tool-Ansicht.
        """
        from tools.customer_audit.application.services import (
            create_customer_assessment_services,
        )
        from tools.customer_audit.gui.customer_audit_widget import (
            CustomerAuditWidget,
        )

        services = create_customer_assessment_services()
        widget = CustomerAuditWidget(services=services, parent=parent)
        widget.setMinimumSize(700, 500)
        return widget
