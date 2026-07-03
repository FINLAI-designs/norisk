"""tool — PasswordCheckerTool Plugin-Definition.

Registriert den Passwort-Policy-Checker in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.base_tool import BaseTool


class PasswordCheckerTool(BaseTool):
    """Plugin-Definition für den Passwort-Policy-Checker.

    Attributes:
        name (str): ``"Passwort-Checker"``.
        icon (str): ``"password"`` (Google Material Symbol).
        feature_name (str): ``"password_checker"``.
    """

    name = "Passwort-Checker"
    icon = "password"
    feature_name = "password_checker"

    def create_widget(self, parent=None):
        """Erstellt das PasswordCheckerWidget mit Service-Stack.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            PasswordCheckerWidget.
        """
        from tools.password_checker.application.password_service import (  # noqa: PLC0415
            PasswordService,
        )
        from tools.password_checker.data.hibp_client import HIBPClient  # noqa: PLC0415
        from tools.password_checker.gui.password_checker_widget import (  # noqa: PLC0415
            PasswordCheckerWidget,
        )

        service = PasswordService(hibp_client=HIBPClient())
        widget = PasswordCheckerWidget(service=service, parent=parent)
        widget.setMinimumSize(600, 500)
        return widget
