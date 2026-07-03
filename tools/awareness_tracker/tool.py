"""tool —:class:`AwarenessTrackerTool` Plugin-Definition.

Registriert den Awareness-Tracker in der NoRisk-ToolRegistry.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from core.base_tool import BaseTool


class AwarenessTrackerTool(BaseTool):
    """Plugin-Definition fuer den Awareness-Tracker.

    Attributes:
        name: ``"Awareness-Tracker"`` — Sidebar-Label.
        icon: Material-Symbol ``"school"``.
        feature_name: Lizenz-Feature-Key ``awareness_tracker``.
    """

    name = "Awareness-Tracker"
    icon = "school"
    feature_name = "awareness_tracker"

    def create_widget(self, parent=None):
        """Erstellt das Widget und initialisiert die Service-Schicht.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
:class:`AwarenessWidget`-Instanz.
        """
        from tools.awareness_tracker.application.awareness_service import (  # noqa: PLC0415
            AwarenessService,
        )
        from tools.awareness_tracker.gui.awareness_widget import (  # noqa: PLC0415
            AwarenessWidget,
        )

        widget = AwarenessWidget(service=AwarenessService(), parent=parent)
        widget.setMinimumSize(720, 480)
        return widget
