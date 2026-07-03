"""tool —:class:`Nis2IncidentsTool` Plugin-Definition.

Registriert den NIS2-Incident-Tracker als eigenstaendigen Tool-Tab.

Schichtzugehoerigkeit: tool-Level (kein domain/data/gui-Import).

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from core.base_tool import BaseTool


class Nis2IncidentsTool(BaseTool):
    """Plugin-Definition fuer den NIS2-Incident-Tracker.

    Lizenz-Reuse: ``feature_name = "customer_audit"`` — wer eine Lizenz
    fuer den Customer-Audit hat, hat damit automatisch auch den NIS2-
    Incident-Tracker. Beide Funktionen teilen sich die Datenmodelle und
    Audit-Compliance-Logik.
    """

    name = "NIS2-Incidents"
    icon = "warning"
    feature_name = "customer_audit"

    def create_widget(self, parent=None):  # noqa: ANN001
        from tools.customer_audit.application.nis2_incident_service import (  # noqa: PLC0415
            Nis2IncidentService,
        )
        from tools.nis2_incidents.gui.nis2_incidents_widget import (  # noqa: PLC0415
            Nis2IncidentsWidget,
        )

        widget = Nis2IncidentsWidget(
            service=Nis2IncidentService(), parent=parent
        )
        widget.setMinimumSize(960, 600)
        return widget
