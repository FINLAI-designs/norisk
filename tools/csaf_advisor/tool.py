"""
csaf_advisor.tool — CsafAdvisorTool Plugin-Definition.

Registriert den CSAF Advisory-Monitor in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool


class CsafAdvisorTool(BaseTool):
    """Plugin-Definition für den CSAF Advisory-Monitor.

    Attributes:
        name (str): ``"Advisory-Monitor"``.
        icon (str): ``"security_update_warning"``.
        feature_name (str): ``"csaf_advisor"``.
    """

    name = "Advisory-Monitor"
    icon = "security_update_warning"
    feature_name = "csaf_advisor"

    def create_widget(self, parent=None):
        """Erstellt eine neue CsafAdvisorWidget-Instanz mit DI.

        Baut den vollständigen Service-Stack auf:
        AdvisoryRepository → AdvisoryService.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            CsafAdvisorWidget: Die initialisierte Advisory-Monitor-Ansicht.
        """
        # Widget-Import lazy (analog file_scanner) — so zieht die
        # Tool-Registrierung nicht schon beim Modul-Load die cross-tool
        # GUI-/application-Kanten (z.B. security_scoring) in den Prozess.
        from tools.csaf_advisor.application.advisory_service import AdvisoryService
        from tools.csaf_advisor.data.advisory_repository_impl import AdvisoryRepository
        from tools.csaf_advisor.gui.csaf_advisor_widget import CsafAdvisorWidget
        from tools.techstack.tool import TechStackTool

        repo = AdvisoryRepository()
        service = AdvisoryService(repository=repo)
        # Der frühere read-only „Inventar"-Tab wird durch das echte
        # Tech-Stack-Tool ersetzt (der eigenständige Sidebar-Eintrag entfällt).
        # Die Factory wird injiziert, damit die GUI-Schicht kein Tool-Plugin
        # importiert (gleiche DI wie der file_scanner-Container, gui↛tool).
        widget = CsafAdvisorWidget(
            service=service,
            techstack_factory=lambda p: TechStackTool().create_widget(p),
            parent=parent,
        )
        widget.setMinimumSize(900, 600)
        return widget
