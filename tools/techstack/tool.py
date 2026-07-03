"""techstack.tool — TechStackTool Plugin-Definition.

Registriert das Techstack-Tool als eigenständigen Sidebar-Eintrag in
der ToolRegistry. Zuvor war Techstack ein Tab innerhalb von
``cyber_dashboard``; seit 2026-04-20 ein separates Tool.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool
from core.exceptions import ConfigurationError


class TechStackTool(BaseTool):
    """Plugin-Definition für das Techstack-Monitoring-Tool.

    Attributes:
        name (str): ``"Techstack"``.
        icon (str): ``"inventory_2"`` — Asset-Inventory-Metapher.
    """

    name = "Techstack"
    icon = "inventory_2"

    def create_widget(self, parent=None):
        """Erstellt das TechStackWidget mit vollständigem Service-Stack.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            TechStackWidget mit initialisiertem DashboardService.

        Raises:
            RuntimeError: Wenn ein Service-Dependency (NVD-Client, Cache, Repo)
                beim Init scheitert. Wird vom Lazy-Loader abgefangen und als
                ErrorPlaceholderWidget angezeigt.
        """
        from core.logger import get_logger
        from tools.cyber_dashboard.application.dashboard_service import DashboardService
        from tools.cyber_dashboard.application.nvd_service import NvdService
        from tools.cyber_dashboard.application.rss_service import RssService
        from tools.cyber_dashboard.application.techstack_sync_service import (
            TechStackSyncService,
        )
        from tools.cyber_dashboard.data.cache_repository import CacheRepository
        from tools.cyber_dashboard.data.cisa_kev_client import CisaKevClient
        from tools.cyber_dashboard.data.techstack_repository import TechStackRepository
        from tools.techstack.gui.techstack_widget import TechStackWidget

        log = get_logger(__name__)

        try:
            service = DashboardService(
                rss=RssService(),
                cache=CacheRepository(),
                nvd=NvdService(),
                techstack=TechStackRepository(),
                kev_client=CisaKevClient(),
                # Sync-Quelle für „Aus System-Scan & Patch-Monitor übernehmen".
                techstack_sync=TechStackSyncService(),
            )
        except Exception as exc:  # noqa: BLE001 — Service-Init ist Dependency-Grenze
            log.error("TechStack Service-Init fehlgeschlagen: %s", exc, exc_info=True)
            raise ConfigurationError(f"Service-Initialisierung fehlgeschlagen: {exc}") from exc

        widget = TechStackWidget(service, parent)
        widget.setMinimumSize(700, 500)
        return widget
