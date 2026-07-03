"""
patch_monitor.tool — PatchMonitorTool Plugin-Definition.

Registriert die Patch-Monitor-Konsole in der NoRisk ToolRegistry
unter der Sidebar-Gruppe "SCANNER & TOOLS".
"""

from __future__ import annotations

from core.base_tool import BaseTool
from tools.patch_monitor.data.upgrade_history_repository import (
    UpgradeHistoryRepository,
)
from tools.patch_monitor.gui.patch_console_widget import PatchConsoleWidget


class PatchMonitorTool(BaseTool):
    """Plugin-Definition fuer die Patch-Monitor-Konsole.

    Attributes:
        name: ``"Patch Monitor"`` — Anzeigetext im Sidebar-Eintrag.
        icon: Material-Symbol ``"system_update_alt"`` (Patch/Update-
            Pfeil-Icon).
        feature_name: leer → ohne Lizenzpruefung verfuegbar.
            Wenn die Free/Pro-Aufteilung steht (intern),
            koennte das auf einen License-Feature-Key gemappt werden.
    """

    name = "Patch Monitor"
    icon = "system_update_alt"
    feature_name = ""

    def create_widget(self, parent=None) -> PatchConsoleWidget:
        """Erstellt das:class:`PatchConsoleWidget`.

        Tool-Registry liefert den parent durch — dort wird der
        Worker-Thread aufgehaengt.

        Args:
            parent: Eltern-Widget (typisch ``QStackedWidget`` o.ae.).

        Returns:
            Das initialisierte Widget.
        """
        # Composition-Root: die data-Schicht wird HIER (nicht in der GUI)
        # verdrahtet und als Factory gereicht (Hex-Vertrag gui!->data). Die
        # Klasse selbst ist die parameterlose Factory (lazy: DB-Open erst beim
        # Oeffnen des Upgrade-Verlaufs).
        widget = PatchConsoleWidget(
            parent=parent,
            upgrade_history_repo_factory=UpgradeHistoryRepository,
        )
        widget.setMinimumSize(900, 620)
        return widget
