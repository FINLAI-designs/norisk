"""
system_tuner.tool — SystemTunerTool Plugin-Definition.

Registriert "System optimieren" (Datenschutz/Telemetrie-Advisor) in der
ToolRegistry. Phase 1: read-only Scan + Bewertung. Das Anwenden (Phase 2)
ist davon getrennt und Pro-/Sign-off-gated.

Author: Patrick Riederich
Version: 1.0
"""

from PySide6.QtWidgets import QWidget

from core.base_tool import BaseTool


class SystemTunerTool(BaseTool):
    """Plugin-Definition fuer "System optimieren" (system_tuner).

    Attributes:
        name (str): ``"System optimieren"``.
        icon (str): ``"tune"``.
        feature_name (str): ``"system_tuner"`` (Free: Scan/Score/Dry-Run).
    """

    name = "System optimieren"
    icon = "tune"
    feature_name = "system_tuner"

    def create_widget(self, parent: QWidget | None = None) -> QWidget:
        """Baut den read-only Scan-Stack + das Widget (lazy Importe)."""
        from core.probes.windows_hardening_probe import WindowsHardeningProbe
        from tools.system_tuner.application.catalog_loader import YamlTweakCatalog
        from tools.system_tuner.application.tuner_scan_use_case import (
            TunerScanUseCase,
        )
        from tools.system_tuner.gui.tuner_widget import SystemTunerWidget

        probe = WindowsHardeningProbe()
        catalog = YamlTweakCatalog()
        scan_use_case = TunerScanUseCase(probe=probe, catalog=catalog)

        widget = SystemTunerWidget(scan_use_case=scan_use_case, parent=parent)
        widget.setMinimumSize(700, 500)
        return widget
