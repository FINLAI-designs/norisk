"""
test_heatmap_klick — Regressions-Guard: Heatmap ist rein informativ.

Heatmap-b2: Der frühere Heatmap-Tageszellen-Deep-Link
(``open_with_filter(tool_key, day)`` → ``set_day_filter``) war toter Code —
keine Tool-Seite implementierte ``set_day_filter``. Er wurde end-to-end
entfernt. Diese Tests stellen sicher, dass der Klick-Contract weg bleibt und
die Heatmap trotzdem rendert.

Author: Patrick Riederich
Version: 0.3 / Heatmap-b2)
"""

from __future__ import annotations

from datetime import datetime

import pytest

from tools.norisk_dashboard.domain.models import ScanEntry, ScanStatus


def test_heatmap_widget_hat_keinen_klick_contract() -> None:
    from tools.norisk_dashboard.gui.heatmap_widget import HeatmapWidget

    # Kein cell_clicked-Signal mehr, kein eigener mousePressEvent-Override.
    assert not hasattr(HeatmapWidget, "cell_clicked")
    assert "mousePressEvent" not in HeatmapWidget.__dict__


def test_section_und_container_haben_keinen_scan_klick_contract() -> None:
    from tools.norisk_dashboard.gui.section_cves_scans import (
        CvesScansSection,
        _ScanHeatmapContainer,
    )

    assert not hasattr(CvesScansSection, "scan_cell_clicked")
    assert not hasattr(_ScanHeatmapContainer, "cell_clicked")


def test_dashboard_widget_hat_keinen_scan_klick_slot() -> None:
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    assert not hasattr(NoRiskDashboardWidget, "_on_scan_cell_clicked")


@pytest.mark.gui
def test_heatmap_rendert_weiterhin_informativ(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.heatmap_widget import HeatmapWidget

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    w = HeatmapWidget()
    qtbot.addWidget(w)
    w.update_data([ScanEntry("sys", "System-Scanner", today, ScanStatus.OK)], days=7)
    w.resize(800, 200)
    w.show()
    qtbot.waitExposed(w)
    # Rendert ohne Klick-Contract; die Höhe wächst mit den Zeilen.
    assert w.minimumHeight() > 0
