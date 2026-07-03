"""Tool-spezifische Visualisierungs-Widgets fuer den Supply-Chain-Monitor.

Adaptiert die hexagonalen Basis-Charts aus ``core.widgets.charts`` auf die
Supply-Chain-Domain (Vendor, AvvDocument,...).
"""

from tools.supply_chain_monitor.gui.widgets.vendor_risk_heatmap import (
    VendorRiskHeatmap,
)

__all__ = ["VendorRiskHeatmap"]
