"""
norisk_dashboard — NoRisk Gesamt-Dashboard.

Modulbasiertes Dashboard mit klappbaren Sektionen:
- Sektion 1: Was hat sich geändert (Zeitraum-basiert)
- Sektion 2: Score kompakt (KPI-Kachel + Trend)
- Sektion 3: CVE-Liste + Scan-Status (zwei Spalten, Heatmap)
- Sektion 4: Score-Aufschlüsselung + Trend (Phase 2)
- Sektion 5: Organisatorische Sicherheit (Phase 2)

Phase 1: Skelett + Sektionen 1-3 mit QPainter-Heatmap.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from .tool import NoRiskDashboardTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["NoRiskDashboardTool"]
