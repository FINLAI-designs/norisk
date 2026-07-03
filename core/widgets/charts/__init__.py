"""Generische, hexagonal-konforme Chart-Widgets fuer FINLAI/NoRisk.

Re-Exportiert die Basis-Widgets fuer komfortable Imports:

    from core.widgets.charts import HeatmapGrid, HeatmapCell

Schicht-Regeln:
- Dieses Paket darf nur ``PySide6``, ``core.theme``, ``numpy`` und ``pyqtgraph``
  importieren — keine Domain-Imports.
- Tool-spezifische Adapter (Domain → Chart-API) liegen in
  ``tools/<tool>/gui/widgets/``.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from core.widgets.charts.donut_chart import (
    DonutChart,
    DonutSegment,
    compute_arc_spans,
)
from core.widgets.charts.heatmap_grid import (
    HeatmapCell,
    HeatmapGrid,
    interpolate_ramp_color,
)
from core.widgets.charts.radar_chart import (
    RadarAxis,
    RadarChart,
    RadarSeries,
    polar_to_cartesian,
)
from core.widgets.charts.stacked_area_chart import (
    StackedAreaChart,
    StackedLayer,
    compute_stacked_layers,
)
from core.widgets.charts.timeline_steps import (
    StepStatus,
    TimelineStep,
    TimelineSteps,
    countdown_color_for,
    format_remaining,
)

__all__ = [
    "DonutChart",
    "DonutSegment",
    "HeatmapCell",
    "HeatmapGrid",
    "RadarAxis",
    "RadarChart",
    "RadarSeries",
    "StackedAreaChart",
    "StackedLayer",
    "StepStatus",
    "TimelineStep",
    "TimelineSteps",
    "compute_arc_spans",
    "compute_stacked_layers",
    "countdown_color_for",
    "format_remaining",
    "interpolate_ramp_color",
    "polar_to_cartesian",
]
