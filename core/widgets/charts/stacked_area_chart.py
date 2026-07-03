"""StackedAreaChart — Stacked-Area-Diagramm fuer Zeitreihen (PyQtGraph).

Use-Cases im NoRisk-Sprint:
- Light-SIEM 7-Tage-Stacked-Area (CRITICAL/ERROR/WARN/INFO ueber Zeit)
- Bandwidth-/Traffic-Schichten ueber den Tag

Hexagonal-konform: nutzt ``PySide6``, ``core.theme`` und ``pyqtgraph`` —
keine Domain-Imports.

PyQtGraph wurde dem Stack hinzugefuegt, weil Live-Daten mit
sub-Sekunden-Updates fuer QPainter ungeeignet sind. Statisches Rendering
weiter via QPainter.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import pyqtgraph as pg
from PySide6.QtCore import QSize
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget

from core import theme


@dataclass(frozen=True)
class StackedLayer:
    """Eine berechnete Schicht eines Stacked-Area-Charts.

    Attributes:
        label: Anzeigename der Schicht (z.B. ``"CRITICAL"``).
        bottom: Untere Y-Werte (= top der darunter liegenden Schicht).
        top: Obere Y-Werte (= bottom + eigene values).
    """

    label: str
    bottom: tuple[float, ...]
    top: tuple[float, ...]


def compute_stacked_layers(
    series: Mapping[str, Sequence[float]],
    sample_count: int,
) -> list[StackedLayer]:
    """Berechnet die Bottom-/Top-Kanten fuer jede Schicht.

    Args:
        series: Mapping ``label → values`` (eine Reihe pro Schicht).
            Reihenfolge bestimmt Stacking-Order (erste = unten).
        sample_count: Erwartete Laenge jeder Werte-Sequenz. Kuerzere Reihen
            werden mit 0 aufgefuellt, laengere abgeschnitten.

    Returns:
        Liste von ``StackedLayer`` in der gleichen Reihenfolge wie das Mapping.
        Bei leerem ``series`` oder ``sample_count == 0`` leere Liste.
    """
    if not series or sample_count <= 0:
        return []
    cumulative = [0.0] * sample_count
    layers: list[StackedLayer] = []
    for label, raw_values in series.items():
        clamped = [max(0.0, float(raw_values[i])) if i < len(raw_values) else 0.0
                   for i in range(sample_count)]
        bottom = tuple(cumulative)
        top = tuple(cumulative[i] + clamped[i] for i in range(sample_count))
        layers.append(StackedLayer(label=label, bottom=bottom, top=top))
        cumulative = list(top)
    return layers


def _default_palette() -> tuple[QColor, ...]:
    """Severity-Standard-Palette (rotierend bei mehr Schichten)."""
    return (
        QColor(theme.SEVERITY_SIGNAL_CRITICAL),
        QColor(theme.SEVERITY_SIGNAL_HIGH),
        QColor(theme.SEVERITY_SIGNAL_MEDIUM),
        QColor(theme.SEVERITY_SIGNAL_LOW),
        QColor(theme.SEVERITY_SIGNAL_OK),
        QColor(theme.SEVERITY_SIGNAL_INFO),
    )


class StackedAreaChart(QWidget):
    """Stacked-Area-Diagramm fuer Zeitreihen (PyQtGraph-basiert).

    Pflicht-API:
        -:meth:`set_data` — ``timestamps`` + ``series``-Dict.
        -:meth:`set_palette` — ueberschreibt die Default-Severity-Palette.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._timestamps: list[float] = []
        self._series: dict[str, tuple[float, ...]] = {}
        self._palette: tuple[QColor, ...] = _default_palette()

        c = theme.get()
        pg.setConfigOption("background", c.BG_MAIN)
        pg.setConfigOption("foreground", c.TEXT_MAIN)
        pg.setConfigOption("antialias", True)

        self._plot = pg.PlotWidget(parent=self, axisItems={"bottom": pg.DateAxisItem()})
        self._plot.setBackground(c.BG_MAIN)
        self._plot.showGrid(x=True, y=True, alpha=0.2)
        self._plot.getPlotItem().getViewBox().setMouseEnabled(x=False, y=False)
        self._legend = self._plot.addLegend(offset=(10, 10))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._plot)

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setMinimumSize(360, 240)

    def set_palette(self, colors: Sequence[QColor]) -> None:
        """Setzt eine eigene Farb-Palette (rotierend bei vielen Schichten)."""
        if not colors:
            raise ValueError("colors darf nicht leer sein")
        self._palette = tuple(QColor(c) for c in colors)
        self._refresh()

    def set_data(
        self,
        timestamps: Sequence[float],
        series: Mapping[str, Sequence[float]],
    ) -> None:
        """Aktualisiert Zeitachse und Schichten.

        Args:
            timestamps: Unix-Epoch-Sekunden (kompatibel mit DateAxisItem).
                Muss aufsteigend sortiert sein.
            series: Mapping ``label → values``. Alle Werte-Sequenzen sollten
                die gleiche Laenge wie ``timestamps`` haben; ungleiche
                Laengen werden mit 0 aufgefuellt bzw. abgeschnitten.
        """
        self._timestamps = [float(t) for t in timestamps]
        self._series = {label: tuple(float(v) for v in vals) for label, vals in series.items()}
        self._refresh()

    def _refresh(self) -> None:
        plot_item = self._plot.getPlotItem()
        plot_item.clear()
        # Legende manuell zuruecksetzen: addLegend baut sie sonst nicht neu.
        self._legend.clear()
        if not self._timestamps or not self._series:
            return
        layers = compute_stacked_layers(self._series, len(self._timestamps))
        x = list(self._timestamps)
        max_top = 0.0
        for idx, layer in enumerate(layers):
            color = self._palette[idx % len(self._palette)]
            pen = pg.mkPen(color=color, width=2)
            fill = QColor(color)
            fill.setAlphaF(0.45)
            bottom_curve = plot_item.plot(x, list(layer.bottom), pen=None)
            top_curve = plot_item.plot(x, list(layer.top), pen=pen, name=layer.label)
            fill_item = pg.FillBetweenItem(bottom_curve, top_curve, brush=fill)
            plot_item.addItem(fill_item)
            if layer.top:
                max_top = max(max_top, max(layer.top))
        plot_item.getViewBox().setXRange(x[0], x[-1], padding=0.02)
        plot_item.getViewBox().setYRange(0.0, max_top * 1.05 if max_top > 0 else 1.0)

    def sizeHint(self) -> QSize:
        return QSize(520, 280)


def _build_light_siem_demo() -> StackedAreaChart:
    """Demo-Helper: 7 Tage Severity-Counts ueber Zeit."""
    chart = StackedAreaChart()
    from datetime import datetime, timedelta

    now = datetime.now()
    timestamps = [(now - timedelta(days=6 - i)).timestamp() for i in range(7)]
    series = {
        "CRITICAL": (1, 0, 2, 1, 0, 3, 1),
        "HIGH":     (4, 6, 3, 5, 7, 4, 6),
        "MEDIUM":   (12, 9, 11, 14, 10, 13, 8),
        "LOW":      (24, 31, 28, 19, 33, 27, 22),
        "INFO":     (88, 102, 95, 110, 87, 99, 116),
    }
    chart.set_data(timestamps, series)
    chart.resize(720, 320)
    return chart


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_light_siem_demo()
    demo.setWindowTitle("StackedAreaChart Demo — Light-SIEM 7 Tage")
    demo.show()
    sys.exit(qapp.exec())
