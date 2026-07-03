"""RadarChart — generisches Spinnen-/Radardiagramm mit QPainter.

Use-Cases im NoRisk-Sprint:
- Security-Score: 5 Achsen (Identify/Protect/Detect/Respond/Recover) mit
  zwei Serien ("Aktuell" vs "Ziel").
- Vendor-Risk-Profile mit mehreren Vergleichs-Polygonen.

Hexagonal-konform: nutzt nur ``PySide6`` und ``core.theme`` — keine
Domain-Imports.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme

_PADDING = 24
_RING_COUNT = 4
_LEGEND_HEIGHT = 28
_LEGEND_SWATCH = 12


@dataclass(frozen=True)
class RadarAxis:
    """Eine Achse des Radar-Charts.

    Attributes:
        label: Achsen-Name (z.B. ``"Identify"``).
        max_value: Skalen-Obergrenze (z.B. 100). Werte > max werden
            visuell auf den Rand geclampt.
    """

    label: str
    max_value: float = 100.0


@dataclass(frozen=True)
class RadarSeries:
    """Eine Serie (= ein Polygon) im Radar-Chart.

    Attributes:
        name: Anzeigename fuer die Legende.
        values: Sequenz mit einem Wert pro Achse, gleiche Reihenfolge wie
            ``axes``. Fehlende Werte werden als 0 behandelt.
        color: Polygon-/Stroke-Farbe. Wenn None, wird DARK_ACCENT verwendet.
        fill_opacity: Alpha-Anteil der Fuell-Flaeche ``[0, 1]``. 0 = nur Stroke.
        dashed: Wenn True, wird die Stroke gestrichelt gerendert
            (typisch fuer "Ziel"-Serien).
    """

    name: str
    values: tuple[float, ...]
    color: QColor | None = None
    fill_opacity: float = 0.25
    dashed: bool = False


def polar_to_cartesian(
    values: Sequence[float],
    axes: Sequence[RadarAxis],
    center: QPointF,
    radius: float,
) -> list[QPointF]:
    """Berechnet die Polygon-Punkte fuer eine Radar-Serie.

    Args:
        values: Werte pro Achse. Werte ueber ``axis.max_value`` werden auf
            den Rand geclampt; negative Werte auf 0.
        axes: Achsen-Liste (Laenge >= 1). Bestimmt Anzahl Speichen und
            Skalierung pro Achse.
        center: Mittelpunkt des Radar-Kreises (Widget-Koordinaten).
        radius: Aussenradius in Pixeln.

    Returns:
        Liste mit ``len(axes)`` QPointF-Punkten. Bei Werte-Listen kuerzer
        als ``axes`` werden fehlende Werte als 0 ergaenzt.
    """
    n = len(axes)
    if n == 0:
        return []
    angle_step = 2 * math.pi / n
    points: list[QPointF] = []
    for i in range(n):
        raw = values[i] if i < len(values) else 0.0
        axis = axes[i]
        clamped = max(0.0, min(float(raw), axis.max_value))
        ratio = clamped / axis.max_value if axis.max_value > 0 else 0.0
        # Start bei 12-Uhr (90 Grad), CW (negative dy nach oben)
        angle = -math.pi / 2 + i * angle_step
        x = center.x() + radius * ratio * math.cos(angle)
        y = center.y() + radius * ratio * math.sin(angle)
        points.append(QPointF(x, y))
    return points


@dataclass
class _LegendItem:
    """Interner Bookkeeper fuer Legende-Rendering."""

    name: str
    color: QColor
    dashed: bool = field(default=False)


class RadarChart(QWidget):
    """Generisches Radar-/Spinnendiagramm mit QPainter-Rendering.

    Pflicht-API:
        -:meth:`set_axes` — Liste der RadarAxis.
        -:meth:`set_series` — Liste der RadarSeries (typisch 1-3).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._axes: list[RadarAxis] = []
        self._series: list[RadarSeries] = []

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setMinimumSize(280, 280)

    def set_axes(self, axes: Sequence[RadarAxis]) -> None:
        """Aktualisiert die Achsen-Liste und triggert Repaint."""
        self._axes = list(axes)
        self.update()

    def set_series(self, series: Sequence[RadarSeries]) -> None:
        """Aktualisiert die Serien-Liste und triggert Repaint."""
        self._series = list(series)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        if not self._axes:
            painter.setPen(QColor(c.TEXT_DIM))
            font = QFont()
            font.setPointSize(theme.FONT_SIZE_BODY)
            painter.setFont(font)
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "Keine Achsen",
            )
            painter.end()
            return

        center, radius = self._chart_geometry()

        self._paint_grid(painter, center, radius)
        self._paint_axis_labels(painter, center, radius)
        self._paint_series(painter, center, radius)
        self._paint_legend(painter)

        painter.end()

    def _chart_geometry(self) -> tuple[QPointF, float]:
        available_h = self.height() - _LEGEND_HEIGHT - 2 * _PADDING
        available_w = self.width() - 2 * _PADDING
        size = max(60, min(available_w, available_h))
        cx = self.width() / 2.0
        cy = _PADDING + size / 2.0
        return QPointF(cx, cy), size / 2.0

    def _paint_grid(self, painter: QPainter, center: QPointF, radius: float) -> None:
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(theme.DARK_BORDER), 1))
        # Konzentrische Polygone
        for ring in range(1, _RING_COUNT + 1):
            polygon = QPolygonF(
                polar_to_cartesian(
                    [axis.max_value * ring / _RING_COUNT for axis in self._axes],
                    self._axes,
                    center,
                    radius,
                )
            )
            painter.drawPolygon(polygon)
        # Speichen
        n = len(self._axes)
        for i in range(n):
            angle = -math.pi / 2 + i * (2 * math.pi / n)
            tip = QPointF(
                center.x() + radius * math.cos(angle),
                center.y() + radius * math.sin(angle),
            )
            painter.drawLine(center, tip)

    def _paint_axis_labels(
        self, painter: QPainter, center: QPointF, radius: float
    ) -> None:
        font = QFont()
        font.setPointSize(theme.FONT_SIZE_BODY_SM)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor(theme.DARK_TEXT_PRIMARY))
        n = len(self._axes)
        for i, axis in enumerate(self._axes):
            angle = -math.pi / 2 + i * (2 * math.pi / n)
            x = center.x() + (radius + 16) * math.cos(angle)
            y = center.y() + (radius + 16) * math.sin(angle)
            rect = QRectF(x - 60, y - 10, 120, 20)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, axis.label)

    def _paint_series(
        self, painter: QPainter, center: QPointF, radius: float
    ) -> None:
        for series in self._series:
            color = QColor(series.color) if series.color else QColor(theme.DARK_ACCENT)
            polygon = QPolygonF(
                polar_to_cartesian(series.values, self._axes, center, radius)
            )
            if series.fill_opacity > 0:
                fill = QColor(color)
                fill.setAlphaF(max(0.0, min(1.0, series.fill_opacity)))
                path = QPainterPath()
                path.addPolygon(polygon)
                path.closeSubpath()
                painter.fillPath(path, fill)
            pen_style = Qt.PenStyle.DashLine if series.dashed else Qt.PenStyle.SolidLine
            painter.setPen(QPen(color, 2, pen_style))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPolygon(polygon)
            # Eckpunkte als kleine Kreise
            painter.setBrush(color)
            painter.setPen(QPen(color, 1))
            for pt in polygon:
                painter.drawEllipse(pt, 3, 3)

    def _paint_legend(self, painter: QPainter) -> None:
        if not self._series:
            return
        font = QFont()
        font.setPointSize(theme.FONT_SIZE_CAPTION)
        painter.setFont(font)
        y = self.height() - _LEGEND_HEIGHT + 4
        x = _PADDING
        for series in self._series:
            color = QColor(series.color) if series.color else QColor(theme.DARK_ACCENT)
            painter.setBrush(color)
            pen_style = Qt.PenStyle.DashLine if series.dashed else Qt.PenStyle.SolidLine
            painter.setPen(QPen(color, 2, pen_style))
            painter.drawLine(
                int(x),
                int(y + _LEGEND_SWATCH / 2),
                int(x + _LEGEND_SWATCH * 2),
                int(y + _LEGEND_SWATCH / 2),
            )
            painter.setPen(QColor(theme.DARK_TEXT_PRIMARY))
            painter.drawText(
                QRectF(x + _LEGEND_SWATCH * 2 + 6, y, 180, _LEGEND_SWATCH + 4),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                series.name,
            )
            x += _LEGEND_SWATCH * 2 + 6 + 140

    def sizeHint(self) -> QSize:
        return QSize(360, 360)


def _build_nist_csf_demo() -> RadarChart:
    """Demo-Helper: NIST CSF 5-Achsen mit Aktuell/Ziel-Serien."""
    chart = RadarChart()
    axes = [
        RadarAxis("Identify"),
        RadarAxis("Protect"),
        RadarAxis("Detect"),
        RadarAxis("Respond"),
        RadarAxis("Recover"),
    ]
    chart.set_axes(axes)
    chart.set_series(
        [
            RadarSeries(
                "Aktuell",
                values=(78, 64, 71, 58, 49),
                color=QColor(theme.DARK_ACCENT),
                fill_opacity=0.25,
            ),
            RadarSeries(
                "Ziel",
                values=(90, 85, 85, 80, 75),
                color=QColor(theme.DARK_TEXT_SECONDARY),
                fill_opacity=0.0,
                dashed=True,
            ),
        ]
    )
    chart.resize(420, 420)
    return chart


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_nist_csf_demo()
    demo.setWindowTitle("RadarChart Demo — NIST CSF Aktuell vs Ziel")
    demo.show()
    sys.exit(qapp.exec())
