"""Tests fuer RadarChart und polar_to_cartesian."""

from __future__ import annotations

import math

import pytest
from PySide6.QtCore import QPointF
from PySide6.QtGui import QColor

from core.widgets.charts.radar_chart import (
    RadarAxis,
    RadarChart,
    RadarSeries,
    polar_to_cartesian,
)

pytestmark = pytest.mark.gui


class TestPolarToCartesian:
    """Pure-Function-Tests fuer Achsen→Punkte-Mapping."""

    def test_empty_axes_returns_empty(self):
        assert polar_to_cartesian([], [], QPointF(0, 0), 100) == []

    def test_single_axis_at_top(self):
        axes = [RadarAxis("A", max_value=100)]
        center = QPointF(100, 100)
        points = polar_to_cartesian([100], axes, center, 50)
        assert len(points) == 1
        # 12-Uhr: x=center.x, y=center.y - radius
        assert points[0].x() == pytest.approx(100.0)
        assert points[0].y() == pytest.approx(50.0)

    def test_value_clamps_to_max(self):
        axes = [RadarAxis("A", max_value=100)]
        center = QPointF(0, 0)
        points = polar_to_cartesian([250], axes, center, 100)
        # Geclamped auf 100 = voller Radius
        dist = math.hypot(points[0].x(), points[0].y())
        assert dist == pytest.approx(100.0)

    def test_negative_value_clamps_to_zero(self):
        axes = [RadarAxis("A", max_value=100)]
        center = QPointF(50, 50)
        points = polar_to_cartesian([-10], axes, center, 100)
        # Geclamped auf 0 = Center
        assert points[0].x() == pytest.approx(50.0)
        assert points[0].y() == pytest.approx(50.0)

    def test_missing_values_treated_as_zero(self):
        axes = [RadarAxis("A"), RadarAxis("B"), RadarAxis("C")]
        center = QPointF(0, 0)
        # Nur ein Wert geliefert, B und C werden als 0 behandelt
        points = polar_to_cartesian([50], axes, center, 100)
        assert len(points) == 3
        # B und C sitzen auf Center
        assert points[1].x() == pytest.approx(0.0)
        assert points[1].y() == pytest.approx(0.0)

    def test_four_axes_distributed_at_cardinal_points(self):
        axes = [RadarAxis(f"A{i}", max_value=100) for i in range(4)]
        center = QPointF(0, 0)
        points = polar_to_cartesian([100, 100, 100, 100], axes, center, 100)
        # Achse 0 = 12-Uhr, Achse 1 = 3-Uhr, Achse 2 = 6-Uhr, Achse 3 = 9-Uhr
        assert points[0].x() == pytest.approx(0.0)
        assert points[0].y() == pytest.approx(-100.0)
        assert points[1].x() == pytest.approx(100.0, abs=1e-9)
        assert points[1].y() == pytest.approx(0.0, abs=1e-9)
        assert points[2].x() == pytest.approx(0.0, abs=1e-9)
        assert points[2].y() == pytest.approx(100.0, abs=1e-9)
        assert points[3].x() == pytest.approx(-100.0, abs=1e-9)
        assert points[3].y() == pytest.approx(0.0, abs=1e-9)


def test_empty_axes_renders_keine_achsen(app, qtbot):
    chart = RadarChart()
    qtbot.addWidget(chart)
    chart.set_axes([])
    chart.resize(360, 360)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()
    assert chart._axes == []


def test_set_axes_and_series_stored(app, qtbot):
    chart = RadarChart()
    qtbot.addWidget(chart)
    axes = [RadarAxis("X"), RadarAxis("Y"), RadarAxis("Z")]
    series = [RadarSeries("S1", (10, 20, 30))]
    chart.set_axes(axes)
    chart.set_series(series)
    assert len(chart._axes) == 3
    assert len(chart._series) == 1
    assert chart._series[0].values == (10, 20, 30)


def test_renders_with_two_series_without_crash(app, qtbot):
    chart = RadarChart()
    qtbot.addWidget(chart)
    chart.set_axes([RadarAxis(f"A{i}") for i in range(5)])
    chart.set_series(
        [
            RadarSeries("Aktuell", (78, 64, 71, 58, 49)),
            RadarSeries(
                "Ziel",
                (90, 85, 85, 80, 75),
                color=QColor(200, 200, 200),
                fill_opacity=0.0,
                dashed=True,
            ),
        ]
    )
    chart.resize(420, 420)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()


def test_short_series_values_renders_without_crash(app, qtbot):
    """Serie mit weniger Werten als Achsen darf nicht crashen."""
    chart = RadarChart()
    qtbot.addWidget(chart)
    chart.set_axes([RadarAxis(f"A{i}") for i in range(5)])
    chart.set_series([RadarSeries("Partial", (50, 75))])  # nur 2 von 5
    chart.resize(360, 360)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()


def test_zero_max_value_axis_does_not_divide_by_zero(app, qtbot):
    """Achse mit max_value=0 darf nicht ZeroDivisionError werfen."""
    chart = RadarChart()
    qtbot.addWidget(chart)
    chart.set_axes([RadarAxis("Zero", max_value=0)])
    chart.set_series([RadarSeries("S", (5,))])
    chart.resize(300, 300)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()
