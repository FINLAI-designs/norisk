"""Tests fuer DonutChart und compute_arc_spans.

Pure-Function-Tests fuer das Wert→Winkel-Mapping, Widget-Tests fuer
Empty-State, Segment-Click-Signal, Center-Text und Inner-Radius-Clamping.
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor

from core.widgets.charts.donut_chart import (
    DonutChart,
    DonutSegment,
    compute_arc_spans,
)

pytestmark = pytest.mark.gui


class TestComputeArcSpans:
    """Pure-Function-Tests fuer das Wert→(start_deg, span_deg)-Mapping."""

    def test_empty_returns_empty(self):
        assert compute_arc_spans([]) == []

    def test_zero_sum_returns_empty(self):
        assert compute_arc_spans([0.0, 0.0, 0.0]) == []

    def test_negative_values_clamped_to_zero(self):
        # Nur das positive Segment ueberlebt → 360 Grad
        spans = compute_arc_spans([-5.0, 0.0, 10.0])
        assert len(spans) == 3
        # Erstes/zweites Segment 0 Grad span
        assert spans[0][1] == 0.0
        assert spans[1][1] == 0.0
        assert spans[2][1] == pytest.approx(-360.0)

    def test_equal_values_split_evenly(self):
        spans = compute_arc_spans([1.0, 1.0, 1.0, 1.0])
        assert len(spans) == 4
        for _, span in spans:
            assert span == pytest.approx(-90.0)

    def test_proportions_sum_to_360_degrees(self):
        spans = compute_arc_spans([2, 3, 5])
        total = sum(-span for _, span in spans)
        assert total == pytest.approx(360.0)

    def test_starts_at_12_uhr_default(self):
        spans = compute_arc_spans([1.0])
        assert spans[0][0] == pytest.approx(90.0)

    def test_custom_start_angle(self):
        spans = compute_arc_spans([1.0, 1.0], start_angle_deg=0.0)
        assert spans[0][0] == pytest.approx(0.0)
        assert spans[1][0] == pytest.approx(-180.0)


def test_empty_segments_renders_keine_daten(app, qtbot):
    chart = DonutChart()
    qtbot.addWidget(chart)
    chart.set_segments([])
    chart.resize(300, 300)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()
    assert chart._segments == []


def test_zero_value_segments_renders_keine_daten(app, qtbot):
    chart = DonutChart()
    qtbot.addWidget(chart)
    chart.set_segments(
        [DonutSegment("A", 0), DonutSegment("B", 0)]
    )
    chart.resize(300, 300)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()
    # Kein Crash, _segments wurden gespeichert
    assert len(chart._segments) == 2


def test_segment_clicked_signal_at_12_uhr(app, qtbot):
    """Klick knapp oberhalb der Mitte (12-Uhr) trifft das erste Segment."""
    chart = DonutChart()
    qtbot.addWidget(chart)
    # Vier gleichgrosse Segmente: 90 Grad pro Segment, Start 12-Uhr CCW
    chart.set_segments(
        [
            DonutSegment("N", 1),
            DonutSegment("W", 1),
            DonutSegment("S", 1),
            DonutSegment("E", 1),
        ]
    )
    chart.resize(400, 400)
    chart.show()
    qtbot.waitExposed(chart)

    # In Qt: positiv = CCW. Start 90 Grad, span -90 Grad → erstes Segment
    # geht von 90 Grad → 0 Grad (rechte obere Viertel). Klick bei (310, 130)
    # = rechts ueber Mitte (200,200) → erste Quadrant → Segment 0.
    outer = chart._outer_rect()
    center = outer.center()
    radius = outer.width() / 2.0
    mid_r = radius * (1.0 + chart._inner_ratio) / 2.0
    # 45 Grad oberhalb der x-Achse → Segment 0 (90..0 Grad-Range)
    import math

    target_x = int(center.x() + mid_r * math.cos(math.radians(45)))
    target_y = int(center.y() - mid_r * math.sin(math.radians(45)))

    with qtbot.waitSignal(chart.segment_clicked, timeout=1000) as blocker:
        qtbot.mouseClick(
            chart,
            Qt.MouseButton.LeftButton,
            pos=QPoint(target_x, target_y),
        )
    assert blocker.args == [0]


def test_click_in_donut_hole_emits_nothing(app, qtbot):
    """Klick in der Mitte (innerhalb Loch) loest kein Signal aus."""
    chart = DonutChart()
    qtbot.addWidget(chart)
    chart.set_segments([DonutSegment("A", 1), DonutSegment("B", 1)])
    chart.resize(400, 400)
    chart.show()
    qtbot.waitExposed(chart)

    center = chart._outer_rect().center()
    with qtbot.assertNotEmitted(chart.segment_clicked, wait=200):
        qtbot.mouseClick(
            chart,
            Qt.MouseButton.LeftButton,
            pos=QPoint(int(center.x()), int(center.y())),
        )


def test_set_center_text_stored(app, qtbot):
    chart = DonutChart()
    qtbot.addWidget(chart)
    chart.set_center_text("87/100")
    assert chart._center_text == "87/100"


def test_set_inner_radius_clamps(app, qtbot):
    chart = DonutChart()
    qtbot.addWidget(chart)
    chart.set_inner_radius_ratio(-0.5)
    assert chart._inner_ratio == 0.0
    chart.set_inner_radius_ratio(1.5)
    assert chart._inner_ratio == 0.95


def test_explicit_color_overrides_palette(app, qtbot):
    chart = DonutChart()
    qtbot.addWidget(chart)
    explicit = QColor(10, 20, 30)
    chart.set_segments(
        [DonutSegment("A", 1, color=explicit), DonutSegment("B", 1)]
    )
    assert chart._color_for(0, chart._segments[0]).red() == 10
    # Zweites Segment nutzt Palette (rotierend)
    palette_color = chart._color_for(1, chart._segments[1])
    assert isinstance(palette_color, QColor)
