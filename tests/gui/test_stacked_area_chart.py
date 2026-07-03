"""Tests fuer StackedAreaChart und compute_stacked_layers."""

from __future__ import annotations

import pytest
from PySide6.QtGui import QColor

from core.widgets.charts.stacked_area_chart import (
    StackedAreaChart,
    compute_stacked_layers,
)

pytestmark = pytest.mark.gui


class TestComputeStackedLayers:
    """Pure-Function-Tests fuer die Stack-Berechnung."""

    def test_empty_series_returns_empty(self):
        assert compute_stacked_layers({}, 5) == []

    def test_zero_samples_returns_empty(self):
        assert compute_stacked_layers({"A": [1, 2]}, 0) == []

    def test_single_layer_starts_at_zero(self):
        layers = compute_stacked_layers({"A": [10, 20, 30]}, 3)
        assert len(layers) == 1
        assert layers[0].bottom == (0.0, 0.0, 0.0)
        assert layers[0].top == (10.0, 20.0, 30.0)

    def test_two_layers_stack_cumulatively(self):
        layers = compute_stacked_layers(
            {"A": [1, 2, 3], "B": [10, 20, 30]}, 3
        )
        assert layers[0].label == "A"
        assert layers[0].top == (1.0, 2.0, 3.0)
        assert layers[1].label == "B"
        assert layers[1].bottom == (1.0, 2.0, 3.0)
        assert layers[1].top == (11.0, 22.0, 33.0)

    def test_short_series_padded_with_zero(self):
        layers = compute_stacked_layers({"A": [5]}, 3)
        # Position 1 und 2 mit 0 aufgefuellt
        assert layers[0].top == (5.0, 0.0, 0.0)

    def test_long_series_truncated(self):
        layers = compute_stacked_layers({"A": [1, 2, 3, 4, 5]}, 3)
        assert layers[0].top == (1.0, 2.0, 3.0)

    def test_negative_values_clamped_to_zero(self):
        layers = compute_stacked_layers({"A": [-5, 10, -3]}, 3)
        assert layers[0].top == (0.0, 10.0, 0.0)

    def test_layer_order_preserves_mapping_order(self):
        layers = compute_stacked_layers(
            {"first": [1], "second": [2], "third": [3]}, 1
        )
        assert [layer.label for layer in layers] == ["first", "second", "third"]


def test_empty_data_smoke(app, qtbot):
    chart = StackedAreaChart()
    qtbot.addWidget(chart)
    chart.set_data([], {})
    chart.resize(400, 240)
    chart.show()
    qtbot.waitExposed(chart)


def test_set_data_renders_without_crash(app, qtbot):
    chart = StackedAreaChart()
    qtbot.addWidget(chart)
    timestamps = [1700000000.0 + i * 86400 for i in range(7)]
    series = {
        "CRITICAL": [1, 0, 2, 1, 0, 3, 1],
        "HIGH": [4, 6, 3, 5, 7, 4, 6],
        "MEDIUM": [12, 9, 11, 14, 10, 13, 8],
    }
    chart.set_data(timestamps, series)
    chart.resize(720, 320)
    chart.show()
    qtbot.waitExposed(chart)
    assert chart._timestamps == timestamps
    assert chart._series["CRITICAL"] == (1.0, 0.0, 2.0, 1.0, 0.0, 3.0, 1.0)


def test_set_palette_rejects_empty(app, qtbot):
    chart = StackedAreaChart()
    qtbot.addWidget(chart)
    with pytest.raises(ValueError):
        chart.set_palette([])


def test_set_palette_overrides_default(app, qtbot):
    chart = StackedAreaChart()
    qtbot.addWidget(chart)
    custom = [QColor(10, 20, 30), QColor(40, 50, 60)]
    chart.set_palette(custom)
    assert len(chart._palette) == 2
    assert chart._palette[0].red() == 10


def test_resetting_data_clears_plot(app, qtbot):
    chart = StackedAreaChart()
    qtbot.addWidget(chart)
    chart.set_data([1.0, 2.0, 3.0], {"A": [1, 2, 3]})
    chart.set_data([], {})
    assert chart._timestamps == []
    assert chart._series == {}
