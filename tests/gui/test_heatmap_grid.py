"""Tests fuer HeatmapGrid und interpolate_ramp_color.

Pure-Function-Tests fuer den Color-Ramp-Mapper, Widget-Tests fuer das
Heatmap-Gitter (Empty-State, Click-Signal, set_color_ramp, explizite
Zell-Farbe ueberschreibt Ramp).
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor

from core.widgets.charts.heatmap_grid import (
    HeatmapCell,
    HeatmapGrid,
    interpolate_ramp_color,
)

pytestmark = pytest.mark.gui


class TestInterpolateRampColor:
    """Pure-Function-Tests fuer das value→QColor-Mapping."""

    def test_first_stop_at_value_zero(self):
        stops = [(0.0, QColor(255, 0, 0)), (1.0, QColor(0, 0, 255))]
        c = interpolate_ramp_color(0.0, stops)
        assert (c.red(), c.green(), c.blue()) == (255, 0, 0)

    def test_last_stop_at_value_one(self):
        stops = [(0.0, QColor(255, 0, 0)), (1.0, QColor(0, 0, 255))]
        c = interpolate_ramp_color(1.0, stops)
        assert (c.red(), c.green(), c.blue()) == (0, 0, 255)

    def test_middle_interpolates_linearly(self):
        stops = [(0.0, QColor(0, 0, 0)), (1.0, QColor(200, 100, 50))]
        c = interpolate_ramp_color(0.5, stops)
        assert (c.red(), c.green(), c.blue()) == (100, 50, 25)

    def test_value_below_zero_clamps_to_first_stop(self):
        stops = [(0.0, QColor(255, 0, 0)), (1.0, QColor(0, 0, 255))]
        c = interpolate_ramp_color(-1.0, stops)
        assert (c.red(), c.green(), c.blue()) == (255, 0, 0)

    def test_value_above_one_clamps_to_last_stop(self):
        stops = [(0.0, QColor(255, 0, 0)), (1.0, QColor(0, 0, 255))]
        c = interpolate_ramp_color(2.0, stops)
        assert (c.red(), c.green(), c.blue()) == (0, 0, 255)

    def test_three_stop_ramp_picks_correct_segment(self):
        stops = [
            (0.0, QColor(0, 0, 0)),
            (0.5, QColor(100, 100, 100)),
            (1.0, QColor(200, 0, 0)),
        ]
        # In zweitem Segment 0.5→1.0
        c = interpolate_ramp_color(0.75, stops)
        # Mitte zwischen (100,100,100) und (200,0,0)
        assert (c.red(), c.green(), c.blue()) == (150, 50, 50)

    def test_empty_stops_raises(self):
        with pytest.raises(ValueError):
            interpolate_ramp_color(0.5, [])


def test_empty_data_renders_without_crash(app, qtbot):
    """``set_data([], [], {})`` darf nicht crashen und zeigt 'Keine Daten'."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    widget.set_data([], [], {})
    widget.resize(300, 200)
    widget.show()
    qtbot.waitExposed(widget)
    widget.repaint()  # paintEvent erzwingen
    assert widget._rows == []
    assert widget._cols == []


def test_cell_clicked_signal_emits_row_col(app, qtbot):
    """Linker Klick in Zelle (row=2, col=1) emittiert ``cell_clicked(2, 1)``."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    rows = ["r0", "r1", "r2", "r3"]
    cols = ["c0", "c1", "c2", "c3"]
    cells = {
        (r, c): HeatmapCell(value=(r + c) / 6.0)
        for r in range(4)
        for c in range(4)
    }
    widget.set_data(rows, cols, cells)
    widget.resize(500, 400)
    widget.show()
    qtbot.waitExposed(widget)

    cell_w, cell_h, grid_x, grid_y = widget._cell_geometry()
    target_x = int(grid_x + 1 * cell_w + cell_w / 2)
    target_y = int(grid_y + 2 * cell_h + cell_h / 2)

    with qtbot.waitSignal(widget.cell_clicked, timeout=1000) as blocker:
        qtbot.mouseClick(
            widget,
            Qt.MouseButton.LeftButton,
            pos=QPoint(target_x, target_y),
        )
    assert blocker.args == [2, 1]


def test_right_click_does_not_emit_signal(app, qtbot):
    """Nur Linksklick triggert ``cell_clicked`` — Rechtsklick wird ignoriert."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    widget.set_data(["r0"], ["c0"], {(0, 0): HeatmapCell(value=0.5)})
    widget.resize(300, 200)
    widget.show()
    qtbot.waitExposed(widget)

    cell_w, cell_h, grid_x, grid_y = widget._cell_geometry()
    target = QPoint(int(grid_x + cell_w / 2), int(grid_y + cell_h / 2))

    with qtbot.assertNotEmitted(widget.cell_clicked, wait=200):
        qtbot.mouseClick(widget, Qt.MouseButton.RightButton, pos=target)


def test_click_outside_grid_emits_nothing(app, qtbot):
    """Klicks links vom Grid (auf Row-Labels) loesen kein Signal aus."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    widget.set_data(
        ["row"], ["col"], {(0, 0): HeatmapCell(value=0.5)}
    )
    widget.resize(300, 200)
    widget.show()
    qtbot.waitExposed(widget)

    with qtbot.assertNotEmitted(widget.cell_clicked, wait=200):
        qtbot.mouseClick(
            widget, Qt.MouseButton.LeftButton, pos=QPoint(10, 60)
        )


def test_set_color_ramp_rejects_empty(app, qtbot):
    """``set_color_ramp([])`` wirft ValueError."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    with pytest.raises(ValueError):
        widget.set_color_ramp([])


def test_set_color_ramp_stores_stops(app, qtbot):
    """Custom-Ramp wird intern uebernommen und kann gerendert werden."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    custom = [(0.0, QColor(255, 0, 0)), (1.0, QColor(0, 255, 0))]
    widget.set_color_ramp(custom)
    assert len(widget._ramp) == 2
    assert widget._ramp[0][1].red() == 255
    assert widget._ramp[-1][1].green() == 255


def test_cell_explicit_color_overrides_ramp(app, qtbot):
    """``HeatmapCell.color`` ueberschreibt das value→Ramp-Mapping."""
    widget = HeatmapGrid()
    qtbot.addWidget(widget)
    explicit = QColor(123, 45, 67)
    cell = HeatmapCell(value=0.5, color=explicit, label="X")
    widget.set_data(["r"], ["c"], {(0, 0): cell})
    stored = widget._cells[(0, 0)]
    assert stored.color is explicit
    assert stored.label == "X"
