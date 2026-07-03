"""Tests fuer TimelineSteps, format_remaining und countdown_color_for."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from PySide6.QtCore import QPoint, Qt

from core import theme
from core.widgets.charts import timeline_steps as _ts
from core.widgets.charts.timeline_steps import (
    StepStatus,
    TimelineStep,
    TimelineSteps,
    countdown_color_for,
    format_remaining,
)

pytestmark = pytest.mark.gui


class TestFormatRemaining:
    """Pure-Function-Tests fuer die Countdown-Formatierung."""

    def test_seconds_only(self):
        assert format_remaining(45) == "00m 45s"

    def test_minutes_seconds(self):
        assert format_remaining(125) == "02m 05s"

    def test_hours_minutes(self):
        assert format_remaining(3 * 3600 + 27 * 60) == "03h 27m"

    def test_days_hours(self):
        assert format_remaining(2 * 86400 + 4 * 3600 + 5 * 60) == "2T 04h"

    def test_negative_returns_abgelaufen(self):
        assert format_remaining(-1) == "abgelaufen"

    def test_zero_seconds(self):
        assert format_remaining(0) == "00m 00s"


class TestCountdownColorFor:
    """Theme-Token-Mapping fuer Countdown-Faerbung."""

    def test_critical_below_one_hour(self):
        assert countdown_color_for(3599) == theme.DARK_DANGER

    def test_warn_between_one_and_six_hours(self):
        assert countdown_color_for(3 * 3600) == theme.WARNING_ORANGE

    def test_accent_above_six_hours(self):
        assert countdown_color_for(12 * 3600) == theme.DARK_ACCENT

    def test_negative_is_critical(self):
        assert countdown_color_for(-1) == theme.DARK_DANGER


def test_empty_steps_renders_keine_stationen(app, qtbot):
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps([])
    widget.resize(600, 130)
    widget.show()
    qtbot.waitExposed(widget)
    widget.repaint()
    assert widget._steps == []


def test_step_clicked_signal_emits_index(app, qtbot):
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(
        [
            TimelineStep("A", StepStatus.DONE),
            TimelineStep("B", StepStatus.IN_PROGRESS),
            TimelineStep("C", StepStatus.PENDING),
        ]
    )
    widget.resize(600, 130)
    widget.show()
    qtbot.waitExposed(widget)

    centers = widget._step_centers()
    target = QPoint(int(centers[1].x()), int(centers[1].y()))
    with qtbot.waitSignal(widget.step_clicked, timeout=1000) as blocker:
        qtbot.mouseClick(widget, Qt.MouseButton.LeftButton, pos=target)
    assert blocker.args == [1]


def test_click_between_steps_emits_nothing(app, qtbot):
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(
        [TimelineStep("A"), TimelineStep("B"), TimelineStep("C")]
    )
    widget.resize(600, 130)
    widget.show()
    qtbot.waitExposed(widget)

    centers = widget._step_centers()
    # Mittig zwischen Step 0 und Step 1
    mid_x = int((centers[0].x() + centers[1].x()) / 2)
    mid_y = int(centers[0].y())
    with qtbot.assertNotEmitted(widget.step_clicked, wait=200):
        qtbot.mouseClick(
            widget, Qt.MouseButton.LeftButton, pos=QPoint(mid_x, mid_y)
        )


def test_countdown_timer_starts_and_stops(app, qtbot):
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    assert not widget._timer.isActive()
    widget.start_countdown_updates()
    assert widget._timer.isActive()
    widget.stop_countdown_updates()
    assert not widget._timer.isActive()


def test_remaining_seconds_uses_now_fn_hook(app, qtbot):
    """Test-Hook ``_now_fn`` ermoeglicht deterministischen Countdown."""
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    fixed_now = datetime(2026, 5, 27, 8, 0, 0)
    widget._now_fn = lambda: fixed_now
    deadline = fixed_now + timedelta(hours=2, minutes=30)
    remaining = widget._remaining_seconds(deadline)
    assert remaining == pytest.approx(2.5 * 3600)


def _nis2_six_phase_steps() -> list[TimelineStep]:
    """Die typischen 6 NIS2-Reporting-Phasen (langer letzter Label-Text)."""
    return [
        TimelineStep("Detect", StepStatus.DONE),
        TimelineStep("Triage", StepStatus.DONE),
        TimelineStep(
            "24h Early-Warning",
            StepStatus.IN_PROGRESS,
            deadline=datetime.now() + timedelta(hours=18),
        ),
        TimelineStep("72h Notification", StepStatus.PENDING),
        TimelineStep("30d Final-Report", StepStatus.PENDING),
        TimelineStep("Post-Incident", StepStatus.PENDING),
    ]


def test_label_rect_clamped_to_widget_on_laptop_width(app, qtbot):
    """6 Phasen auf 1366px-Laptop: kein Label-Rect ragt aus dem Widget.

    Regression: die Label-/Countdown-Rechtecke waren fest
    ``center.x-80.. +80`` breit; der erste Knoten begann links bei einem
    negativen X (abgeschnitten), der letzte ragte rechts ueber die Breite
    hinaus. Jetzt clampt:meth:`_text_rect` an ``[_PADDING, width-_PADDING]``.
    """
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(_nis2_six_phase_steps())
    # Rechte Splitter-Haelfte eines 1366px-Laptops — schmaler als die
    # natuerliche Breite von 6*160 = 960px.
    widget.resize(560, 130)
    widget.show()
    qtbot.waitExposed(widget)

    centers = widget._step_centers()
    top = centers[0].y() + 18 + 12  # _STEP_RADIUS + _LABEL_GAP
    min_left = float(_ts._PADDING)
    max_right = float(widget.width() - _ts._PADDING)
    for center in centers:
        rect = widget._text_rect(center.x(), top, _ts._LABEL_HEIGHT)
        assert rect.left() >= min_left - 0.001
        assert rect.right() <= max_right + 0.001
        assert rect.width() > 0


def test_six_phases_paint_without_error_on_narrow_widget(app, qtbot):
    """Ein Paint-Durchlauf mit 6 Phasen auf schmaler Breite crasht nicht."""
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(_nis2_six_phase_steps())
    widget.resize(560, 130)
    widget.show()
    qtbot.waitExposed(widget)
    # Erzwingt einen synchronen paintEvent-Durchlauf inkl. Clamp-Pfad.
    widget.repaint()
    assert len(widget._step_centers()) == 6


@pytest.mark.parametrize("width", [400, 560, 800, 1200])
def test_last_circle_stays_within_widget_bounds(app, qtbot, width):
    """Regression D5: der letzte Knoten-KREIS ragt nie ueber den rechten Rand.

    Vorher rechnete ``_step_centers`` mit ``width - 2*_PADDING`` als Spanne,
    obwohl die Center bei ``_PADDING + _STEP_RADIUS`` beginnen -> der letzte
    Center landete bei ``width - _PADDING + _STEP_RADIUS`` und der Kreis war
    ~36px ausserhalb (NIS2-Timeline: letzte Phase unsichtbar).
    """
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(_nis2_six_phase_steps())
    widget.resize(width, 130)
    widget.show()
    qtbot.waitExposed(widget)

    centers = widget._step_centers()
    assert len(centers) == 6
    # Erster und letzter Kreis komplett im sichtbaren Bereich.
    assert centers[0].x() - _ts._STEP_RADIUS >= -0.001
    assert centers[-1].x() + _ts._STEP_RADIUS <= widget.width() + 0.001
    # Knoten bleiben in Reihenfolge und ueberschneidungsfrei.
    for prev, nxt in zip(centers[:-1], centers[1:], strict=True):
        assert nxt.x() - prev.x() >= 2 * _ts._STEP_RADIUS - 0.001


def test_natural_width_scrollable_via_size_hint(app, qtbot):
    """sizeHint waechst mit der Phasenzahl, damit ein QScrollArea scrollen kann.

    Liegt das Widget in einem horizontalen QScrollArea, liefert der
    breitere sizeHint (n*160) die natuerliche Breite, sodass bei Bedarf
    horizontal gescrollt werden kann statt zu clippen.
    """
    widget = TimelineSteps()
    qtbot.addWidget(widget)
    widget.set_steps(_nis2_six_phase_steps())
    assert widget.sizeHint().width() >= 6 * 160
