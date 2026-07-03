"""
test_hardening_trend_indicator — Phase-4d Trend-Pfeil Tests.

Deckt:
    * Initial-State zeigt "kein Vergleich".
    * Up / Down / Flat-Cases liefern korrekte Pfeil-Symbole + Delta.
    * Stable-Threshold: |delta| < 0.5 → Flat.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.security_scoring.gui.widgets.hardening_trend_indicator import (
    _NO_HISTORY_TEXT,
    HardeningTrendIndicator,
)

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# Initial State
# ---------------------------------------------------------------------------


class TestInitialState:
    def test_initial_shows_no_history(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        assert w.delta_text == _NO_HISTORY_TEXT
        assert w.arrow_text == "→"


# ---------------------------------------------------------------------------
# set_trend — Pfeil-Logik
# ---------------------------------------------------------------------------


class TestTrendArrows:
    def test_up_arrow_with_positive_delta(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=60.0, current=72.5)
        assert w.arrow_text == "↑"
        assert w.delta_text == "+12.5"

    def test_down_arrow_with_negative_delta(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=80.0, current=72.5)
        assert w.arrow_text == "↓"
        assert w.delta_text == "-7.5"

    def test_flat_arrow_with_zero_delta(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=75.0, current=75.0)
        assert w.arrow_text == "→"
        assert w.delta_text == "± 0"

    def test_flat_arrow_under_stable_threshold(self, app, qtbot):  # noqa: ARG002
        # Threshold = 0.5 → delta=0.4 ist stabil
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=75.0, current=75.4)
        assert w.arrow_text == "→"
        assert w.delta_text == "± 0"

    def test_up_arrow_at_threshold_boundary(self, app, qtbot):  # noqa: ARG002
        # delta=0.5 ist GENAU am Threshold → "stabil" (< 0.5 ist Bedingung)
        # delta=0.6 muss "up" zeigen
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=75.0, current=75.6)
        assert w.arrow_text == "↑"
        assert w.delta_text == "+0.6"


# ---------------------------------------------------------------------------
# set_trend — None-Cases
# ---------------------------------------------------------------------------


class TestNoHistory:
    def test_previous_none_shows_no_history(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=None, current=80.0)
        assert w.delta_text == _NO_HISTORY_TEXT

    def test_current_none_shows_no_history(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=80.0, current=None)
        assert w.delta_text == _NO_HISTORY_TEXT

    def test_both_none_shows_no_history(self, app, qtbot):  # noqa: ARG002
        w = HardeningTrendIndicator()
        qtbot.add_widget(w)
        w.set_trend(previous=None, current=None)
        assert w.delta_text == _NO_HISTORY_TEXT
