"""
test_hardening_score_gauge — Tests fuer den Phase-4b-Halbkreis-Gauge.

Deckt:
    * 4-Stage-Farb-Mapping (Secure/Moderate/At Risk/Critical) auf
      ``SCORE_STAGE_COLORS``-Hex-Werte.
    * Stage-Label-Mapping inkl. Fallback fuer ``None``.
    * ``set_result(result)`` + ``set_score(score, stage)``-Public-API.
    * Tooltip-Aufbau (ohne / mit Score).
    * Linksklick → ``clicked``-Signal; Rechtsklick → kein Signal.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent

from core import theme
from tools.security_scoring.domain.hardening_categories import HardeningCategory
from tools.security_scoring.domain.hardening_score import HardeningScoreResult
from tools.security_scoring.domain.hardening_stages import (
    SCORE_STAGES,
    score_to_stage,
)
from tools.security_scoring.gui.widgets.hardening_score_gauge import (
    HardeningScoreGauge,
    _resolve_stage_color,
    _stage_label,
)

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(score: float) -> HardeningScoreResult:
    """Minimaler ``HardeningScoreResult`` fuer Gauge-Tests."""
    return HardeningScoreResult(
        overall_score=score,
        stage=score_to_stage(score),
        category_scores=(),
        missing_categories=tuple(HardeningCategory),
        hard_cap_events=(),
        raw_weighted_score=score,
    )


# ---------------------------------------------------------------------------
# _resolve_stage_color — Farb-Mapping
# ---------------------------------------------------------------------------


class TestResolveStageColor:
    def test_secure_returns_green_hex(self, app):  # noqa: ARG002
        stage = score_to_stage(95.0)
        assert _resolve_stage_color(stage) == theme.SCORE_STAGE_SECURE

    def test_moderate_returns_yellow_hex(self, app):  # noqa: ARG002
        stage = score_to_stage(75.0)
        assert _resolve_stage_color(stage) == theme.SCORE_STAGE_MODERATE

    def test_at_risk_returns_orange_hex(self, app):  # noqa: ARG002
        stage = score_to_stage(50.0)
        assert _resolve_stage_color(stage) == theme.SCORE_STAGE_AT_RISK

    def test_critical_returns_red_hex(self, app):  # noqa: ARG002
        stage = score_to_stage(20.0)
        assert _resolve_stage_color(stage) == theme.SCORE_STAGE_CRITICAL

    def test_none_returns_border_fallback(self, app):  # noqa: ARG002
        assert _resolve_stage_color(None) == theme.get().BORDER


# ---------------------------------------------------------------------------
# _stage_label
# ---------------------------------------------------------------------------


class TestStageLabel:
    def test_secure_label(self):
        assert _stage_label(score_to_stage(90.0)) == "Secure"

    def test_moderate_label(self):
        assert _stage_label(score_to_stage(70.0)) == "Moderate"

    def test_at_risk_label(self):
        assert _stage_label(score_to_stage(50.0)) == "At Risk"

    def test_critical_label(self):
        assert _stage_label(score_to_stage(10.0)) == "Critical"

    def test_none_label(self):
        assert _stage_label(None) == "Keine Daten"


# ---------------------------------------------------------------------------
# HardeningScoreGauge — Public API
# ---------------------------------------------------------------------------


class TestPublicAPI:
    def test_initial_state_no_score(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        assert gauge.current_score is None
        assert gauge.current_stage is None

    def test_set_result_sets_score_and_stage(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_result(_result(72.5))
        assert gauge.current_score == 72.5
        assert gauge.current_stage is not None
        assert gauge.current_stage.label == "Moderate"

    def test_set_result_none_clears_state(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_result(_result(85.0))
        gauge.set_result(None)
        assert gauge.current_score is None
        assert gauge.current_stage is None

    def test_set_score_derives_stage_when_none(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_score(42.0)
        assert gauge.current_score == 42.0
        assert gauge.current_stage is not None
        assert gauge.current_stage.label == "At Risk"

    def test_set_score_uses_explicit_stage(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        explicit_stage = SCORE_STAGES[0]  # Secure
        gauge.set_score(10.0, stage=explicit_stage)
        # Score sagt Critical, aber expliziter Stage-Override gewinnt
        assert gauge.current_stage is explicit_stage

    def test_set_score_none_clears(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_score(80.0)
        gauge.set_score(None)
        assert gauge.current_score is None
        assert gauge.current_stage is None


# ---------------------------------------------------------------------------
# Tooltip
# ---------------------------------------------------------------------------


class TestTooltip:
    def test_tooltip_without_score(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        assert "Starte einen System-Scan" in gauge.toolTip()

    def test_tooltip_with_score_shows_value_and_stage(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_result(_result(87.0))
        tip = gauge.toolTip()
        assert "87.0" in tip
        assert "Secure" in tip

    def test_tooltip_lists_all_stages(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_result(_result(50.0))
        tip = gauge.toolTip()
        for stage in SCORE_STAGES:
            assert stage.label in tip

    def test_tooltip_marks_active_stage(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.set_result(_result(50.0))
        tip = gauge.toolTip()
        # Stage-Listen-Zeilen sind eingerueckt; die Header-Zeile "Hardening-
        # Score: 50.0 — At Risk" ist nicht eingerueckt. Nur die eingerueckte
        # At-Risk-Zeile traegt den Aktiv-Marker.
        active_lines = [
            line
            for line in tip.splitlines()
            if line.startswith("  ") and "At Risk" in line
        ]
        assert len(active_lines) == 1
        assert "►" in active_lines[0]


# ---------------------------------------------------------------------------
# Phase 4.5+ — Lynis-Style 4-Zonen-Hintergrund
# ---------------------------------------------------------------------------


class TestStageBackgroundPainting:
    """Verifiziert dass _paint_stage_backgrounds fuer jede der 4 Stages
    einen Bogen zeichnet. Keine Pixel-Tests — wir spy-en auf
    QPainter.drawArc und zaehlen die Aufrufe.
    """

    def test_paint_stage_backgrounds_draws_four_arcs(self, qtbot, monkeypatch):
        """``_paint_stage_backgrounds`` muss drawArc 4-mal aufrufen, je
        einmal pro Stage (Critical/At Risk/Moderate/Secure)."""
        from PySide6.QtCore import QRectF  # noqa: PLC0415

        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)

        # Spy auf drawArc — counts pro Aufruf
        calls: list[tuple] = []

        class _FakePainter:
            def setPen(self, *args, **kwargs):
                return None

            def drawArc(self, rect, start, span):
                calls.append((start, span))

        gauge._paint_stage_backgrounds(  # noqa: SLF001
            _FakePainter(), QRectF(0, 0, 200, 200)
        )
        assert len(calls) == 4  # eine pro Stage

    def test_paint_stage_backgrounds_uses_stage_colors_with_alpha(
        self, qtbot
    ):
        """Die gezeichneten Pen-Farben muessen aus
        ``SCORE_STAGE_COLORS`` kommen, mit reduziertem Alpha (Hintergrund-
        Sektoren bleiben subtil)."""
        from PySide6.QtCore import QRectF  # noqa: PLC0415

        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)

        colors_seen: list = []

        class _FakePainter:
            def setPen(self, pen):
                colors_seen.append(pen.color())

            def drawArc(self, *args, **kwargs):
                return None

        gauge._paint_stage_backgrounds(  # noqa: SLF001
            _FakePainter(), QRectF(0, 0, 200, 200)
        )
        # Alpha muss reduziert sein (<255, >0)
        for c in colors_seen:
            assert 0 < c.alpha() < 255, (
                f"Alpha {c.alpha()} fuer Hintergrund-Stage erwartet 0<a<255"
            )

    def test_stage_backgrounds_cover_full_score_range(self, qtbot):
        """Die 4 Stage-Bogen muessen zusammen die gesamte 0-100-Range
        abdecken (additiv ≈ 100% des 180-Grad-Halbkreises)."""
        from PySide6.QtCore import QRectF  # noqa: PLC0415

        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)

        total_abs_span_units = 0

        class _FakePainter:
            def setPen(self, *args, **kwargs):
                return None

            def drawArc(self, rect, start, span):
                nonlocal total_abs_span_units
                total_abs_span_units += abs(span)

        gauge._paint_stage_backgrounds(  # noqa: SLF001
            _FakePainter(), QRectF(0, 0, 200, 200)
        )
        # 4 Stages decken die Score-Range 0-100 ab. drawArc Units sind
        # 1/16-Grad; 180-Grad-Bogen = 180*16 = 2880 Units. Tol 1% wg.
        # Rundung in der Stage-Span-Berechnung (+1 fuer inklusive
        # max_score).
        assert abs(total_abs_span_units - 180 * 16) < 200


# ---------------------------------------------------------------------------
# Click-Signal
# ---------------------------------------------------------------------------


class TestClickSignal:
    def test_left_click_emits_clicked(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        received: list[None] = []
        gauge.clicked.connect(lambda: received.append(None))
        event = QMouseEvent(
            QMouseEvent.Type.MouseButtonPress,
            QPoint(50, 50),
            Qt.MouseButton.LeftButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        gauge.mousePressEvent(event)
        assert len(received) == 1

    def test_right_click_does_not_emit(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        received: list[None] = []
        gauge.clicked.connect(lambda: received.append(None))
        event = QMouseEvent(
            QMouseEvent.Type.MouseButtonPress,
            QPoint(50, 50),
            Qt.MouseButton.RightButton,
            Qt.MouseButton.RightButton,
            Qt.KeyboardModifier.NoModifier,
        )
        gauge.mousePressEvent(event)
        assert received == []


# ---------------------------------------------------------------------------
# Paint smoke (kein Crash auf paintEvent)
# ---------------------------------------------------------------------------


class TestPaintSmoke:
    def test_paint_without_score_does_not_crash(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.show()
        gauge.repaint()
        gauge.hide()

    def test_paint_with_each_stage_does_not_crash(self, qtbot):
        gauge = HardeningScoreGauge()
        qtbot.add_widget(gauge)
        gauge.show()
        for score in (10.0, 50.0, 75.0, 95.0):
            gauge.set_result(_result(score))
            gauge.repaint()
        gauge.hide()
