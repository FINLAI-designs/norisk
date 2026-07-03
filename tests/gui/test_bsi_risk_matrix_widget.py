"""Tests fuer BsiRiskMatrixWidget und die Score-/Mapping-Helper."""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor

from core import theme
from tools.customer_audit.domain.risk_entities import (
    RiskAssessment,
    RiskImpact,
    RiskProbability,
)
from tools.customer_audit.gui.widgets.bsi_risk_matrix_widget import (
    BsiRiskMatrixWidget,
    build_matrix_cells,
    col_to_impact,
    row_to_probability,
    score_zone_color,
)

pytestmark = pytest.mark.gui


def _assess(catalog_key: str, prob: RiskProbability, imp: RiskImpact) -> RiskAssessment:
    return RiskAssessment(
        id=None,
        audit_id="",
        catalog_key=catalog_key,
        probability=prob,
        impact=imp,
    )


class TestScoreZoneColor:
    """4-Zonen-Schwellen: 1-4 / 5-8 / 9-12 / 13-16."""

    def test_score_1_is_secure(self):
        assert score_zone_color(1) == QColor(theme.SCORE_STAGE_SECURE)

    def test_score_4_is_secure(self):
        assert score_zone_color(4) == QColor(theme.SCORE_STAGE_SECURE)

    def test_score_5_is_moderate(self):
        assert score_zone_color(5) == QColor(theme.SCORE_STAGE_MODERATE)

    def test_score_8_is_moderate(self):
        assert score_zone_color(8) == QColor(theme.SCORE_STAGE_MODERATE)

    def test_score_9_is_at_risk(self):
        assert score_zone_color(9) == QColor(theme.SCORE_STAGE_AT_RISK)

    def test_score_12_is_at_risk(self):
        assert score_zone_color(12) == QColor(theme.SCORE_STAGE_AT_RISK)

    def test_score_13_is_critical(self):
        assert score_zone_color(13) == QColor(theme.SCORE_STAGE_CRITICAL)

    def test_score_16_is_critical(self):
        assert score_zone_color(16) == QColor(theme.SCORE_STAGE_CRITICAL)

    def test_score_below_one_clamps_to_secure(self):
        assert score_zone_color(0) == QColor(theme.SCORE_STAGE_SECURE)

    def test_score_above_sixteen_clamps_to_critical(self):
        assert score_zone_color(100) == QColor(theme.SCORE_STAGE_CRITICAL)


class TestRowColMapping:
    """row/col-Indices ↔ Domain-Enum-Werte."""

    def test_row_0_is_sehr_haeufig(self):
        assert row_to_probability(0) == RiskProbability.SEHR_HAEUFIG

    def test_row_3_is_selten(self):
        assert row_to_probability(3) == RiskProbability.SELTEN

    def test_col_0_is_vernachlaessigbar(self):
        assert col_to_impact(0) == RiskImpact.VERNACHLAESSIGBAR

    def test_col_3_is_existenzbedrohend(self):
        assert col_to_impact(3) == RiskImpact.EXISTENZBEDROHEND


class TestBuildMatrixCells:
    """Aggregation in (row, col)-Buckets."""

    def test_empty_returns_16_empty_cells(self):
        cells = build_matrix_cells([])
        assert len(cells) == 16
        for cell in cells.values():
            assert cell.label == ""

    def test_single_risk_in_correct_bucket(self):
        risk = _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH)
        cells = build_matrix_cells([risk])
        # P=3 → row 1, S=3 → col 2
        assert cells[(1, 2)].label == "1"
        # Andere Zellen leer
        assert cells[(0, 0)].label == ""

    def test_multiple_risks_same_bucket_counter_increments(self):
        risks = [
            _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
            _assess("patch_luecke", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
            _assess(
                "ransomware", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH
            ),
        ]
        cells = build_matrix_cells(risks)
        assert cells[(1, 2)].label == "3"

    def test_every_cell_has_zone_color(self):
        cells = build_matrix_cells([])
        # Ecke oben links (row=0, col=0) = P=4, S=1 → score 4 → secure
        assert cells[(0, 0)].color == QColor(theme.SCORE_STAGE_SECURE)
        # Ecke oben rechts (row=0, col=3) = P=4, S=4 → score 16 → critical
        assert cells[(0, 3)].color == QColor(theme.SCORE_STAGE_CRITICAL)
        # Ecke unten links (row=3, col=0) = P=1, S=1 → score 1 → secure
        assert cells[(3, 0)].color == QColor(theme.SCORE_STAGE_SECURE)
        # Ecke unten rechts (row=3, col=3) = P=1, S=4 → score 4 → secure
        assert cells[(3, 3)].color == QColor(theme.SCORE_STAGE_SECURE)


def test_widget_initial_state(app, qtbot):
    widget = BsiRiskMatrixWidget()
    qtbot.addWidget(widget)
    assert widget._assessments == []
    assert widget.selected_cell() is None


def test_set_assessments_populates_summary(app, qtbot):
    widget = BsiRiskMatrixWidget()
    qtbot.addWidget(widget)
    risks = [
        _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
        _assess("ransomware", RiskProbability.MITTEL, RiskImpact.EXISTENZBEDROHEND),
    ]
    widget.set_assessments(risks)
    assert len(widget._assessments) == 2
    # Liste wurde mit beiden Risiken befuellt
    assert widget._risk_list.count() == 2


def test_cell_selected_signal_emits_prob_impact_values(app, qtbot):
    widget = BsiRiskMatrixWidget()
    qtbot.addWidget(widget)
    risks = [
        _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
    ]
    widget.set_assessments(risks)
    # Pixel-Klick durchs verschachtelte Layout ist Layout-fragil; daher
    # ueber den HeatmapGrid-Signal direkt — das ist der Pfad, der in der
    # echten App von QPainter→mousePressEvent ausgeloest wird.
    with qtbot.waitSignal(widget.cell_selected, timeout=1000) as blocker:
        widget._grid.cell_clicked.emit(1, 2)  # row=1 (P=3), col=2 (S=3)
    assert blocker.args == [3, 3]
    assert widget.selected_cell() == (3, 3)


def test_qpainter_grid_click_through_pixel(app, qtbot):
    """End-to-End: Pixel-Klick auf das HeatmapGrid-Widget triggert das Signal.

    Wir klicken direkt auf das ``HeatmapGrid``-Child statt auf den
    Outer-Widget-Wrapper, damit das Mapping nicht durch das HBoxLayout-Offset
    bricht.
    """
    widget = BsiRiskMatrixWidget()
    qtbot.addWidget(widget)
    risks = [
        _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
    ]
    widget.set_assessments(risks)
    widget.resize(900, 500)
    widget.show()
    qtbot.waitExposed(widget)

    grid = widget._grid
    cell_w, cell_h, grid_x, grid_y = grid._cell_geometry()
    target_x = int(grid_x + 2 * cell_w + cell_w / 2)
    target_y = int(grid_y + 1 * cell_h + cell_h / 2)
    with qtbot.waitSignal(widget.cell_selected, timeout=1000) as blocker:
        qtbot.mouseClick(
            grid,
            Qt.MouseButton.LeftButton,
            pos=QPoint(target_x, target_y),
        )
    assert blocker.args == [3, 3]


def test_filter_after_click_shows_only_bucket_items(app, qtbot):
    widget = BsiRiskMatrixWidget()
    qtbot.addWidget(widget)
    risks = [
        _assess("phishing", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
        _assess("ransomware", RiskProbability.MITTEL, RiskImpact.EXISTENZBEDROHEND),
        _assess("patch_luecke", RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH),
    ]
    widget.set_assessments(risks)
    # Direkter Aufruf (umgeht Pixel-Klick)
    widget._on_cell_clicked(row_idx=1, col_idx=2)  # P=3, S=3
    # Bucket P=3xS=3 enthaelt phishing + patch_luecke
    assert widget._risk_list.count() == 2
