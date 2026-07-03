"""bsi_risk_matrix_widget — visualisiert RiskAssessments in einer 4x4-BSI-Matrix.

Reuse des generischen:class:`HeatmapGrid` aus ``core.widgets.charts`` mit
Customer-Audit-Domain-Adapter.

- Y-Achse: Eintrittswahrscheinlichkeit (oben P=4 SEHR_HAEUFIG → unten P=1 SELTEN)
- X-Achse: Schadenshoehe (links S=1 VERNACHL. → rechts S=4 EXISTENZBEDR.)
- Zellfarbe nach Score-Zone (score = prob.value * impact.value, 1-16):
    * 1-4 → SCORE_STAGE_SECURE (gruen)
    * 5-8 → SCORE_STAGE_MODERATE (gelb)
    * 9-12 → SCORE_STAGE_AT_RISK (orange)
    * 13-16 → SCORE_STAGE_CRITICAL (rot)
- Zell-Label: Anzahl Risiken in dieser (P, S)-Konstellation
- Klick auf Zelle → emittiert ``cell_selected(prob, impact)`` und blendet die
  Liste der dort gruppierten Risiken im rechten Panel ein.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.widgets.charts import HeatmapCell, HeatmapGrid
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskAssessment,
    RiskImpact,
    RiskProbability,
)

_ROW_LABELS: tuple[str, ...] = (
    "P=4 sehr haeufig",
    "P=3 haeufig",
    "P=2 mittel",
    "P=1 selten",
)
_COL_LABELS: tuple[str, ...] = (
    "S=1 vernachl.",
    "S=2 begrenzt",
    "S=3 betraechtl.",
    "S=4 existenzbedr.",
)


def score_zone_color(score: int) -> QColor:
    """Mappt einen Score (1-16) auf eine BSI-Zonen-Farbe.

    Diskrete 4-Zonen-Schwellen (1-4/5-8/9-12/13-16). Werte ausserhalb [1,16]
    werden geclamped.
    """
    capped = max(1, min(16, int(score)))
    if capped <= 4:
        return QColor(theme.SCORE_STAGE_SECURE)
    if capped <= 8:
        return QColor(theme.SCORE_STAGE_MODERATE)
    if capped <= 12:
        return QColor(theme.SCORE_STAGE_AT_RISK)
    return QColor(theme.SCORE_STAGE_CRITICAL)


def row_to_probability(row_idx: int) -> RiskProbability:
    """row_idx 0..3 → RiskProbability (oben 4, unten 1)."""
    return RiskProbability(4 - row_idx)


def col_to_impact(col_idx: int) -> RiskImpact:
    """col_idx 0..3 → RiskImpact (links 1, rechts 4)."""
    return RiskImpact(col_idx + 1)


def build_matrix_cells(
    assessments: Sequence[RiskAssessment],
) -> dict[tuple[int, int], HeatmapCell]:
    """Aggregiert Assessments in 16 (row, col)-Buckets.

    Args:
        assessments: Die zu visualisierenden RiskAssessments.

    Returns:
        Mapping ``(row_idx, col_idx) → HeatmapCell``. Jede Zelle ist farbig
        (Score-Zone), label = Counter, tooltip = Risiko-Titel (max 3 + "...").
    """
    catalog = DEFAULT_RISK_CATALOG_BY_KEY
    buckets: dict[tuple[int, int], list[RiskAssessment]] = {}
    for assessment in assessments:
        prob = assessment.probability
        imp = assessment.impact
        row_idx = 4 - prob.value
        col_idx = imp.value - 1
        if 0 <= row_idx < 4 and 0 <= col_idx < 4:
            buckets.setdefault((row_idx, col_idx), []).append(assessment)
    cells: dict[tuple[int, int], HeatmapCell] = {}
    for row in range(4):
        for col in range(4):
            prob_val = 4 - row
            imp_val = col + 1
            score = prob_val * imp_val
            color = score_zone_color(score)
            items = buckets.get((row, col), [])
            label = str(len(items)) if items else ""
            tooltip = _tooltip_for(items, catalog)
            cells[(row, col)] = HeatmapCell(
                label=label,
                value=(score - 1) / 15.0,
                color=color,
                tooltip=tooltip,
            )
    return cells


def _tooltip_for(items: list[RiskAssessment], catalog: dict) -> str:
    if not items:
        return "Keine Risiken in dieser Zelle"
    titles = [item.display_title(catalog) for item in items]
    if len(titles) > 3:
        return ", ".join(titles[:3]) + f" (+{len(titles) - 3} weitere)"
    return ", ".join(titles)


class BsiRiskMatrixWidget(QWidget):
    """4x4-BSI-Risikomatrix mit gruppierter Risiko-Liste.

    Signals:
        cell_selected(int, int): ``(prob_value, impact_value)`` (1..4 / 1..4).
            Wird bei Klick auf eine Zelle emittiert, leere Zellen senden
            ebenfalls ein Signal (Liste wird dann leer).
    """

    cell_selected = Signal(int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._assessments: list[RiskAssessment] = []
        self._buckets: dict[tuple[int, int], list[RiskAssessment]] = {}
        self._selected: tuple[int, int] | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        # Sichtbarkeit (Patrick-Feedback): die Matrix verschwamm frueher im
        # Hintergrund (kein Rahmen, BG identisch) und wurde unter einem
        # vertikalen ``addStretch`` auf ihre Minimalhoehe gequetscht. Eine
        # eigene Karte (Rahmen + CARD_BG) + feste Mindesthoehe machen sie an
        # JEDER Einbettungsstelle (Audit-Summary, Cockpit) klar erkennbar.
        # WA_StyledBackground: ein nacktes QWidget malt den QSS-Background sonst
        # nicht (coding-rules R23).
        c = theme.get()
        self.setObjectName("BsiRiskMatrixWidget")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            f"#BsiRiskMatrixWidget {{ background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 6px; }}"
        )
        self.setMinimumHeight(320)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(16)

        self._grid = HeatmapGrid()
        self._grid.cell_clicked.connect(self._on_cell_clicked)
        root.addWidget(self._grid, stretch=3)

        # Rechtes Panel: Header + Liste + Legende
        right = QVBoxLayout()
        right.setSpacing(6)

        self._panel_title = QLabel("Klicke eine Zelle, um die Risiken anzuzeigen.")
        self._panel_title.setObjectName("BsiMatrixPanelTitle")
        self._panel_title.setWordWrap(True)
        right.addWidget(self._panel_title)

        self._risk_list = QListWidget()
        self._risk_list.setObjectName("BsiMatrixRiskList")
        self._risk_list.setAlternatingRowColors(True)
        right.addWidget(self._risk_list, stretch=1)

        right.addWidget(self._build_legend())

        right_widget = QWidget()
        right_widget.setLayout(right)
        root.addWidget(right_widget, stretch=2)

    def _build_legend(self) -> QFrame:
        colors = theme.get()
        legend = QFrame()
        legend.setObjectName("BsiMatrixLegend")
        layout = QVBoxLayout(legend)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        title = QLabel("Score-Zonen")
        title.setStyleSheet(
            f"color: {colors.TEXT_MAIN}; font-weight: bold;"
        )
        layout.addWidget(title)
        for score_range, color, label in (
            ((1, 4), theme.SCORE_STAGE_SECURE, "1-4 gering"),
            ((5, 8), theme.SCORE_STAGE_MODERATE, "5-8 mittel"),
            ((9, 12), theme.SCORE_STAGE_AT_RISK, "9-12 hoch"),
            ((13, 16), theme.SCORE_STAGE_CRITICAL, "13-16 sehr hoch"),
        ):
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(6)
            swatch = QLabel()
            swatch.setFixedSize(14, 14)
            swatch.setStyleSheet(
                f"background-color: {color}; border: 1px solid {colors.BORDER};"
            )
            row.addWidget(swatch)
            text = QLabel(label)
            text.setStyleSheet(f"color: {colors.TEXT_MAIN};")
            row.addWidget(text)
            row.addStretch(1)
            container = QWidget()
            container.setLayout(row)
            layout.addWidget(container)
        return legend

    def set_assessments(self, assessments: Sequence[RiskAssessment]) -> None:
        """Aktualisiert Matrix und rechtes Panel."""
        self._assessments = list(assessments)
        self._buckets = {}
        for assessment in self._assessments:
            row_idx = 4 - assessment.probability.value
            col_idx = assessment.impact.value - 1
            if 0 <= row_idx < 4 and 0 <= col_idx < 4:
                self._buckets.setdefault((row_idx, col_idx), []).append(
                    assessment
                )
        self._grid.set_data(
            rows=_ROW_LABELS,
            cols=_COL_LABELS,
            cells=build_matrix_cells(self._assessments),
        )
        if self._selected is not None:
            self._render_panel(*self._selected)
        else:
            self._render_summary()

    def _render_summary(self) -> None:
        total = len(self._assessments)
        self._panel_title.setText(
            f"<b>{total}</b> Risiken insgesamt. Klicke eine Zelle "
            "zum Filtern."
        )
        self._risk_list.clear()
        if not self._assessments:
            return
        catalog = DEFAULT_RISK_CATALOG_BY_KEY
        for assessment in sorted(
            self._assessments,
            key=lambda a: (
                -(a.probability.value * a.impact.value),
                a.display_title(catalog),
            ),
        ):
            item = QListWidgetItem(
                f"{assessment.probability.value}x{assessment.impact.value} "
                f"= {assessment.probability.value * assessment.impact.value}  "
                f"·  {assessment.display_title(catalog)}"
            )
            self._risk_list.addItem(item)

    def _render_panel(self, row_idx: int, col_idx: int) -> None:
        prob = row_to_probability(row_idx)
        imp = col_to_impact(col_idx)
        score = prob.value * imp.value
        items = self._buckets.get((row_idx, col_idx), [])
        self._panel_title.setText(
            f"<b>P={prob.value} ({prob.label})</b> "
            f"x <b>S={imp.value} ({imp.label})</b> = Score {score}"
            f" — {len(items)} Risiken"
        )
        self._risk_list.clear()
        catalog = DEFAULT_RISK_CATALOG_BY_KEY
        for assessment in items:
            self._risk_list.addItem(
                QListWidgetItem(assessment.display_title(catalog))
            )

    def _on_cell_clicked(self, row_idx: int, col_idx: int) -> None:
        self._selected = (row_idx, col_idx)
        self._render_panel(row_idx, col_idx)
        prob = row_to_probability(row_idx)
        imp = col_to_impact(col_idx)
        self.cell_selected.emit(prob.value, imp.value)

    def selected_cell(self) -> tuple[int, int] | None:
        """Liefert ``(prob_value, impact_value)`` der aktuellen Auswahl."""
        if self._selected is None:
            return None
        row_idx, col_idx = self._selected
        return (4 - row_idx, col_idx + 1)
