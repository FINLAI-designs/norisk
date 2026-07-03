"""risk_matrix_export — BSI-Risikomatrix als PNG-Bild Phase D).

Rendert die 4×4-BSI-Risikomatrix (Eintrittswahrscheinlichkeit × Schadenshöhe)
headless via matplotlib (Agg) zu PNG-Bytes — wiederverwendbar für den
Kunden-PDF-Report. Spiegelt die Zonen-Farben + Achsen des
``BsiRiskMatrixWidget`` (oben P4, links S1; Zonen 1-4/5-8/9-12/13-16). Keine
Qt-Anbindung -> funktioniert in Headless-Tests + im PDF-Export.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import io
from collections.abc import Sequence
from typing import Protocol

from core import theme
from core.logger import get_logger
from tools.customer_audit.domain.risk_entities import RiskImpact, RiskProbability

log = get_logger(__name__)

# Light-Theme Text-/Gitterfarbe (identisch zu dashboard_chart_export).
_TEXT = "#1a1e24"  # noqa: pdf-light-color
_GRID = "#d9dde3"  # noqa: pdf-light-color


class _AssessmentLike(Protocol):
    probability: RiskProbability
    impact: RiskImpact


def _zone_hex(score: int) -> str:
    """Score (1–16) → BSI-Zonen-Hex (spiegelt ``score_zone_color`` des Widgets)."""
    capped = max(1, min(16, int(score)))
    if capped <= 4:
        return theme.SCORE_STAGE_SECURE
    if capped <= 8:
        return theme.SCORE_STAGE_MODERATE
    if capped <= 12:
        return theme.SCORE_STAGE_AT_RISK
    return theme.SCORE_STAGE_CRITICAL


def render_risk_matrix_png(
    assessments: Sequence[_AssessmentLike],
    *,
    width_inch: float = 5.6,
    height_inch: float = 4.6,
    dpi: int = 180,
) -> bytes | None:
    """Rendert die BSI-Risikomatrix mit Risiko-Zählern je Zelle als PNG.

    Args:
        assessments: Risiko-Bewertungen (je mit ``probability``/``impact``).
        width_inch: Breite in Zoll.
        height_inch: Höhe in Zoll.
        dpi: Auflösung.

    Returns:
        PNG-Bytes, oder ``None`` wenn keine Bewertungen vorliegen oder matplotlib
        fehlt (fail-soft — der PDF-Report lässt die Grafik dann weg).
    """
    if not assessments:
        return None
    try:
        import matplotlib

        matplotlib.use("Agg")
        from matplotlib.figure import Figure
        from matplotlib.patches import Rectangle
    except ImportError:
        log.warning("matplotlib fehlt — Risikomatrix-PNG übersprungen.")
        return None

    # Zähler je (Wahrscheinlichkeit 1..4, Schaden 1..4).
    counts: dict[tuple[int, int], int] = {
        (p, s): 0 for p in range(1, 5) for s in range(1, 5)
    }
    for a in assessments:
        key = (a.probability.value, a.impact.value)
        if key in counts:
            counts[key] += 1

    fig = Figure(figsize=(width_inch, height_inch), dpi=dpi)
    ax = fig.add_subplot(111)

    for p in range(1, 5):  # Wahrscheinlichkeit: y = p-1 (P1 unten, P4 oben)
        for s in range(1, 5):  # Schaden: x = s-1 (S1 links, S4 rechts)
            x, y = s - 1, p - 1
            ax.add_patch(
                Rectangle(
                    (x, y), 1, 1,
                    facecolor=_zone_hex(p * s),
                    edgecolor=_GRID,
                    linewidth=1.0,
                )
            )
            n = counts[(p, s)]
            if n:
                ax.text(
                    x + 0.5, y + 0.5, str(n),
                    ha="center", va="center",
                    fontsize=13, fontweight="bold", color=_TEXT,
                )

    ax.set_xlim(0, 4)
    ax.set_ylim(0, 4)
    ax.set_xticks([0.5, 1.5, 2.5, 3.5])
    ax.set_yticks([0.5, 1.5, 2.5, 3.5])
    ax.set_xticklabels(
        [RiskImpact(s).label for s in range(1, 5)], fontsize=7, color=_TEXT
    )
    ax.set_yticklabels(
        [RiskProbability(p).label for p in range(1, 5)], fontsize=7, color=_TEXT
    )
    ax.set_xlabel("Schadenshöhe", fontsize=8, color=_TEXT)
    ax.set_ylabel("Eintrittswahrscheinlichkeit", fontsize=8, color=_TEXT)
    ax.set_title("BSI-200-3-Risikomatrix", fontsize=10, color=_TEXT, fontweight="bold")
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, facecolor="white")
    return buf.getvalue()
