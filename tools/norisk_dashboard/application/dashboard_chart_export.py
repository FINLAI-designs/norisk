"""
dashboard_chart_export — Matplotlib-basierter Chart-Export für den PDF-Report.

Erzeugt Light-Theme-PNG-Buffer für den Score-Trend, ohne Qt-Anbindung.
Dadurch funktioniert der Export auch in Headless-Tests und erzeugt
druckfertige Grafiken mit hoher DPI-Auflösung.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

import io
from datetime import datetime

from core import theme
from core.logger import get_logger

log = get_logger(__name__)

# Light-Theme-Farb-Strings für matplotlib (Single Source of Truth: core.theme +
# core.pdf.pdf_light_colors). matplotlib akzeptiert Hex-Strings — wir leiten
# sie aus den theme-Konstanten ab statt sie erneut hardcoded zu definieren.
_TEAL = theme.DARK_ACCENT
_TEAL_DEEP = theme.DARK_ACCENT_DIM
# Light-Theme-Konstanten — identisch mit core.pdf.pdf_light_colors.LIGHT_*
# (dort als ReportLab-HexColor-Objekte; hier als Hex-Strings für matplotlib).
_TEXT = "#1a1e24"  # noqa: pdf-light-color — = LIGHT_TEXT_PRIMARY (pdf_light_colors:30)
_TEXT_DIM = "#5a6472"  # noqa: pdf-light-color — = LIGHT_TEXT_SECONDARY (pdf_light_colors:31)
_GRID = "#d9dde3"  # noqa: pdf-light-color — = LIGHT_BORDER (pdf_light_colors:51)


def render_score_trend_png(
    pairs: list[tuple[datetime, float]],
    width_inch: float = 6.5,
    height_inch: float = 2.8,
    dpi: int = 180,
) -> bytes | None:
    """Rendert den Score-Trend als Light-Theme-PNG.

    Args:
        pairs: Liste (Timestamp, Score) — aufsteigend sortiert.
        width_inch: Breite in Zoll.
        height_inch: Höhe in Zoll.
        dpi: Auflösung in DPI.

    Returns:
        PNG-Bytes oder None, wenn zu wenig Datenpunkte oder matplotlib fehlt.
    """
    if len(pairs) < 2:
        return None
    try:
        import matplotlib

        matplotlib.use("Agg")
        from matplotlib.dates import AutoDateLocator, DateFormatter
        from matplotlib.figure import Figure
    except ImportError:  # pragma: no cover
        log.warning("matplotlib fehlt — Trend-Chart wird übersprungen")
        return None

    fig = Figure(figsize=(width_inch, height_inch), facecolor="white")
    ax = fig.add_subplot(111)

    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]

    ax.fill_between(xs, ys, 0, color=_TEAL, alpha=0.18)
    ax.plot(
        xs,
        ys,
        color=_TEAL_DEEP,
        linewidth=1.8,
        marker="o",
        markersize=4,
        markerfacecolor=_TEAL_DEEP,
    )

    ax.set_facecolor("white")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Score", color=_TEXT_DIM, fontsize=9)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(_GRID)
    ax.tick_params(colors=_TEXT_DIM, labelsize=8)
    ax.grid(True, color=_GRID, alpha=0.6, linestyle="-", linewidth=0.4)

    ax.xaxis.set_major_locator(AutoDateLocator(maxticks=6))
    ax.xaxis.set_major_formatter(DateFormatter("%d.%m"))
    for label in ax.get_xticklabels():
        label.set_color(_TEXT)

    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, facecolor="white")
    buf.seek(0)
    return buf.getvalue()


def render_breakdown_png(
    components: list,
    width_inch: float = 6.5,
    height_inch: float = 3.0,
    dpi: int = 180,
) -> bytes | None:
    """Rendert die Score-Aufschlüsselung (Balken) als Light-Theme-PNG.

    Args:
        components: Liste ``ScoreComponent`` (mit ``name`` + ``score``).
        width_inch: Breite in Zoll.
        height_inch: Höhe in Zoll.
        dpi: Auflösung.

    Returns:
        PNG-Bytes oder None, wenn keine Komponenten oder matplotlib fehlt.
    """
    if not components:
        return None
    try:
        import matplotlib

        matplotlib.use("Agg")
        from matplotlib.figure import Figure
    except ImportError:  # pragma: no cover
        return None

    names = [getattr(c, "name", "?") for c in components]
    scores = [float(getattr(c, "score", 0.0)) for c in components]

    fig = Figure(figsize=(width_inch, height_inch), facecolor="white")
    ax = fig.add_subplot(111)
    ax.set_facecolor("white")

    y_pos = list(range(len(names)))
    colors = [_score_color(s) for s in scores]
    ax.barh(y_pos, scores, color=colors, edgecolor="none", height=0.55)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, color=_TEXT, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Score", color=_TEXT_DIM, fontsize=9)

    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(_GRID)
    ax.tick_params(colors=_TEXT_DIM, labelsize=8)
    ax.grid(True, axis="x", color=_GRID, alpha=0.6, linestyle="-", linewidth=0.4)

    for i, score in enumerate(scores):
        ax.text(
            min(score + 2, 96),
            i,
            f"{score:.0f}",
            va="center",
            fontsize=8,
            color=_TEXT,
        )

    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, facecolor="white")
    buf.seek(0)
    return buf.getvalue()


def _score_color(score: float) -> str:
    """Hex-Farbe (Light-Theme) für Balken je nach Score-Niveau.

    Werte identisch zu core.pdf.pdf_light_colors.LIGHT_SUCCESS / LIGHT_WARNING
    / LIGHT_ERROR / LIGHT_DANGER (dort als ReportLab-HexColor-Objekte; hier
    als Hex-Strings für matplotlib).
    """
    if score >= 75.0:
        return "#2e7d32"  # noqa: pdf-light-color — = LIGHT_SUCCESS
    if score >= 55.0:
        return "#ed6c02"  # noqa: pdf-light-color — = LIGHT_WARNING
    if score >= 35.0:
        return "#d32f2f"  # noqa: pdf-light-color — = LIGHT_ERROR
    return "#b71c1c"  # noqa: pdf-light-color — = LIGHT_DANGER
