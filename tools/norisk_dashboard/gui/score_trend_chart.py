"""
score_trend_chart — Sektion 4b: Score-Trend als Linien-/Flächen-Chart.

Nutzt matplotlib (``FigureCanvasQTAgg``). Import ist lokal in dieser
Datei gekapselt — der Rest des Dashboards bleibt matplotlib-frei.

Farben:
- Hintergrund: theme BG_MAIN (#1e1e1e)
- Linie: theme DARK_ACCENT (#51dacf)
- Fill: DARK_ACCENT mit Alpha 0.25
- Achsen/Text: theme TEXT_DIM
- Grid: theme BORDER (Alpha 0.3)

Bei weniger als 2 Datenpunkten wird nichts gezeichnet — ein externer
Empty-Fallback-Text liegt dann über dem Canvas (wird vom Sektion-4-
Container gehandhabt).

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QSizePolicy, QStackedLayout, QWidget

from core import theme

try:
    import matplotlib

    matplotlib.use("QtAgg")
    from matplotlib.backends.backend_qtagg import (
        FigureCanvasQTAgg,
    )
    from matplotlib.dates import AutoDateLocator, DateFormatter
    from matplotlib.figure import Figure

    HAS_MPL = True
except ImportError:  # pragma: no cover - matplotlib ist in requirements.txt
    HAS_MPL = False


class ScoreTrendChart(QWidget):
    """Matplotlib-Canvas für den Score-Trend.

    ``update_data(pairs)`` zeichnet neu. Bei < 2 Punkten erscheint ein
    Hinweis-Label statt des Canvas.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()

        self._stack = QStackedLayout(self)
        self._stack.setContentsMargins(0, 0, 0, 0)

        self._empty = QLabel("Noch nicht genug Historie", self)
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px; background: {c.BG_MAIN};"
        )
        self._stack.addWidget(self._empty)

        self._canvas: FigureCanvasQTAgg | None = None
        if HAS_MPL:
            self._figure = Figure(figsize=(6, 3), facecolor=c.BG_MAIN)
            self._axes = self._figure.add_subplot(111)
            self._canvas = FigureCanvasQTAgg(self._figure)
            self._canvas.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
            )
            self._stack.addWidget(self._canvas)

        self._stack.setCurrentWidget(self._empty)
        self.setMinimumHeight(180)

    def update_data(self, pairs: list[tuple[datetime, float]]) -> None:
        """Rendert neuen Trend. Bei < 2 Punkten → Empty-Label."""
        if self._canvas is None or len(pairs) < 2:
            self._stack.setCurrentWidget(self._empty)
            return

        c = theme.get()
        ax = self._axes
        ax.clear()

        xs = [p[0] for p in pairs]
        ys = [p[1] for p in pairs]

        accent = theme.DARK_ACCENT
        ax.fill_between(xs, ys, 0, color=accent, alpha=0.25)
        ax.plot(xs, ys, color=accent, linewidth=1.8, marker="o", markersize=4)

        ax.set_facecolor(c.BG_MAIN)
        ax.set_ylim(0, 100)
        for spine in ax.spines.values():
            spine.set_color(c.BORDER)
        ax.tick_params(colors=c.TEXT_DIM, labelsize=8)
        ax.yaxis.label.set_color(c.TEXT_DIM)
        ax.xaxis.label.set_color(c.TEXT_DIM)
        ax.grid(True, color=c.BORDER, alpha=0.3, linestyle="-", linewidth=0.5)

        ax.xaxis.set_major_locator(AutoDateLocator(maxticks=6))
        ax.xaxis.set_major_formatter(DateFormatter("%d.%m"))

        self._figure.tight_layout()
        self._canvas.draw_idle()
        self._stack.setCurrentWidget(self._canvas)
