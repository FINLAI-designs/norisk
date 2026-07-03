"""
section_breakdown_trend — Sektion 4: Score-Aufschlüsselung + Trend.

Zweispaltiges Layout mit ``QSplitter``:
- Links: BreakdownBars (Sektion 4a)
- Rechts: ScoreTrendChart (Sektion 4b)

Unter 900 px Gesamtbreite wechselt die Splitter-Orientation auf vertikal.

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.gui.breakdown_bars import BreakdownBars
from tools.norisk_dashboard.gui.score_trend_chart import ScoreTrendChart
from tools.security_scoring.domain.models import ScoreComponent

_BREAKPOINT_PX = 900


class BreakdownTrendSection(QWidget):
    """Container für Sektion 4 — responsive Breakdown + Trend."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setHandleWidth(6)
        self._splitter.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        self._left = _Panel("Score-Aufschlüsselung", self)
        self._bars = BreakdownBars(self._left)
        self._left.set_content(self._bars)

        self._right = _Panel("Score-Trend", self)
        self._trend = ScoreTrendChart(self._right)
        self._right.set_content(self._trend)

        self._splitter.addWidget(self._left)
        self._splitter.addWidget(self._right)
        self._splitter.setSizes([500, 500])
        root.addWidget(self._splitter)

    def update_data(
        self,
        components: list[ScoreComponent],
        trend: list[tuple[datetime, float]],
    ) -> None:
        """Aktualisiert beide Unter-Widgets."""
        self._bars.update_data(components)
        self._trend.update_data(trend)

    def resizeEvent(self, event) -> None:  # noqa: ANN001
        super().resizeEvent(event)
        desired = (
            Qt.Orientation.Horizontal
            if self.width() >= _BREAKPOINT_PX
            else Qt.Orientation.Vertical
        )
        if self._splitter.orientation() != desired:
            self._splitter.setOrientation(desired)
            if desired == Qt.Orientation.Horizontal:
                self._splitter.setSizes([self.width() // 2, self.width() // 2])
            else:
                self._splitter.setSizes([self.height() // 2, self.height() // 2])


class _Panel(QFrame):
    """Gerahmtes Unter-Panel mit Titel-Zeile."""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("dashPanel")
        self.setStyleSheet(
            f"#dashPanel {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(10, 10, 10, 10)
        self._lay.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(6)
        title_lbl = QLabel(title, self)
        title_lbl.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; font-weight: bold;"
        )
        head.addWidget(title_lbl)
        head.addStretch()
        self._lay.addLayout(head)

    def set_content(self, widget: QWidget) -> None:
        self._lay.addWidget(widget, stretch=1)
