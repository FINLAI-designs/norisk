"""
section_score — Sektion 2: 'Score kompakt'.

Große KPI-Kachel mit aktuellem Security-Score + Trend-Pfeil zum
Vorgänger-Score. Klick springt (später) zu Sektion 4.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.domain.models import ScoreSnapshot
from tools.norisk_dashboard.gui.score_gauge import ScoreGauge
from tools.security_scoring.domain.models import ScoreComponent


class ScoreSection(QWidget):
    """KPI-Kachel + Halbkreis-Gauge + Trend-Pfeil für den Security-Score.

    Sprint S3b: Statt der ``addStretch``-Lücke neben der Kachel sitzt
    jetzt ein:class:`ScoreGauge` (Halbkreis-Tachometer mit Farbzonen
    nach den ``cve_exposure``-Schwellen 60/80). Beide Klicks (Tile +
    Gauge) leiten auf das gemeinsame ``clicked``-Signal weiter — der
    Dashboard-Container scrollt damit zur Score-Aufschlüsselungs-
    Sektion (Sektion 4 / ``BreakdownTrendSection``).

    Signals:
        clicked: Emittiert wenn Tile oder Gauge geklickt wird.
    """

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._snapshot = ScoreSnapshot()

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        self._tile = _ScoreTile(self)
        self._tile.clicked.connect(self.clicked.emit)
        root.addWidget(self._tile)

        self._gauge = ScoreGauge(self)
        self._gauge.clicked.connect(self.clicked.emit)
        root.addWidget(self._gauge)

        root.addStretch()

    def update_data(
        self,
        snapshot: ScoreSnapshot,
        breakdown: list[ScoreComponent] | None = None,
    ) -> None:
        """Aktualisiert Score-Zahl + Trend + Halbkreis + Tooltip-Aufschlüsselung.

        Args:
            snapshot: Aktueller Score-Snapshot (Wert, Vorgängerwert, Ziel).
            breakdown: Optionale Komponenten-Liste für den Gauge-Tooltip.
                Wird vom:class:`NoRiskDashboardWidget` aus
                ``DashboardData.breakdown`` durchgereicht.
        """
        self._snapshot = snapshot
        self._tile.set_snapshot(snapshot)
        self._gauge.set_data(snapshot.current, breakdown)


class _ScoreTile(QFrame):
    """Klickbare KPI-Kachel mit großer Zahl + Trend."""

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("scoreTile")
        self.setStyleSheet(
            f"#scoreTile {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 6px; }} "
            f"#scoreTile:hover {{ border-color: {theme.DARK_ACCENT}; }}"
        )
        self.setFixedSize(260, 140)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)

        title = QLabel("SECURITY-SCORE", self)
        title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px;"
        )
        lay.addWidget(title)

        self._value = QLabel("—", self)
        self._value.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 48px; font-weight: bold;"
        )
        lay.addWidget(self._value)

        self._trend = QLabel("", self)
        self._trend.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 12px;")
        lay.addWidget(self._trend)

    def set_snapshot(self, snap: ScoreSnapshot) -> None:
        c = theme.get()
        if snap.current is None:
            self._value.setText("—")
            self._trend.setText("Noch kein Score berechnet")
            self._trend.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 12px;")
            return
        self._value.setText(f"{snap.current:.1f}")
        delta = snap.delta
        if delta is None:
            self._trend.setText("Kein Vergleichswert")
            self._trend.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 12px;")
            return
        if delta > 0:
            arrow = "▲"
            color = theme.DARK_ACCENT
        elif delta < 0:
            arrow = "▼"
            color = c.DANGER
        else:
            arrow = "→"
            color = c.TEXT_DIM
        self._trend.setText(f"{arrow} {delta:+.1f} gegenüber Vorwoche")
        self._trend.setStyleSheet(
            f"color: {color}; font-size: 12px; font-weight: bold;"
        )

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
