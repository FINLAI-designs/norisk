"""cvss_percentile_widget — Quick-Win W6 (Sprint S3c).

Drei CVSS-Perzentile (p10/p50/p90) der zuletzt gecachten CVEs plus eine
QPainter-Sparkline ueber die Median-Werte der letzten N Refreshes.
Beantwortet die Frau-M-Frage "Ist es diese Woche schlimmer?".

Datenquelle::class:`CvssPercentiles` aus dem
:class:`DashboardAggregator` (Loader rechnet die Perzentile aus dem
``nvd_cache``).

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.domain.models import CvssPercentiles


class CvssPercentileWidget(QFrame):
    """KPI-Tile mit p10/p50/p90 + Sparkline-Mini-Chart."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data: CvssPercentiles | None = None
        self.setObjectName("cvssPercentile")
        self.setFixedSize(280, 140)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        c = theme.get()
        self.setStyleSheet(
            f"#cvssPercentile {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 6px; }}"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(4)

        title = QLabel("CVSS-PERZENTILE", self)
        title.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; "
            f"font-weight: bold; letter-spacing: 1px; background: transparent;"
        )
        outer.addWidget(title)

        # Drei Perzentil-Werte horizontal nebeneinander
        body = QHBoxLayout()
        body.setSpacing(12)

        self._labels: dict[str, QLabel] = {}
        for key, caption in (("p10", "p10"), ("p50", "p50"), ("p90", "p90")):
            cell = QVBoxLayout()
            cell.setSpacing(0)
            value_lbl = QLabel("—", self)
            value_lbl.setStyleSheet(
                f"color: {c.TEXT_MAIN}; font-size: 22px; "
                f"font-weight: bold; background: transparent;"
            )
            cell.addWidget(value_lbl)
            cap_lbl = QLabel(caption, self)
            cap_lbl.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 10px; background: transparent;"
            )
            cell.addWidget(cap_lbl)
            body.addLayout(cell)
            self._labels[key] = value_lbl

        # Sparkline rechts
        self._sparkline = _Sparkline(self)
        body.addWidget(self._sparkline, 1)
        outer.addLayout(body)

        # Subline mit Sample-Count
        self._sub = QLabel("Noch keine CVE-Daten gecached", self)
        self._sub.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 10px; background: transparent;"
        )
        outer.addWidget(self._sub)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(self, data: CvssPercentiles | None) -> None:
        """Aktualisiert Perzentil-Werte + Sparkline."""
        self._data = data
        if data is None or data.sample_count == 0:
            for lbl in self._labels.values():
                lbl.setText("—")
            self._sparkline.set_values([])
            self._sub.setText("Noch keine CVE-Daten gecached")
            self.setToolTip(
                "CVSS-Perzentile werden aus dem NVD-Cache berechnet — "
                "starte einen Cyber-Dashboard-Refresh, um Daten zu sammeln."
            )
            return
        self._labels["p10"].setText(f"{data.p10:.1f}")
        self._labels["p50"].setText(f"{data.p50:.1f}")
        self._labels["p90"].setText(f"{data.p90:.1f}")
        self._sparkline.set_values(list(data.sparkline))
        self._sub.setText(
            f"{data.sample_count} CVEs ausgewertet · Sparkline: "
            f"Median-Trend"
        )
        self.setToolTip(
            "CVSS-Perzentile der zuletzt geladenen CVEs:\n"
            f"  p10 = {data.p10:.1f}  (untere 10 % darunter)\n"
            f"  p50 = {data.p50:.1f}  (Median)\n"
            f"  p90 = {data.p90:.1f}  (obere 10 % darueber)\n\n"
            f"Stichprobe: {data.sample_count} CVEs."
        )


class _Sparkline(QWidget):
    """Mini-Linien-Chart fuer die Sparkline."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._values: list[float] = []
        self.setFixedHeight(34)
        self.setMinimumWidth(80)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_values(self, values: list[float]) -> None:
        self._values = list(values)
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: D401, N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        try:
            self._paint(painter)
        finally:
            painter.end()

    def _paint(self, painter: QPainter) -> None:
        c = theme.get()
        rect = QRectF(0, 0, self.width(), self.height())

        if len(self._values) < 2:
            # Empty-State: dezente Strich-Linie
            pen = QPen(QColor(c.BORDER))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.drawLine(
                QPointF(0, rect.height() / 2),
                QPointF(rect.width(), rect.height() / 2),
            )
            return

        lo = min(self._values)
        hi = max(self._values)
        span = max(hi - lo, 0.001)
        step = rect.width() / max(len(self._values) - 1, 1)

        path_points: list[QPointF] = []
        for idx, val in enumerate(self._values):
            x = idx * step
            # Y-Achse invertieren (oben = hoeher), 4 px Padding oben/unten
            y_norm = (val - lo) / span
            y = rect.height() - 4 - y_norm * (rect.height() - 8)
            path_points.append(QPointF(x, y))

        pen = QPen(QColor(theme.DARK_ACCENT))
        pen.setWidth(2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        for a, b in zip(path_points, path_points[1:], strict=False):
            painter.drawLine(a, b)
