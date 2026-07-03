"""DonutChart — generisches Donut-/Ringdiagramm mit QPainter.

Use-Cases im NoRisk-Sprint:
- Light-SIEM Severity-Donut (CRITICAL/ERROR/WARN/INFO mit Counts)
- KPI-Anteil-Donut mit Center-Text (z.B. "Score 87/100")

Hexagonal-konform: nutzt nur ``PySide6`` und ``core.theme`` — keine
Domain-Imports.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from core import theme

_PADDING = 12
_QT_DEG = 16  # Qt nutzt 1/16-Grad-Einheiten
_START_ANGLE_DEG = 90  # 12-Uhr-Position als Startpunkt (Qt: positiv = CCW)
_DEFAULT_INNER_RATIO = 0.6


@dataclass(frozen=True)
class DonutSegment:
    """Ein Segment des Donut-Charts.

    Attributes:
        label: Anzeigename (z.B. ``"CRITICAL"``). Wird in der Legende
            und im Hover-Tooltip verwendet.
        value: Numerischer Anteil (>= 0). Negative Werte werden geclamped.
            Anteile werden intern auf ``sum(values)`` normalisiert.
        color: Optional explizite Farbe. Wenn None, wird die Default-
            Severity-Palette (rotierend) verwendet.
        tooltip: Optionaler eigener Hover-Text. Wenn leer, wird automatisch
            ``"{label}: {value:g}"`` gerendert.
    """

    label: str
    value: float
    color: QColor | None = None
    tooltip: str = ""


def _default_palette() -> tuple[QColor, ...]:
    """Severity-Standard-Palette (rotierend bei vielen Segmenten)."""
    return (
        QColor(theme.SEVERITY_SIGNAL_CRITICAL),
        QColor(theme.SEVERITY_SIGNAL_HIGH),
        QColor(theme.SEVERITY_SIGNAL_MEDIUM),
        QColor(theme.SEVERITY_SIGNAL_LOW),
        QColor(theme.SEVERITY_SIGNAL_OK),
        QColor(theme.SEVERITY_SIGNAL_INFO),
    )


def compute_arc_spans(
    values: Sequence[float],
    start_angle_deg: float = _START_ANGLE_DEG,
) -> list[tuple[float, float]]:
    """Berechnet ``(start_deg, span_deg)``-Paare fuer die Donut-Segmente.

    Args:
        values: Sequenz numerischer Werte (>= 0). Negative Werte werden
            geclamped, ``sum <= 0`` ergibt eine leere Liste.
        start_angle_deg: Startwinkel in Grad (CCW, 12 Uhr = 90 Grad).

    Returns:
        Liste mit gleich vielen Paaren wie ``values`` (sofern total > 0),
        sortiert in derselben Reihenfolge. ``span_deg`` summiert sich auf
        360. Bei total <= 0 leere Liste.
    """
    clamped = [max(0.0, float(v)) for v in values]
    total = sum(clamped)
    if total <= 0:
        return []
    spans: list[tuple[float, float]] = []
    current = float(start_angle_deg)
    for v in clamped:
        span = (v / total) * 360.0
        spans.append((current, -span))  # CW im visuellen Sinn = negativ in Qt
        current -= span
    return spans


class DonutChart(QWidget):
    """Generisches Donut-/Ringdiagramm mit QPainter-Rendering.

    Signals:
        segment_clicked(int): Index des Segments bei linkem Mausklick.

    Pflicht-API:
        -:meth:`set_segments` — Liste der DonutSegmente.
        -:meth:`set_center_text` — Text in der Mitte des Lochs (KPI etc.).
        -:meth:`set_inner_radius_ratio` — Loch-Anteil ``[0, 0.95]``.
        - ``segment_clicked: Signal(int)``.
    """

    segment_clicked = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._segments: list[DonutSegment] = []
        self._center_text: str = ""
        self._inner_ratio: float = _DEFAULT_INNER_RATIO
        self._palette: tuple[QColor, ...] = _default_palette()

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setMinimumSize(200, 200)
        self.setMouseTracking(True)

    def set_segments(self, segments: Sequence[DonutSegment]) -> None:
        """Aktualisiert die Segment-Liste und triggert Repaint."""
        self._segments = list(segments)
        self.update()

    def set_center_text(self, text: str) -> None:
        """Setzt den Text in der Mitte des Donut-Lochs (KPI/Total)."""
        self._center_text = text
        self.update()

    def set_inner_radius_ratio(self, ratio: float) -> None:
        """Setzt das Verhaeltnis Loch-Radius / Aussen-Radius.

        Args:
            ratio: Wert in ``[0, 0.95]``. Werte ausserhalb werden geclamped.
        """
        self._inner_ratio = max(0.0, min(0.95, float(ratio)))
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        spans = compute_arc_spans([s.value for s in self._segments])
        if not spans:
            painter.setPen(QColor(c.TEXT_DIM))
            font = QFont()
            font.setPointSize(theme.FONT_SIZE_BODY)
            painter.setFont(font)
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "Keine Daten",
            )
            painter.end()
            return

        outer_rect = self._outer_rect()
        for idx, segment in enumerate(self._segments):
            start_deg, span_deg = spans[idx]
            color = self._color_for(idx, segment)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPie(
                outer_rect,
                int(round(start_deg * _QT_DEG)),
                int(round(span_deg * _QT_DEG)),
            )

        inner_rect = self._inner_rect(outer_rect)
        painter.setBrush(QColor(c.BG_MAIN))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(inner_rect)

        if self._center_text:
            painter.setPen(QColor(c.TEXT_MAIN))
            font = QFont()
            font.setPointSize(theme.FONT_SIZE_H2)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(
                inner_rect,
                Qt.AlignmentFlag.AlignCenter,
                self._center_text,
            )

        painter.end()

    def _outer_rect(self) -> QRectF:
        """Quadratischer Aussen-Rect, zentriert im Widget."""
        size = max(0, min(self.width(), self.height()) - 2 * _PADDING)
        x = (self.width() - size) / 2.0
        y = (self.height() - size) / 2.0
        return QRectF(x, y, size, size)

    def _inner_rect(self, outer: QRectF) -> QRectF:
        """Inner-Rect fuer das Donut-Loch."""
        inner_size = outer.width() * self._inner_ratio
        x = outer.x() + (outer.width() - inner_size) / 2.0
        y = outer.y() + (outer.height() - inner_size) / 2.0
        return QRectF(x, y, inner_size, inner_size)

    def _color_for(self, idx: int, segment: DonutSegment) -> QColor:
        if segment.color is not None:
            return QColor(segment.color)
        return QColor(self._palette[idx % len(self._palette)])

    def _segment_at(self, pos: QPointF) -> int | None:
        """Mappt eine Widget-Position auf einen Segment-Index oder None."""
        if not self._segments:
            return None
        spans = compute_arc_spans([s.value for s in self._segments])
        if not spans:
            return None
        outer = self._outer_rect()
        center = outer.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        radius = math.hypot(dx, dy)
        outer_r = outer.width() / 2.0
        inner_r = outer_r * self._inner_ratio
        if radius < inner_r or radius > outer_r:
            return None
        # Qt: 0 Grad = 3-Uhr, CCW positiv. atan2(-dy, dx) ergibt Qt-konformen Winkel.
        angle = math.degrees(math.atan2(-dy, dx))
        if angle < 0:
            angle += 360
        for idx, (start_deg, span_deg) in enumerate(spans):
            end_deg = start_deg + span_deg  # span ist negativ (CW)
            lo = min(start_deg, end_deg) % 360
            hi = max(start_deg, end_deg) % 360
            # Behandle Wrap-Around bei 0/360
            if lo <= hi:
                if lo <= angle <= hi:
                    return idx
            else:
                if angle >= lo or angle <= hi:
                    return idx
        return None

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        idx = self._segment_at(event.position())
        if idx is not None:
            self.segment_clicked.emit(idx)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001
        idx = self._segment_at(event.position())
        if idx is None:
            QToolTip.hideText()
            return
        segment = self._segments[idx]
        text = segment.tooltip or f"{segment.label}: {segment.value:g}"
        QToolTip.showText(event.globalPosition().toPoint(), text, self)

    def sizeHint(self) -> QSize:
        return QSize(260, 260)


def _build_severity_demo() -> DonutChart:
    """Demo-Helper: Severity-Donut mit Center-Text (fuer __main__ + Snapshot)."""
    chart = DonutChart()
    segments = [
        DonutSegment("CRITICAL", 4),
        DonutSegment("HIGH", 11),
        DonutSegment("MEDIUM", 27),
        DonutSegment("LOW", 58),
        DonutSegment("INFO", 142),
    ]
    chart.set_segments(segments)
    chart.set_center_text("242\nEvents")
    chart.resize(360, 360)
    return chart


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_severity_demo()
    demo.setWindowTitle("DonutChart Demo — Light-SIEM Severity")
    demo.show()
    sys.exit(qapp.exec())
