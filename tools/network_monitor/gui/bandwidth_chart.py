"""network_monitor.gui.bandwidth_chart — Live-Linien-Chart (QPainter, 60s Fenster).

Zeichnet zwei Linien (Upload/Download) über ein 60-Sekunden-Ringbuffer-
Fenster. Keine externen Chart-Bibliotheken — reiner QPainter.

Theme-konform: alle Farben via ``core.theme.get``, keine Hex-Werte.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections import deque

from PySide6.QtCore import QPointF, QRectF
from PySide6.QtGui import (
    QColor,
    QFontMetrics,
    QPainter,
    QPaintEvent,
    QPen,
)
from PySide6.QtWidgets import QWidget

from core import theme
from tools.network_monitor.domain.models import AnomalyType

_WINDOW_SECONDS = 60
_PADDING_LEFT = 50
_PADDING_RIGHT = 12
_PADDING_TOP = 18
_PADDING_BOTTOM = 24
_GRID_ROWS = 4
_MARKER_RADIUS = 5
_TICK_HEIGHT = 6


def marker_color_for(anomaly_type: AnomalyType) -> str:
    """Liefert den Theme-Hex-Token fuer einen Anomaly-Marker.

    Pure-Function — separat vom Widget testbar.

    - VOLUME_SPIKE / SINGLE_IP / UNKNOWN_PATH / DNS_TUNNELING → DANGER (rot)
    - OFF_HOURS → WARNING_ORANGE
    - GAME_CDN → INFO (grau-blau)
    """
    if anomaly_type in (
        AnomalyType.VOLUME_SPIKE,
        AnomalyType.SINGLE_IP,
        AnomalyType.UNKNOWN_PATH,
        AnomalyType.DNS_TUNNELING,
    ):
        return theme.DARK_DANGER
    if anomaly_type is AnomalyType.OFF_HOURS:
        return theme.WARNING_ORANGE
    return theme.SEVERITY_SIGNAL_INFO


class BandwidthChart(QWidget):
    """60s-Live-Chart für Upload/Download (in KB/s).

    Eingangspunkt: ``append_sample(upload_kbps, download_kbps)`` — einmal
    pro Sekunde vom Worker aus aufgerufen. Der Chart zeichnet daraus
    zwei gleitende Linien plus Legende.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._uploads: deque[float] = deque(maxlen=_WINDOW_SECONDS)
        self._downloads: deque[float] = deque(maxlen=_WINDOW_SECONDS)
        self._anomalies: deque[AnomalyType | None] = deque(
            maxlen=_WINDOW_SECONDS
        )
        self.setMinimumHeight(180)

    def append_sample(
        self,
        upload_kbps: float,
        download_kbps: float,
        anomaly: AnomalyType | None = None,
    ) -> None:
        """Fügt einen Datenpunkt hinzu (rollt alte Samples heraus).

        Args:
            upload_kbps: Upload-Rate in KB/s.
            download_kbps: Download-Rate in KB/s.
            anomaly: Optional ein:class:`AnomalyType` fuer diesen
                Sample. Wird als farbiger Marker auf der Download-Linie
                und als vertikaler Tick auf der X-Achse gerendert.
        """
        self._uploads.append(float(max(0.0, upload_kbps)))
        self._downloads.append(float(max(0.0, download_kbps)))
        self._anomalies.append(anomaly)
        self.update()

    def clear(self) -> None:
        """Setzt den Puffer zurück."""
        self._uploads.clear()
        self._downloads.clear()
        self._anomalies.clear()
        self.update()

    def paintEvent(self, _event: QPaintEvent) -> None:  # noqa: D401 — Qt-Override
        """Zeichnet Grid, Achsen, zwei Linien, Legende."""
        colors = theme.get()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Hintergrund
        painter.fillRect(self.rect(), QColor(colors.CARD_BG))

        rect = self._plot_rect()
        if rect.width() <= 0 or rect.height() <= 0:
            painter.end()
            return

        max_val = self._max_value()

        self._draw_grid(painter, rect, max_val, colors)
        self._draw_line(painter, rect, self._downloads, max_val, QColor(colors.ACCENT))
        self._draw_line(painter, rect, self._uploads, max_val, QColor(colors.SUCCESS))
        self._draw_anomaly_markers(painter, rect, max_val)
        self._draw_legend(painter, rect, colors)
        painter.end()

    def _plot_rect(self) -> QRectF:
        return QRectF(
            _PADDING_LEFT,
            _PADDING_TOP,
            self.width() - _PADDING_LEFT - _PADDING_RIGHT,
            self.height() - _PADDING_TOP - _PADDING_BOTTOM,
        )

    def _max_value(self) -> float:
        """Y-Achsen-Obergrenze (mit 10 % Puffer, Minimum 1 KB/s)."""
        current_max = 0.0
        if self._uploads:
            current_max = max(current_max, max(self._uploads))
        if self._downloads:
            current_max = max(current_max, max(self._downloads))
        return max(current_max * 1.1, 1.0)

    def _draw_grid(
        self,
        painter: QPainter,
        rect: QRectF,
        max_val: float,
        colors: object,
    ) -> None:
        grid_pen = QPen(QColor(colors.BORDER))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)

        fm = QFontMetrics(painter.font())
        text_pen = QPen(QColor(colors.TEXT_DIM))

        for i in range(_GRID_ROWS + 1):
            y = rect.top() + (rect.height() / _GRID_ROWS) * i
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))

            value = max_val - (max_val / _GRID_ROWS) * i
            label = _format_rate(value)
            painter.setPen(text_pen)
            painter.drawText(
                QPointF(
                    rect.left() - fm.horizontalAdvance(label) - 6,
                    y + fm.height() / 3,
                ),
                label,
            )

        # X-Achsen-Label
        painter.setPen(text_pen)
        painter.drawText(
            QPointF(rect.left(), rect.bottom() + fm.height() + 2),
            "-60s",
        )
        painter.drawText(
            QPointF(
                rect.right() - fm.horizontalAdvance("jetzt"),
                rect.bottom() + fm.height() + 2,
            ),
            "jetzt",
        )

    def _draw_line(
        self,
        painter: QPainter,
        rect: QRectF,
        samples: deque[float],
        max_val: float,
        color: QColor,
    ) -> None:
        if not samples:
            return
        step = rect.width() / max(_WINDOW_SECONDS - 1, 1)
        start_x = rect.left() + (
            rect.width() - step * (len(samples) - 1) if len(samples) > 1 else 0
        )

        pen = QPen(color)
        pen.setWidthF(2.0)
        painter.setPen(pen)

        prev_point: QPointF | None = None
        for i, value in enumerate(samples):
            x = start_x + step * i
            norm = 0.0 if max_val <= 0 else min(value / max_val, 1.0)
            y = rect.bottom() - rect.height() * norm
            point = QPointF(x, y)
            if prev_point is not None:
                painter.drawLine(prev_point, point)
            prev_point = point

    def _draw_anomaly_markers(
        self,
        painter: QPainter,
        rect: QRectF,
        max_val: float,
    ) -> None:
        """Zeichnet Marker auf der Download-Linie + X-Achsen-Ticks.

        Marker liegen pixel-getreu am selben x-Offset wie die Linien, damit
        die User die Anomalie zeitlich klar zur Spitze zuordnen koennen.
        """
        if not any(a is not None for a in self._anomalies):
            return
        step = rect.width() / max(_WINDOW_SECONDS - 1, 1)
        n = len(self._anomalies)
        start_x = rect.left() + (
            rect.width() - step * (n - 1) if n > 1 else 0
        )
        for i, anomaly in enumerate(self._anomalies):
            if anomaly is None:
                continue
            color = QColor(marker_color_for(anomaly))
            x = start_x + step * i
            value = self._downloads[i] if i < len(self._downloads) else 0.0
            norm = 0.0 if max_val <= 0 else min(value / max_val, 1.0)
            y = rect.bottom() - rect.height() * norm
            # Filled-Marker auf der Linie
            painter.setBrush(color)
            painter.setPen(QPen(color, 1))
            painter.drawEllipse(QPointF(x, y), _MARKER_RADIUS, _MARKER_RADIUS)
            # Tick unter der X-Achse
            tick_pen = QPen(color, 2)
            painter.setPen(tick_pen)
            painter.drawLine(
                QPointF(x, rect.bottom()),
                QPointF(x, rect.bottom() + _TICK_HEIGHT),
            )

    def _draw_legend(self, painter: QPainter, rect: QRectF, colors: object) -> None:
        fm = QFontMetrics(painter.font())
        margin = 12
        swatch = 10
        gap = 6
        items = [
            ("Download", QColor(colors.ACCENT)),
            ("Upload", QColor(colors.SUCCESS)),
        ]
        # rechts oben
        x = rect.right()
        y = rect.top() - 2
        for label, color in reversed(items):
            text_w = fm.horizontalAdvance(label)
            x -= text_w
            painter.setPen(QPen(QColor(colors.TEXT_MAIN)))
            painter.drawText(QPointF(x, y), label)
            x -= gap + swatch
            painter.fillRect(
                QRectF(x, y - swatch, swatch, swatch),
                color,
            )
            x -= margin


def _format_rate(value_kbps: float) -> str:
    """Formatiert KB/s oder MB/s je nach Größenordnung."""
    if value_kbps >= 1024:
        return f"{value_kbps / 1024:.1f} MB/s"
    return f"{value_kbps:.0f} KB/s"
