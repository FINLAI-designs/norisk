"""
breakdown_bars — Sektion 4a: Score-Aufschlüsselung als horizontale Balken.

Eine Zeile pro ScoreComponent:
  [Label 160 px] [Balken-Track mit Füllung] [Score 60 px]

Füllfarbe interpoliert linear zwischen rot (#c62828 bei 0) über gelb
(#c9a227 bei 50) nach grün (#43a047 bei 100).

Bewusst als QPainter-Widget — geringe Datenmenge, keine Abhängigkeit
zu matplotlib und kein separater Canvas.

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme
from tools.security_scoring.domain.models import ScoreComponent

_ROW_HEIGHT = 24
_ROW_SPACING = 6
_PADDING = 10
_LABEL_WIDTH = 160
_VALUE_WIDTH = 60

# RGB-Tupel — Werte identisch zu theme.GRADE_F / GRADE_MID_AMBER / GRADE_A.
# QPainter braucht hier RGB-Komponenten, daher als Tupel; die Hex-Strings
# leben nur im Kommentar. Bei Theme-Änderung beide Stellen synchron halten.
_COLOR_LOW = (198, 40, 40)      # = theme.GRADE_F ("#c62828")
_COLOR_MID = (201, 162, 39)     # = theme.GRADE_MID_AMBER("#c9a227")
_COLOR_HIGH = (67, 160, 71)     # = theme.GRADE_A ("#43a047")


class BreakdownBars(QWidget):
    """Horizontales Balken-Diagramm für ScoreComponents."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._components: list[ScoreComponent] = []
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.setMinimumHeight(80)

    def update_data(self, components: list[ScoreComponent]) -> None:
        """Aktualisiert die Balken-Liste."""
        self._components = list(components)
        needed = max(80, 2 * _PADDING + max(1, len(self._components)) * (
            _ROW_HEIGHT + _ROW_SPACING
        ))
        self.setMinimumHeight(needed)
        self.updateGeometry()
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        if not self._components:
            painter.setPen(QColor(c.TEXT_DIM))
            painter.setFont(QFont("", 10))
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "Noch kein Score berechnet",
            )
            painter.end()
            return

        track_x = _PADDING + _LABEL_WIDTH + 8
        track_width = max(
            50, self.width() - track_x - _VALUE_WIDTH - 2 * _PADDING
        )
        font_label = QFont()
        font_label.setPointSize(10)
        font_value = QFont()
        font_value.setPointSize(10)
        font_value.setBold(True)

        for idx, comp in enumerate(self._components):
            y = _PADDING + idx * (_ROW_HEIGHT + _ROW_SPACING)

            painter.setPen(QColor(c.TEXT_MAIN))
            painter.setFont(font_label)
            painter.drawText(
                QRectF(_PADDING, y, _LABEL_WIDTH, _ROW_HEIGHT),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                comp.name,
            )

            # Track
            painter.setPen(QPen(QColor(c.BORDER), 1))
            painter.setBrush(QColor(c.BG_BUTTON_DISABLED))
            painter.drawRoundedRect(
                QRectF(track_x, y + 4, track_width, _ROW_HEIGHT - 8), 3, 3
            )

            score = max(0.0, min(100.0, float(comp.score)))
            fill_w = track_width * (score / 100.0)
            if fill_w > 0:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(_gradient_color(score))
                painter.drawRoundedRect(
                    QRectF(track_x, y + 4, fill_w, _ROW_HEIGHT - 8), 3, 3
                )

            # Wert
            painter.setPen(QColor(theme.DARK_ACCENT))
            painter.setFont(font_value)
            painter.drawText(
                QRectF(
                    track_x + track_width + 8,
                    y,
                    _VALUE_WIDTH,
                    _ROW_HEIGHT,
                ),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{score:.0f}",
            )

        painter.end()


def _gradient_color(score: float) -> QColor:
    """Lineare RGB-Interpolation zwischen rot (0) → gelb (50) → grün (100)."""
    s = max(0.0, min(100.0, score))
    if s <= 50.0:
        t = s / 50.0
        a, b = _COLOR_LOW, _COLOR_MID
    else:
        t = (s - 50.0) / 50.0
        a, b = _COLOR_MID, _COLOR_HIGH
    r = int(a[0] + (b[0] - a[0]) * t)
    g = int(a[1] + (b[1] - a[1]) * t)
    bl = int(a[2] + (b[2] - a[2]) * t)
    return QColor(r, g, bl)
