"""HeatmapGrid — generisches Heatmap-Gitter mit QPainter-Rendering.

Vorbild: ``tools/norisk_dashboard/gui/heatmap_widget.py`` (Tag x Scanner-Matrix).
Generalisiert auf beliebige ``rows x cols`` mit Color-Ramp und Klick-Signal.

Hexagonal-konform: nutzt nur ``PySide6`` und ``core.theme`` — keine
Domain-Imports, keine Tool-spezifischen Importe.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from core import theme

_PADDING = 8
_TOP_LABEL_HEIGHT = 24
_LEFT_LABEL_WIDTH = 100
_MIN_CELL_SIZE = 32
_CELL_BORDER = 1


@dataclass(frozen=True)
class HeatmapCell:
    """Daten einer einzelnen Heatmap-Zelle.

    Attributes:
        label: Text in der Zelle (z.B. Counter ``"3"``). Leer = kein Text.
        value: Numerischer Wert in ``[0,1]`` fuer Color-Ramp-Mapping.
            Wird ignoriert wenn ``color`` gesetzt ist.
        color: Optional explizite Farbe (ueberschreibt ``value``).
        tooltip: Hover-Tooltip-Text (z.B. Risiko-Titel).
    """

    label: str = ""
    value: float = 0.0
    color: QColor | None = None
    tooltip: str = ""


def _default_ramp() -> tuple[tuple[float, QColor], ...]:
    """Vier-Stufen-Ampel als Standard-Color-Ramp (SCORE_STAGE_*)."""
    return (
        (0.0, QColor(theme.SCORE_STAGE_SECURE)),
        (0.34, QColor(theme.SCORE_STAGE_MODERATE)),
        (0.67, QColor(theme.SCORE_STAGE_AT_RISK)),
        (1.0, QColor(theme.SCORE_STAGE_CRITICAL)),
    )


def interpolate_ramp_color(
    value: float,
    stops: Sequence[tuple[float, QColor]],
) -> QColor:
    """Interpoliert linear in RGB zwischen den naechsten Color-Ramp-Stops.

    Args:
        value: Wert in ``[0,1]``. Werte ausserhalb werden geclamped.
        stops: Liste von ``(position, QColor)``-Tupeln. Muss mindestens
            einen Stop enthalten und nach Position aufsteigend sortiert
            sein.

    Returns:
        QColor durch lineare RGB-Interpolation der umgebenden Stops.

    Raises:
        ValueError: Wenn ``stops`` leer ist.
    """
    if not stops:
        raise ValueError("stops darf nicht leer sein")
    v = max(0.0, min(1.0, float(value)))
    if v <= stops[0][0]:
        return QColor(stops[0][1])
    if v >= stops[-1][0]:
        return QColor(stops[-1][1])
    for i in range(len(stops) - 1):
        pos_left, color_left = stops[i]
        pos_right, color_right = stops[i + 1]
        if pos_left <= v <= pos_right:
            span = pos_right - pos_left
            if span <= 0:
                return QColor(color_left)
            t = (v - pos_left) / span
            r = round(color_left.red() + t * (color_right.red() - color_left.red()))
            g = round(color_left.green() + t * (color_right.green() - color_left.green()))
            b = round(color_left.blue() + t * (color_right.blue() - color_left.blue()))
            return QColor(r, g, b)
    return QColor(stops[-1][1])


class HeatmapGrid(QWidget):
    """Generisches Heatmap-Gitter (rows x cols) mit QPainter-Rendering.

    Signals:
        cell_clicked(int, int): ``(row_idx, col_idx)`` bei linkem Mausklick
            auf eine Zelle.

    Pflicht-API:
        -:meth:`set_data` — befuellt rows/cols/cells.
        -:meth:`set_color_ramp` — ueberschreibt die Default-Ampel.
        - ``cell_clicked: Signal(int, int)``.

    Theme-konform: nutzt ausschliesslich Tokens aus ``core.theme``.
    """

    cell_clicked = Signal(int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[str] = []
        self._cols: list[str] = []
        self._cells: dict[tuple[int, int], HeatmapCell] = {}
        self._ramp: tuple[tuple[float, QColor], ...] = _default_ramp()

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setMinimumSize(200, 150)
        self.setMouseTracking(True)

    def set_data(
        self,
        rows: Sequence[str],
        cols: Sequence[str],
        cells: dict[tuple[int, int], HeatmapCell],
    ) -> None:
        """Aktualisiert das Gitter.

        Args:
            rows: Zeilen-Labels (oben → unten).
            cols: Spalten-Labels (links → rechts).
            cells: Mapping ``(row_idx, col_idx) → HeatmapCell``. Fehlende
                Eintraege werden als Zelle mit ``HeatmapCell`` (value=0)
                gerendert.
        """
        self._rows = list(rows)
        self._cols = list(cols)
        self._cells = dict(cells)
        self.updateGeometry()
        self.update()

    def set_color_ramp(
        self, stops: Sequence[tuple[float, QColor]]
    ) -> None:
        """Setzt eine neue Color-Ramp fuer das value→color-Mapping.

        Args:
            stops: Mindestens ein ``(position, QColor)``-Tupel.
                Positionen sollten nach Position aufsteigend sortiert sein.

        Raises:
            ValueError: Wenn ``stops`` leer ist.
        """
        if not stops:
            raise ValueError("stops darf nicht leer sein")
        self._ramp = tuple((float(p), QColor(col)) for p, col in stops)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        if not self._rows or not self._cols:
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

        cell_w, cell_h, grid_x, grid_y = self._cell_geometry()

        col_font = QFont()
        col_font.setPointSize(theme.FONT_SIZE_BODY_SM)
        painter.setFont(col_font)
        painter.setPen(QColor(c.TEXT_DIM))
        for col_idx, col_label in enumerate(self._cols):
            x = grid_x + col_idx * cell_w
            painter.drawText(
                QRectF(x, _PADDING, cell_w, _TOP_LABEL_HEIGHT),
                Qt.AlignmentFlag.AlignCenter,
                col_label,
            )

        row_font = QFont()
        row_font.setPointSize(theme.FONT_SIZE_BODY_SM)
        painter.setFont(row_font)
        painter.setPen(QColor(c.TEXT_MAIN))
        for row_idx, row_label in enumerate(self._rows):
            y = grid_y + row_idx * cell_h
            painter.drawText(
                QRectF(_PADDING, y, _LEFT_LABEL_WIDTH - _PADDING, cell_h),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                row_label,
            )

        cell_font = QFont()
        cell_font.setPointSize(theme.FONT_SIZE_BODY)
        cell_font.setBold(True)
        painter.setFont(cell_font)
        for row_idx in range(len(self._rows)):
            for col_idx in range(len(self._cols)):
                cell = self._cells.get((row_idx, col_idx), HeatmapCell())
                fill = (
                    cell.color
                    if cell.color is not None
                    else interpolate_ramp_color(cell.value, self._ramp)
                )
                x = grid_x + col_idx * cell_w
                y = grid_y + row_idx * cell_h
                rect = QRectF(
                    x + _CELL_BORDER,
                    y + _CELL_BORDER,
                    cell_w - 2 * _CELL_BORDER,
                    cell_h - 2 * _CELL_BORDER,
                )
                painter.fillRect(rect, fill)
                painter.setPen(QPen(QColor(c.BORDER), _CELL_BORDER))
                painter.drawRect(rect)
                if cell.label:
                    painter.setPen(QColor(theme.TEXT_ON_ACCENT_DEEP))
                    painter.drawText(
                        rect,
                        Qt.AlignmentFlag.AlignCenter,
                        cell.label,
                    )

        painter.end()

    def _cell_geometry(self) -> tuple[float, float, float, float]:
        """Liefert ``(cell_w, cell_h, grid_x, grid_y)`` fuer das aktuelle Widget."""
        n_cols = max(1, len(self._cols))
        n_rows = max(1, len(self._rows))
        avail_w = max(
            _MIN_CELL_SIZE * n_cols,
            self.width() - _LEFT_LABEL_WIDTH - 2 * _PADDING,
        )
        avail_h = max(
            _MIN_CELL_SIZE * n_rows,
            self.height() - _TOP_LABEL_HEIGHT - 2 * _PADDING,
        )
        cell_w = avail_w / n_cols
        cell_h = avail_h / n_rows
        grid_x = _LEFT_LABEL_WIDTH + _PADDING
        grid_y = _TOP_LABEL_HEIGHT + _PADDING
        return cell_w, cell_h, grid_x, grid_y

    def _cell_at(self, pos: QPointF) -> tuple[int, int] | None:
        """Mappt eine Widget-Position auf ``(row_idx, col_idx)`` oder None."""
        if not self._rows or not self._cols:
            return None
        cell_w, cell_h, grid_x, grid_y = self._cell_geometry()
        if pos.x() < grid_x or pos.y() < grid_y:
            return None
        col_idx = int((pos.x() - grid_x) // cell_w)
        row_idx = int((pos.y() - grid_y) // cell_h)
        if 0 <= row_idx < len(self._rows) and 0 <= col_idx < len(self._cols):
            return row_idx, col_idx
        return None

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        hit = self._cell_at(event.position())
        if hit is not None:
            self.cell_clicked.emit(*hit)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001
        hit = self._cell_at(event.position())
        if hit is None:
            QToolTip.hideText()
            return
        cell = self._cells.get(hit)
        if cell is None or not cell.tooltip:
            QToolTip.hideText()
            return
        QToolTip.showText(
            event.globalPosition().toPoint(), cell.tooltip, self
        )

    def sizeHint(self) -> QSize:
        n_cols = max(1, len(self._cols))
        n_rows = max(1, len(self._rows))
        w = _LEFT_LABEL_WIDTH + n_cols * _MIN_CELL_SIZE + 2 * _PADDING
        h = _TOP_LABEL_HEIGHT + n_rows * _MIN_CELL_SIZE + 2 * _PADDING
        return QSize(w, h)


def _build_bsi_demo() -> HeatmapGrid:
    """Erzeugt ein HeatmapGrid mit einer BSI-200-3-konformen 4x4-Risikomatrix.

    Verwendet von ``__main__`` und vom Snapshot-Test in tests/gui/.
    """
    widget = HeatmapGrid()
    rows = [
        "P=4 (sehr hoch)",
        "P=3 (hoch)",
        "P=2 (moeglich)",
        "P=1 (selten)",
    ]
    cols = [
        "S=1 (gering)",
        "S=2 (begrenzt)",
        "S=3 (betraechtl.)",
        "S=4 (existenzbedr.)",
    ]
    cells: dict[tuple[int, int], HeatmapCell] = {}
    for r in range(4):
        prob = 4 - r  # Wahrscheinlichkeit absteigend (P=4..1)
        for col_idx in range(4):
            impact = col_idx + 1
            score = prob * impact  # 1..16
            cells[(r, col_idx)] = HeatmapCell(
                label=str(score),
                value=(score - 1) / 15.0,
                tooltip=f"P={prob} x S={impact} = {score}",
            )
    widget.set_data(rows, cols, cells)
    widget.resize(640, 420)
    return widget


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_bsi_demo()
    demo.setWindowTitle("HeatmapGrid Demo — BSI 4x4 Risikomatrix")
    demo.show()
    sys.exit(qapp.exec())
