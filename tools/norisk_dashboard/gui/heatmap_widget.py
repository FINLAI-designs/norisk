"""
heatmap_widget — Scan-Status-Heatmap (QPainter-custom).

Zeigt je Scanner (Zeile) und Tag (Spalte) eine farbige Zelle:
- OK → Teal (DARK_ACCENT)
- WARN → Gelb
- FAIL → Rot
- MISSING → Grau (gedimmt)

Zellgröße ist adaptiv; die Widget-Höhe wächst linear mit der Anzahl
Scanner-Zeilen. Die Heatmap ist rein informativ — kein Klick-Deep-Link
(der frühere Tagesfilter war toter Code, entfernt per / Heatmap-b2).

Bewusst ohne matplotlib — geringe Datenmengen, schneller Render und
keine zusätzliche Abhängigkeit.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from datetime import datetime, timedelta

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme
from tools.norisk_dashboard.domain.models import ScanEntry, ScanStatus

_ROW_HEIGHT = 22
_ROW_SPACING = 3
_LEFT_LABEL_WIDTH = 140
_TOP_LABEL_HEIGHT = 20
_PADDING = 8
_MIN_CELL_WIDTH = 14


class HeatmapWidget(QWidget):
    """Scan-Status-Heatmap (Tool-Zeilen × Tage-Spalten).

    Rein informativ — keine Klick-Navigation: der frühere
    Tagesfilter-Deep-Link war toter Code und wurde entfernt).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[ScanEntry] = []
        self._days: list[datetime] = []
        self._rows: list[tuple[str, str]] = []  # (tool_key, tool_label)
        self._cells: dict[tuple[str, datetime], ScanStatus] = {}

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.setMinimumHeight(80)

    # ------------------------------------------------------------------
    # Daten
    # ------------------------------------------------------------------

    def update_data(self, entries: list[ScanEntry], days: int = 14) -> None:
        """Aktualisiert die Anzeige.

        Args:
            entries: Liste der zuletzt bekannten Scan-Läufe.
            days: Anzahl Tage in der Heatmap (Default: 14).
        """
        self._entries = entries
        self._rows = _unique_rows(entries)
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        self._days = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
        self._cells = {
            (e.tool_key, e.day): e.status for e in entries
        }
        height = _TOP_LABEL_HEIGHT + 2 * _PADDING + max(
            1, len(self._rows)
        ) * (_ROW_HEIGHT + _ROW_SPACING)
        self.setMinimumHeight(height)
        self.updateGeometry()
        self.update()

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        if not self._rows or not self._days:
            painter.setPen(QColor(c.TEXT_DIM))
            painter.setFont(QFont("", 10))
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "Noch keine Scan-Daten",
            )
            painter.end()
            return

        cell_w = max(
            _MIN_CELL_WIDTH,
            (self.width() - _LEFT_LABEL_WIDTH - 2 * _PADDING) // len(self._days),
        )

        # Datum-Labels (oben): nur erste, mittlere, letzte um Clutter zu vermeiden
        painter.setPen(QColor(c.TEXT_DIM))
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        label_y = _PADDING
        for idx, (day_i, label) in enumerate(
            [(0, self._days[0]), (len(self._days) // 2, self._days[len(self._days) // 2]), (len(self._days) - 1, self._days[-1])]
        ):
            x = _LEFT_LABEL_WIDTH + _PADDING + day_i * cell_w
            painter.drawText(
                QRectF(x, label_y, cell_w * 3, _TOP_LABEL_HEIGHT),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                f"{label:%d.%m}",
            )

        # Zeilen
        font_label = QFont()
        font_label.setPointSize(9)
        painter.setFont(font_label)

        for row_idx, (tool_key, tool_label) in enumerate(self._rows):
            row_y = (
                _PADDING
                + _TOP_LABEL_HEIGHT
                + row_idx * (_ROW_HEIGHT + _ROW_SPACING)
            )
            # Tool-Label links
            painter.setPen(QColor(c.TEXT_MAIN))
            painter.drawText(
                QRectF(_PADDING, row_y, _LEFT_LABEL_WIDTH, _ROW_HEIGHT),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                tool_label,
            )

            # Zellen
            for day_idx, day in enumerate(self._days):
                x = _LEFT_LABEL_WIDTH + _PADDING + day_idx * cell_w
                status = self._cells.get((tool_key, day), ScanStatus.MISSING)
                color = _status_color(status, c)
                painter.setBrush(color)
                painter.setPen(QPen(QColor(c.BORDER), 1))
                painter.drawRect(
                    int(x + 1),
                    int(row_y + 1),
                    int(cell_w - 2),
                    int(_ROW_HEIGHT - 2),
                )

        painter.end()


# ----------------------------------------------------------------------
# Hilfen
# ----------------------------------------------------------------------


def _unique_rows(entries: list[ScanEntry]) -> list[tuple[str, str]]:
    """Stabile Reihenfolge pro erstmaligem Auftreten."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for e in entries:
        if e.tool_key in seen:
            continue
        seen.add(e.tool_key)
        out.append((e.tool_key, e.tool_label))
    return out


def _status_color(status: ScanStatus, c) -> QColor:  # noqa: ANN001
    """Farbzuordnung für eine Heatmap-Zelle."""
    if status == ScanStatus.OK:
        return QColor(theme.DARK_ACCENT)
    if status == ScanStatus.WARN:
        return QColor(theme.GRADE_MID_AMBER)
    if status == ScanStatus.FAIL:
        return QColor(c.DANGER)
    return QColor(c.BG_BUTTON_DISABLED)
