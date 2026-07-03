"""
neon_splitter — QSplitter mit Custom-Paint-Handle (neutrale Hairline).

Sprint 7 Phase 1: Aus core/main_window.py extrahiert.
Tonale Schale — neutrale 1px-Hairline (BORDER).
Live-Test (2026-06-27, Patrick): Der frühere Teal-Hover am Sidebar-Trennbalken
wirkte überladen und wurde entfernt. Der Trennbalken selbst (BORDER-Hairline)
bleibt; nur der Teal-Effekt beim Überfahren entfällt. (Betrifft NICHT die
Teal-Hervorhebung der Sidebar-Einträge — die liegt in sidebar_item.py.)

Author: Patrick Riederich
Version: 1.2
"""

from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QSplitter, QSplitterHandle

from core import theme


class NeonSplitterHandle(QSplitterHandle):
    """Splitter-Griff: durchgehend neutrale Hairline (theme BORDER), kein Hover.

    Zeichnet per QPainter in jedem Zustand eine neutrale 1px-Linie. Der frühere
    Teal-Hover ist auf Patrick-Wunsch entfernt — der Trennbalken bleibt,
    der Teal-Effekt beim Navigieren in der Sidebar entfällt.
    """

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(theme.get().BORDER))
        painter.end()

    def sizeHint(self) -> QSize:
        # Effektiv bestimmt setHandleWidth(1) im MainWindow die Breite;
        # der Hint bleibt als Fallback synchron auf 1px.
        return QSize(1, 1)


class NeonSplitter(QSplitter):
    """QSplitter der NeonSplitterHandle fuer alle Griffe verwendet."""

    def createHandle(self) -> QSplitterHandle:
        return NeonSplitterHandle(self.orientation(), self)
