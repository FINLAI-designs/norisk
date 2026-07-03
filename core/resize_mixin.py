"""
resize_mixin — Mouse-Edge-Resize fuer rahmenlose QMainWindow-Subklassen.

Sprint 7 Phase 2a: Erster Mixin-Extract aus dem
``MainWindow``-God-Class-Refactor.

Implementiert die 8-Richtungs-Edge-Resize-Logik (Top/Bottom/Left/Right
plus 4 Ecken) ueber einen application-weiten Event-Filter, der
Mouse-Events oberhalb von Child-Widgets abfaengt.

State-Anforderungen (vom MainWindow.__init__ zu setzen):

    self._resize_dir: str = ""
    self._last_cursor_zone: str = ""
    self._resize_cursor_set: bool = False

Verwendung in MainWindow:

    class MainWindow(ResizeMixin, QMainWindow):
        def __init__(self,...):
            super.__init__
            self._resize_dir = ""
            self._last_cursor_zone = ""
            self._resize_cursor_set = False
            QApplication.instance.installEventFilter(self)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPoint, Qt
from PySide6.QtWidgets import QApplication, QWidget

# Pixel vom Rand, innerhalb derer Resize ausgeloest wird.
RESIZE_MARGIN = 8


class ResizeMixin:
    """Mixin: 8-Richtungs-Edge-Resize fuer rahmenlose Hauptfenster.

    Erwartet vom mixenden QMainWindow:
    - geometry/setGeometry/width/height/minimumWidth/minimumHeight
    - mapFromGlobal
    - isMaximized/isFullScreen

    Plus die drei `_resize_*`-State-Felder (siehe Modul-Docstring).
    """

    # Type-Hints fuer State-Felder (nur dokumentarisch — werden vom
    # MainWindow.__init__ gesetzt, nicht hier initialisiert um den
    # Mixin frei von __init__-Verwicklungen zu halten).
    _resize_dir: str
    _last_cursor_zone: str
    _resize_cursor_set: bool

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Applikationsweiter Event-Filter fuer rahmenlose Resize-Logik.

        Args:
            watched: Objekt das das Event empfangen hat.
            event: Das aufgetretene Qt-Event.

        Returns:
            True wenn das Event konsumiert wurde, sonst False.
        """
        if not isinstance(watched, QWidget):
            return False
        if watched.window() is not self:
            return False
        if self.isMaximized() or self.isFullScreen():
            if self._resize_cursor_set:
                QApplication.restoreOverrideCursor()
                self._resize_cursor_set = False
                self._last_cursor_zone = ""
            return False

        etype = event.type()

        if etype == QEvent.Type.MouseButtonPress:
            if event.button() == Qt.MouseButton.LeftButton:
                local = self.mapFromGlobal(event.globalPosition().toPoint())
                direction = self._resize_dir_at(local)
                if direction:
                    self._resize_dir = direction
                    return True

        elif etype == QEvent.Type.MouseMove:
            gpos = event.globalPosition().toPoint()
            local = self.mapFromGlobal(gpos)

            if self._resize_dir:
                self._do_resize(gpos)
                return True
            else:
                d = self._resize_dir_at(local)
                if d != self._last_cursor_zone:
                    self._last_cursor_zone = d
                    if d:
                        cursor = self._cursor_for_dir(d)
                        if not self._resize_cursor_set:
                            QApplication.setOverrideCursor(cursor)
                            self._resize_cursor_set = True
                        else:
                            QApplication.changeOverrideCursor(cursor)
                    else:
                        if self._resize_cursor_set:
                            QApplication.restoreOverrideCursor()
                            self._resize_cursor_set = False

        elif etype == QEvent.Type.MouseButtonRelease:
            if self._resize_dir:
                self._resize_dir = ""
                if self._resize_cursor_set:
                    QApplication.restoreOverrideCursor()
                    self._resize_cursor_set = False
                    self._last_cursor_zone = ""
                return True

        return False

    def _resize_dir_at(self, local: QPoint) -> str:
        """Gibt die Resize-Richtung fuer eine Fenster-lokale Position zurueck.

        Args:
            local: Position relativ zur oberen linken Ecke des Fensters.

        Returns:
            Richtungsstring oder leerer String wenn keine Resize-Zone.
        """
        x, y = local.x(), local.y()
        w, h = self.width(), self.height()
        m = RESIZE_MARGIN

        at_left = x <= m
        at_right = x >= w - m
        at_top = y <= m
        at_bottom = y >= h - m

        if at_top and at_left:
            return "top-left"
        if at_top and at_right:
            return "top-right"
        if at_bottom and at_left:
            return "bottom-left"
        if at_bottom and at_right:
            return "bottom-right"
        if at_left:
            return "left"
        if at_right:
            return "right"
        if at_top:
            return "top"
        if at_bottom:
            return "bottom"
        return ""

    @staticmethod
    def _cursor_for_dir(direction: str) -> Qt.CursorShape:
        """Gibt den passenden Cursor fuer eine Resize-Richtung zurueck.

        Args:
            direction: Richtungsstring wie von ``_resize_dir_at`` zurueckgegeben.

        Returns:
            Qt.CursorShape fuer die gewuenschte Resize-Richtung.
        """
        if direction in ("left", "right"):
            return Qt.CursorShape.SizeHorCursor
        if direction in ("top", "bottom"):
            return Qt.CursorShape.SizeVerCursor
        if direction in ("top-left", "bottom-right"):
            return Qt.CursorShape.SizeFDiagCursor
        if direction in ("top-right", "bottom-left"):
            return Qt.CursorShape.SizeBDiagCursor
        return Qt.CursorShape.ArrowCursor

    def _do_resize(self, global_pos: QPoint) -> None:
        """Passt die Fenster-Geometrie an die aktuelle Mausposition an.

        Args:
            global_pos: Aktuelle globale Mausposition.
        """
        g = self.geometry()
        min_w = self.minimumWidth()
        min_h = self.minimumHeight()
        d = self._resize_dir
        mx = global_pos.x()
        my = global_pos.y()

        x, y, w, h = g.x(), g.y(), g.width(), g.height()

        if "left" in d:
            new_w = g.right() - mx + 1
            if new_w >= min_w:
                x = mx
                w = new_w

        if "right" in d:
            new_w = mx - g.x() + 1
            if new_w >= min_w:
                w = new_w

        if "top" in d:
            new_h = g.bottom() - my + 1
            if new_h >= min_h:
                y = my
                h = new_h

        if "bottom" in d:
            new_h = my - g.y() + 1
            if new_h >= min_h:
                h = new_h

        self.setGeometry(x, y, w, h)
