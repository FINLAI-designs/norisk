"""
dock_title_bar — Custom-Titlebar fuer QDockWidgets.

Sprint 7 Phase 1: Aus core/main_window.py extrahiert.
Wird vom MainWindow als ``setTitleBarWidget`` an jedes Tool-Dock
gehaengt -- ersetzt die Qt-Standard-Titlebar mit dem FINLAI-Theme
(Teal-Akzent + zwei eckige Buttons fuer Float/Close).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QColor, QEnterEvent, QMouseEvent, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon


class _IconButton(QPushButton):
    """QPushButton mit Material-Symbol-Icon + Hover-Color-Wechsel.

    FE-1-Folge: ersetzt die Unicode-Symbol-Buttons (⧉/✕)
    in der DockTitleBar. Hover-Color-Wechsel laeuft ueber
    ``enterEvent``/``leaveEvent``, weil QIcon nicht ueber CSS-Selektoren
    eingefaerbt werden kann.

    Args:
        icon_name: Material-Symbol-Key (siehe ``core.icons.Icons``).
        normal_color: Default-Icon-Farbe (Hex).
        hover_color: Hover-Icon-Farbe (Hex).
    """

    def __init__(
        self,
        icon_name: str,
        normal_color: str,
        hover_color: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._icon_name = icon_name
        self._normal_color = normal_color
        self._hover_color = hover_color
        self._apply_icon(normal_color)

    def set_icon_name(self, icon_name: str) -> None:
        """Wechselt den Material-Symbol-Key (z. B. fuer State-Toggle)."""
        self._icon_name = icon_name
        self._apply_icon(self._normal_color)

    def _apply_icon(self, color: str) -> None:
        self.setIcon(get_icon(self._icon_name, color=color))

    def enterEvent(self, event: QEnterEvent) -> None:  # noqa: D401
        self._apply_icon(self._hover_color)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: ANN001
        self._apply_icon(self._normal_color)
        super().leaveEvent(event)


class DockTitleBar(QWidget):
    """Eigener DockWidget-Titelbalken mit Float- und Close-Button.

    Reagiert auf ``topLevelChanged`` des zugehörigen QDockWidget,
    damit das Float-Icon immer korrekt ist — auch wenn der Nutzer
    das Dock per Drag abdockt statt über den Button.

    Sicherheit: Verwendet objectName-basierte QSS-Selektoren damit
    der Container-Stylesheet die Kind-Buttons nicht überschreibt.
    """

    def __init__(self, title: str, dock: QDockWidget) -> None:
        super().__init__()
        self._dock = dock
        self.setObjectName("DockTitleBar")
        #/: Drag-State fuer Tab-Drag-to-Split.
        # Der setTitleBarWidget-Setup hat den Qt-Standard-Drag-Handler
        # abgeschaltet — wir bilden ihn hier manuell nach: bei Maus-Drag
        # ueber die start_drag_distance wird das Dock auf floating
        # geschaltet und mit der Maus verfolgt. Wenn der User auf eine
        # MainWindow-Edge oder einen anderen Dock dropt, snapt Qt's
        # ``AllowNestedDocks`` automatisch in einen Split bzw. Tab.
        self._drag_start_pos: QPoint | None = None
        self._drag_global_offset: QPoint | None = None
        self.setCursor(Qt.CursorShape.SizeAllCursor)

        # Expliziter Hintergrund über QPalette (verhindert Transparenz)
        self.setAutoFillBackground(True)
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(theme.get().CARD_BG))
        self.setPalette(pal)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 6, 4)
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            f"color: {theme.get().TEXT_MAIN}; "
            f"font-family: 'Raleway'; font-size: 13px; "
            f"border: none; background: transparent;"
        )
        layout.addWidget(title_label)
        layout.addStretch()

        # Float-Button (abdocken/andocken)
        self._btn_float = self._make_btn(
            icon_name=Icons.OPEN_IN_FULL,
            tooltip="Fenster abdocken",
            hover_color=theme.DARK_ACCENT_DIM,
        )
        self._btn_float.clicked.connect(self._toggle_float)
        layout.addWidget(self._btn_float)

        # Close-Button
        self._btn_close = self._make_btn(
            icon_name=Icons.CLOSE,
            tooltip="Fenster schließen",
            hover_color=theme.get().DANGER,
            is_close=True,
        )
        self._btn_close.clicked.connect(dock.close)
        layout.addWidget(self._btn_close)

        self.setFixedHeight(36)
        self.setMinimumWidth(80)

        # Sync float icon when dock is dragged out / snapped back
        dock.topLevelChanged.connect(self._on_top_level_changed)
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    # ------------------------------------------------------------------
    @staticmethod
    def _make_btn(
        icon_name: str,
        tooltip: str,
        hover_color: str,
        is_close: bool = False,
    ) -> _IconButton:
        """Erzeugt einen 26x26 Teal-Button mit Material-Symbol fuer die Dock-Titelleiste.

        Hover-Icon-Color: weiss fuer Close (roter Background), dunkel fuer Float
        (heller Background). Background-/Border-Hover laeuft ueber QSS; die
        Icon-Farbe wechselt die ``_IconButton``-Klasse via enter/leave.
        """
        hover_icon_color = "#ffffff" if is_close else theme.get().BG_DARK
        btn = _IconButton(
            icon_name=icon_name,
            normal_color=theme.DARK_ACCENT,
            hover_color=hover_icon_color,
        )
        btn.setFixedSize(26, 26)
        btn.setIconSize(QSize(14, 14))
        btn.setToolTip(tooltip)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {theme.DARK_ACCENT};
                border-radius: 4px;
                padding: 0px;
            }}
            QPushButton:hover {{
                background: {hover_color};
                border: 1px solid {hover_color};
            }}
            QPushButton:pressed {{
                background: {hover_color};
                border: 1px solid {hover_color};
            }}
        """)
        # KEIN setVisible(True)/raise_ vor dem Parenting — der Button
        # ist hier noch parentlos; setVisible(True) mappt ihn sofort als
        # natives Top-Level-Fenster (~31 ms sichtbarer Blitz, 2 Buttons x
        # ~20 Docks = 40 Blitze beim MainWindow-Bau). Nach layout.addWidget
        # sind Kinder ohnehin default-sichtbar.
        return btn

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert DockTitleBar-Farben auf das aktive Theme."""
        c = theme.get()
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(c.CARD_BG))
        self.setPalette(pal)
        self.setStyleSheet(f"""
            QWidget#DockTitleBar {{
                background: {c.CARD_BG};
                border-bottom: 1px solid {theme.DARK_BORDER};
            }}
        """)
        self._btn_float.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {theme.DARK_ACCENT};
                border-radius: 4px;
                padding: 0px;
            }}
            QPushButton:hover {{
                background: {theme.DARK_ACCENT_DIM};
                border: 1px solid {theme.DARK_ACCENT_DIM};
            }}
            QPushButton:pressed {{
                background: {theme.DARK_ACCENT_DIM};
                border: 1px solid {theme.DARK_ACCENT_DIM};
            }}
        """)
        self._btn_close.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {theme.DARK_ACCENT};
                border-radius: 4px;
                padding: 0px;
            }}
            QPushButton:hover {{
                background: {c.DANGER};
                border: 1px solid {c.DANGER};
            }}
            QPushButton:pressed {{
                background: {c.DANGER};
                border: 1px solid {c.DANGER};
            }}
        """)

    # ------------------------------------------------------------------
    def _toggle_float(self) -> None:
        self._dock.setFloating(not self._dock.isFloating())

    def _on_top_level_changed(self, floating: bool) -> None:
        if floating:
            # Losgeloeste Docks bekommen OS-Fensterrahmen mit Resize-Handles
            self._dock.setWindowFlags(
                Qt.WindowType.Window
                | Qt.WindowType.WindowCloseButtonHint
                | Qt.WindowType.WindowMaximizeButtonHint
                | Qt.WindowType.WindowMinimizeButtonHint
            )
            self._dock.show()
            self._btn_float.set_icon_name(Icons.CLOSE_FULLSCREEN)
            self._btn_float.setToolTip("Fenster andocken")
        else:
            self._btn_float.set_icon_name(Icons.OPEN_IN_FULL)
            self._btn_float.setToolTip("Fenster abdocken")

    # ------------------------------------------------------------------
    # /: Drag-to-Float (Voraussetzung fuer Drag-to-Split/-Tab)
    # ------------------------------------------------------------------
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Speichert den Drag-Start-Punkt bei Linksklick auf die Title-Bar."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos = event.position().toPoint()
            # Offset von der Maus-Position zur linken oberen Ecke des Docks
            # — wird beim Drag verwendet, damit der Cursor relativ zur
            # Title-Bar bleibt.
            self._drag_global_offset = (
                event.globalPosition().toPoint() - self._dock.frameGeometry().topLeft()
            )
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Bei Drag > startDragDistance: Dock floaten + mit Maus verfolgen.

        Sobald das Dock floating ist, kann der User es per Maus an eine
        andere Edge des MainWindow oder ueber einen anderen Dock ziehen —
        Qt snapt automatisch in Split (``AllowNestedDocks``) oder Tab
        (``AllowTabbedDocks``). Beim Loslassen der Maus passiert das
        finale Snap.
        """
        if (
            not (event.buttons() & Qt.MouseButton.LeftButton)
            or self._drag_start_pos is None
            or self._drag_global_offset is None
        ):
            super().mouseMoveEvent(event)
            return

        distance = (event.position().toPoint() - self._drag_start_pos).manhattanLength()
        threshold = QApplication.startDragDistance()

        if not self._dock.isFloating():
            # Erst losschalten, wenn die Drag-Schwelle ueberschritten ist —
            # einfache Klicks oder Mikrobewegungen sollen nichts ausloesen.
            if distance < threshold:
                super().mouseMoveEvent(event)
                return
            self._dock.setFloating(True)

        # Floating-Dock mit Maus mitziehen — relativer Offset bleibt konstant.
        new_pos = event.globalPosition().toPoint() - self._drag_global_offset
        self._dock.move(new_pos)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        """Drag-State zuruecksetzen — Qt-Native-Snap macht den Rest.

        Wenn der User das floating Dock ueber einer Edge oder einem
        anderen Dock loslaesst, snapt Qt es automatisch in das Layout
        (``setFloating(False)``-equivalent). Wenn das Dock outside snapt,
        bleibt es floating.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos = None
            self._drag_global_offset = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        """Doppelklick auf Title-Bar = Float-Toggle (Qt-Standard-Verhalten)."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._toggle_float()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)
