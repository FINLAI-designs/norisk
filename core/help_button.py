"""
help_button — Schwebender Hilfe-Button für das Hauptfenster.

HelpButton ist ein kreisrunder QPushButton der sich rechts unten im
Eltern-Widget positioniert. Er ist per Drag-and-Drop frei verschiebbar;
die Position wird in QSettings gespeichert und beim nächsten Start
wiederhergestellt. Seit trägt er das FINLAI-Maskottchen
(``core.branding.robot_pixmap``) als Badge.

Sicherheitsdesign (STRIDE):
    Elevation: Kein privilegierter Code — nur GUI-Navigation.
    Info Discl.: Kein Logging von Nutzeraktionen.

Schichtzugehörigkeit: core/ — darf PySide6 importieren.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, QSettings, QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QPushButton

from core import theme
from core.branding import robot_pixmap
from core.icons import Icons, get_icon

_BUTTON_SIZE = 48
_BUTTON_RADIUS = 24
_MARGIN = 20
_DRAG_THRESHOLD = 5  # Manhattan-Länge um Drag von Klick zu trennen

_SETTINGS_KEY_X = "HelpButton/x"
_SETTINGS_KEY_Y = "HelpButton/y"


class HelpButton(QPushButton):
    """Schwebender Hilfe-Button — frei verschiebbar, Position persistent.

    Öffnet HelpDialog bei Klick (nicht modal). Ein zweiter Klick
    schließt den Dialog wieder (Toggle-Verhalten). Drag-Threshold von
    5px Manhattan-Länge trennt versehentliche Bewegung von Klick.

    Attributes:
        _dialog: Aktive HelpDialog-Instanz oder None.
        _drag_start: Mausposition beim Drücken (für Drag-Erkennung).
        _drag_origin: Widget-Position beim Drücken.
        _is_dragging: True wenn aktiver Drag läuft.
    """

    def __init__(self, parent=None) -> None:
        """Initialisiert den HelpButton.

        Args:
            parent: Eltern-Widget (typischerweise MainWindow).
        """
        super().__init__(parent)
        self._dialog: object | None = None
        self._drag_start: QPoint | None = None
        self._drag_origin: QPoint | None = None
        self._is_dragging = False
        self._setup_style()
        self.clicked.connect(self._on_click)

    # ------------------------------------------------------------------
    # Positionierung
    # ------------------------------------------------------------------

    def reposition(self) -> None:
        """Positioniert den Button — gespeicherte Position oder rechts unten.

        Wird bei Resize des Eltern-Widgets aufgerufen.
        Prüft ob die gespeicherte Position noch innerhalb des Eltern-Widgets
        liegt; falls nicht, fällt er auf die Standard-Ecke zurück.
        """
        parent = self.parent()
        if parent is None:
            return

        settings = QSettings("finLai", "HelpButton")
        sx = settings.value(_SETTINGS_KEY_X, None)
        sy = settings.value(_SETTINGS_KEY_Y, None)

        default_x = parent.width() - _BUTTON_SIZE - _MARGIN
        default_y = parent.height() - _BUTTON_SIZE - _MARGIN

        if sx is not None and sy is not None:
            x = int(sx)
            y = int(sy)
            # Bounds-Check nach Resize
            x = max(0, min(x, parent.width() - _BUTTON_SIZE))
            y = max(0, min(y, parent.height() - _BUTTON_SIZE))
        else:
            x, y = default_x, default_y

        self.move(x, y)
        self.raise_()

    # ------------------------------------------------------------------
    # Drag-and-Drop
    # ------------------------------------------------------------------

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.pos()
            self._drag_origin = self.pos()
            self._is_dragging = False
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            return
        if self._drag_start is None or self._drag_origin is None:
            return

        delta = event.pos() - self._drag_start
        if not self._is_dragging and delta.manhattanLength() < _DRAG_THRESHOLD:
            return

        self._is_dragging = True
        parent = self.parent()
        if parent is None:
            return

        new_pos = self._drag_origin + delta
        # Innerhalb der Eltern-Grenzen halten
        new_x = max(0, min(new_pos.x(), parent.width() - _BUTTON_SIZE))
        new_y = max(0, min(new_pos.y(), parent.height() - _BUTTON_SIZE))
        self.move(new_x, new_y)
        self.raise_()

    def mouseReleaseEvent(self, event) -> None:
        if self._is_dragging:
            # Position persistieren
            settings = QSettings("finLai", "HelpButton")
            settings.setValue(_SETTINGS_KEY_X, self.x())
            settings.setValue(_SETTINGS_KEY_Y, self.y())
            self._is_dragging = False
            self._drag_start = None
            self._drag_origin = None
            # Klick-Signal unterdrücken: kein clicked nach Drag
            event.accept()
            return
        self._drag_start = None
        self._drag_origin = None
        super().mouseReleaseEvent(event)

    # ------------------------------------------------------------------
    # Interne Methoden
    # ------------------------------------------------------------------

    def _setup_style(self) -> None:
        """Setzt Größe, Icon und Stylesheet des Buttons.

        Der Button trägt das FINLAI-Maskottchen (rundes Badge aus
        ``core.branding.robot_pixmap``) statt des Teal-Kreises mit
        Hilfe-Icon. Fehlt das Asset, bleibt der bisherige Stil als
        Fallback erhalten.
        """
        self.setFixedSize(QSize(_BUTTON_SIZE, _BUTTON_SIZE))
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        c = theme.get()
        robot = robot_pixmap(_BUTTON_SIZE)
        if not robot.isNull():
            self.setIcon(QIcon(robot))
            self.setIconSize(QSize(_BUTTON_SIZE, _BUTTON_SIZE))
            self.setToolTip(
                "Ich bin FINLAI — Handbuch & KI-Chat. Du kannst mich verschieben."
            )
            # Badge ist selbst rund; Button bleibt transparent, Hover/Pressed
            # zeigen einen Ring (R26: je State color+background+border).
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: transparent;
                    border-radius: {_BUTTON_RADIUS}px;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: transparent;
                    color: transparent;
                    border-radius: {_BUTTON_RADIUS}px;
                    border: 2px solid {c.ACCENT};
                }}
                QPushButton:pressed {{
                    background-color: transparent;
                    color: transparent;
                    border-radius: {_BUTTON_RADIUS}px;
                    border: 2px solid {c.BG_SIDEBAR_SELECTED};
                }}
                QPushButton:disabled {{
                    background-color: transparent;
                    color: transparent;
                    border-radius: {_BUTTON_RADIUS}px;
                    border: none;
                }}
            """)
            return

        self.setIcon(get_icon(Icons.HELP_CENTER))
        self.setIconSize(QSize(28, 28))
        self.setToolTip("Hilfe & Handbuch (FINLAI) — verschiebbar")
        # R26-Nachzug (Boy-Scout): je State color+background+border.
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {c.ACCENT};
                color: {c.BG_MAIN};
                border-radius: {_BUTTON_RADIUS}px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {c.BG_SIDEBAR_HOVER};
                color: {c.BG_MAIN};
                border: none;
            }}
            QPushButton:pressed {{
                background-color: {c.BG_SIDEBAR_SELECTED};
                color: {c.BG_MAIN};
                border: none;
            }}
            QPushButton:disabled {{
                background-color: {c.BG_SIDEBAR_HOVER};
                color: {c.BG_MAIN};
                border: none;
            }}
        """)

    def _on_click(self) -> None:
        """Öffnet das zentrale NoRisk-HelpDialog (Tab Handbuch + FINLAI-Assistent).

        Seit Phase 2 (24.04.2026) wird das neue kombinierte HelpDialog aus
        ``core.help.help_dialog`` geöffnet statt direkt den alten RAG-Chat.
        Toggle-Verhalten (zweiter Klick schließt den Dialog) bleibt erhalten.

        Das neue HelpDialog hat zwei Tabs:
          * "Handbuch" — statisches Kapitel-Handbuch mit Volltextsuche
          * "FINLAI-Assistent" — inline eingebetteter vereinter Assistent
            (Bedienung + IT-Sicherheit), seit kein Launcher mehr
        """
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        if self._dialog is not None and self._dialog.isVisible():  # type: ignore[union-attr]
            self._dialog.close()  # type: ignore[union-attr]
            self._dialog = None
            return

        parent = self.parent()
        self._dialog = HelpDialog(parent=parent)
        self._dialog.show()  # type: ignore[union-attr]
