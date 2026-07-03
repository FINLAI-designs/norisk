"""
frameless_shell — Kompakte FINLAI-Titelzeile für rahmenlose Dialoge.

Baustein der „FINLAI-Kapsel"-Hülle: ein rahmenloser Dialog
(``Qt.FramelessWindowHint``) bekommt eine eigene kompakte Titelzeile mit
Maskottchen-Badge, Titel und Minimize-/Close-Buttons. Drag läuft über die
NATIVE Qt6-API ``QWindow.startSystemMove`` — kein kopiertes
``move``-Tracking (DPI-sicher, OS-Kanten-Snap bleibt erhalten).

Kanten-Resize ist bewusst NICHT Teil dieses Moduls: rahmenlose Fenster
mixen dafür den bestehenden:class:`core.resize_mixin.ResizeMixin` ein
(8-Zonen-Resize, scoped per ``watched.window is self`` — koexistiert
mit dem MainWindow-Filter).

Dokumentierter Trade-off der Kapsel (Patrick-Entscheid): Das
Win11-Snap-Layouts-Hover-Menü entfällt (kein nativer Maximize-Button);
Win+Pfeil-Snap und Drag-an-Bildschirmkante bleiben (native Move-Loop).

Schichtzugehörigkeit: core/widgets — kein Tool-spezifisches Wissen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from core import theme
from core.branding import robot_badge_label
from core.icons import ICON_SIZE_SM, Icons, get_icon

# Höhe der kompakten Titelzeile (schlanker als die MainWindow-TitleBar).
TITLE_BAR_HEIGHT = 38

# Badge-Größe des Maskottchens in der Titelzeile.
_BADGE_SIZE = 24

# Kantenlänge der Fenster-Buttons.
_BUTTON_SIZE = 28


class FinlaiChatTitleBar(QWidget):
    """Kompakte Titelzeile mit Maskottchen-Badge für rahmenlose Dialoge.

    Zeigt links das FINLAI-Maskottchen (Null-Fallback: ohne Badge) und den
    Fenstertitel, rechts Minimize- und Close-Buttons. Linksklick + Ziehen
    startet die native System-Move-Loop des Top-Level-Fensters.

    Args:
        title: Anzeigetitel der Titelzeile.
        parent: Eltern-Widget (der rahmenlose Dialog).

    Signals:
        minimize_requested: Klick auf den Minimize-Button.
        close_requested: Klick auf den Close-Button.
    """

    minimize_requested = Signal()
    close_requested = Signal()

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("FinlaiChatTitleBar")
        self.setFixedHeight(TITLE_BAR_HEIGHT)
        self._build_ui(title)
        self.restyle()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self, title: str) -> None:
        """Baut Badge, Titel und Fenster-Buttons auf."""
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 6, 0)
        row.setSpacing(8)

        badge = robot_badge_label(_BADGE_SIZE)
        if badge is not None:
            row.addWidget(badge)

        self._lbl_title = QLabel(title)
        self._lbl_title.setObjectName("FinlaiChatTitleBarTitle")
        # R22: Titel kann dynamisch befüllt werden — nie Auto-RichText
        self._lbl_title.setTextFormat(Qt.TextFormat.PlainText)
        row.addWidget(self._lbl_title)
        row.addStretch()

        self._btn_min = QPushButton()
        self._btn_min.setObjectName("FinlaiChatTitleBarMin")
        self._btn_min.setFixedSize(_BUTTON_SIZE, _BUTTON_SIZE)
        self._btn_min.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_min.setToolTip("Minimieren")
        self._btn_min.clicked.connect(self.minimize_requested)
        row.addWidget(self._btn_min)

        self._btn_close = QPushButton()
        self._btn_close.setObjectName("FinlaiChatTitleBarClose")
        self._btn_close.setFixedSize(_BUTTON_SIZE, _BUTTON_SIZE)
        self._btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_close.setToolTip("Schließen")
        self._btn_close.clicked.connect(self.close_requested)
        row.addWidget(self._btn_close)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def restyle(self) -> None:
        """Wendet den aktiven Theme-Look auf Titelzeile und Buttons an.

        Wird vom Eltern-Dialog im ``apply_theme``-Pfad aufgerufen — die
        Titelzeile registriert bewusst KEINEN eigenen Theme-Listener
        (Lifecycle liegt beim Dialog-Lehre).
        """
        c = theme.get()
        self.setStyleSheet(
            f"QWidget#FinlaiChatTitleBar {{"
            f" background-color: {c.CARD_BG};"
            f" border: none;"
            f" border-bottom: 1px solid {c.BORDER_SIDEBAR};"
            f" border-top-left-radius: 10px;"
            f" border-top-right-radius: 10px;"
            f" }}"
            f"QLabel#FinlaiChatTitleBarTitle {{"
            f" color: {c.TEXT_MAIN};"
            f" font-family: 'Raleway';"
            f" font-size: {theme.FONT_SIZE_BODY_LG}px;"
            f" font-weight: 600;"
            f" background: transparent; border: none;"
            f" }}"
        )
        # Fenster-Buttons: volle State-Matrix mit color+background+border
        # pro State (R26) — eigenes Widget-Stylesheet, da der Container
        # selbst ein Stylesheet trägt (R23).
        flat_states = (
            "QPushButton {{"
            " color: {fg}; background-color: transparent; border: none;"
            " border-radius: 4px; }}"
            "QPushButton:hover {{"
            " color: {fg_hover}; background-color: {bg_hover}; border: none; }}"
            "QPushButton:pressed {{"
            " color: {fg_hover}; background-color: {bg_pressed}; border: none; }}"
            "QPushButton:disabled {{"
            " color: {fg_disabled}; background-color: transparent; border: none; }}"
        )
        self._btn_min.setStyleSheet(
            flat_states.format(
                fg=c.TEXT_DIM,
                fg_hover=c.TEXT_MAIN,
                bg_hover=c.BG_SIDEBAR_HOVER,
                bg_pressed=c.BG_SIDEBAR_SELECTED,
                fg_disabled=c.TEXT_BUTTON_DISABLED,
            )
        )
        self._btn_close.setStyleSheet(
            flat_states.format(
                fg=c.TEXT_DIM,
                fg_hover=c.TEXT_MAIN,
                bg_hover=c.DANGER,
                bg_pressed=c.DANGER,
                fg_disabled=c.TEXT_BUTTON_DISABLED,
            )
        )
        self._btn_min.setIcon(get_icon(Icons.MINIMIZE, color=c.TEXT_DIM))
        self._btn_close.setIcon(get_icon(Icons.CLOSE, color=c.TEXT_DIM))
        for btn in (self._btn_min, self._btn_close):
            btn.setIconSize(QSize(ICON_SIZE_SM, ICON_SIZE_SM))

    # ------------------------------------------------------------------
    # Native Drag
    # ------------------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 — Qt-Override
        """Startet die native System-Move-Loop beim Linksklick.

        ``startSystemMove`` übergibt das Fenster-Verschieben ans
        Betriebssystem — DPI-sicher über Monitorgrenzen, Snap-Verhalten
        an Bildschirmkanten bleibt erhalten (kein manuelles
        ``move``-Tracking, Komitee-Must-Fix).
        """
        if event.button() == Qt.MouseButton.LeftButton:
            window = self.window().windowHandle()
            if window is not None:
                window.startSystemMove()
                event.accept()
                return
        super().mousePressEvent(event)
