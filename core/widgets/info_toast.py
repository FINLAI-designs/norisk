"""info_toast — Generischer, nicht-modaler Hinweis-Toast (Bottom-Right).

Im Gegensatz zum personalisierten:class:`core.widgets.welcome_toast.WelcomeToast`
(Login-spezifisch, Audit-Event, Vorname-Pflicht) ist dieser Toast bewusst
entkoppelt: er zeigt eine beliebige kurze Hinweis-Nachricht an und raeumt
sich danach selbst auf. Erste Verwendung: Patch-Monitor-Hintergrund-Check
meldet "N Updates verfuegbar", auch wenn das Tool gerade nicht
geoeffnet ist.

Design (analog WelcomeToast, Farben aus:mod:`core.theme` statt hardcodiert):
    * Breite: 360 px, Hoehe: 52 px, Margin 24 px
    * Einblenden: 200 ms Slide-In von rechts + Fade-In
    * Sichtbar: 5 s (konfigurierbar)
    * Ausblenden: 500 ms Fade-Out +:meth:`deleteLater`

Defensive Guards:
    * Leere Nachricht →:meth:`show_toast` zeigt NICHTS und raeumt sich auf.
    * Kein Primaer-Screen verfuegbar (Headless/Tests) → Toast wird ohne
      Animation gezeigt und nicht positioniert (kein Crash).
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QGraphicsOpacityEffect, QHBoxLayout, QLabel, QWidget

from core import theme


class InfoToast(QWidget):
    """Nicht-modaler Hinweis-Toast (Bottom-Right), generisch wiederverwendbar."""

    WIDTH = 360
    HEIGHT = 52
    MARGIN = 24
    VISIBLE_MS = 5000
    SLIDE_MS = 200
    FADE_MS = 500

    def __init__(
        self,
        message: str,
        *,
        visible_ms: int = VISIBLE_MS,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Toast.

        Args:
            message: Anzuzeigender Hinweistext (Sie-Form, kurz). Leer →
                der Toast rendert spaeter nicht (:meth:`show_toast`).
            visible_ms: Sichtbarkeitsdauer in Millisekunden (ohne Slide/Fade).
            parent: Optionales Eltern-Widget (Standard: Top-Level).
        """
        super().__init__(parent)
        self._message = (message or "").strip()
        self._visible_ms = visible_ms

        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self.setWindowFlag(Qt.WindowType.Tool, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedSize(self.WIDTH, self.HEIGHT)

        self._build_ui()

        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity)

        self._slide_anim: QPropertyAnimation | None = None
        self._fade_in_anim: QPropertyAnimation | None = None
        self._fade_out_anim: QPropertyAnimation | None = None

    def _build_ui(self) -> None:
        c = theme.get()
        container = QWidget(self)
        container.setObjectName("info_toast_container")
        # Fill am Container selbst (R23): #id-Selektor allein malt den
        # Hintergrund auf einem nackten QWidget nicht zuverlaessig — daher
        # WA_StyledBackground aktivieren. Farben aus dem Theme (R1).
        container.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        container.setStyleSheet(
            "QWidget#info_toast_container {"
            f" background-color: {c.CARD_BG};"
            f" border: 1px solid {c.ACCENT};"
            " border-radius: 10px;"
            "}"
        )
        container.setGeometry(0, 0, self.WIDTH, self.HEIGHT)

        layout = QHBoxLayout(container)
        layout.setContentsMargins(18, 8, 18, 8)
        layout.setSpacing(0)

        label = QLabel(self._message)
        label.setWordWrap(True)
        label.setStyleSheet(
            "QLabel {"
            f" color: {c.ACCENT};"
            " font-family: 'Raleway';"
            " font-size: 13pt;"
            " font-weight: 600;"
            " background: transparent;"
            "}"
        )
        label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(label)

    def show_toast(self) -> None:
        """Positioniert, animiert und zeigt den Toast.

        Defensive Guard: leere Nachricht → kein Render, Self-Cleanup.
        """
        if not self._message:
            self.deleteLater()
            return

        screen = QGuiApplication.primaryScreen()
        if screen is None:
            # Headless/Tests: ohne Screen kein Positionieren/Animieren.
            self.show()
            return
        geo = screen.availableGeometry()

        end_x = geo.right() - self.WIDTH - self.MARGIN
        end_y = geo.bottom() - self.HEIGHT - self.MARGIN
        start_x = geo.right() + 10  # knapp ausserhalb rechts

        self.move(start_x, end_y)
        self.show()
        self.raise_()

        self._slide_anim = QPropertyAnimation(self, b"pos")
        self._slide_anim.setDuration(self.SLIDE_MS)
        self._slide_anim.setStartValue(self.pos())
        self._slide_anim.setEndValue(QPoint(end_x, end_y))
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._fade_in_anim = QPropertyAnimation(self._opacity, b"opacity")
        self._fade_in_anim.setDuration(self.SLIDE_MS)
        self._fade_in_anim.setStartValue(0.0)
        self._fade_in_anim.setEndValue(1.0)

        self._slide_anim.start()
        self._fade_in_anim.start()

        QTimer.singleShot(self.SLIDE_MS + self._visible_ms, self._start_fade_out)

    def _start_fade_out(self) -> None:
        """Startet die Fade-Out-Animation und raeumt danach auf."""
        self._fade_out_anim = QPropertyAnimation(self._opacity, b"opacity")
        self._fade_out_anim.setDuration(self.FADE_MS)
        self._fade_out_anim.setStartValue(1.0)
        self._fade_out_anim.setEndValue(0.0)
        self._fade_out_anim.finished.connect(self._cleanup)
        self._fade_out_anim.start()

    def _cleanup(self) -> None:
        """Schliesst das Fenster und gibt Ressourcen frei."""
        self.close()
        self.deleteLater()


__all__ = ["InfoToast"]
