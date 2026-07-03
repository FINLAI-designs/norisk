"""
welcome_toast — Kleiner Bottom-Right-Toast für die Willkommensnachricht.

Erscheint nach erfolgreichem Login. Zwei Varianten:
    * First-Login (unmittelbar nach Wizard-Completion):
      ``"Willkommen bei {app}, {Vorname}! Dein Konto ist eingerichtet."``
    * Regulär (jeder weitere Login):
      ``"Willkommen zurück, {Vorname}."``

Der App-Name kommt aus:attr:`apps.app_config.AppConfig.display_name` und
wird vom Aufrufer übergeben — kein Hardcoding auf "NoRisk" o. Ä.

Defensive Guards:
    * Leerer / ``None`` Vorname →:meth:`show_toast` bricht früh ab, zeigt
      NICHTS, loggt kein Audit-Event und räumt sich selbst auf. Damit kann
      der Toast niemals einen personalisierten Platzhalter rendern.

Design:
    * Breite: 400 px, Höhe: 56 px
    * Hintergrund: #2A2D30 mit 92 % Opazität
    * Text: FINLAI Teal (#51dacf), Raleway 14 pt
    * Einblenden: 200 ms Slide-In von rechts
    * Sichtbar: 5 s
    * Ausblenden: 500 ms Fade-Out +:meth:`deleteLater`

Audit-Event: ``WELCOME_TOAST_SHOWN`` mit ``{"username", "variant"}``.

Author: Patrick Riederich
Version: 1.1
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

from core.audit_log import AuditLogger
from core.theme import DARK_ACCENT


class WelcomeToast(QWidget):
    """Nicht-modaler Willkommens-Toast (Bottom-Right)."""

    WIDTH = 400
    HEIGHT = 56
    MARGIN = 24
    VISIBLE_MS = 5000
    SLIDE_MS = 200
    FADE_MS = 500

    def __init__(
        self,
        first_name: str | None,
        *,
        first_login: bool,
        app_display_name: str,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Toast.

        Args:
            first_name: Vorname für die persönliche Ansprache.
                              Leer oder ``None`` → Toast rendert später
                              nicht (:meth:`show_toast`).
            first_login: ``True`` direkt nach dem Wizard, sonst ``False``.
            app_display_name: Kurz-Anzeigename der App (z. B. ``"NoRisk"``,
                              ``"FINLAI"``). Wird vom Aufrufer aus der
:class:`AppConfig` geholt.
            parent: Optionales Eltern-Widget (Standard: Top-Level).
        """
        super().__init__(parent)
        self._first_name = (first_name or "").strip()
        self._first_login = first_login
        self._app_display_name = app_display_name.strip() or "FINLAI"

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
        container = QWidget(self)
        container.setObjectName("toast_container")
        container.setStyleSheet(
            "QWidget#toast_container {"
            " background-color: rgba(42, 45, 48, 235);"
            " border-radius: 10px;"
            "}"
        )
        container.setGeometry(0, 0, self.WIDTH, self.HEIGHT)

        layout = QHBoxLayout(container)
        layout.setContentsMargins(18, 8, 18, 8)
        layout.setSpacing(0)

        if self._first_login:
            text = (
                f"Willkommen bei {self._app_display_name}, "
                f"{self._first_name}! Dein Konto ist eingerichtet."
            )
        else:
            text = f"Willkommen zurück, {self._first_name}."

        label = QLabel(text)
        label.setStyleSheet(
            "QLabel {"
            f" color: {DARK_ACCENT};"
            " font-family: 'Raleway';"
            " font-size: 14pt;"
            " font-weight: 600;"
            " background: transparent;"
            "}"
        )
        label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(label)

    def show_toast(self, username: str) -> None:
        """Positioniert, animiert und zeigt den Toast.

        Defensive Guard: Wenn ``first_name`` leer/``None`` ist, wird der
        Toast NICHT gerendert und kein Audit-Event geloggt. Damit kann
        nie ein unpersönlicher Platzhalter-Toast erscheinen.

        Args:
            username: Technischer Benutzername fürs Audit-Log.
        """
        if not self._first_name:
            self.deleteLater()
            return

        screen = QGuiApplication.primaryScreen()
        if screen is None:
            self.show()
            return
        geo = screen.availableGeometry()

        end_x = geo.right() - self.WIDTH - self.MARGIN
        end_y = geo.bottom() - self.HEIGHT - self.MARGIN
        start_x = geo.right() + 10  # knapp außerhalb rechts

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

        QTimer.singleShot(self.SLIDE_MS + self.VISIBLE_MS, self._start_fade_out)

        AuditLogger().log_action(
            "WELCOME_TOAST_SHOWN",
            {
                "username": username,
                "variant": "first_login" if self._first_login else "regular",
            },
        )

    def _start_fade_out(self) -> None:
        """Startet die Fade-Out-Animation und räumt danach auf."""
        self._fade_out_anim = QPropertyAnimation(self._opacity, b"opacity")
        self._fade_out_anim.setDuration(self.FADE_MS)
        self._fade_out_anim.setStartValue(1.0)
        self._fade_out_anim.setEndValue(0.0)
        self._fade_out_anim.finished.connect(self._cleanup)
        self._fade_out_anim.start()

    def _cleanup(self) -> None:
        """Schließt das Fenster und gibt Ressourcen frei."""
        self.close()
        self.deleteLater()
