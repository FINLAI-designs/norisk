"""
header_widget — Begrüßungs-Header des Mainpage-Dashboards.

Zeigt eine tageszeit-abhängige Begrüßung mit Live-Uhr.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core import theme
from core.auth.session import Session
from core.branding import robot_pixmap

_WEEKDAYS = [
    "Montag",
    "Dienstag",
    "Mittwoch",
    "Donnerstag",
    "Freitag",
    "Samstag",
    "Sonntag",
]
_MONTHS = [
    "Januar",
    "Februar",
    "März",
    "April",
    "Mai",
    "Juni",
    "Juli",
    "August",
    "September",
    "Oktober",
    "November",
    "Dezember",
]


class HeaderWidget(QWidget):
    """Begrüßungs-Header mit Live-Uhr.

    Zeigt Begrüßungstext (Orbitron, ACCENT) und Datum/Zeit (Exo 2, TEXT_DIM).
    Die Uhr wird jede Sekunde aktualisiert.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Header-Widget.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self.setFixedHeight(80)
        t = theme.get()
        self.setStyleSheet(
            f"background-color: {t.CARD_BG}; border-bottom: 1px solid {t.ACCENT};"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 8, 20, 8)
        layout.setSpacing(12)

        # FINLAI-Roboter — Fallback: rundes Firmen-Emblem
        logo = QLabel()
        logo.setFixedSize(64, 64)
        logo.setStyleSheet("background: transparent; border: none;")
        pm = robot_pixmap(64)
        if not pm.isNull():
            logo.setPixmap(pm)
        else:
            _logo_path = (
                Path(__file__).parents[3] / "assets" / "logo" / "finlai_logo.png"
            )
            pixmap = QPixmap(str(_logo_path))
            if not pixmap.isNull():
                logo.setPixmap(
                    pixmap.scaled(
                        64,
                        64,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        layout.addWidget(logo)

        # Text-Bereich
        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        self._lbl_greeting = QLabel()
        self._lbl_greeting.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 18px; font-weight: bold; "
            f"color: {t.ACCENT}; background: transparent; border: none;"
        )
        text_col.addWidget(self._lbl_greeting)

        self._lbl_datetime = QLabel()
        self._lbl_datetime.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; color: {t.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )
        text_col.addWidget(self._lbl_datetime)

        layout.addLayout(text_col)
        layout.addStretch()

        # Initialer Update
        self._update_time()

        # Live-Uhr
        self._clock = QTimer(self)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._update_time)
        self._clock.start()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"background-color: {c.CARD_BG}; border-bottom: 1px solid {c.ACCENT};"
        )
        self._lbl_greeting.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 18px; font-weight: bold; "
            f"color: {c.ACCENT}; background: transparent; border: none;"
        )
        self._lbl_datetime.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; color: {c.TEXT_DIM}; "
            f"background: transparent; border: none;"
        )

    def _get_greeting(self) -> str:
        """Gibt eine tageszeit-abhängige Begrüßung zurück."""
        h = datetime.now().hour
        if h < 12:
            return "Guten Morgen"
        if h < 17:
            return "Guten Tag"
        if h < 21:
            return "Guten Abend"
        return "Gute Nacht"

    @staticmethod
    def _resolve_display_name() -> str:
        """Liest den Anzeigenamen des angemeldeten Benutzers aus der Session.

        Prioritaet: ``first_name`` (falls gepflegt) → ``full_name`` →
        ``username``. Wenn kein Benutzer angemeldet ist, wird ein
        leerer String zurueckgegeben — die Begruessung erscheint dann
        ohne Anrede.

        Returns:
            Anzeigename oder ``""``.
        """
        user = Session().current_user
        if user is None:
            return ""
        return user.first_name or user.full_name or user.username or ""

    def _update_time(self) -> None:
        """Aktualisiert Begrüßung und Datum/Zeit-Anzeige."""
        now = datetime.now()
        greeting = self._get_greeting()
        name = self._resolve_display_name()
        if name:
            self._lbl_greeting.setText(f"{greeting}, {name}!")
        else:
            self._lbl_greeting.setText(f"{greeting}!")

        weekday = _WEEKDAYS[now.weekday()]
        month = _MONTHS[now.month - 1]
        self._lbl_datetime.setText(
            f"{weekday}, {now.day}. {month} {now.year} · {now.strftime('%H:%M')}"
        )
