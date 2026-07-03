"""
empty_state — Zentraler Empty-State für Daten-Flächen AP7, Muster R3).

Vereinheitlicht die drei in AP5 validierten Ad-hoc-Empty-States
(techstack/password_checker/cert_monitor): ein leeres Tabellen-/Tree-
Raster füllt keine halbe Bildschirmhälfte mehr — stattdessen ein
zentrierter Hinweistext, optional mit Call-to-Action-Button.

Typische Verwendung mit ``QStackedWidget``::

    self._empty = EmptyState("Noch keine Daten — klicke auf Scan.")
    stack.addWidget(self._empty) # Index 0
    stack.addWidget(self._tabelle) # Index 1

Bewusst KEIN Ersatz für ``PlaceholderWidget`` (coming-soon-Optik mit
Emoji, R2-Altlast) — dieses Widget ist die Daten-Flächen-Variante.
Kein theme-Listener pro Instanz (Lehre Review-P2-3); Tools rufen
bei Bedarf:meth:`apply_theme` aus ihrem eigenen Theme-Pfad.

Author: Patrick Riederich
Version: 1.0 AP7)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from core import theme
from core.widgets.button_styles import outline_button_qss


class EmptyState(QWidget):
    """Zentrierter Hinweistext mit optionalem CTA-Button.

    Args:
        message: Hinweistext (Du-Form, gern mit 1-2-3-Anleitung).
        cta_text: Beschriftung des optionalen Buttons; leer = kein Button.
        parent: Optionales Eltern-Widget.
        pixmap: Optionales Bild (z. B. ``core.branding.robot_pixmap``);
            wird zentriert OBERHALB der Message angezeigt. ``None`` oder
            Null-Pixmap = kein Bild.

    Signals:
        cta_clicked: Klick auf den CTA-Button.
    """

    cta_clicked = Signal()

    def __init__(
        self,
        message: str,
        cta_text: str = "",
        parent: QWidget | None = None,
        pixmap: QPixmap | None = None,
    ) -> None:
        super().__init__(parent)
        lyt = QVBoxLayout(self)
        lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.setSpacing(12)

        self._pixmap_lbl: QLabel | None = None
        if pixmap is not None and not pixmap.isNull():
            self._pixmap_lbl = QLabel()
            self._pixmap_lbl.setPixmap(pixmap)
            self._pixmap_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._pixmap_lbl.setStyleSheet(
                "background: transparent; border: none;"
            )
            lyt.addWidget(self._pixmap_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        self._message_lbl = QLabel(message)
        self._message_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message_lbl.setWordWrap(True)
        # Hinweistexte sind statisch, aber setText kann dynamische Teile
        # tragen — nie als Auto-RichText interpretieren (R22).
        self._message_lbl.setTextFormat(Qt.TextFormat.PlainText)
        lyt.addWidget(self._message_lbl)

        self._cta_btn: QPushButton | None = None
        if cta_text:
            self._cta_btn = QPushButton(cta_text)
            self._cta_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._cta_btn.setMinimumHeight(36)
            self._cta_btn.clicked.connect(self.cta_clicked)
            lyt.addWidget(self._cta_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.apply_theme()

    # ------------------------------------------------------------------
    def setText(self, text: str) -> None:  # noqa: N802 — Qt-API-Parität
        """Setzt den Hinweistext (API-kompatibel zu QLabel.setText)."""
        self._message_lbl.setText(text)

    def text(self) -> str:
        """Gibt den aktuellen Hinweistext zurück (QLabel-Parität)."""
        return self._message_lbl.text()

    def apply_theme(self) -> None:
        """Aktualisiert die Farben auf den aktiven Look (explizit, kein
        eigener Listener — siehe Modul-Docstring)."""
        c = theme.get()
        self._message_lbl.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
            f" background: transparent; border: none;"
        )
        if self._cta_btn is not None:
            self._cta_btn.setStyleSheet(outline_button_qss())
