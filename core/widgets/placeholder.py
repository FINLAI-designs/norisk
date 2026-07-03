"""
placeholder — "coming soon"-Platzhalter-Widget.

Sprint 7 Phase 1: Aus core/main_window.py extrahiert.
Wird vom MainWindow als Default-Widget fuer den Home-Bereich
verwendet, falls kein eigenes Home-Tool registriert ist.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core import theme


class PlaceholderWidget(QWidget):
    """Einfaches Platzhalter-Widget für noch nicht implementierte Features.

    Zeigt einen zentrierten Hinweistext an.
    """

    def __init__(
        self, title: str, message: str = "coming soon", parent: QWidget | None = None
    ) -> None:
        """Initialisiert das Platzhalter-Widget.

        Args:
            title: Titel des Features.
            message: Angezeigter Hinweistext.
            parent: Optionaler Eltern-Widget.
        """
        super().__init__(parent)

        lyt = QVBoxLayout(self)
        lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lyt.setSpacing(12)

        lbl_icon = QLabel("🚧")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_icon.setStyleSheet(
            "font-size: 48px; border: none; background: transparent;"
        )

        lbl_title = QLabel(title)
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_title.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 18px; font-weight: bold; "
            f"color: {theme.get().ACCENT}; border: none; background: transparent;"
        )

        lbl_msg = QLabel(message)
        lbl_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_msg.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; color: {theme.get().TEXT_DIM}; "
            f"border: none; background: transparent;"
        )

        lyt.addWidget(lbl_icon)
        lyt.addWidget(lbl_title)
        lyt.addWidget(lbl_msg)
