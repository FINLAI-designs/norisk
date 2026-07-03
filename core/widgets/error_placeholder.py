"""
error_placeholder — Fallback-Widget für fehlgeschlagene Tool-Initialisierungen.

Wird vom Lazy-Loader (``MainWindow._on_dock_visible``) eingesetzt, wenn
``tool_ref.create_widget`` eine Exception wirft. Verhindert dass das
Dock stumm leer bleibt und zeigt dem Anwender eine klare Meldung
statt einer unsichtbaren Fehlfunktion.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from core import theme
from core.icons import Icons, get_icon


class ErrorPlaceholderWidget(QWidget):
    """Zeigt eine freundliche Fehlermeldung anstelle eines gescheiterten Tool-Widgets.

    Args:
        tool_title: Dock-Titel des Tools (z.B. ``"Techstack"``).
        message: Kurze Fehlerbeschreibung für den Anwender.
        detail: Technische Detail-Meldung (Exception-Text). Wird als
            monospace-Label angezeigt, abgeschnitten bei 300 Zeichen.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        tool_title: str,
        message: str,
        detail: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._tool_title = tool_title
        self._message = message
        self._detail = detail[:300] + ("…" if len(detail) > 300 else "")
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.setContentsMargins(40, 40, 40, 40)
        root.setSpacing(16)

        card = QFrame()
        card.setObjectName("error_card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(32, 24, 32, 24)
        card_layout.setSpacing(12)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_icon(Icons.WARNING).pixmap(48, 48))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(icon_lbl)

        self._lbl_title = QLabel(f"{self._tool_title} konnte nicht geladen werden")
        self._lbl_title.setObjectName("error_title")
        self._lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_title.setWordWrap(True)
        card_layout.addWidget(self._lbl_title)

        self._lbl_message = QLabel(self._message)
        self._lbl_message.setObjectName("error_message")
        self._lbl_message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_message.setWordWrap(True)
        card_layout.addWidget(self._lbl_message)

        if self._detail:
            self._lbl_detail = QLabel(self._detail)
            self._lbl_detail.setObjectName("error_detail")
            self._lbl_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._lbl_detail.setWordWrap(True)
            card_layout.addWidget(self._lbl_detail)

        hint = QLabel(
            "Bitte App neu starten. Bleibt das Problem bestehen, "
            "kontaktiere den Support."
        )
        hint.setObjectName("error_hint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        card_layout.addWidget(hint)

        root.addWidget(card)

    def apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; }}"
            f"QFrame#error_card {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 8px; max-width: 520px; }}"
            f"QLabel#error_title {{ color: {c.TEXT_MAIN}; font-size: 15px;"
            f" font-weight: 600; background: transparent; border: none; }}"
            f"QLabel#error_message {{ color: {c.TEXT_MAIN}; font-size: 13px;"
            f" background: transparent; border: none; }}"
            f"QLabel#error_detail {{ color: {c.TEXT_DIM}; font-size: 11px;"
            f" font-family: 'JetBrains Mono', Consolas, monospace;"
            f" background: transparent; border: none; }}"
            f"QLabel#error_hint {{ color: {c.TEXT_DIM}; font-size: 11px;"
            f" font-style: italic; background: transparent; border: none; }}"
        )
