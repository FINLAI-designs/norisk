"""
help_tooltip — Kleiner ``?``-Button mit QToolTip oder InfoDialog.

``HelpButton`` ist ein runder 18×18-Pixel-Button mit Material-Symbol
``help``. Bei Klick wird der Tooltip-Text angezeigt:

* **Kurze Texte (< 120 Zeichen):** wirksam über ``QToolTip.showText``
  an der Cursor-Position.
* **Längere Texte:** über einen kleinen, nicht-blockierenden
:class:`InfoDialog` neben dem Button (via ``show``, nicht ``exec``).

Ein klassischer Hover-Tooltip (``setToolTip``) ist zusätzlich gesetzt,
damit auch Tastaturnutzer die Kurzfassung ohne Klick sehen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon

# Grenze ab der statt QToolTip ein InfoDialog geöffnet wird.
_TOOLTIP_CHARS_LIMIT = 120

_BUTTON_SIZE = 18
_INFO_DIALOG_MIN_W = 320
_INFO_DIALOG_MAX_W = 440


class HelpButton(QPushButton):
    """Runder ``?``-Button neben wichtigen UI-Elementen.

    Args:
        tooltip_text: Der anzuzeigende Hilfetext. Bei < 120 Zeichen wird
            er über ``QToolTip`` angezeigt; bei längeren Texten öffnet
            sich ein:class:`InfoDialog` neben dem Button.
        title: Optionaler Titel für den InfoDialog (Standard: "Hinweis").
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        tooltip_text: str,
        title: str = "Hinweis",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._tooltip_text = tooltip_text or ""
        self._title = title
        self._dialog: InfoDialog | None = None

        self.setFixedSize(_BUTTON_SIZE, _BUTTON_SIZE)
        self.setCursor(Qt.CursorShape.WhatsThisCursor)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setIcon(get_icon(Icons.HELP))
        self.setIconSize(self.size() - self.size() / 3)

        # Hover-Tooltip immer gesetzt — auch für Keyboard-Nutzer.
        self.setToolTip(self._tooltip_text)

        self._apply_theme()
        theme.register_listener(self._apply_theme)
        self.clicked.connect(self._on_clicked)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _on_clicked(self) -> None:
        """Entscheidet nach Textlänge: QToolTip oder InfoDialog."""
        text = self._tooltip_text.strip()
        if not text:
            return
        if len(text) <= _TOOLTIP_CHARS_LIMIT:
            QToolTip.showText(QCursor.pos(), text, self)
            return
        self._open_info_dialog()

    def _open_info_dialog(self) -> None:
        """Öffnet einen kleinen, nicht-blockierenden InfoDialog neben dem Button."""
        if self._dialog is not None and self._dialog.isVisible():
            self._dialog.raise_()
            self._dialog.activateWindow()
            return
        self._dialog = InfoDialog(
            title=self._title, text=self._tooltip_text, parent=self.window()
        )
        # Direkt neben dem Button positionieren.
        global_pos = self.mapToGlobal(self.rect().bottomRight())
        # Verzögert positionieren, damit der Dialog seine tatsächliche
        # Breite kennt und nicht über den Bildschirmrand rutscht.
        QTimer.singleShot(0, lambda: self._position_near_button(global_pos))
        self._dialog.show()

    def _position_near_button(self, anchor) -> None:
        if self._dialog is None:
            return
        x = anchor.x() + 4
        y = anchor.y() + 4
        # Einfacher Rand-Check gegen den Bildschirm des Top-Level-Widgets.
        screen = self.screen() or self.window().screen()
        if screen is not None:
            geo = screen.availableGeometry()
            dialog_rect = self._dialog.rect()
            if x + dialog_rect.width() > geo.right():
                x = max(geo.left(), geo.right() - dialog_rect.width() - 8)
            if y + dialog_rect.height() > geo.bottom():
                y = max(geo.top(), geo.bottom() - dialog_rect.height() - 8)
        self._dialog.move(x, y)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QPushButton {{"
            f" background: transparent; border: none; padding: 0;"
            f" color: {c.TEXT_DIM}; border-radius: {_BUTTON_SIZE // 2}px;"
            f" }}"
            f"QPushButton:hover {{"
            f" background: {c.BG_INPUT}; color: {c.ACCENT};"
            f" }}"
            f"QPushButton:pressed {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK};"
            f" }}"
        )


class InfoDialog(QDialog):
    """Nicht-modaler Info-Dialog für ``HelpButton``-Texte > 120 Zeichen.

    Bewusst klein, mit Titel, Fließtext und einem ``Schließen``-Button.
    Der Dialog blockiert den Workflow nicht — er wird über ``show``
    angezeigt und kann neben dem auslösenden Button bestehen bleiben.

    Args:
        title: Dialog-Titel.
        text: Anzuzeigender Hilfetext.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        title: str,
        text: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(False)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setMinimumWidth(_INFO_DIALOG_MIN_W)
        self.setMaximumWidth(_INFO_DIALOG_MAX_W)

        self._build_ui(title, text)
        self._apply_theme()
        theme.register_listener(self._apply_theme)

    def _build_ui(self, title: str, text: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(8)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("info_dialog_title")
        layout.addWidget(title_lbl)

        body = QLabel(text)
        body.setObjectName("info_dialog_body")
        body.setWordWrap(True)
        body.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(body)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Schließen")
        close_btn.setObjectName("info_dialog_close_btn")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def _apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QLabel#info_dialog_title {{"
            f" color: {c.ACCENT}; font-size: 13px; font-weight: 700;"
            f" background: transparent; border: none;"
            f" }}"
            f"QLabel#info_dialog_body {{"
            f" color: {c.TEXT_MAIN}; font-size: 12px; background: transparent;"
            f" border: none;"
            f" }}"
            f"QPushButton#info_dialog_close_btn {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK}; border: none;"
            f" border-radius: 4px; padding: 6px 14px; font-size: 12px;"
            f" }}"
            f"QPushButton#info_dialog_close_btn:hover {{"
            f" background: {c.ACCENT_DIM};"
            f" }}"
        )
