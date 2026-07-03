"""
theme_selector — Look-Auswahl-Widget für die Einstellungen.

Zeigt zwei Radio-Buttons (Dark / Hell) mit Mini-Farbvorschau.
Emittiert ``theme_changed(str)`` bei Auswahl.

Author: Patrick Riederich
Version: 2.1
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from core import theme


def _look_previews(name: str) -> dict[str, str]:
    """Gibt echte Farbwerte des Looks für die Mini-Vorschau zurück."""
    c = theme.get(name)
    return {
        "sidebar": c.BG_SIDEBAR,
        "accent": c.ACCENT,
        "content": c.BG_MAIN,
        "bg": c.BG_TITLEBAR,
    }


_LOOK_LABELS_ALL: list[tuple[str, str, str]] = [
    ("dark", "Dark", "Dunkler Hintergrund · FINLAI Teal Akzente"),
]

# Light Theme wurde entfernt — nur noch Dark verfügbar
_LOOK_LABELS: list[tuple[str, str, str]] = _LOOK_LABELS_ALL


class ThemeSelector(QWidget):
    """Widget zur Auswahl eines der zwei FINLAI-Looks.

    Signals:
        theme_changed(str): Emittiert den Look-Namen (``"dark"`` oder ``"hell"``) bei Wechsel.
    """

    theme_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        c = theme.get()

        title = QLabel("Erscheinungsbild")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 14px; "
            f"color: {c.ACCENT}; font-weight: bold;"
        )
        layout.addWidget(title)

        self._group = QButtonGroup(self)
        self._buttons: dict[str, QRadioButton] = {}

        for name, label, desc in _LOOK_LABELS:
            row = QHBoxLayout()
            row.setSpacing(12)

            preview = _make_preview(name)
            row.addWidget(preview)

            rb = QRadioButton(f"{label}  —  {desc}")
            rb.setChecked(theme._current_name == name)
            rb.setStyleSheet(
                f"QRadioButton {{ color: {c.TEXT_MAIN}; font-size: 13px; }}"
            )
            self._group.addButton(rb)
            self._buttons[name] = rb
            row.addWidget(rb)
            row.addStretch()

            layout.addLayout(row)

        layout.addStretch()

        for name, rb in self._buttons.items():
            rb.toggled.connect(lambda checked, n=name: self._on_toggled(checked, n))
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        for name, rb in self._buttons.items():
            rb.setChecked(theme._current_name == name)
            rb.setStyleSheet(
                f"QRadioButton {{ color: {c.TEXT_MAIN}; font-size: 13px; }}"
            )

    def _on_toggled(self, checked: bool, name: str) -> None:
        if not checked:
            return
        theme.set_theme(name)
        app = QApplication.instance()
        if app is not None:
            theme.apply(app)
        self.theme_changed.emit(name)


def _make_preview(name: str) -> QLabel:
    """Zeichnet eine Mini-Farbvorschau des Looks."""
    colors = _look_previews(name)
    pixmap = QPixmap(80, 48)
    painter = QPainter(pixmap)

    bg = QColor(colors["bg"])
    sidebar = QColor(colors["sidebar"])
    accent = QColor(colors["accent"])
    content = QColor(colors["content"])

    painter.fillRect(0, 0, 80, 48, bg)
    painter.fillRect(0, 0, 18, 48, sidebar)
    painter.fillRect(18, 0, 2, 48, accent)
    painter.fillRect(20, 0, 60, 48, content)
    painter.fillRect(26, 10, 28, 4, QColor(accent).lighter(120))
    painter.fillRect(26, 20, 44, 3, QColor(accent).darker(160))
    painter.fillRect(26, 29, 36, 3, QColor(accent).darker(160))
    painter.end()

    label = QLabel()
    label.setPixmap(pixmap)
    label.setFixedSize(80, 48)
    label.setStyleSheet(
        f"border-radius: 4px; border: 1px solid {theme.get().BORDER}; background: transparent;"
    )
    return label
