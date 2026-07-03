"""
_time_filter — Woche / Monat / Quartal-Umschalter für das Dashboard.

Steuert global den Zeitraum, auf dessen Basis die Sektion 1
('Was hat sich geändert') und andere zeit-sensitive Widgets arbeiten.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QPushButton,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.domain.models import TimeRange


class _TimeFilter(QWidget):
    """Drei-Button-Gruppe: Woche / Monat / Quartal.

    Default: ``TimeRange.WEEK``.

    Signals:
        range_changed(TimeRange): Emittiert bei Auswahl-Wechsel.
    """

    range_changed = Signal(object)  # TimeRange

    def __init__(
        self,
        initial: TimeRange = TimeRange.WEEK,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._current = initial
        self._buttons: dict[TimeRange, QPushButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._build_ui()
        self._select(initial, emit=False)

    def _build_ui(self) -> None:
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        for tr in (TimeRange.WEEK, TimeRange.MONTH, TimeRange.QUARTER):
            btn = QPushButton(tr.label, self)
            btn.setCheckable(True)
            btn.setFixedHeight(28)
            btn.setMinimumWidth(80)
            btn.clicked.connect(lambda _=False, t=tr: self._select(t))
            self._buttons[tr] = btn
            self._group.addButton(btn)
            lay.addWidget(btn)
        self._apply_styles()

    def _apply_styles(self) -> None:
        c = theme.get()
        for tr, btn in self._buttons.items():
            is_active = tr == self._current
            bg = theme.DARK_ACCENT if is_active else c.BG_BUTTON
            fg = c.BG_DARK if is_active else c.TEXT_MAIN
            border = theme.DARK_ACCENT if is_active else c.BORDER
            btn.setStyleSheet(
                f"QPushButton {{ background: {bg}; color: {fg}; "
                f"border: 1px solid {border}; border-radius: 4px; "
                f"padding: 0 12px; font-size: 12px; }} "
                f"QPushButton:hover {{ border-color: {theme.DARK_ACCENT}; }}"
            )

    def _select(self, tr: TimeRange, emit: bool = True) -> None:
        self._current = tr
        for candidate, btn in self._buttons.items():
            btn.setChecked(candidate == tr)
        self._apply_styles()
        if emit:
            self.range_changed.emit(tr)

    def current(self) -> TimeRange:
        """Gibt den aktuell ausgewählten Zeitraum zurück."""
        return self._current
