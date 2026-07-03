"""
section_changes — Sektion 1: 'Was hat sich geändert'.

Zeigt Änderungen seit dem im Dashboard-Header gewählten Zeitraum
(Woche / Monat / Quartal) als Liste mit Badges NEU / GEÄNDERT / GELÖSCHT.

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.norisk_dashboard.domain.models import (
    ChangeEntry,
    ChangeType,
    TimeRange,
)

# noqa: domain-change-badge-palette — gedämpfte Change-Badge-Farben (eigene
# semantische Achse). NICHT in core/theme.py — zentrales Dict pro Tool.
_BADGE_COLORS: dict[ChangeType, tuple[str, str]] = {
    ChangeType.NEW: ("#3a7a43", theme.DARK_TEXT_ON_ACCENT),  # noqa: domain-change-badge-new
    ChangeType.CHANGED: ("#7a5e1f", theme.DARK_TEXT_ON_ACCENT),  # noqa: domain-change-badge-changed
    ChangeType.DELETED: ("#7a3a3a", theme.DARK_TEXT_ON_ACCENT),  # noqa: domain-change-badge-deleted
}


class ChangesSection(QWidget):
    """Liste der Änderungen seit Zeitraum.

    API:
        - update_data(entries, time_range): Liste neu rendern.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(6)

        self._range_hint = QLabel("")
        self._range_hint.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 11px;"
        )
        self._root.addWidget(self._range_hint)

        self._list_host = QWidget(self)
        self._list_layout = QVBoxLayout(self._list_host)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(4)
        self._root.addWidget(self._list_host)

        self._empty = QLabel("Keine Änderungen im ausgewählten Zeitraum.", self)
        self._empty.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 12px;"
        )
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._root.addWidget(self._empty)

    def update_data(
        self,
        entries: list[ChangeEntry],
        time_range: TimeRange,
    ) -> None:
        """Rendert die Liste neu.

        Args:
            entries: Änderungs-Einträge, sortiert (neueste zuerst).
            time_range: Für die Hinweis-Zeile ('Seit Zeitraum').
        """
        self._range_hint.setText(
            f"Seit {time_range.label.lower()} ({time_range.days} Tage) — "
            f"{len(entries)} Einträge"
        )

        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()

        self._empty.setVisible(not entries)
        for e in entries:
            self._list_layout.addWidget(_ChangeRow(e, self._list_host))


class _ChangeRow(QFrame):
    """Einzelne Zeile: [Badge] Titel — Detail — Datum."""

    def __init__(self, entry: ChangeEntry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("changeRow")
        self.setStyleSheet(
            f"#changeRow {{ background: {c.BG_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.setFixedHeight(38)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 4, 10, 4)
        lay.setSpacing(10)

        lay.addWidget(_Badge(entry.change_type, self))

        title = QLabel(entry.title, self)
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; font-weight: bold;"
        )
        title.setFixedWidth(180)
        lay.addWidget(title)

        detail = QLabel(entry.detail, self)
        detail.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 12px;")
        detail.setWordWrap(False)
        detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        lay.addWidget(detail, stretch=1)

        ts = QLabel(f"{entry.timestamp:%d.%m.%Y}", self)
        ts.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        lay.addWidget(ts)


class _Badge(QLabel):
    """Farbiges Label für NEU / GEÄNDERT / GELÖSCHT."""

    def __init__(self, change_type: ChangeType, parent: QWidget | None = None) -> None:
        super().__init__(change_type.badge, parent)
        bg, fg = _BADGE_COLORS[change_type]
        self.setStyleSheet(
            f"background: {bg}; color: {fg}; "
            f"border-radius: 3px; padding: 2px 8px; "
            f"font-size: 10px; font-weight: bold;"
        )
        self.setFixedHeight(20)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
