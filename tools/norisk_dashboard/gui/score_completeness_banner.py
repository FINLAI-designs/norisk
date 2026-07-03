"""score_completeness_banner — Quick-Win W3 (Sprint S3c).

Banner ueber dem Score-Tile, das die UX-Luege "Score 68/100" entkraeftet,
wenn die Daten veraltet/fehlend sind. Liefert pro Tool einen knappen
Status-Pin (frisch / veraltet / fehlend) und eine zusammenfassende Zeile.

Datenquelle: ``DashboardData.completeness`` aus dem
:class:`DashboardAggregator` (Loader fuettert sich aus
:func:`core.registry.last_scan_registry.get_last_scan` — Sprint S0b).

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
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
    CompletenessEntry,
    CompletenessStatus,
)


class ScoreCompletenessBanner(QFrame):
    """Banner mit Frische-Status pro Scan-Tool."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[CompletenessEntry] = []
        self.setObjectName("completenessBanner")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        c = theme.get()
        self.setStyleSheet(
            f"#completenessBanner {{ background: {c.BG_INPUT}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }}"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 8, 14, 8)
        outer.setSpacing(4)

        head_row = QHBoxLayout()
        head_row.setSpacing(8)

        self._icon = QLabel("●", self)
        self._icon.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 14px; background: transparent;"
        )
        head_row.addWidget(self._icon)

        self._headline = QLabel("Vollstaendigkeit unbekannt", self)
        self._headline.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 12px; "
            f"font-weight: bold; background: transparent;"
        )
        head_row.addWidget(self._headline, 1)
        outer.addLayout(head_row)

        # Tool-Pins-Row (1 Pin pro Tool, klickbar fuer Tooltip).
        self._pins_row = QHBoxLayout()
        self._pins_row.setSpacing(6)
        outer.addLayout(self._pins_row)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_entries(self, entries: list[CompletenessEntry]) -> None:
        """Aktualisiert Headline + Pins."""
        self._entries = list(entries)
        self._update_headline()
        self._rebuild_pins()

    # ------------------------------------------------------------------
    # Interna
    # ------------------------------------------------------------------

    def _update_headline(self) -> None:
        c = theme.get()
        if not self._entries:
            self._icon.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 14px; background: transparent;"
            )
            self._headline.setText("Vollstaendigkeit unbekannt")
            return

        outdated = [
            e
            for e in self._entries
            if e.status == CompletenessStatus.OUTDATED
        ]
        missing = [
            e
            for e in self._entries
            if e.status == CompletenessStatus.MISSING
        ]
        total = len(self._entries)
        ok_count = total - len(outdated) - len(missing)

        if missing:
            self._icon.setStyleSheet(
                f"color: {c.DANGER}; font-size: 14px; background: transparent;"
            )
            self._headline.setText(
                f"{len(missing)} Tool(s) ohne Scan, {len(outdated)} veraltet — "
                f"Score-Aussage eingeschraenkt"
            )
        elif outdated:
            self._icon.setStyleSheet(
                f"color: {theme.WARNING_ORANGE}; font-size: 14px; "
                f"background: transparent;"
            )
            self._headline.setText(
                f"{len(outdated)} Tool(s) mit veralteten Daten — "
                f"Refresh empfohlen"
            )
        else:
            self._icon.setStyleSheet(
                f"color: {c.SUCCESS}; font-size: 14px; background: transparent;"
            )
            self._headline.setText(
                f"Score basiert auf frischen Daten ({ok_count}/{total} Tools)"
            )

    def _rebuild_pins(self) -> None:
        # Vorhandene Pins entfernen.
        while self._pins_row.count():
            item = self._pins_row.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

        if not self._entries:
            return

        for entry in self._entries:
            self._pins_row.addWidget(_ToolPin(entry, self))
        self._pins_row.addStretch()


class _ToolPin(QLabel):
    """Ein kleiner Status-Pin pro Tool: Label + Farbe + Tooltip."""

    def __init__(
        self,
        entry: CompletenessEntry,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(entry.tool_label, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(20)

        c = theme.get()
        if entry.status == CompletenessStatus.FRESH:
            border_color = c.SUCCESS
            text_color = c.SUCCESS
        elif entry.status == CompletenessStatus.OUTDATED:
            border_color = theme.WARNING_ORANGE
            text_color = theme.WARNING_ORANGE
        else:
            border_color = c.DANGER
            text_color = c.DANGER
        self.setStyleSheet(
            f"color: {text_color}; font-size: 10px; font-weight: bold; "
            f"background: transparent; "
            f"border: 1px solid {border_color}; border-radius: 3px; "
            f"padding: 1px 6px;"
        )
        self.setToolTip(_pin_tooltip(entry))


def _pin_tooltip(entry: CompletenessEntry) -> str:
    """Baut den Hover-Text fuer einen Tool-Pin."""
    label = {
        CompletenessStatus.FRESH: "frisch (< 7 Tage)",
        CompletenessStatus.OUTDATED: "veraltet (7-30 Tage)",
        CompletenessStatus.MISSING: "kein aktueller Scan",
    }[entry.status]
    if entry.last_scan is None:
        time_part = "Letzter Scan: noch nie"
    else:
        time_part = f"Letzter Scan: {entry.last_scan:%d.%m.%Y %H:%M}"
    return f"{entry.tool_label} — {label}\n{time_part}"
