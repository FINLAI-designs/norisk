"""
upgrade_history_view — Tabellen-Ansicht der bisherigen Patch-Upgrade-Versuche.

Zeigt die letzten N Eintraege (Zeit / App / Version von->auf / Status / Dauer /
Fehler) aus dem:class:`UpgradeHistoryRepository`. Das gemeinsame Verlaufs-Geruest
(Tabelle + Aktualisieren-Button + Empty-State + QSS) liefert die Basis
:class:`core.widgets.history_table_view.HistoryTableView`; hier bleibt nur die
Upgrade-spezifische Zell-Befuellung.

Schichtzugehoerigkeit: gui/ — Repository per Constructor-Injection (Hex-Vertrag).

Author: Patrick Riederich
Version: 2.0 (auf HistoryTableView-Basis)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem

from core import theme
from core.patch_upgrade import UpgradeStatus
from core.widgets.history_table_view import HistoryTableView

_STATUS_LABEL: dict[UpgradeStatus, str] = {
    UpgradeStatus.SUCCESS: "Erfolg",
    UpgradeStatus.FAILED: "Fehlgeschlagen",
    UpgradeStatus.TIMEOUT: "Timeout",
    UpgradeStatus.SKIPPED: "Uebersprungen",
}


def _status_color(status: UpgradeStatus) -> str:
    if status is UpgradeStatus.SUCCESS:
        return theme.SEVERITY_SIGNAL_OK
    if status is UpgradeStatus.FAILED:
        return theme.SEVERITY_SIGNAL_CRITICAL
    return theme.SEVERITY_SIGNAL_HIGH  # TIMEOUT / SKIPPED


class UpgradeHistoryView(HistoryTableView):
    """Verlauf der Patch-Upgrade-Versuche (Zeit/App/Version/Status/Dauer/Fehler)."""

    COL_HEADERS = ("Zeit", "App", "Version", "Status", "Dauer", "Fehler")
    STRETCH_COLS = (1, 5)
    TITLE = "Bisherige Upgrades"
    EMPTY_HINT = "Noch keine Upgrade-Versuche in der Datenbank."
    _NAME = "UpgradeHistory"

    def _fill_row(self, row: int, entry) -> None:  # type: ignore[no-untyped-def]
        self._table.setItem(
            row, 0, QTableWidgetItem(entry.created_at.strftime("%Y-%m-%d %H:%M"))
        )
        self._table.setItem(row, 1, QTableWidgetItem(entry.display_name))
        self._table.setItem(
            row,
            2,
            QTableWidgetItem(f"{entry.version_from or '?'} → {entry.version_to or '?'}"),
        )

        status_item = QTableWidgetItem(_STATUS_LABEL.get(entry.status, str(entry.status)))
        status_item.setBackground(QColor(_status_color(entry.status)))
        status_item.setForeground(QColor("#1a1a1a"))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 3, status_item)

        dur_item = QTableWidgetItem(f"{entry.duration_ms / 1000:.1f}s")
        dur_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 4, dur_item)

        err_item = QTableWidgetItem(entry.error or "")
        if entry.error:
            err_item.setToolTip(entry.error)
        self._table.setItem(row, 5, err_item)
