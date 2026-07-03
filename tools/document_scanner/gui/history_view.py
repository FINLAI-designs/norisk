"""
history_view — Tabellen-Ansicht der bisherigen Datei-Scans.

Zeigt die letzten N Eintraege aus dem:class:`HistoryRepository`. Das gemeinsame
Verlaufs-Geruest (Tabelle + Aktualisieren-Button + Empty-State + QSS) liefert die
Basis:class:`core.widgets.history_table_view.HistoryTableView`; hier bleibt nur
die Scan-spezifische Zell-Befuellung (Verdict-Farbe, Groessen-Format).

Schichtzugehoerigkeit: gui/ — Repository per Constructor-Injection (Hex-Vertrag).

Author: Patrick Riederich
Version: 0.2 (auf HistoryTableView-Basis)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTableWidgetItem

from core import theme
from core.widgets.history_table_view import HistoryTableView
from tools.document_scanner.domain.models import ScanVerdict

_VERDICT_LABEL = {
    ScanVerdict.SAFE: "Sicher",
    ScanVerdict.SUSPICIOUS: "Verdaechtig",
    ScanVerdict.DANGEROUS: "Gefaehrlich",
}


def _verdict_color(verdict: ScanVerdict) -> str:
    if verdict is ScanVerdict.DANGEROUS:
        return theme.SEVERITY_SIGNAL_CRITICAL
    if verdict is ScanVerdict.SUSPICIOUS:
        return theme.SEVERITY_SIGNAL_HIGH
    return theme.SEVERITY_SIGNAL_OK


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    v = float(n)
    for u in units:
        if v < 1024:
            return f"{v:.1f} {u}"
        v /= 1024
    return f"{v:.1f} TB"


class HistoryView(HistoryTableView):
    """Liste der historischen Datei-Scans aus der EncryptedDatabase."""

    COL_HEADERS = (
        "Zeit",
        "Datei",
        "Magika",
        "Verdict",
        "Score",
        "Befunde",
        "Groesse",
    )
    STRETCH_COLS = (1,)
    TITLE = "Bisherige Scans"
    EMPTY_HINT = "Noch keine Scans in der Datenbank."
    _NAME = "History"

    def _fill_row(self, row: int, entry) -> None:  # type: ignore[no-untyped-def]
        self._table.setItem(
            row, 0, QTableWidgetItem(entry.scanned_at.strftime("%Y-%m-%d %H:%M"))
        )
        self._table.setItem(row, 1, QTableWidgetItem(entry.original_name))
        self._table.setItem(row, 2, QTableWidgetItem(entry.magika_label))

        verdict_item = QTableWidgetItem(_VERDICT_LABEL[entry.verdict])
        verdict_item.setBackground(QColor(_verdict_color(entry.verdict)))
        verdict_item.setForeground(QColor("#1a1a1a"))
        verdict_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 3, verdict_item)

        score_item = QTableWidgetItem(f"{entry.risk_score}")
        score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 4, score_item)

        tc_item = QTableWidgetItem(str(entry.threat_count))
        tc_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 5, tc_item)

        self._table.setItem(row, 6, QTableWidgetItem(_human_size(entry.size_bytes)))
