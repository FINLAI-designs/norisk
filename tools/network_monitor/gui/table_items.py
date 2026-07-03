"""network_monitor.gui.table_items — geteilte Tabellen-Item-Helfer.

Geteilte Qt-Tabellen-Items für die Netzwerkmonitor-Tabs, damit die Sortier-Logik
nur EINMAL existiert (DRY-Review ARCH-01): genutzt von
``process_traffic_view`` (Byte-Spalten) und ``conversation_tab`` (Verbindungs-Anzahl).

Schichtzugehörigkeit: gui/ (Qt-Widgets-Helfer).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidgetItem


class NumericTableItem(QTableWidgetItem):
    """Tabellen-Item, das numerisch (per UserRole) statt lexikalisch sortiert.

    ``QTableWidget`` sortiert standardmäßig über den DisplayRole-Text — bei
    „27,43 MB" vs „929,00 KB" oder „9" vs „100" wäre das falsch. Dieses Item
    vergleicht über den in ``Qt.ItemDataRole.UserRole`` hinterlegten Roh-Wert und
    fällt bei nicht-numerischen Werten auf den Standard-Vergleich zurück.
    """

    def __lt__(self, other: QTableWidgetItem) -> bool:  # noqa: D401 — Qt-Override
        mine = self.data(Qt.ItemDataRole.UserRole)
        theirs = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(mine, (int, float)) and isinstance(theirs, (int, float)):
            return mine < theirs
        return super().__lt__(other)
