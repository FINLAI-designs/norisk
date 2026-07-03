"""network_monitor.gui.anomaly_alert_tab — Live-Anomalie-Alert-Tab F-E).

Zeigt die vom:class:`AnomalyDetectionWorker` periodisch erkannten
Netzwerk-Anomalien als durchsuchbare Tabelle (Muster ``connection_table``) mit
Schweregrad-Farbcodierung und Deep-Link „Diese IP scannen" (Kontextmenue →
``network_scanner``).: Single-Tenant-OSS — kein Free/Pro-Gating mehr.

Der Tab ist rein praesentativ; die Detektion liefert der Worker. Auf Plattformen
ohne den (Windows-only) ETW-Collector bleibt die Liste leer — der Leer-Zustand
benennt die Voraussetzung ehrlich (SoT: ehrliche UI-Degradation).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.network_monitor.domain.models import Anomaly, AnomalySeverity, AnomalyType
from tools.network_monitor.gui.scan_link import show_scan_ip_menu

#: Deutsche Klartext-Labels der sechs Anomalie-Typen (KMU-Sprache, kein Dev-Jargon).
_TYPE_LABELS: dict[AnomalyType, str] = {
    AnomalyType.VOLUME_SPIKE: "Volumen-Spitze",
    AnomalyType.OFF_HOURS: "Aktivität außerhalb der Bürozeiten",
    AnomalyType.GAME_CDN: "Spiele-/CDN-Verkehr",
    AnomalyType.UNKNOWN_PATH: "Unbekannter Programmpfad",
    AnomalyType.DNS_TUNNELING: "Mögliches DNS-Tunneling",
    AnomalyType.SINGLE_IP: "Einzel-IP-Häufung",
}

#: Schweregrad-Labels (deutsch).
_SEVERITY_LABELS: dict[AnomalySeverity, str] = {
    AnomalySeverity.HIGH: "Hoch",
    AnomalySeverity.MEDIUM: "Mittel",
    AnomalySeverity.LOW: "Niedrig",
}

_COLUMNS = ["Schweregrad", "Prozess", "Typ", "Wert / Schwelle", "Ziel-IP", "Detail"]


def _human_bytes(num: int) -> str:
    """Formatiert eine Byte-Zahl menschenlesbar (KB/MB/GB)."""
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024.0 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"


def _value_display(anomaly: Anomaly) -> str:
    """Liefert „Wert / Schwelle" — Query-Anzahl bei DNS-Tunneling, sonst Bytes."""
    if anomaly.anomaly_type is AnomalyType.DNS_TUNNELING:
        return f"{anomaly.value_bytes} / {anomaly.threshold_bytes} Queries"
    return f"{_human_bytes(anomaly.value_bytes)} / {_human_bytes(anomaly.threshold_bytes)}"


class AnomalyAlertTab(QWidget):
    """Tab „Auffälligkeiten" — Live-Anomalie-Alerts (durchsuchbare Detail-Tabelle).

    Single-Tenant-OSS — kein Free/Pro-Gating mehr.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._anomalies: list[Anomaly] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(10)
        self._build_pro_ui(root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def anomaly_count(self) -> int:
        """Anzahl aktuell erkannter Anomalien (fuer den Tab-Titel-Zaehler)."""
        return len(self._anomalies)

    def update_anomalies(self, anomalies: list[Anomaly]) -> None:
        """Uebernimmt die aktuelle Anomalie-Liste und rendert die Tabelle."""
        self._anomalies = list(anomalies)
        self._render_table()

    # ------------------------------------------------------------------
    # Pro-Darstellung: durchsuchbare Tabelle + Deep-Link
    # ------------------------------------------------------------------

    def _build_pro_ui(self, root: QVBoxLayout) -> None:
        self._search = QLineEdit()
        self._search.setObjectName("anomalySearch")
        self._search.setPlaceholderText("Auffälligkeiten durchsuchen (Prozess, IP, Typ) …")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._render_table)
        root.addWidget(self._search)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)
        root.addWidget(self._table, 1)

        self._status = QLabel()
        self._status.setStyleSheet(f"color: {theme.get().TEXT_DIM};")
        root.addWidget(self._status)
        self._render_table()

    def _filtered(self) -> list[Anomaly]:
        """Wendet den Suchtext (case-insensitiv) auf Prozess/IP/Typ-Label an."""
        needle = self._search.text().strip().lower()
        if not needle:
            return self._anomalies
        return [
            a
            for a in self._anomalies
            if needle in a.process_name.lower()
            or needle in a.remote_ip.lower()
            or needle in _TYPE_LABELS.get(a.anomaly_type, a.anomaly_type).lower()
        ]

    def _render_table(self) -> None:
        colors = theme.get()
        rows = self._filtered()
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(rows))
        for row, anomaly in enumerate(rows):
            cells = [
                _SEVERITY_LABELS.get(anomaly.severity, anomaly.severity),
                anomaly.process_name or "–",
                _TYPE_LABELS.get(anomaly.anomaly_type, anomaly.anomaly_type),
                _value_display(anomaly),
                anomaly.remote_ip or "–",
                anomaly.detail or "",
            ]
            bg, fg = self._severity_colors(anomaly.severity, colors)
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if bg is not None:
                    item.setBackground(bg)
                    item.setForeground(fg)
                if col == 4 and anomaly.remote_ip:
                    # Deep-Link-Ziel an der Zeile ablegen (Spalte „Ziel-IP").
                    item.setData(Qt.ItemDataRole.UserRole, anomaly.remote_ip)
                self._table.setItem(row, col, item)
        self._table.setSortingEnabled(True)
        self._update_status(len(rows))

    @staticmethod
    def _severity_colors(
        severity: AnomalySeverity, colors: object
    ) -> tuple[QColor | None, QColor | None]:
        """Mapt Schweregrad → (Hintergrund, Text); LOW bleibt neutral (kein BG)."""
        if severity is AnomalySeverity.HIGH:
            return QColor(colors.SEVERITY_HIGH_BG), QColor(colors.SEVERITY_HIGH_TEXT)
        if severity is AnomalySeverity.MEDIUM:
            return QColor(colors.SEVERITY_MEDIUM_BG), QColor(colors.SEVERITY_MEDIUM_TEXT)
        return None, None

    def _update_status(self, shown: int) -> None:
        total = len(self._anomalies)
        if total == 0:
            hint = (
                "Keine Auffälligkeiten in den letzten 24 h."
                if sys.platform == "win32"
                else "Live-Anomalie-Erkennung benötigt den Windows-Netzwerk-Collector."
            )
            self._status.setText(hint)
        elif shown == total:
            self._status.setText(f"{total} Auffälligkeiten in den letzten 24 h.")
        else:
            self._status.setText(f"{shown} von {total} Auffälligkeiten (gefiltert).")

    def _on_context_menu(self, pos: QPoint) -> None:
        """Rechtsklick auf eine Zeile mit Ziel-IP → „Diese IP scannen" (Deep-Link)."""
        item = self._table.itemAt(pos)
        if item is None:
            return
        ip_item = self._table.item(item.row(), 4)
        ip = ip_item.data(Qt.ItemDataRole.UserRole) if ip_item is not None else None
        show_scan_ip_menu(
            self, str(ip) if ip else "", self._table.viewport().mapToGlobal(pos)
        )
