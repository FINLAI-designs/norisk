"""network_monitor.gui.interface_overview — Rechte Spalte: Interface-Cards.

Zeigt pro Netzwerk-Interface: Name, IP, MAC, Totalbytes seit Boot,
aktuelle Up-/Download-Rate.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.network_monitor.domain.models import InterfaceStats


class InterfaceOverview(QScrollArea):
    """Scrollbare Liste von Interface-Cards.

    Nimmt per ``update_interfaces(stats)`` den aktuellen Snapshot entgegen
    und baut die Cards komplett neu auf (einfacher als Diff-Tracking —
    Interfaces ändern sich selten).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        self._layout.addStretch(1)
        self.setWidget(self._container)

    def update_interfaces(self, stats: dict[str, InterfaceStats]) -> None:
        """Baut die Interface-Liste anhand eines Stats-Snapshots neu auf."""
        self._clear()
        for name in sorted(stats.keys()):
            card = _build_interface_card(stats[name])
            self._layout.insertWidget(self._layout.count() - 1, card)

    def _clear(self) -> None:
        """Entfernt alle Interface-Cards (nicht den End-Stretch)."""
        while self._layout.count() > 1:
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()


def _build_interface_card(stats: InterfaceStats) -> QFrame:
    """Erstellt eine Card für ein einzelnes Interface."""
    colors = theme.get()
    card = QFrame()
    card.setObjectName("networkMonitorIfaceCard")
    card.setFrameShape(QFrame.Shape.StyledPanel)
    card.setStyleSheet(
        f"QFrame#networkMonitorIfaceCard {{"
        f" background-color: {colors.CARD_BG};"
        f" border: 1px solid {colors.BORDER};"
        f" border-radius: 6px;"
        f" padding: 8px;"
        f"}}"
    )

    layout = QVBoxLayout(card)
    layout.setContentsMargins(10, 8, 10, 8)
    layout.setSpacing(4)

    header = QLabel(stats.name)
    header.setStyleSheet(
        f"font-weight: 600; color: {colors.ACCENT};"
    )
    layout.addWidget(header)

    status_text = "aktiv" if stats.is_up else "inaktiv"
    status_lbl = QLabel(f"Status: {status_text}")
    status_lbl.setStyleSheet(
        f"color: {colors.SUCCESS if stats.is_up else colors.TEXT_DIM};"
    )
    layout.addWidget(status_lbl)

    if stats.ip_address:
        ip_lbl = QLabel(f"IP: {stats.ip_address}")
        ip_lbl.setStyleSheet(f"color: {colors.TEXT_MAIN};")
        layout.addWidget(ip_lbl)

    if stats.mac_address:
        mac_lbl = QLabel(f"MAC: {stats.mac_address}")
        mac_lbl.setStyleSheet(f"color: {colors.TEXT_DIM};")
        layout.addWidget(mac_lbl)

    rate_lbl = QLabel(
        f"↑ {_fmt_rate(stats.upload_kbps)}   ↓ {_fmt_rate(stats.download_kbps)}"
    )
    rate_lbl.setStyleSheet(f"color: {colors.TEXT_MAIN};")
    rate_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
    layout.addWidget(rate_lbl)

    total_lbl = QLabel(
        f"Gesamt: ↑ {_fmt_bytes(stats.bytes_sent_total)}   "
        f"↓ {_fmt_bytes(stats.bytes_recv_total)}"
    )
    total_lbl.setStyleSheet(f"color: {colors.TEXT_DIM};")
    layout.addWidget(total_lbl)

    return card


def _fmt_rate(kbps: float) -> str:
    if kbps >= 1024:
        return f"{kbps / 1024:.2f} MB/s"
    return f"{kbps:.1f} KB/s"


def _fmt_bytes(total: int) -> str:
    mb = total / (1024 * 1024)
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.1f} MB"
