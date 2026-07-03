"""network_monitor.gui.connection_table — Sortierbare Verbindungstabelle.

Zeigt aktive Verbindungen (Remote-IP, Ports, Prozess, Status). Verdächtige
Verbindungen werden rot unterlegt (Tooltip = Grund).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from core import theme
from core.help.explain_mode import ExplainMode
from core.help.help_registry import HelpRegistry
from tools.network_monitor.domain.models import ConnectionInfo
from tools.network_monitor.gui.labels import friendly_status, port_with_service
from tools.network_monitor.gui.scan_link import show_scan_ip_menu

# Sprint S1c: Mapping psutil-Status → element_id im
# HELP_NETWORK_MONITOR.explanations-Dict. Wird im Erklär-Mode genutzt,
# um Status-Zellen mit Klartext-Erklärung statt der Kurz-Tooltip
# auszustatten.
_STATUS_EXPLAIN_KEY: dict[str, str] = {
    "ESTABLISHED": "status_established",
    "LISTEN": "status_listen",
    "TIME_WAIT": "status_time_wait",
    "CLOSE_WAIT": "status_close_wait",
    "SYN_SENT": "status_syn_sent",
}

# Mapping Spalten-Index → element_id für die Erklär-Tooltips auf den
# Header-Zellen. Reihenfolge passt zu:data:`_COLUMNS`.
_COLUMN_EXPLAIN_KEYS: list[str] = [
    "col_remote_ip",
    "col_remote_port",
    "col_local_port",
    "col_process",
    "col_pid",
    "col_status",
]

# Sprint S1b: User-facing Spalten-Header in deutscher KMU-Sprache
# (statt "R-Port"/"L-Port"/"PID" aus dem Dev-Jargon). Original-Begriffe
# leben in:data:`_COLUMN_TOOLTIPS` als Hover-Erklärung weiter, damit
# technisch versierte Nutzer:innen den Bezug zur psutil-Welt behalten.
_COLUMNS = [
    "Ziel-IP",
    "Ziel-Port",
    "Eigener Port",
    "Prozess",
    "Prozess-Nr.",
    "Status",
]

_COLUMN_TOOLTIPS = [
    "IP-Adresse des Servers, mit dem dein Computer redet (Remote-IP).",
    "Port am Server (Remote-Port). 443 = HTTPS, 80 = HTTP, 22 = SSH.",
    "Port auf deinem Computer (Local-Port). Meist eine zufällige Nummer.",
    "Name des Programms, das die Verbindung aufgebaut hat.",
    "Eindeutige Nummer des Prozesses im Betriebssystem (PID).",
    "Lebenszyklus der Verbindung — zeigt 'Aktiv verbunden', 'Wartet …' usw.",
]


class ConnectionTable(QTableWidget):
    """QTableWidget für die aktive Verbindungsansicht.

    Args:
        highlight_suspicious: Wenn True werden als verdächtig
            markierte Verbindungen rot unterlegt.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        highlight_suspicious: bool = False,
    ) -> None:
        super().__init__(0, len(_COLUMNS), parent)
        self._highlight_suspicious = highlight_suspicious
        self._last_fingerprint: tuple = ()
        self._setup_ui()
        # Sprint S1c: Erklär-Mode-Wechsel löst Re-Application der
        # Header-Tooltips aus. Die Status-Cell-Tooltips werden bei jedem
        # ``update_connections``-Aufruf neu gesetzt — kein zusätzlicher
        # Subscribe nötig.
        ExplainMode.instance().mode_changed.connect(self._apply_explain_mode)
        self._apply_explain_mode(ExplainMode.instance().is_enabled())
        # Sprint S3d: Cross-Tool-Deep-Link "Diese IP scannen".
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

    def set_highlight_suspicious(self, enabled: bool) -> None:
        """Aktiviert/deaktiviert das Rot-Highlight (z.B. nach Lizenzwechsel)."""
        self._highlight_suspicious = enabled
        # Highlight-Flip erzwingt Re-Render im nächsten update
        self._last_fingerprint = ()

    def update_connections(self, connections: list[ConnectionInfo]) -> None:
        """Ersetzt den Tabelleninhalt; skippt den Rebuild wenn unverändert.

        Der Fingerprint (tuple aus den relevanten Feldern aller Verbindungen)
        wird mit der vorherigen Version verglichen — bei Identität wird kein
        QTableWidgetItem erzeugt. Damit bleibt die Tabelle ruhig, solange
        sich keine Verbindung ändert (häufiger Fall bei stabilem Netzwerk).

        Args:
            connections: Aktuelle Liste aktiver Verbindungen.
        """
        fingerprint = tuple(
            (
                c.remote_ip,
                c.remote_port,
                c.local_port,
                c.pid,
                c.process_name,
                c.status,
                c.suspicious,
            )
            for c in connections
        )
        if fingerprint == self._last_fingerprint:
            return
        self._last_fingerprint = fingerprint

        colors = theme.get()
        self.setSortingEnabled(False)  # während Update deaktivieren
        self.setRowCount(len(connections))
        warn_bg = QColor(colors.SEVERITY_CRITICAL_BG)
        warn_fg = QColor(colors.SEVERITY_CRITICAL_TEXT)

        for row, conn in enumerate(connections):
            remote_display = conn.remote_ip or "–"
            # Sprint S1b: V3 (Well-Known-Port-Anreicherung "443 (HTTPS)")
            # und V1 (Status-Klartext "ESTABLISHED" → "Aktiv verbunden").
            remote_port_display = port_with_service(conn.remote_port)
            local_port_display = port_with_service(conn.local_port)
            status_display = friendly_status(conn.status)
            values = [
                remote_display,
                remote_port_display,
                local_port_display,
                conn.process_name,
                str(conn.pid) if conn.pid else "–",
                status_display,
            ]
            # Tooltip-Beigaben: Original-Werte (Port roh, TCP-Status roh)
            # bleiben für technisch versierte Nutzer:innen verfügbar.
            # Im Erklär-Mode (S1c) wird der Status-Tooltip durch den
            # ausführlichen Klartext aus HELP_NETWORK_MONITOR.explanations
            # ersetzt — Frau M.-Persona soll auf Hover einen Satz lesen,
            # nicht "TCP-Status: ESTABLISHED".
            status_tooltip = (
                f"TCP-Status: {conn.status}" if conn.status else ""
            )
            if ExplainMode.instance().is_enabled() and conn.status:
                explain_key = _STATUS_EXPLAIN_KEY.get(conn.status.upper(), "")
                if explain_key:
                    detail = self._explain_text(explain_key)
                    if detail:
                        status_tooltip = detail
            tooltips: list[str] = [
                "",
                f"Roh-Port: {conn.remote_port}" if conn.remote_port else "",
                f"Roh-Port: {conn.local_port}" if conn.local_port else "",
                "",
                "",
                status_tooltip,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                # Numerische Spalten rechtsbündig und sortierbar
                if col in (1, 2, 4):
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                    )
                    # Port-Spalten: Sortierschlüssel ist die rohe Port-Nummer
                    # (nicht das angereicherte Display "443 (HTTPS)") —
                    # sonst sortiert die Tabelle alphabetisch nach Service-Name.
                    if col == 1:
                        item.setData(
                            Qt.ItemDataRole.UserRole, conn.remote_port or -1
                        )
                    elif col == 2:
                        item.setData(
                            Qt.ItemDataRole.UserRole, conn.local_port or -1
                        )
                    else:
                        item.setData(Qt.ItemDataRole.UserRole, _safe_int(value))
                if tooltips[col]:
                    item.setToolTip(tooltips[col])
                if self._highlight_suspicious and conn.suspicious:
                    item.setBackground(warn_bg)
                    item.setForeground(warn_fg)
                    if conn.suspicious_reason:
                        # Tooltip ohne Emoji-Prefix — die Zeile ist eh
                        # via warn_bg/warn_fg farbcodiert (R2-Compliance).
                        item.setToolTip(
                            f"Verdaechtig: {conn.suspicious_reason}"
                        )
                self.setItem(row, col, item)
        self.setSortingEnabled(True)

    def _setup_ui(self) -> None:
        self.setHorizontalHeaderLabels(_COLUMNS)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, len(_COLUMNS)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

    # ------------------------------------------------------------------
    # Erklär-Layer (Sprint S1c)
    # ------------------------------------------------------------------

    def _explain_text(self, element_id: str) -> str:
        """Liest einen Erklär-Text aus dem HelpRegistry.

        Returns ``""`` wenn der Help-Eintrag oder die element_id fehlt —
        Konsumenten fallen auf den Standard-Tooltip zurück.
        """
        hc = HelpRegistry.get("network_monitor")
        if hc is None:
            return ""
        return hc.explanations.get(element_id, "")

    def _apply_explain_mode(self, enabled: bool) -> None:
        """Wechselt zwischen Standard- und Erklär-Tooltip auf den Headern.

        Bei ``enabled=True`` erhalten die Spalten-Header die ausführlichen
        Erklär-Texte aus:data:`HELP_NETWORK_MONITOR.explanations`. Bei
        ``enabled=False`` greift wieder der knappe S1b-Tooltip aus
:data:`_COLUMN_TOOLTIPS`.

        Cell-Tooltips für Status-Werte werden in:meth:`update_connections`
        beim nächsten Rebuild gesetzt — wenn der Mode sich ändert, ohne
        dass neue Daten kommen, erzwingen wir hier einen Rebuild über
        Reset des Fingerprints.
        """
        for col, fallback in enumerate(_COLUMN_TOOLTIPS):
            header_item = self.horizontalHeaderItem(col)
            if header_item is None:
                continue
            tooltip = fallback
            if enabled:
                detail = self._explain_text(_COLUMN_EXPLAIN_KEYS[col])
                if detail:
                    tooltip = detail
            header_item.setToolTip(tooltip)
        # Re-Render erzwingen, damit die Status-Cell-Tooltips neu gesetzt werden.
        self._last_fingerprint = ()


    # ------------------------------------------------------------------
    # Cross-Tool-Deep-Link (Sprint S3d)
    # ------------------------------------------------------------------

    def _on_context_menu(self, pos: QPoint) -> None:
        """Rechtsklick auf eine Verbindungs-Zeile → "Diese IP scannen" (Deep-Link).

        Liest die Ziel-IP aus der ersten Spalte und delegiert an den geteilten
:func:`tools.network_monitor.gui.scan_link.show_scan_ip_menu`.
        """
        item = self.itemAt(pos)
        if item is None:
            return
        ip_item = self.item(item.row(), 0)
        ip = (ip_item.text() or "").strip() if ip_item is not None else ""
        if ip == "–":
            ip = ""
        show_scan_ip_menu(self, ip, self.viewport().mapToGlobal(pos))


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1
