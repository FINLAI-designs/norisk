"""network_monitor.gui.conversation_tab — Tab „Konversationen" Phase 5).

Macht die „Wer-mit-Wem"-Aggregation sichtbar (Pro): je (Prozess, Ziel-IP) eine
Zeile mit Verbindungs-Anzahl, Ports, Status, Verdacht und Zeitpunkt — reine
Aggregation der Verbindungs-Historie, **kein** Capture.

Filter in zwei Stufen (Phase 5):
  - Laien-Schnellfilter: Toggles „Nur verdächtige" / „Nur extern" + Volltext-Suche.
  - Experten-Filter: ein deklarativer Ausdruck (Feld-Whitelist, kein ``eval``) —
    Parse-Fehler erscheinen inline, die Tabelle bleibt bedienbar.

Daten kommen synchron über den:class:`ConversationService` (30-s-Timer + manueller
Refresh), gespiegelt am ``ProcessTrafficView``-Muster; die Aggregation ist eine
SQL-``GROUP BY`` und damit günstig (vom Parent eingehängt).

Schicht: GUI (Qt). Importiert nur Application + Filter-Logik (gui→application).

Author: Patrick Riederich
Version: 1.0 Phase 5)
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.button_styles import toolbar_button_qss
from tools.network_monitor.application import conversation_filter as cf
from tools.network_monitor.domain.exceptions import ConversationFilterError
from tools.network_monitor.gui.labels import format_bytes
from tools.network_monitor.gui.scan_link import show_scan_ip_menu
from tools.network_monitor.gui.table_items import NumericTableItem

if TYPE_CHECKING:
    from tools.network_monitor.application.conversation_service import (
        ConversationService,
    )
    from tools.network_monitor.domain.models import Conversation

#: Refresh-Intervall der Tabelle in ms (30 s, wie ProcessTrafficView).
_REFRESH_INTERVAL_MS = 30_000
#: Maximale Anzahl Ports/Status, die je Zelle ausgeschrieben werden (Rest „…").
_MAX_TOKENS_PER_CELL = 6
#: Spaltenindex der numerischen „Verbindungen"-Spalte (für Default-Sort).
_COUNT_COLUMN = 2


class ConversationTab(QWidget):
    """Pro-Tab: aggregierte Konversationen + Laien-/Experten-Filter.

    Args:
        service: Liefert die Aggregation. ``None`` baut den echten
:class:`ConversationService` (benötigt ``KeyManager``) fail-soft;
            Tests injizieren ein Fake.
    """

    _COLUMNS = (
        "Prozess",
        "Ziel-IP",
        "Verbindungen",
        "Gesendet",
        "Empfangen",
        "Ports",
        "Status",
        "Verdächtig",
        "Zuletzt",
    )

    def __init__(
        self,
        service: ConversationService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._log = get_logger(__name__)
        self._service = service if service is not None else self._make_service()
        self._all: list[Conversation] = []

        self._build_layout()

        # Synchroner Refresh-Takt (Aggregation ist eine günstige SQL-GROUP-BY).
        self._timer = QTimer(self)
        self._timer.setInterval(_REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def _make_service(self) -> ConversationService | None:
        """Baut den echten Service fail-soft (kein KeyManager/DB → ``None``)."""
        try:
            from tools.network_monitor.application.monitor_service import (  # noqa: PLC0415
                MonitorService,
            )

            return MonitorService.create_conversation_service()
        except Exception as exc:  # noqa: BLE001 — kein KeyManager/keine DB → fail-soft
            self._log.info("Konversations-Service nicht verfügbar: %s", type(exc).__name__)
            return None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        colors = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addLayout(self._build_header(colors))
        root.addLayout(self._build_filter_row(colors))
        root.addLayout(self._build_expert_row(colors))

        self._empty_state = QLabel(
            "Noch keine Konversationen — die Verbindungs-Historie füllt sich im "
            "Hintergrund (Pro). Schau in ein paar Minuten erneut."
        )
        self._empty_state.setWordWrap(True)
        self._empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_state.setStyleSheet(f"color: {colors.TEXT_DIM}; padding: 16px;")
        root.addWidget(self._empty_state)

        self._table = self._build_table()
        root.addWidget(self._table, 1)

    def _build_header(self, colors: object) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        title = QLabel("Konversationen (Wer-mit-Wem)")
        title.setStyleSheet(
            f"font-size: 14px; font-weight: 600; color: {colors.ACCENT};"
        )
        row.addWidget(title, 0)

        self._status = QLabel("")
        self._status.setStyleSheet(f"color: {colors.TEXT_DIM};")
        row.addWidget(self._status, 1)

        self._refresh_btn = QPushButton("Aktualisieren")
        self._refresh_btn.setIcon(get_icon(Icons.REFRESH))
        self._refresh_btn.setStyleSheet(toolbar_button_qss())
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.setAccessibleName("Konversationen aktualisieren")
        self._refresh_btn.clicked.connect(self.refresh)
        row.addWidget(self._refresh_btn, 0, Qt.AlignmentFlag.AlignRight)
        return row

    def _build_filter_row(self, colors: object) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self._chip_suspicious = QCheckBox("Nur verdächtige")
        self._chip_suspicious.setAccessibleName("Nur verdächtige Konversationen zeigen")
        self._chip_suspicious.toggled.connect(self._apply_filters)
        row.addWidget(self._chip_suspicious, 0)

        self._chip_external = QCheckBox("Nur extern")
        self._chip_external.setToolTip(
            "Nur Konversationen zu externen (nicht-privaten) IP-Adressen."
        )
        self._chip_external.setAccessibleName("Nur externe Ziele zeigen")
        self._chip_external.toggled.connect(self._apply_filters)
        row.addWidget(self._chip_external, 0)

        self._search = QLineEdit()
        self._search.setObjectName("searchBar")
        self._search.setPlaceholderText("Suche: Prozess, IP oder Status …")
        self._search.setAccessibleName("Konversationen durchsuchen")
        self._search.textChanged.connect(self._apply_filters)
        row.addWidget(self._search, 1)
        return row

    def _build_expert_row(self, colors: object) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(4)

        row = QHBoxLayout()
        row.setSpacing(8)
        label = QLabel("Experten-Filter:")
        label.setStyleSheet(f"color: {colors.TEXT_DIM};")
        row.addWidget(label, 0)

        self._expert = QLineEdit()
        self._expert.setPlaceholderText(
            "z. B.  prozess ~ chrome und ip in 10.0.0.0/8 und port >= 1024"
        )
        self._expert.setAccessibleName("Deklarativer Experten-Filter")
        self._expert.textChanged.connect(self._apply_filters)
        row.addWidget(self._expert, 1)
        box.addLayout(row)

        self._filter_error = QLabel("")
        self._filter_error.setWordWrap(True)
        self._filter_error.setStyleSheet(f"color: {colors.DANGER}; font-size: 12px;")
        self._filter_error.setVisible(False)
        box.addWidget(self._filter_error)

        hint = QLabel(
            "Felder: "
            + ", ".join(cf.ALLOWED_FIELDS)
            + "  ·  =, !=, >, <, >=, <=, ~, in  ·  mit 'und' verknüpfen"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {colors.TEXT_DIM}; font-size: 11px;")
        box.addWidget(hint)
        return box

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(0, len(self._COLUMNS))
        table.setHorizontalHeaderLabels(list(self._COLUMNS))
        table.setAccessibleName("Konversationen")
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSortingEnabled(True)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self._on_context_menu)
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        return table

    # ------------------------------------------------------------------
    # Daten + Filter
    # ------------------------------------------------------------------

    @Slot()
    def refresh(self) -> None:
        """Lädt die Konversationen neu (fail-soft) und wendet die Filter an."""
        if self._service is None:
            self._all = []
            self._apply_filters()
            return
        try:
            self._all = self._service.aggregate(hours=24)
        except Exception as exc:  # noqa: BLE001 — DB-/Lesefehler nie hart
            self._log.warning("Konversationen laden fehlgeschlagen: %s", exc)
            self._all = []
        self._apply_filters()

    @Slot()
    def _apply_filters(self) -> None:
        """Wendet Schnellfilter + Experten-Filter auf den Cache an (kein Re-Query)."""
        convs = cf.apply_chips(
            self._all,
            only_suspicious=self._chip_suspicious.isChecked(),
            only_external=self._chip_external.isChecked(),
            search=self._search.text(),
        )
        expr = self._expert.text().strip()
        if expr:
            try:
                predicate = cf.parse_filter(expr)
            except ConversationFilterError as exc:
                # Kaputter Experten-Filter: Hinweis zeigen, Schnellfilter-Ergebnis
                # weiterhin anzeigen (der Tab bleibt bedienbar, keine leere Tabelle).
                self._filter_error.setText(str(exc))
                self._filter_error.setVisible(True)
                self._populate(convs)
                return
            convs = [c for c in convs if predicate(c)]
        self._filter_error.setVisible(False)
        self._populate(convs)

    def _populate(self, conversations: list[Conversation]) -> None:
        colors = theme.get()
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(conversations))
        for r, conv in enumerate(conversations):
            self._table.setItem(r, 0, QTableWidgetItem(conv.process_name))
            self._table.setItem(r, 1, QTableWidgetItem(conv.remote_ip))

            count_item = NumericTableItem(str(conv.connection_count))
            count_item.setData(Qt.ItemDataRole.UserRole, conv.connection_count)
            self._table.setItem(r, _COUNT_COLUMN, count_item)

            self._table.setItem(r, 3, _bytes_item(conv.bytes_sent))
            self._table.setItem(r, 4, _bytes_item(conv.bytes_recv))

            self._table.setItem(r, 5, QTableWidgetItem(_join_tokens(conv.ports)))
            self._table.setItem(r, 6, QTableWidgetItem(_join_tokens(conv.statuses)))

            susp_item = QTableWidgetItem("ja" if conv.suspicious else "–")
            if conv.suspicious:
                susp_item.setForeground(_color(colors.DANGER))
                if conv.suspicious_reason:
                    susp_item.setToolTip(conv.suspicious_reason)
            self._table.setItem(r, 7, susp_item)

            self._table.setItem(r, 8, QTableWidgetItem(_relative_time(conv.last_seen)))

        self._table.setSortingEnabled(True)
        has_rows = bool(conversations)
        self._table.setVisible(has_rows)
        self._empty_state.setVisible(not has_rows and bool(self._service))
        if not self._service:
            self._empty_state.setVisible(True)
        self._update_status(len(conversations))

    def _update_status(self, shown: int) -> None:
        total = len(self._all)
        if shown == total:
            self._status.setText(f"{total} Konversationen")
        else:
            self._status.setText(f"{shown} von {total} Konversationen (gefiltert)")

    # ------------------------------------------------------------------
    # Deep-Link „Diese IP scannen" (wie ConnectionTable/AnomalyAlertTab)
    # ------------------------------------------------------------------

    @Slot(object)
    def _on_context_menu(self, pos: object) -> None:
        item = self._table.itemAt(pos)
        if item is None:
            return
        ip_item = self._table.item(item.row(), 1)
        ip = ip_item.text().strip() if ip_item is not None else ""
        show_scan_ip_menu(self, ip, self._table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Stoppt den Refresh-Timer (Parent-Teardown/Tab-Wechsel)."""
        self._timer.stop()

    def start(self) -> None:
        """Nimmt den Refresh-Timer wieder auf (Wieder-Betreten des Live-Tabs).

        Pendant zu:meth:`stop`: laedt sofort frisch und startet dann den Timer
        (Reihenfolge wie:meth:`ProcessTrafficView.start` — ein fehlschlagender
        Refresh laesst den Timer nicht trotzdem anlaufen), damit die Konversations-
        Tabelle beim Tab-Wechsel nicht bis zu 30s veraltet steht.
        """
        self.refresh()
        self._timer.start()


def _bytes_item(num_bytes: int) -> NumericTableItem:
    """Byte-Spalten-Item: laienlesbar formatiert, aber numerisch sortierbar."""
    item = NumericTableItem(format_bytes(num_bytes))
    item.setData(Qt.ItemDataRole.UserRole, num_bytes)
    return item


def _join_tokens(tokens: tuple[object, ...]) -> str:
    """Joint Ports/Status zu einer Zelle, lange Listen werden mit „…" gekappt."""
    parts = [str(t) for t in tokens[:_MAX_TOKENS_PER_CELL]]
    if len(tokens) > _MAX_TOKENS_PER_CELL:
        parts.append("…")
    return ", ".join(parts)


def _relative_time(ts: float) -> str:
    """Formatiert einen Unix-Zeitstempel als „vor X s/min/h" (leer bei 0)."""
    if not ts:
        return "–"
    age = max(0, int(time.time() - ts))
    if age < 60:
        return f"vor {age} s"
    if age < 3600:
        return f"vor {age // 60} min"
    return f"vor {age // 3600} h"


def _color(hex_value: str):
    """Erzeugt einen QColor aus einem Theme-Hex (lazy QtGui-Import)."""
    from PySide6.QtGui import QColor  # noqa: PLC0415

    return QColor(hex_value)
