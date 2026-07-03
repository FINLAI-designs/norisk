"""network_monitor.gui.process_traffic_view — Per-Prozess-Datenverbrauch C).

Live-View (Stop-Step C): zeigt pro Prozess die kumulierten gesendeten/empfangenen
Bytes der letzten 24h aus der ``process_traffic``-Tabelle (vom Hintergrund-
Collector befuellt).

Liest ausschliesslich ueber das Domain-Interface
:class:`~tools.network_monitor.domain.interfaces.IProcessTrafficRepository`
(hexagonaler Contract: ``gui`` importiert nie ``data``).

Author: Patrick Riederich
Version: 1.0 Stop-Step C)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IProcessTrafficRepository
from tools.network_monitor.domain.models import ProcessTrafficAggregate
from tools.network_monitor.gui.labels import format_bytes
from tools.network_monitor.gui.table_items import NumericTableItem

_COLUMNS = ["Prozess", "Prozess-Nr.", "Gesendet", "Empfangen", "Gesamt"]
#: Numerische Spalten (rechtsbuendig, nach Roh-Wert sortierbar). 1=PID,
#: 2/3/4=Byte-Spalten.
_NUMERIC_COLUMNS = (1, 2, 3, 4)
#: Spalte „Gesamt" — Default-Sortierung (groesste Verbraucher zuerst).
_TOTAL_COLUMN = 4
_REFRESH_INTERVAL_MS = 30_000


class _AggregateWorker(QThread):
    """Laedt das 24h-GROUP-BY-Aggregat im Hintergrund — kein UI-Freeze.

    ``aggregate_last_24h`` ist ein GROUP-BY ueber bis zu 24h ``process_traffic``-
    Snapshots. Frueher lief es SYNCHRON im UI-Thread: im Konstruktor, beim
    Wieder-Betreten des Live-Tabs (:meth:`ProcessTrafficView.start`) UND alle
    30s -> beim ersten Oeffnen des Live-Monitors ein Freeze-Residual).
    Wie: DB-I/O nie im UI-Slot, frische thread-lokale Verbindung pro Call.

    Signals:
        fertig: Liste der ``ProcessTrafficAggregate`` (als ``object`` transportiert).
        fehlgeschlagen: Exception-Klassenname (DB-/IO-Fehler) -> ruhiger Hinweis.
    """

    fertig: Signal = Signal(object)
    fehlgeschlagen: Signal = Signal(str)

    def __init__(self, repository: IProcessTrafficRepository) -> None:
        super().__init__()
        self._repo = repository

    def run(self) -> None:
        """Laedt das Aggregat; Ergebnis bzw. Fehler via Signal (fail-safe)."""
        try:
            aggregates = self._repo.aggregate_last_24h()
        except Exception as exc:  # noqa: BLE001 -- Worker muss fail-safe sein, nie den Thread sterben lassen
            self.fehlgeschlagen.emit(type(exc).__name__)
            return
        self.fertig.emit(aggregates)


class ProcessTrafficView(QWidget):
    """Per-Prozess-Datenverbrauch der letzten 24h.

    Args:
        repository: Lese-Port auf die Traffic-History. ``None`` (z. B. ohne Daten
            oder DB-Fehler) → Hinweis-Darstellung statt Tabelle.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        repository: IProcessTrafficRepository | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("processTrafficView")
        self._log = get_logger(__name__)
        self._repo = repository
        self._table: QTableWidget | None = None
        self._status_label: QLabel | None = None
        self._refresh_timer: QTimer | None = None
        # Residual: 24h-Aggregat asynchron laden (kein UI-Freeze). Die
        # Worker-Referenz haelt den QThread am Leben, bis ``finished`` ihn
        # aufraeumt; ein laufender Worker blockt einen Reentrant-Refresh.
        self._worker: _AggregateWorker | None = None

        # kein Free/Pro-Gating mehr — immer die volle Tabelle + Auto-Refresh.
        self._build_table()
        self.refresh()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start()

    # ------------------------------------------------------------------
    # Aufbau
    # ------------------------------------------------------------------

    def _build_table(self) -> None:
        colors = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)
        title = QLabel("Datenverbrauch pro Prozess (letzte 24 h)")
        title.setStyleSheet(
            f"font-size: 15px; font-weight: 600; color: {colors.ACCENT};"
        )
        header.addWidget(title, 0)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color: {colors.TEXT_DIM};")
        header.addWidget(self._status_label, 1, Qt.AlignmentFlag.AlignLeft)

        refresh_btn = QPushButton("Aktualisieren")
        refresh_btn.setIcon(get_icon(Icons.REFRESH))
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn, 0, Qt.AlignmentFlag.AlignRight)
        root.addLayout(header)

        table = QTableWidget(0, len(_COLUMNS), self)
        table.setHorizontalHeaderLabels(_COLUMNS)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        head = table.horizontalHeader()
        head.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, len(_COLUMNS)):
            head.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._table = table
        root.addWidget(table, 1)

    # ------------------------------------------------------------------
    # Daten
    # ------------------------------------------------------------------

    @Slot()
    def refresh(self) -> None:
        """Startet das Laden des 24h-Aggregats im Hintergrund — KEIN UI-Freeze.

        Das GROUP-BY lief frueher synchron im UI-Slot (Konstruktor / start /
        30s-Timer) -> Freeze beim Live-Tab-Oeffnen-Residual). Jetzt im
:class:`_AggregateWorker`. Ein bereits laufender Refresh wird NICHT
        doppelt gestartet (der 30s-Timer kann waehrend einer langsamen Abfrage
        re-feuern).
        """
        if self._repo is None or self._table is None:
            return
        # is-not-None statt isRunning: nach dem ``finished``-Signal, aber vor
        # ``_on_worker_finished``, wuerde ein zweiter Start (Button / 30s-Timer)
        # den noch nicht geraeumten Worker verwaisen lassen (Review-Befund).
        if self._worker is not None:
            return
        worker = _AggregateWorker(self._repo)
        worker.fertig.connect(self._on_aggregates_loaded)
        worker.fehlgeschlagen.connect(self._on_aggregate_error)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _on_aggregates_loaded(
        self, aggregates: list[ProcessTrafficAggregate]
    ) -> None:
        """Rendert das im Worker geladene Aggregat (UI-Thread)."""
        self._populate(aggregates)

    def _on_aggregate_error(self, exc_name: str) -> None:
        """Ruhiger Hinweis bei DB-/IO-Fehler (kein roter Alarm)."""
        self._log.warning(
            "Traffic-Aggregat konnte nicht geladen werden: %s", exc_name
        )
        if self._status_label is not None:
            self._status_label.setText("Daten momentan nicht verfügbar")

    def _on_worker_finished(self) -> None:
        """Raeumt den fertigen Worker auf (UI-Thread)."""
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None

    def _populate(self, aggregates: list[ProcessTrafficAggregate]) -> None:
        table = self._table
        if table is None:
            return
        table.setSortingEnabled(False)
        table.setRowCount(len(aggregates))
        for row, agg in enumerate(aggregates):
            total = agg.total_bytes_sent + agg.total_bytes_recv
            cells = [
                (agg.process_name or "–", None),
                (str(agg.pid), agg.pid),
                (format_bytes(agg.total_bytes_sent), agg.total_bytes_sent),
                (format_bytes(agg.total_bytes_recv), agg.total_bytes_recv),
                (format_bytes(total), total),
            ]
            for col, (text, sort_key) in enumerate(cells):
                numeric = col in _NUMERIC_COLUMNS
                item = NumericTableItem(text) if numeric else QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if numeric:
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                    )
                if sort_key is not None:
                    item.setData(Qt.ItemDataRole.UserRole, sort_key)
                table.setItem(row, col, item)
        table.setSortingEnabled(True)
        # Default: groesste Verbraucher zuerst (Spec „groesste zuerst").
        table.sortItems(_TOTAL_COLUMN, Qt.SortOrder.DescendingOrder)
        if self._status_label is not None:
            if aggregates:
                self._status_label.setText(f"{len(aggregates)} Prozesse")
            else:
                self._status_label.setText(
                    "Noch keine Daten — die Hintergrund-Erfassung sammelt "
                    "Per-Prozess-Traffic (Aktivierung in den Einstellungen)."
                )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Haelt den Auto-Refresh an (Tab verlassen / Teardown).

        Verhindert, dass das 24h-GROUP-BY-Aggregat (``aggregate_last_24h``)
        synchron im UI-Thread weiterlaeuft, waehrend der Live-Tab nicht aktiv ist
, S5a-Zusage „kein CPU/DB-I/O auf anderem Tab"). Pendant::meth:`start`.
        """
        if self._refresh_timer is not None:
            self._refresh_timer.stop()

    def start(self) -> None:
        """Nimmt den Auto-Refresh wieder auf (Wieder-Betreten des Live-Tabs).

        Laedt sofort einmal frisch (sonst stuende die Tabelle bis zu 30s alt da)
        und startet den periodischen Timer neu.
        """
        self.refresh()
        if self._refresh_timer is not None:
            self._refresh_timer.start()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: D401 — Qt-Override
        """Stoppt den Auto-Refresh-Timer + wartet auf einen laufenden Worker.

        Der QThread darf nicht waehrend des Laufs zerstoert werden (sonst
        Teardown-Crash) — daher vor dem Schliessen kurz auf das Aggregat warten.
        """
        self.stop()
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)
        super().closeEvent(event)
