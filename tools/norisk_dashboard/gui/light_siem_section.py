"""
light_siem_section — Light-SIEM-Section fuer das NoRisk-Dashboard.

Iter 3d: Zeigt eine kompakte Live-Sicht auf den
Light-SIEM-Event-Pool:

- KPI-Zeile mit Severity-Counts (CRITICAL / ERROR / WARN / INFO).
- "Refresh"-Button → triggert:meth:`LightSiemAggregator.run_ingest`
  und re-rendert.
- Tabelle mit den 20 neuesten Events (Timestamp / Source / Severity /
  Summary).

Die Section laeuft auf:class:`_DashboardSection` (gleiches Card-Pattern
wie die anderen Sections), damit sie ins Theming einsortiert ist.

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.widgets.button_styles import link_button_qss
from core.widgets.charts import (
    DonutChart,
    DonutSegment,
    StackedAreaChart,
)
from tools.norisk_dashboard.application.light_siem_aggregator import (
    LightSiemAggregator,
)
from tools.norisk_dashboard.domain.light_siem_models import (
    EventSeverity,
    EventSource,
    LightSiemEvent,
    LightSiemSummary,
)

_log = get_logger(__name__)

_SEVERITY_DISPLAY: dict[EventSeverity, str] = {
    EventSeverity.INFO: "INFO",
    EventSeverity.WARN: "WARN",
    EventSeverity.ERROR: "ERROR",
    EventSeverity.CRITICAL: "CRITICAL",
}

_SOURCE_DISPLAY: dict[EventSource, str] = {
    EventSource.PATCH_MONITOR: "Patch-Monitor",
    EventSource.SYSTEM_SCANNER: "System-Scanner",
    EventSource.CERT_MONITOR: "Cert-Monitor",
    EventSource.SUPPLY_CHAIN_MONITOR: "Supply-Chain",
    EventSource.AWARENESS_TRACKER: "Awareness",
    EventSource.OTHER: "Sonstige",
}

_TABLE_HEADERS: list[str] = ["Zeit", "Quelle", "Severity", "Beschreibung"]
_MAX_ROWS: int = 20
_STACKED_DAYS_DEFAULT: int = 7

#: Konkrete Tool-Quellen, aus denen der Light-SIEM passiv Events einsammelt
#: (alle ausser ``OTHER``/"Sonstige"). Wird in der sichtbaren Erklaerzeile
#: genutzt, damit der User versteht, WOHER die Events stammen (Patrick-Live-
#: Test 2026-06-25, D11 — die passive Sammlung war ohne sichtbare Erklaerung).
#: Effekt: Aenderungen an ``_SOURCE_DISPLAY`` ziehen die Erklaerzeile mit;
#: keine zweite, driftende Quellen-Liste pflegen.
_INGEST_SOURCE_NAMES: str = ", ".join(
    label
    for source, label in _SOURCE_DISPLAY.items()
    if source is not EventSource.OTHER
)


_SEVERITY_TOKEN: dict[EventSeverity, str] = {
    EventSeverity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
    EventSeverity.ERROR: theme.SEVERITY_SIGNAL_HIGH,
    EventSeverity.WARN: theme.SEVERITY_SIGNAL_MEDIUM,
    EventSeverity.INFO: theme.SEVERITY_SIGNAL_INFO,
}

_SEVERITY_DONUT_ORDER: tuple[EventSeverity, ...] = (
    EventSeverity.CRITICAL,
    EventSeverity.ERROR,
    EventSeverity.WARN,
    EventSeverity.INFO,
)


def compute_severity_donut_segments(
    summary: LightSiemSummary,
) -> list[DonutSegment]:
    """Pure: erzeugt DonutSegmente aus einem LightSiemSummary.

    Nur Severities mit Count > 0 erscheinen. Reihenfolge:
    CRITICAL → ERROR → WARN → INFO. Farben aus ``_SEVERITY_TOKEN``.
    """
    segments: list[DonutSegment] = []
    for severity in _SEVERITY_DONUT_ORDER:
        count = summary.by_severity.get(severity, 0)
        if count <= 0:
            continue
        segments.append(
            DonutSegment(
                label=_SEVERITY_DISPLAY[severity],
                value=float(count),
                color=QColor(_SEVERITY_TOKEN[severity]),
                tooltip=f"{_SEVERITY_DISPLAY[severity]}: {count}",
            )
        )
    return segments


def compute_daily_stacked_series(
    events: Sequence[LightSiemEvent],
    end_date: datetime,
    days: int = _STACKED_DAYS_DEFAULT,
) -> tuple[list[float], dict[str, list[float]]]:
    """Pure: aggregiert Events in N Tages-Buckets nach Severity.

    Args:
        events: Roh-Events (Zeitstempel beliebig). Ausserhalb des
            Fensters liegende Events werden ignoriert.
        end_date: Ende des Aggregations-Fensters (inklusiv).
        days: Anzahl Tages-Buckets (Default 7).

    Returns:
        ``(timestamps, series)`` mit ``timestamps`` als Unix-Sekunden-Liste
        (jeweils 00:00 UTC des Tages, aelteste zuerst) und ``series`` als
        Mapping ``severity_label → list[count]`` in Stacking-Order
        (CRITICAL → ERROR → WARN → INFO).
    """
    if days <= 0:
        return [], {}
    end_day = end_date.replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    buckets: list[datetime] = [
        end_day - timedelta(days=days - 1 - i) for i in range(days)
    ]
    by_severity: dict[str, list[float]] = {
        _SEVERITY_DISPLAY[sev]: [0.0] * days for sev in _SEVERITY_DONUT_ORDER
    }
    bucket_index = {bucket: idx for idx, bucket in enumerate(buckets)}
    for event in events:
        event_day = event.timestamp.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        if event_day.tzinfo is None:
            event_day = event_day.replace(tzinfo=UTC)
        # Vergleichbar machen: alle in UTC.
        if event_day.tzinfo != UTC:
            event_day = event_day.astimezone(UTC)
        # Lookup ueber tzinfo-normierten Key
        key = event_day.replace(tzinfo=buckets[0].tzinfo)
        idx = bucket_index.get(key)
        if idx is None:
            continue
        label = _SEVERITY_DISPLAY.get(event.severity)
        if label is None or label not in by_severity:
            continue
        by_severity[label][idx] += 1.0
    timestamps = [b.timestamp() for b in buckets]
    return timestamps, by_severity


class _IngestWorker(QThread):
    """Fuehrt ``LightSiemAggregator.run_ingest`` im Hintergrund aus.

    Der Ingest liest jetzt fuenf Tool-DBs (Supply-Chain/Awareness/Patch/System/
    Cert) — synchron im UI-Thread wuerde das die Card beim Auto-Ingest und beim
    Button-Klick einfrieren. Wie: DB-I/O nie im UI-Slot.

    Signals:
        fertig: ``(added, skipped_dedup)`` nach erfolgreichem Ingest.
        fehlgeschlagen: Exception-Klassenname (run_ingest ist je Adapter
            fail-soft, ein Wurf bis hierher ist also unerwartet).
    """

    fertig: Signal = Signal(int, int)
    fehlgeschlagen: Signal = Signal(str)

    def __init__(self, aggregator: LightSiemAggregator) -> None:
        super().__init__()
        self._aggregator = aggregator

    def run(self) -> None:
        try:
            added, skipped = self._aggregator.run_ingest()
        except Exception as exc:  # noqa: BLE001 -- Worker muss fail-safe sein
            self.fehlgeschlagen.emit(type(exc).__name__)
            return
        self.fertig.emit(added, skipped)


# (Review): Modul-weite Referenz auf laufende Ingest-Worker.
#
# Effekt: haelt den parentlosen QThread am Leben, bis ``finished`` feuert — auch
# wenn die:class:`LightSiemSection` waehrend des Auto-Ingests zerstoert wird
# (das Cockpit baut die Card lazy und kann sie per ``deleteLater`` ohne
# ``closeEvent`` entsorgen). Ohne diese Referenz koennte der Python-Wrapper des
# noch laufenden QThread eingesammelt werden -> "QThread destroyed while running"
# -> Crash-Teardown-Klasse). Der Worker entfernt sich beim ``finished``
# selbst wieder aus dem Set.
_ACTIVE_INGEST_WORKERS: set[_IngestWorker] = set()


class LightSiemSection(QWidget):
    """Light-SIEM-Card im Dashboard.

    Hat einen eigenen:class:`LightSiemAggregator` (Standard-Adapter aus
    3d) — Tests koennen via Konstruktor einen anderen injizieren.
    """

    def __init__(
        self,
        aggregator: LightSiemAggregator | None = None,
        parent: QWidget | None = None,
        auto_ingest: bool = True,
    ) -> None:
        super().__init__(parent)
        self._aggregator = aggregator or LightSiemAggregator()
        self._ingest_worker: _IngestWorker | None = None
        self._build_ui()
        self.reload()
        # einmaliger Auto-Ingest beim Oeffnen (Hintergrund-Thread) — der
        # Pool war frueher leer, weil run_ingest NUR am manuellen Button hing.
        # Tests koennen ihn via auto_ingest=False abschalten.
        if auto_ingest:
            self._start_ingest()

    def _build_ui(self) -> None:
        c = theme.get()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Header-Zeile: KPI-Pillen + Refresh-Button
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        self._kpi_critical = _SeverityPill("CRITICAL", c.DANGER)
        self._kpi_error = _SeverityPill("ERROR", c.ERROR)
        self._kpi_warn = _SeverityPill("WARN", c.WARNING)
        self._kpi_info = _SeverityPill("INFO", c.INFO)
        for pill in (
            self._kpi_critical,
            self._kpi_error,
            self._kpi_warn,
            self._kpi_info,
        ):
            header_row.addWidget(pill)

        header_row.addStretch(1)

        self._refresh_btn = QPushButton("Ingest aktualisieren")
        self._refresh_btn.setObjectName("LightSiemRefreshButton")
        self._refresh_btn.setStyleSheet(link_button_qss())
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        header_row.addWidget(self._refresh_btn)

        layout.addLayout(header_row)

        # Sichtbare Erklaerung der Datenquellen (D11): der Light-SIEM laeuft
        # passiv — er sammelt nur, was die anderen Tools beim Scannen erzeugen.
        # Ohne diesen Hinweis war unklar, woher die Events stammen und was
        # "Ingest aktualisieren" tut.
        self._source_hint = QLabel(
            "Sammelt sicherheitsrelevante Ereignisse passiv aus deinen Scans "
            f"({_INGEST_SOURCE_NAMES}). Der Knopf Ingest aktualisieren holt "
            "die neuesten Ereignisse aus diesen Tools in den SIEM-Pool."
        )
        self._source_hint.setWordWrap(True)
        self._source_hint.setObjectName("LightSiemSourceHint")
        self._source_hint.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        layout.addWidget(self._source_hint)

        # Visualisierungs-Zeile: Donut links + StackedArea rechts
        viz_row = QHBoxLayout()
        viz_row.setSpacing(12)
        self._donut = DonutChart()
        self._donut.set_center_text("0\nEvents")
        self._donut.setFixedHeight(220)
        self._donut.setMaximumWidth(260)
        viz_row.addWidget(self._donut, stretch=1)

        self._stacked_area = StackedAreaChart()
        self._stacked_area.setFixedHeight(220)
        self._stacked_area.set_palette(
            [QColor(_SEVERITY_TOKEN[sev]) for sev in _SEVERITY_DONUT_ORDER]
        )
        viz_row.addWidget(self._stacked_area, stretch=2)
        layout.addLayout(viz_row)

        # Tabelle mit den letzten Events
        self._table = QTableWidget(0, len(_TABLE_HEADERS))
        self._table.setHorizontalHeaderLabels(_TABLE_HEADERS)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        for col in range(len(_TABLE_HEADERS) - 1):
            header.setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine Events im Pool. Klicke auf "
            "'Ingest aktualisieren', um Events aus den anderen Tools zu sammeln."
        )
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setObjectName("LightSiemEmptyHint")
        self._empty_hint.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-style: italic; padding: 16px;"
        )
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_refresh_clicked(self) -> None:
        self._start_ingest()

    def _start_ingest(self) -> None:
        """Startet einen Ingest im Hintergrund (Auto + Button-Klick).

        Off-Thread, weil der Ingest fuenf Tool-DBs liest. Ein bereits laufender
        Ingest wird nicht doppelt gestartet (``_ingest_worker`` ist die
        in-flight-Invariante).
        """
        if self._ingest_worker is not None:
            return
        self._refresh_btn.setEnabled(False)
        worker = _IngestWorker(self._aggregator)
        worker.fertig.connect(self._on_ingest_done)
        worker.fehlgeschlagen.connect(self._on_ingest_error)
        worker.finished.connect(self._on_ingest_finished)
        # Ueberlebt eine Zerstoerung der Section ohne closeEvent (s. Set-Doc).
        _ACTIVE_INGEST_WORKERS.add(worker)
        worker.finished.connect(lambda: _ACTIVE_INGEST_WORKERS.discard(worker))
        self._ingest_worker = worker
        worker.start()

    def _on_ingest_done(self, added: int, skipped: int) -> None:
        """Rendert nach erfolgreichem Ingest neu (UI-Thread)."""
        _log.info(
            "light_siem_dashboard_ingest added=%s skipped=%s", added, skipped
        )
        self.reload()

    def _on_ingest_error(self, exc_name: str) -> None:
        """Loggt einen unerwarteten Ingest-Fehler (run_ingest ist sonst fail-soft)."""
        _log.warning("light_siem_dashboard_ingest_failed: %s", exc_name)

    def _on_ingest_finished(self) -> None:
        """Raeumt den Worker auf + gibt den Button frei (UI-Thread)."""
        if self._ingest_worker is not None:
            self._ingest_worker.deleteLater()
            self._ingest_worker = None
        self._refresh_btn.setEnabled(True)

    def closeEvent(self, event) -> None:  # noqa: N802, ANN001
        """Wartet kurz auf einen laufenden Ingest (QThread-Teardown-Schutz)."""
        worker = self._ingest_worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Liest Summary + Recent-Events neu vom Aggregator und rendert.

        Ein einziger Aggregator-Call (``load_dashboard_bundle``) statt 3 separater
        (summary + 2x list_recent) -> ein Connection-Open statt drei (Perf).
        Fenster/Limits unveraendert: Tabelle + Summary 30-Tage, Chart 7-Tage.
        """
        try:
            summary, events, chart_events = self._aggregator.load_dashboard_bundle(
                table_limit=_MAX_ROWS,
                chart_lookback_days=_STACKED_DAYS_DEFAULT,
                chart_limit=2000,
            )
        except Exception:  # noqa: BLE001
            _log.exception("light_siem_dashboard_reload_failed")
            return
        self._render_kpis(summary)
        self._render_donut(summary)
        self._render_stacked(chart_events)
        self._render_table(events)

    def _render_donut(self, summary: LightSiemSummary) -> None:
        segments = compute_severity_donut_segments(summary)
        self._donut.set_segments(segments)
        total = sum(summary.by_severity.get(sev, 0) for sev in EventSeverity)
        self._donut.set_center_text(
            f"{total}\nEvents" if total else "0\nEvents"
        )

    def _render_stacked(self, events: list[LightSiemEvent]) -> None:
        end = datetime.now(UTC)
        timestamps, series = compute_daily_stacked_series(
            events, end_date=end, days=_STACKED_DAYS_DEFAULT
        )
        self._stacked_area.set_data(timestamps, series)

    def _render_kpis(self, summary: LightSiemSummary) -> None:
        sev_counts = summary.by_severity
        self._kpi_critical.set_count(
            sev_counts.get(EventSeverity.CRITICAL, 0)
        )
        self._kpi_error.set_count(sev_counts.get(EventSeverity.ERROR, 0))
        self._kpi_warn.set_count(sev_counts.get(EventSeverity.WARN, 0))
        self._kpi_info.set_count(sev_counts.get(EventSeverity.INFO, 0))

    def _render_table(self, events: list[LightSiemEvent]) -> None:
        self._table.setRowCount(len(events))
        for row, event in enumerate(events):
            self._set_row(row, event)
        self._empty_hint.setVisible(len(events) == 0)
        self._table.setVisible(len(events) > 0)

    def _set_row(self, row: int, event: LightSiemEvent) -> None:
        time_str = event.timestamp.strftime("%Y-%m-%d %H:%M")
        time_item = QTableWidgetItem(time_str)
        time_item.setData(Qt.ItemDataRole.UserRole, event.id)
        self._table.setItem(row, 0, time_item)

        self._table.setItem(
            row,
            1,
            QTableWidgetItem(
                _SOURCE_DISPLAY.get(event.source, event.source.value)
            ),
        )

        sev_item = QTableWidgetItem(
            _SEVERITY_DISPLAY.get(event.severity, event.severity.value)
        )
        sev_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        # Severity-Farbe als Foreground, gleiche Skala wie KPI-Pille.
        sev_item.setForeground(_severity_brush(event.severity))
        self._table.setItem(row, 2, sev_item)

        self._table.setItem(row, 3, QTableWidgetItem(event.summary))


# ---------------------------------------------------------------------------
# Internal — KPI-Pille (kleine farbige Severity-Anzeige)
# ---------------------------------------------------------------------------


class _SeverityPill(QFrame):
    """Kleine farbcodierte Severity-Pille mit Label + Count."""

    def __init__(
        self,
        label: str,
        accent_hex: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent_hex
        c = theme.get()
        self.setObjectName("LightSiemSeverityPill")
        self.setStyleSheet(
            f"#{self.objectName()} {{"
            f"  background-color: {c.CARD_BG};"
            f"  border: 1px solid {accent_hex};"
            f"  border-radius: 12px;"
            f"  padding: 4px 10px;"
            f"}}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 2, 8, 2)
        layout.setSpacing(6)
        self._label = QLabel(label)
        self._label.setStyleSheet(
            f"color: {accent_hex}; font-weight: 600; font-size: 11px;"
        )
        layout.addWidget(self._label)
        self._count_label = QLabel("0")
        self._count_label.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-weight: 700; font-size: 12px;"
        )
        layout.addWidget(self._count_label)

    def set_count(self, count: int) -> None:
        self._count_label.setText(str(count))


def _severity_brush(severity: EventSeverity):  # noqa: ANN201 — Qt-Brush opaque
    from PySide6.QtGui import QBrush, QColor  # noqa: PLC0415

    c = theme.get()
    color_map = {
        EventSeverity.INFO: c.INFO,
        EventSeverity.WARN: c.WARNING,
        EventSeverity.ERROR: c.ERROR,
        EventSeverity.CRITICAL: c.DANGER,
    }
    return QBrush(QColor(color_map.get(severity, c.TEXT_MAIN)))


__all__ = ["LightSiemSection"]
