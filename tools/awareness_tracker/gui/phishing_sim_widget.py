"""
phishing_sim_widget — Phishing-Simulations-Tab des Awareness-Trackers.

Iteration 3c:

- KPI-Card-Zeile (3 Karten: Kampagnen-Anzahl, durchschn. Klick-Rate, Trend)
- Trend-Chart der Klick-Raten ueber Zeit (matplotlib, analog
  ``score_trend_chart.py``). Bei < 2 Datenpunkten Empty-Hinweis.
- Tabelle aller Kampagnen mit Add/Edit/Delete.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
    PhishingSimKpi,
)
from tools.awareness_tracker.domain.models import PhishingSimEvent
from tools.awareness_tracker.gui.phishing_sim_form_dialog import (
    PhishingSimFormDialog,
)

_log = get_logger(__name__)

try:
    import matplotlib

    matplotlib.use("QtAgg")
    from matplotlib.backends.backend_qtagg import (
        FigureCanvasQTAgg,
    )
    from matplotlib.dates import AutoDateLocator, DateFormatter
    from matplotlib.figure import Figure

    HAS_MPL = True
except ImportError:  # pragma: no cover — matplotlib ist in requirements/base.txt
    HAS_MPL = False

_TABLE_HEADERS: list[str] = [
    "Datum",
    "Kampagne",
    "Anbieter",
    "Targets",
    "Klicks",
    "Klick-Rate",
    "Reports",
    "Nachgeschult",
]


class PhishingSimWidget(QWidget):
    """Hauptansicht des Phishing-Sim-Tabs."""

    def __init__(
        self,
        service: AwarenessService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        self._kpi_row = QHBoxLayout()
        self._kpi_count = _KpiCard(title="Kampagnen", subtitle="(insgesamt)")
        self._kpi_click = _KpiCard(
            title="Durchschnittl. Klick-Rate", subtitle="(gewichtet)"
        )
        self._kpi_trend = _KpiCard(
            title="Trend", subtitle="(letzte vs. Vorgaenger)"
        )
        for card in (self._kpi_count, self._kpi_click, self._kpi_trend):
            self._kpi_row.addWidget(card)
        layout.addLayout(self._kpi_row)

        self._trend_chart = _ClickRateTrendChart(parent=self)
        layout.addWidget(self._trend_chart)

        button_row = QHBoxLayout()
        self._add_btn = QPushButton("Kampagne hinzufuegen")
        self._add_btn.setObjectName("PhishingSimAddButton")
        self._add_btn.clicked.connect(self._on_add_clicked)
        button_row.addWidget(self._add_btn)

        self._edit_btn = QPushButton("Bearbeiten")
        self._edit_btn.setObjectName("PhishingSimEditButton")
        self._edit_btn.setEnabled(False)
        self._edit_btn.clicked.connect(self._on_edit_clicked)
        button_row.addWidget(self._edit_btn)

        self._delete_btn = QPushButton("Loeschen")
        self._delete_btn.setObjectName("PhishingSimDeleteButton")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        button_row.addWidget(self._delete_btn)

        button_row.addStretch(1)
        layout.addLayout(button_row)

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
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine Phishing-Kampagnen erfasst — lege eine ueber "
            "den Button oben an."
        )
        self._empty_hint.setObjectName("PhishingSimEmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add_clicked(self) -> None:
        dialog = PhishingSimFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            new_event = dialog.collected_event()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.add_phishing_sim(
                name=new_event.name,
                vendor=new_event.vendor,
                run_date=new_event.run_date,
                target_count=new_event.target_count,
                click_count=new_event.click_count,
                report_count=new_event.report_count,
                training_assigned=new_event.training_assigned,
                custom_vendor_label=new_event.custom_vendor_label,
                notes=new_event.notes,
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()

    def _on_edit_clicked(self) -> None:
        event = self._selected_event()
        if event is None:
            return
        dialog = PhishingSimFormDialog(parent=self, event=event)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected_event()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.update_phishing_sim(updated)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Aktualisierung fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()

    def _on_delete_clicked(self) -> None:
        event = self._selected_event()
        if event is None or event.id is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Phishing-Sim loeschen",
            message=f"Die Kampagne '{event.name}' wirklich loeschen?",
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        if not self._service.delete_phishing_sim(event.id):
            FinlaiInfoDialog(
                title="Loeschen fehlgeschlagen",
                message=f"Die Kampagne mit ID {event.id} wurde nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
        self._reload()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._edit_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Public-Reload — vom AwarenessWidget gerufen wenn der Tab
        sichtbar wird."""
        self._reload()

    def _reload(self) -> None:
        events = self._service.list_phishing_sims()
        kpi = self._service.compute_phishing_sim_kpi()
        self._update_kpi_cards(kpi)
        self._update_trend_chart(events)
        self._table.setRowCount(len(events))
        for row, event in enumerate(events):
            self._set_row(row, event)
        self._empty_hint.setVisible(len(events) == 0)
        self._table.setVisible(len(events) > 0)
        self._table.clearSelection()
        self._edit_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)

    def _update_kpi_cards(self, kpi: PhishingSimKpi) -> None:
        self._kpi_count.set_value(str(kpi.campaign_count))
        if kpi.is_empty:
            self._kpi_click.set_value("—")
            self._kpi_trend.set_value("—")
            return
        self._kpi_click.set_value(f"{kpi.avg_click_rate:.1f} %")
        self._kpi_trend.set_value(kpi.trend_label)

    def _update_trend_chart(self, events: list[PhishingSimEvent]) -> None:
        # ascending nach run_date fuer den Chart (Repository ist desc).
        pairs = [
            (e.run_date, e.click_rate)
            for e in sorted(events, key=lambda e: e.run_date)
        ]
        self._trend_chart.update_data(pairs)

    def _set_row(self, row: int, event: PhishingSimEvent) -> None:
        date_item = QTableWidgetItem(event.run_date.strftime("%Y-%m-%d"))
        date_item.setData(Qt.ItemDataRole.UserRole, event.id)
        self._table.setItem(row, 0, date_item)
        self._table.setItem(row, 1, QTableWidgetItem(event.name))
        self._table.setItem(
            row, 2, QTableWidgetItem(event.display_vendor_label)
        )
        self._table.setItem(
            row, 3, QTableWidgetItem(str(event.target_count))
        )
        self._table.setItem(row, 4, QTableWidgetItem(str(event.click_count)))
        rate_item = QTableWidgetItem(f"{event.click_rate:.1f} %")
        rate_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 5, rate_item)
        self._table.setItem(
            row, 6, QTableWidgetItem(str(event.report_count))
        )
        self._table.setItem(
            row,
            7,
            QTableWidgetItem("Ja" if event.training_assigned else "Nein"),
        )

    def _selected_event(self) -> PhishingSimEvent | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        if item is None:
            return None
        event_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(event_id, int):
            return None
        return self._service.get_phishing_sim(event_id)


# ---------------------------------------------------------------------------
# Internal KPI-Card
# ---------------------------------------------------------------------------


class _KpiCard(QFrame):
    """Schlanke KPI-Karte mit Titel, grossem Wert + Subtitel."""

    def __init__(
        self,
        *,
        title: str,
        subtitle: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("PhishingSimKpiCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)

        self._title_label = QLabel(title)
        self._title_label.setObjectName("PhishingSimKpiTitle")
        layout.addWidget(self._title_label)

        self._value_label = QLabel("—")
        self._value_label.setObjectName("PhishingSimKpiValue")
        layout.addWidget(self._value_label)

        self._subtitle_label = QLabel(subtitle)
        self._subtitle_label.setObjectName("PhishingSimKpiSubtitle")
        layout.addWidget(self._subtitle_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


# ---------------------------------------------------------------------------
# Trend-Chart (matplotlib, analog ``norisk_dashboard/gui/score_trend_chart``)
# ---------------------------------------------------------------------------


class _ClickRateTrendChart(QWidget):
    """Klick-Raten-Trend-Chart fuer Phishing-Sim-Kampagnen.

    Bei < 2 Datenpunkten erscheint ein Empty-Label. Bei vorhandenem
    matplotlib wird ein Line/Fill-Chart mit Accent-Farbe gerendert.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self._stack = QStackedLayout(self)
        self._stack.setContentsMargins(0, 0, 0, 0)

        self._empty = QLabel(
            "Mindestens zwei Kampagnen erforderlich fuer einen Trend.", self
        )
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 12px; background: {c.BG_MAIN};"
        )
        self._stack.addWidget(self._empty)

        self._canvas: FigureCanvasQTAgg | None = None
        if HAS_MPL:
            self._figure = Figure(figsize=(6, 2.5), facecolor=c.BG_MAIN)
            self._axes = self._figure.add_subplot(111)
            self._canvas = FigureCanvasQTAgg(self._figure)
            self._canvas.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
            )
            self._stack.addWidget(self._canvas)

        self._stack.setCurrentWidget(self._empty)
        self.setMinimumHeight(160)

    def update_data(self, pairs: list[tuple[datetime, float]]) -> None:
        """Rendert neuen Trend. Bei < 2 Punkten erscheint das Empty-Label."""
        if self._canvas is None or len(pairs) < 2:
            self._stack.setCurrentWidget(self._empty)
            return

        from core import theme  # noqa: PLC0415

        c = theme.get()
        ax = self._axes
        ax.clear()

        xs = [p[0] for p in pairs]
        ys = [p[1] for p in pairs]

        accent = theme.DARK_ACCENT
        ax.fill_between(xs, ys, 0, color=accent, alpha=0.25)
        ax.plot(
            xs, ys, color=accent, linewidth=1.8, marker="o", markersize=4
        )

        ax.set_facecolor(c.BG_MAIN)
        ax.set_ylim(0, max(20.0, max(ys) * 1.2))
        for spine in ax.spines.values():
            spine.set_color(c.BORDER)
        ax.tick_params(colors=c.TEXT_DIM, labelsize=8)
        ax.yaxis.label.set_color(c.TEXT_DIM)
        ax.xaxis.label.set_color(c.TEXT_DIM)
        ax.grid(
            True,
            color=c.BORDER,
            alpha=0.3,
            linestyle="-",
            linewidth=0.5,
        )
        ax.xaxis.set_major_locator(AutoDateLocator(maxticks=6))
        ax.xaxis.set_major_formatter(DateFormatter("%d.%m"))

        self._figure.tight_layout()
        self._canvas.draw_idle()
        self._stack.setCurrentWidget(self._canvas)


__all__ = ["PhishingSimWidget"]
