"""vendor_risk_heatmap — Heatmap Kritikalitaet x AVV-Health pro Vendor.

Zweiter Reuse-Proof des generischen:class:`HeatmapGrid` aus
``core.widgets.charts``. Visualisiert das Konzentrationsrisiko in der
Lieferanten-Liste:

- Y-Achse: Vendor-Kritikalitaet 5..1 (oben hoechstkritisch).
- X-Achse: AVV-Health 0..3 (KEIN_AVV / OVERDUE / EXPIRING_SOON / OK).
- Zellfarbe: Risiko-Score = criticality * (4 - avv_health) → [0,20], normalisiert
  auf [0,1] und mit der Default-4-Stufen-Ampel-Ramp gefaerbt.
- Zell-Label: Anzahl Vendoren in dieser Konstellation.
- Tooltip: bis zu drei Vendor-Namen.

Hexagonal-konform: importiert ``core.widgets.charts`` (Basis-Widget) und die
eigene Domain — KEINE data-Zugriffe. Repository-/Service-Wiring uebernimmt
der Tool-Tab.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.widgets.charts import HeatmapCell, HeatmapGrid
from tools.supply_chain_monitor.domain.models import (
    AvvDocument,
    RenewalStatus,
    Vendor,
)

_CRITICALITY_LABELS: tuple[str, ...] = (
    "K=5 hoechstkritisch",
    "K=4 kritisch",
    "K=3 wichtig",
    "K=2 standard",
    "K=1 gering",
)
_HEALTH_LABELS: tuple[str, ...] = (
    "kein AVV",
    "OVERDUE",
    "EXPIRING",
    "OK",
)


def avv_health_for_vendor(
    vendor: Vendor,
    avvs_by_vendor: Mapping[int, Sequence[AvvDocument]],
    now: datetime | None = None,
) -> int:
    """Liefert den AVV-Health-Bucket-Index 0..3 fuer einen Vendor.

    - 0 = KEIN_AVV (keine AVV-Dokumente fuer diesen Vendor)
    - 1 = OVERDUE (mind. ein AVV vorhanden, aber alle bestens OVERDUE)
    - 2 = EXPIRING_SOON (bester AVV-Status ist EXPIRING_SOON)
    - 3 = OK (mind. ein AVV mit RenewalStatus.OK)

    Args:
        vendor: Vendor mit gesetzter ``id``.
        avvs_by_vendor: Mapping ``vendor_id → list[AvvDocument]``.
        now: Referenzzeitpunkt fuer Renewal-Berechnung (Test-Hook).
    """
    if vendor.id is None:
        return 0
    docs = list(avvs_by_vendor.get(vendor.id, ()))
    if not docs:
        return 0
    best = -1
    for doc in docs:
        status = doc.renewal_status(now=now)
        if status is RenewalStatus.OK:
            return 3
        if status is RenewalStatus.EXPIRING_SOON:
            best = max(best, 2)
        elif status is RenewalStatus.OVERDUE:
            best = max(best, 1)
    return best if best >= 0 else 0


def build_vendor_risk_cells(
    vendors: Sequence[Vendor],
    avvs_by_vendor: Mapping[int, Sequence[AvvDocument]],
    now: datetime | None = None,
) -> dict[tuple[int, int], HeatmapCell]:
    """Aggregiert Vendoren in 5x4 (criticality, avv_health)-Buckets.

    Returns:
        Mapping ``(row_idx, col_idx) → HeatmapCell``. Cell-Color via
        Risk-Score-Berechnung (siehe Modul-Docstring), Cell-Label = Counter.
    """
    buckets: dict[tuple[int, int], list[Vendor]] = {}
    for vendor in vendors:
        row_idx = 5 - vendor.criticality_score  # K=5 → row 0, K=1 → row 4
        col_idx = avv_health_for_vendor(vendor, avvs_by_vendor, now=now)
        if 0 <= row_idx < 5 and 0 <= col_idx < 4:
            buckets.setdefault((row_idx, col_idx), []).append(vendor)
    cells: dict[tuple[int, int], HeatmapCell] = {}
    for row in range(5):
        criticality = 5 - row
        for col in range(4):
            avv_health = col
            # Risk-Score: hohe Kritikalitaet + schlechte Health = hohes Risiko.
            score = criticality * (4 - avv_health)  # [0, 20]
            value = score / 20.0
            items = buckets.get((row, col), [])
            cells[(row, col)] = HeatmapCell(
                label=str(len(items)) if items else "",
                value=value,
                tooltip=_tooltip_for(items),
            )
    return cells


def _tooltip_for(vendors: list[Vendor]) -> str:
    if not vendors:
        return "Keine Vendoren in dieser Zelle"
    names = [v.name for v in vendors]
    if len(names) > 3:
        return ", ".join(names[:3]) + f" (+{len(names) - 3} weitere)"
    return ", ".join(names)


class VendorRiskHeatmap(QWidget):
    """Heatmap Kritikalitaet x AVV-Health mit gefilterter Vendor-Liste.

    Signals:
        cell_selected(int, int): ``(criticality, avv_health_bucket)`` mit
            criticality 1..5 und avv_health 0..3.
    """

    cell_selected = Signal(int, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vendors: list[Vendor] = []
        self._buckets: dict[tuple[int, int], list[Vendor]] = {}
        self._selected: tuple[int, int] | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(16)

        self._grid = HeatmapGrid()
        self._grid.cell_clicked.connect(self._on_cell_clicked)
        root.addWidget(self._grid, stretch=3)

        right = QVBoxLayout()
        right.setSpacing(6)
        self._panel_title = QLabel(
            "Klicke eine Zelle, um die Vendoren anzuzeigen."
        )
        self._panel_title.setObjectName("VendorRiskPanelTitle")
        self._panel_title.setWordWrap(True)
        right.addWidget(self._panel_title)

        self._vendor_list = QListWidget()
        self._vendor_list.setObjectName("VendorRiskList")
        self._vendor_list.setAlternatingRowColors(True)
        right.addWidget(self._vendor_list, stretch=1)

        right.addWidget(self._build_legend())

        right_widget = QWidget()
        right_widget.setLayout(right)
        root.addWidget(right_widget, stretch=2)

    def _build_legend(self) -> QFrame:
        legend = QFrame()
        legend.setObjectName("VendorRiskLegend")
        layout = QVBoxLayout(legend)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        title = QLabel("Risk-Score-Skala")
        title.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; font-weight: bold;"
        )
        layout.addWidget(title)
        for color, label in (
            (theme.SCORE_STAGE_SECURE, "Score 0-5 (gering)"),
            (theme.SCORE_STAGE_MODERATE, "Score 6-10 (mittel)"),
            (theme.SCORE_STAGE_AT_RISK, "Score 11-15 (hoch)"),
            (theme.SCORE_STAGE_CRITICAL, "Score 16-20 (sehr hoch)"),
        ):
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(6)
            swatch = QLabel()
            swatch.setFixedSize(14, 14)
            swatch.setStyleSheet(
                f"background-color: {color}; border: 1px solid {theme.DARK_BORDER};"
            )
            row.addWidget(swatch)
            text = QLabel(label)
            text.setStyleSheet(f"color: {theme.DARK_TEXT_PRIMARY};")
            row.addWidget(text)
            row.addStretch(1)
            container = QWidget()
            container.setLayout(row)
            layout.addWidget(container)
        return legend

    def set_data(
        self,
        vendors: Sequence[Vendor],
        avvs_by_vendor: Mapping[int, Sequence[AvvDocument]],
        now: datetime | None = None,
    ) -> None:
        """Aktualisiert Matrix und rechtes Panel."""
        self._vendors = list(vendors)
        reference = now or datetime.now(UTC)
        self._buckets = {}
        for vendor in self._vendors:
            row_idx = 5 - vendor.criticality_score
            col_idx = avv_health_for_vendor(vendor, avvs_by_vendor, now=reference)
            if 0 <= row_idx < 5 and 0 <= col_idx < 4:
                self._buckets.setdefault((row_idx, col_idx), []).append(vendor)
        cells = build_vendor_risk_cells(
            self._vendors, avvs_by_vendor, now=reference
        )
        self._grid.set_data(
            rows=_CRITICALITY_LABELS, cols=_HEALTH_LABELS, cells=cells
        )
        if self._selected is not None:
            self._render_panel(*self._selected)
        else:
            self._render_summary()

    def _render_summary(self) -> None:
        total = len(self._vendors)
        self._panel_title.setText(
            f"<b>{total}</b> Vendoren insgesamt. Klicke eine Zelle "
            "zum Filtern."
        )
        self._vendor_list.clear()
        for vendor in sorted(
            self._vendors,
            key=lambda v: (-v.criticality_score, v.name.lower()),
        ):
            self._vendor_list.addItem(
                QListWidgetItem(
                    f"K={vendor.criticality_score}  ·  {vendor.name}"
                )
            )

    def _render_panel(self, row_idx: int, col_idx: int) -> None:
        criticality = 5 - row_idx
        health_label = _HEALTH_LABELS[col_idx]
        items = self._buckets.get((row_idx, col_idx), [])
        self._panel_title.setText(
            f"<b>K={criticality}</b> · <b>{health_label}</b> — "
            f"{len(items)} Vendoren"
        )
        self._vendor_list.clear()
        for vendor in items:
            self._vendor_list.addItem(QListWidgetItem(vendor.name))

    def _on_cell_clicked(self, row_idx: int, col_idx: int) -> None:
        self._selected = (row_idx, col_idx)
        self._render_panel(row_idx, col_idx)
        self.cell_selected.emit(5 - row_idx, col_idx)

    def selected_cell(self) -> tuple[int, int] | None:
        if self._selected is None:
            return None
        row_idx, col_idx = self._selected
        return (5 - row_idx, col_idx)
