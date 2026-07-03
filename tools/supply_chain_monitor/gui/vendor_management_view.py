"""
vendor_management_view — Lieferanten-Verwaltung / IA-Umbau 2026-06-30).

Aus:class:`SupplyChainWidget` herausgeloeste Vendor-/Lieferanten-Verwaltung:
Tabelle (Name/Kategorie/Kritikalitaet/Patch-Status/Off-Boarding/Notizen) plus
Anlegen/Bearbeiten/Loeschen/Off-Boarding. Lebt jetzt im 'Lieferanten'-Bereich des
AVV-Trackers (oben; darunter die AVVs).

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1/IA-Umbau, 2026-06-30)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.supply_chain_monitor.application.offboarding_service import (
    OffBoardingService,
)
from tools.supply_chain_monitor.application.patch_monitor_linker import (
    PatchMonitorLinker,
    VendorPatchSummary,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.domain.models import (
    OffBoardingStatus,
    Vendor,
    VendorCategory,
)
from tools.supply_chain_monitor.gui._tab_style import supply_chain_tab_stylesheet
from tools.supply_chain_monitor.gui.offboarding_dialog import OffBoardingDialog
from tools.supply_chain_monitor.gui.vendor_form_dialog import VendorFormDialog

_log = get_logger(__name__)

_CATEGORY_DISPLAY: dict[VendorCategory, str] = {
    VendorCategory.KANZLEISOFTWARE: "Kanzlei-Software",
    VendorCategory.CLOUD: "Cloud / SaaS",
    VendorCategory.MSP: "IT-Dienstleister",
    VendorCategory.KOMMUNIKATION: "Kommunikation",
    VendorCategory.SPEZIAL: "Spezial",
}

_TABLE_HEADERS: list[str] = [
    "Name",
    "Kategorie",
    "Kritikalitaet",
    "Patch-Status",
    "Off-Boarding",
    "Notizen",
]

_OFFBOARDING_LABELS: dict[OffBoardingStatus, str] = {
    OffBoardingStatus.IN_PROGRESS: "in Arbeit",
    OffBoardingStatus.COMPLETED: "abgeschlossen",
    OffBoardingStatus.CANCELLED: "abgebrochen",
}


class VendorManagementView(QWidget):
    """Lieferanten-Inventar (Vendoren) mit Anlegen/Bearbeiten/Loeschen/Off-Boarding.

    Signals:
        vendors_changed: emittiert, wenn ein Vendor angelegt/geaendert/geloescht
            wurde — die AVV-Sicht darunter kann ihre Vendor-Namensaufloesung
            aktualisieren.
    """

    vendors_changed = Signal()

    def __init__(
        self,
        *,
        vendor_service: VendorService | None = None,
        patch_linker: PatchMonitorLinker | None = None,
        offboarding_service: OffBoardingService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = vendor_service or VendorService()
        self._patch_linker = patch_linker or PatchMonitorLinker()
        self._offboarding_service = offboarding_service or OffBoardingService()
        self._patch_summaries: dict[int, VendorPatchSummary] = {}
        self._offb_progress: dict = {}
        self._build_ui()
        self.reload()

    def _build_ui(self) -> None:
        self.setStyleSheet(supply_chain_tab_stylesheet())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("Lieferanten verwalten")
        title.setObjectName("SupplyChainSectionTitle")
        layout.addWidget(title)

        button_row = QHBoxLayout()
        self._add_btn = QPushButton("Lieferant hinzufuegen")
        self._add_btn.setObjectName("SupplyChainAddButton")
        self._add_btn.clicked.connect(self._on_add_clicked)
        button_row.addWidget(self._add_btn)

        self._edit_btn = QPushButton("Bearbeiten")
        self._edit_btn.setObjectName("SupplyChainEditButton")
        self._edit_btn.setEnabled(False)
        self._edit_btn.clicked.connect(self._on_edit_clicked)
        button_row.addWidget(self._edit_btn)

        self._delete_btn = QPushButton("Loeschen")
        self._delete_btn.setObjectName("SupplyChainDeleteButton")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._on_delete_clicked)
        button_row.addWidget(self._delete_btn)

        self._offboarding_btn = QPushButton("Off-Boarding ...")
        self._offboarding_btn.setObjectName("SupplyChainOffBoardingButton")
        self._offboarding_btn.setEnabled(False)
        self._offboarding_btn.clicked.connect(self._on_offboarding_clicked)
        button_row.addWidget(self._offboarding_btn)

        button_row.addStretch(1)
        layout.addLayout(button_row)

        self._table = QTableWidget(0, len(_TABLE_HEADERS))
        self._table.setHorizontalHeaderLabels(_TABLE_HEADERS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        for col_idx in range(len(_TABLE_HEADERS) - 1):
            header.setSectionResizeMode(col_idx, QHeaderView.ResizeMode.ResizeToContents)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine Lieferanten erfasst — legen Sie ueber den Button oben einen "
            "ersten Eintrag an."
        )
        self._empty_hint.setObjectName("SupplyChainEmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add_clicked(self) -> None:
        dialog = VendorFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            vendor = dialog.collected_vendor()
        except ValueError as exc:
            self._warn("Eingabe ungueltig", str(exc))
            return
        self._service.add_vendor(
            name=vendor.name,
            category=vendor.category,
            criticality_score=vendor.criticality_score,
            notes=vendor.notes,
        )
        self.reload()
        self.vendors_changed.emit()

    def _on_edit_clicked(self) -> None:
        vendor = self._selected_vendor()
        if vendor is None:
            return
        dialog = VendorFormDialog(parent=self, vendor=vendor)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected_vendor()
        except ValueError as exc:
            self._warn("Eingabe ungueltig", str(exc))
            return
        try:
            self._service.update_vendor(updated)
        except ValueError as exc:
            self._warn("Aktualisierung fehlgeschlagen", str(exc))
            return
        self.reload()
        self.vendors_changed.emit()

    def _on_delete_clicked(self) -> None:
        vendor = self._selected_vendor()
        if vendor is None or vendor.id is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Lieferant loeschen",
            message=f"Den Lieferanten '{vendor.name}' wirklich loeschen?",
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        if not self._service.delete_vendor(vendor.id):
            self._warn(
                "Loeschen fehlgeschlagen",
                f"Der Lieferant mit ID {vendor.id} wurde nicht gefunden.",
            )
        self.reload()
        self.vendors_changed.emit()

    def _on_offboarding_clicked(self) -> None:
        vendor = self._selected_vendor()
        if vendor is None or vendor.id is None:
            return
        dialog = OffBoardingDialog(
            vendor_id=vendor.id,
            vendor_name=vendor.name,
            service=self._offboarding_service,
            parent=self,
        )
        dialog.exec()
        self.reload()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._edit_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)
        self._offboarding_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def reload(self) -> None:
        vendors = self._service.list_vendors()
        # Patch-Aggregate + Off-Boarding-Progress nur einmal pro Reload holen
        # (sonst zu viele DB-Roundtrips pro Vendor-Row).
        try:
            self._patch_summaries = self._patch_linker.summarize_per_vendor()
        except Exception:  # noqa: BLE001 — Patch-Status darf den Tab nie crashen
            _log.exception("PatchMonitorLinker.summarize_per_vendor fehlgeschlagen")
            self._patch_summaries = {}
        try:
            self._offb_progress = self._offboarding_service.progress_per_vendor()
        except Exception:  # noqa: BLE001
            _log.exception("OffBoardingService.progress_per_vendor fehlgeschlagen")
            self._offb_progress = {}

        self._table.setRowCount(len(vendors))
        for row, vendor in enumerate(vendors):
            self._set_row(row, vendor)
        self._empty_hint.setVisible(len(vendors) == 0)
        self._table.setVisible(len(vendors) > 0)
        self._table.clearSelection()
        self._edit_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)
        self._offboarding_btn.setEnabled(False)

    def _set_row(self, row: int, vendor: Vendor) -> None:
        name_item = QTableWidgetItem(vendor.name)
        name_item.setData(Qt.ItemDataRole.UserRole, vendor.id)
        self._table.setItem(row, 0, name_item)

        category_label = _CATEGORY_DISPLAY.get(vendor.category, vendor.category.value)
        self._table.setItem(row, 1, QTableWidgetItem(category_label))

        crit_item = QTableWidgetItem(str(vendor.criticality_score))
        crit_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 2, crit_item)

        patch_item = QTableWidgetItem(self._format_patch_summary(vendor.id))
        patch_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 3, patch_item)

        offb_item = QTableWidgetItem(self._format_offboarding(vendor.id))
        offb_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 4, offb_item)

        notes_preview = vendor.notes.splitlines()[0] if vendor.notes else ""
        if len(notes_preview) > 120:
            notes_preview = notes_preview[:117] + "..."
        self._table.setItem(row, 5, QTableWidgetItem(notes_preview))

    def _format_patch_summary(self, vendor_id: int | None) -> str:
        if vendor_id is None:
            return "-"
        summary = self._patch_summaries.get(vendor_id)
        if summary is None or summary.matched_app_count == 0:
            return "-"
        parts: list[str] = []
        if summary.apps_with_updates:
            parts.append(f"{summary.apps_with_updates} Update")
        if summary.apps_with_cves:
            cvss = (
                f" (CVSS≤{summary.max_cvss:.1f})"
                if summary.max_cvss is not None
                else ""
            )
            parts.append(f"{summary.apps_with_cves} CVE{cvss}")
        if not parts:
            return "OK"
        if summary.has_exploit:
            parts.append("Warnung: Exploit")
        return " / ".join(parts)

    def _format_offboarding(self, vendor_id: int | None) -> str:
        if vendor_id is None:
            return "-"
        progress = self._offb_progress.get(vendor_id)
        if progress is None:
            return "-"
        label = _OFFBOARDING_LABELS.get(progress.status, progress.status.value)
        if progress.status is OffBoardingStatus.IN_PROGRESS:
            return f"{label} {progress.done}/{progress.total}"
        return label

    def _selected_vendor(self) -> Vendor | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        item = self._table.item(row, 0)
        if item is None:
            return None
        vendor_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(vendor_id, int):
            return None
        return self._service.get_vendor(vendor_id)

    def _warn(self, title: str, message: str) -> None:
        FinlaiInfoDialog(
            title=title, message=message, icon_name=Icons.WARNING, parent=self
        ).exec()
