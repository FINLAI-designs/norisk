"""
catalog_management_dialog — Verwaltungs-Dialog fuer den Vendor-Catalog.

Iter 2b: Modaler Dialog mit Tabelle aller bekannten
Catalog-Eintraege plus Add/Edit/Delete-Buttons. Aufgerufen aus dem
Auto-Detection-Tab des Supply-Chain-Widgets.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
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
from tools.supply_chain_monitor.application.catalog_service import CatalogService
from tools.supply_chain_monitor.domain.models import (
    VendorCatalogEntry,
    VendorCategory,
)
from tools.supply_chain_monitor.gui.catalog_entry_form_dialog import (
    CatalogEntryFormDialog,
)

_log = get_logger(__name__)

_CATEGORY_DISPLAY: dict[VendorCategory, str] = {
    VendorCategory.KANZLEISOFTWARE: "Kanzlei-Software",
    VendorCategory.CLOUD: "Cloud / SaaS",
    VendorCategory.MSP: "IT-Dienstleister",
    VendorCategory.KOMMUNIKATION: "Kommunikation",
    VendorCategory.SPEZIAL: "Spezial",
}

_HEADERS: list[str] = [
    "Canonical Name",
    "Kategorie",
    "App-Patterns",
    "MX-Patterns",
    "Cert-Patterns",
]


class CatalogManagementDialog(QDialog):
    """Modaler Dialog zur Verwaltung der Catalog-Eintraege."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        service: CatalogService | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or CatalogService()
        self.setWindowTitle("Vendor-Catalog verwalten")
        self.setMinimumSize(820, 480)
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        info = QLabel(
            "Hier verwalten Sie den Vendor-Catalog. Jeder Eintrag hat drei "
            "Pattern-Listen (App-Namen / MX-Hostnames / Cert-Issuer), die als "
            "case-insensitive Substring-Match gegen Detection-Ergebnisse "
            "laufen."
        )
        info.setWordWrap(True)
        info.setObjectName("SupplyChainCatalogInfo")
        layout.addWidget(info)

        # Buttons
        row = QHBoxLayout()
        self._add_btn = QPushButton("Neuer Eintrag")
        self._add_btn.clicked.connect(self._on_add)
        row.addWidget(self._add_btn)
        self._edit_btn = QPushButton("Bearbeiten")
        self._edit_btn.setEnabled(False)
        self._edit_btn.clicked.connect(self._on_edit)
        row.addWidget(self._edit_btn)
        self._delete_btn = QPushButton("Loeschen")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._on_delete)
        row.addWidget(self._delete_btn)
        row.addStretch(1)
        layout.addLayout(row)

        # Tabelle
        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("Schliessen")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add(self) -> None:
        dialog = CatalogEntryFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            entry = dialog.collected_entry()
            self._service.add_entry(entry)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eintrag abgelehnt",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()

    def _on_edit(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        dialog = CatalogEntryFormDialog(parent=self, entry=entry)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected_entry()
            self._service.update_entry(updated)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Update fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()

    def _on_delete(self) -> None:
        entry = self._selected_entry()
        if entry is None or entry.id is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Catalog-Eintrag loeschen",
            message=(
                f"Den Catalog-Eintrag '{entry.canonical_name}' wirklich loeschen?\n\n"
                "Bereits angelegte Vendoren bleiben erhalten; nur die "
                "Detection-Schablone wird entfernt."
            ),
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        if not self._service.delete_entry(entry.id):
            FinlaiInfoDialog(
                title="Loeschen fehlgeschlagen",
                message=f"Catalog-Eintrag mit ID {entry.id} nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
        self._reload()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._edit_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def _reload(self) -> None:
        entries = self._service.list_entries()
        self._table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self._set_row(row, entry)
        self._table.clearSelection()
        self._edit_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)

    def _set_row(self, row: int, entry: VendorCatalogEntry) -> None:
        name_item = QTableWidgetItem(entry.canonical_name)
        name_item.setData(Qt.ItemDataRole.UserRole, entry.id)
        self._table.setItem(row, 0, name_item)
        self._table.setItem(
            row,
            1,
            QTableWidgetItem(
                _CATEGORY_DISPLAY.get(entry.default_category, entry.default_category.value)
            ),
        )
        self._table.setItem(row, 2, QTableWidgetItem(", ".join(entry.app_name_patterns)))
        self._table.setItem(row, 3, QTableWidgetItem(", ".join(entry.mx_hostname_patterns)))
        self._table.setItem(
            row, 4, QTableWidgetItem(", ".join(entry.cert_issuer_patterns))
        )

    def _selected_entry(self) -> VendorCatalogEntry | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        if item is None:
            return None
        entry_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(entry_id, int):
            return None
        return self._service.get_entry(entry_id)
