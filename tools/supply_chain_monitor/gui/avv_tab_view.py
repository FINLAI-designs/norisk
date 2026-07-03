"""
avv_tab_view — AVV-Tab im Supply-Chain-Monitor.

Iter 2c-i: Ersetzt den Placeholder aus 2a. Zeigt:

- Renewal-Banner (Count "X laufen ab in <90 Tagen, Y ueberfaellig").
- Tabelle aller AVV-Dokumente mit Renewal-Status-Spalte.
- Buttons "Hochladen" / "Checkliste bearbeiten" / "Loeschen".

Subprocessor-UI + KI-Todo-Emitter folgen in 2c-ii.

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
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
from tools.supply_chain_monitor.application.avv_service import (
    AvvPdfCipherError,
    AvvPdfDecryptError,
    AvvService,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.domain.models import (
    RENEWAL_WARNING_DAYS_DEFAULT,
    AvvDocument,
    RenewalStatus,
)
from tools.supply_chain_monitor.gui._tab_style import (
    supply_chain_tab_stylesheet,
)
from tools.supply_chain_monitor.gui.avv_checklist_dialog import AvvChecklistDialog
from tools.supply_chain_monitor.gui.avv_upload_dialog import AvvUploadDialog

_log = get_logger(__name__)

_HEADERS: list[str] = [
    "Vendor",
    "Datei",
    "Gueltig bis",
    "Renewal",
    "Status",
]

_RENEWAL_LABEL: dict[RenewalStatus, str] = {
    RenewalStatus.OK: "OK",
    RenewalStatus.EXPIRING_SOON: "LAEUFT AB",
    RenewalStatus.OVERDUE: "UEBERFAELLIG",
}


class AvvTabView(QWidget):
    """AVV-Tracker-Tab im Supply-Chain-Monitor.

    Signals:
        avv_changed: emittiert, wenn ein AVV angelegt/geaendert/geloescht wurde
            — das umgebende Widget kann sich aktualisieren.
    """

    avv_changed = Signal()

    def __init__(
        self,
        *,
        vendor_service: VendorService | None = None,
        avv_service: AvvService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendor_service = vendor_service or VendorService()
        self._avv_service = avv_service or AvvService()
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        self.setStyleSheet(supply_chain_tab_stylesheet())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        title = QLabel("AVV-Tracker")
        title.setObjectName("SupplyChainSectionTitle")
        layout.addWidget(title)

        info = QLabel(
            "Auftragsverarbeitungsvertraege (AVV) nach DSGVO Art. 28 — pro "
            "Vendor PDF hochladen, Gueltigkeitsdatum + Pflichtinhalts-Checkliste "
            "pflegen. PDFs werden verschluesselt unter ~/.finlai/avv/ abgelegt."
        )
        info.setWordWrap(True)
        info.setObjectName("AvvTabInfo")
        layout.addWidget(info)

        # Renewal-Banner als Card
        self._banner_card = QFrame()
        self._banner_card.setObjectName("AvvRenewalBannerCard")
        banner_layout = QVBoxLayout(self._banner_card)
        banner_layout.setContentsMargins(0, 0, 0, 0)
        banner_layout.setSpacing(2)
        banner_title = QLabel("Renewal-Status")
        banner_title.setObjectName("SupplyChainCardTitle")
        banner_layout.addWidget(banner_title)
        self._banner = QLabel()
        self._banner.setWordWrap(True)
        self._banner.setObjectName("AvvRenewalBanner")
        banner_layout.addWidget(self._banner)
        layout.addWidget(self._banner_card)

        # Buttons
        row = QHBoxLayout()
        self._upload_btn = QPushButton("AVV hochladen ...")
        self._upload_btn.setObjectName("AvvUploadButton")
        self._upload_btn.clicked.connect(self._on_upload)
        row.addWidget(self._upload_btn)

        self._open_btn = QPushButton("AVV oeffnen")
        self._open_btn.setObjectName("AvvOpenButton")
        self._open_btn.setEnabled(False)
        self._open_btn.clicked.connect(self._on_open)
        row.addWidget(self._open_btn)

        self._checklist_btn = QPushButton("Checkliste bearbeiten")
        self._checklist_btn.setEnabled(False)
        self._checklist_btn.clicked.connect(self._on_edit_checklist)
        row.addWidget(self._checklist_btn)

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
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        self._empty_hint = QLabel(
            "Noch keine AVV-Dokumente erfasst. Klicke 'AVV hochladen ...' um "
            "einen Vertrag zu importieren."
        )
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setObjectName("AvvEmptyHint")
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_upload(self) -> None:
        vendors = self._vendor_service.list_vendors()
        if not vendors:
            FinlaiInfoDialog(
                title="Kein Vendor",
                message=(
                    "Legen Sie zuerst im Vendoren-Tab einen Vendor an, bevor Sie "
                    "einen AVV importieren."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        dialog = AvvUploadDialog(vendors=vendors, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        vendor_id = dialog.selected_vendor_id()
        source = dialog.selected_file()
        if vendor_id is None or source is None:
            return
        try:
            self._avv_service.upload_avv(
                vendor_id=vendor_id,
                source_path=source,
                valid_from=dialog.selected_valid_from(),
                valid_until=dialog.selected_valid_until(),
                notes=dialog.selected_notes(),
            )
        except (FileNotFoundError, ValueError) as exc:
            FinlaiInfoDialog(
                title="Upload fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload()
        self.avv_changed.emit()

    def _on_open(self) -> None:
        """Entschluesselt die hinterlegte AVV-PDF in eine Temp-Datei und oeffnet sie.

        Die PDF liegt verschluesselt at-rest. Zum Ansehen wird sie kurz
        nach ``~/.finlai/avv/.open_tmp/`` entschluesselt und im System-Viewer
        geoeffnet; alte Temp-PDFs werden dabei zuerst geloescht. Fehler (Datei
        weg, altes Klartext-Format, kein Schluessel) werden gemeldet statt still
        verschluckt (coding-rules R3).
        """
        avv = self._selected_avv()
        if avv is None or avv.id is None:
            return
        try:
            temp_pdf = self._avv_service.open_decrypted(avv.id)
        except (FileNotFoundError, ValueError):
            FinlaiInfoDialog(
                title="Datei nicht gefunden",
                message=(
                    "Die hinterlegte AVV-PDF wurde nicht gefunden. Moeglicherweise "
                    "wurde sie ausserhalb von NoRisk verschoben oder geloescht."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        except AvvPdfDecryptError:
            FinlaiInfoDialog(
                title="Aelteres Format",
                message=(
                    "Dieses AVV-PDF stammt aus der unverschluesselten Vorversion und "
                    "kann nicht geoeffnet werden. Bitte laden Sie den Vertrag erneut "
                    "hoch."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        except AvvPdfCipherError:
            FinlaiInfoDialog(
                title="Verschluesselung nicht verfuegbar",
                message=(
                    "Das AVV-PDF kann nicht entschluesselt werden — der Schluessel "
                    "ist nicht verfuegbar (anderes Windows-Profil?)."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(temp_pdf)))

    def _on_edit_checklist(self) -> None:
        avv = self._selected_avv()
        if avv is None or avv.id is None:
            return
        entries = self._avv_service.get_checklist(avv.id)
        dialog = AvvChecklistDialog(avv_id=avv.id, entries=entries, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._avv_service.update_checklist(avv.id, dialog.collected_entries())
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Speichern fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self.avv_changed.emit()

    def _on_delete(self) -> None:
        avv = self._selected_avv()
        if avv is None or avv.id is None:
            return
        dlg = FinlaiConfirmDialog(
            title="AVV loeschen",
            message=(
                f"AVV '{avv.original_filename}' wirklich loeschen?\n\n"
                "PDF im Storage und alle Checklist-Eintraege werden entfernt."
            ),
            confirm_text="Loeschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._avv_service.delete_avv(avv.id)
        self._reload()
        self.avv_changed.emit()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._open_btn.setEnabled(has_selection)
        self._checklist_btn.setEnabled(has_selection)
        self._delete_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def _reload(self) -> None:
        avvs = self._avv_service.list_all()
        self._avvs: list[AvvDocument] = avvs
        # Vendor-Map fuer Name-Anzeige + KI-Todo-Emit
        vendor_map = {
            v.id: v.name for v in self._vendor_service.list_vendors() if v.id is not None
        }

        self._table.setRowCount(len(avvs))
        for row, avv in enumerate(avvs):
            self._set_row(row, avv, vendor_map.get(avv.vendor_id, "?"))
        self._empty_hint.setVisible(len(avvs) == 0)
        self._table.setVisible(len(avvs) > 0)
        self._table.clearSelection()
        self._open_btn.setEnabled(False)
        self._checklist_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)
        self._update_banner()

        # Iter 2c-ii: bei jedem Reload aktionable Renewal-Findings an die
        # KI-Todo-Engine reichen. Idempotent dank Dedup auf evidence_id.
        try:
            self._avv_service.emit_renewal_findings(vendor_name_lookup=vendor_map)
        except Exception:  # noqa: BLE001 — Hook darf den Tab nie crashen
            _log.exception("AvvTabView: emit_renewal_findings fehlgeschlagen")

    def _set_row(self, row: int, avv: AvvDocument, vendor_name: str) -> None:
        vendor_item = QTableWidgetItem(vendor_name)
        vendor_item.setData(Qt.ItemDataRole.UserRole, avv.id)
        self._table.setItem(row, 0, vendor_item)

        self._table.setItem(row, 1, QTableWidgetItem(avv.original_filename))
        self._table.setItem(
            row, 2, QTableWidgetItem(avv.valid_until.strftime("%Y-%m-%d"))
        )

        renewal = avv.renewal_status()
        renewal_item = QTableWidgetItem(_RENEWAL_LABEL[renewal])
        renewal_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 3, renewal_item)

        self._table.setItem(row, 4, QTableWidgetItem(avv.status.value.upper()))

    def _selected_avv(self) -> AvvDocument | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        if 0 <= idx < len(self._avvs):
            return self._avvs[idx]
        return None

    def _update_banner(self) -> None:
        expiring = self._avv_service.list_expiring(
            within_days=RENEWAL_WARNING_DAYS_DEFAULT,
            include_overdue=True,
        )
        if not expiring:
            self._banner.setText(
                "Alle AVVs laufen noch laenger als "
                f"{RENEWAL_WARNING_DAYS_DEFAULT} Tage — keine Renewal-Pflicht."
            )
            return
        overdue = [e for e in expiring if e.status is RenewalStatus.OVERDUE]
        soon = [e for e in expiring if e.status is RenewalStatus.EXPIRING_SOON]
        parts: list[str] = []
        if overdue:
            parts.append(f"{len(overdue)} ueberfaellig")
        if soon:
            parts.append(
                f"{len(soon)} laufen in <{RENEWAL_WARNING_DAYS_DEFAULT} Tagen ab"
            )
        self._banner.setText("Renewal-Status: " + ", ".join(parts) + ".")

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 — Qt-Override
        """Loescht entschluesselte Temp-PDFs beim Schliessen (best-effort)."""
        try:
            self._avv_service.purge_open_temp()
        except Exception:  # noqa: BLE001 — Teardown darf nie crashen
            _log.exception("AvvTabView: purge_open_temp beim Schliessen fehlgeschlagen")
        super().closeEvent(event)
