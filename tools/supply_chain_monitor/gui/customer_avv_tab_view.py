"""
customer_avv_tab_view — Kunden-Perspektive des AVV-Trackers.

Gegenstueck zu:class:`AvvTabView`: WIR sind Auftragsverarbeiter, der Kunde ist
Verantwortlicher. Zeigt die archivierten Kunden-AVVs (gekoppelt an ``subject_id``)
mit Renewal-Banner, Tabelle und denselben Aktionen (Hochladen/Oeffnen/Checkliste/
Loeschen). Die Art-28-Checkliste wird unveraendert wiederverwendet.

Perf/Tier-1): Der Kundenname wird BATCH ueber ein einmaliges
``subject_store.list_all`` aufgeloest (Dict, kein ``get`` pro Zeile = kein
N+1 auf die security_scoring-DB); die geladene Liste wird an Banner + KI-Todo-
Emit weitergereicht (kein dreifaches ``list_all``).

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren. Die
Kunden-Identitaet kommt ausschliesslich ueber den ``SubjectStore``-Port.

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
from core.security_subject.models import SubjectKind
from core.security_subject.ports import SubjectStore
from core.security_subject.resolver import create_subject_store
from tools.supply_chain_monitor.application.customer_avv_service import (
    AvvPdfCipherError,
    AvvPdfDecryptError,
    CustomerAvvService,
)
from tools.supply_chain_monitor.domain.models import (
    RENEWAL_WARNING_DAYS_DEFAULT,
    CustomerAvvDocument,
    RenewalStatus,
)
from tools.supply_chain_monitor.gui._tab_style import supply_chain_tab_stylesheet
from tools.supply_chain_monitor.gui.avv_checklist_dialog import AvvChecklistDialog
from tools.supply_chain_monitor.gui.customer_avv_upload_dialog import (
    CustomerAvvUploadDialog,
)

_log = get_logger(__name__)

_HEADERS: list[str] = [
    "Kunde",
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


class CustomerAvvTabView(QWidget):
    """Kunden-Perspektive des AVV-Trackers (wir = Auftragsverarbeiter).

    Signals:
        avv_changed: emittiert, wenn ein Kunden-AVV angelegt/geaendert/geloescht
            wurde.
    """

    avv_changed = Signal()

    def __init__(
        self,
        *,
        customer_avv_service: CustomerAvvService | None = None,
        subject_store: SubjectStore | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        # Store ZUERST aufloesen (fail-soft None) und an den Service durchreichen,
        # damit Picker/Namensaufloesung und Upload-Validierung denselben Store
        # (eine security_scoring-DB-Verbindung) nutzen.
        self._subject_store = subject_store or create_subject_store()
        self._service = customer_avv_service or CustomerAvvService(
            subject_store=self._subject_store
        )
        self._avvs: list[CustomerAvvDocument] = []
        self._build_ui()
        self._reload()

    def _build_ui(self) -> None:
        self.setStyleSheet(supply_chain_tab_stylesheet())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        title = QLabel("AVV-Tracker — Unsere Kunden")
        title.setObjectName("SupplyChainSectionTitle")
        layout.addWidget(title)

        info = QLabel(
            "Hier sind WIR der Auftragsverarbeiter: Archivieren Sie die AVVs Ihrer "
            "Kunden (nach DSGVO Art. 28). Pro Kunde PDF hochladen, Gueltigkeit + "
            "Pflichtinhalts-Checkliste pflegen. PDFs werden verschluesselt unter "
            "~/.finlai/avv/customers/ abgelegt."
        )
        info.setWordWrap(True)
        info.setObjectName("AvvTabInfo")
        layout.addWidget(info)

        # Renewal-Banner
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
        self._upload_btn = QPushButton("Kunden-AVV hochladen ...")
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
            "Noch keine Kunden-AVVs erfasst. Klicken Sie 'Kunden-AVV hochladen ...' "
            "um einen Vertrag zu importieren."
        )
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_hint.setObjectName("AvvEmptyHint")
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_upload(self) -> None:
        if self._subject_store is None:
            FinlaiInfoDialog(
                title="Kunden-Verwaltung nicht verfuegbar",
                message=(
                    "Die Kunden-Verwaltung ist derzeit nicht verfuegbar — ein "
                    "Kunden-AVV kann nicht angelegt werden."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        customers = self._list_customers()
        dialog = CustomerAvvUploadDialog(customers=customers, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        source = dialog.selected_file()
        if source is None:
            return
        subject_id = self._resolve_subject_id(dialog)
        if subject_id is None:
            return
        try:
            self._service.upload_avv_for_customer(
                subject_id=subject_id,
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

    def _resolve_subject_id(self, dialog: CustomerAvvUploadDialog) -> str | None:
        """Ermittelt die subject_id — bestehender Kunde oder Neuanlage.

        Returns:
            Die subject_id oder ``None`` bei Fehler (Meldung wurde gezeigt).
        """
        existing = dialog.selected_subject_id()
        if existing is not None:
            return existing
        new_name = dialog.new_customer_name()
        if not new_name or self._subject_store is None:
            return None
        try:
            subject = self._subject_store.find_or_create_client(new_name)
        except Exception as exc:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("find_or_create_client fehlgeschlagen")
            FinlaiInfoDialog(
                title="Kunde konnte nicht angelegt werden",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return None
        return subject.subject_id

    def _on_open(self) -> None:
        avv = self._selected_avv()
        if avv is None or avv.id is None:
            return
        try:
            temp_pdf = self._service.open_decrypted(avv.id)
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
                    "Dieses AVV-PDF kann nicht entschluesselt werden. Bitte laden "
                    "Sie den Vertrag erneut hoch."
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
        entries = self._service.get_checklist(avv.id)
        dialog = AvvChecklistDialog(avv_id=avv.id, entries=entries, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.update_checklist(avv.id, dialog.collected_entries())
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
            title="Kunden-AVV loeschen",
            message=(
                f"Kunden-AVV '{avv.original_filename}' wirklich loeschen?\n\n"
                "PDF im Storage und alle Checklist-Eintraege werden entfernt. "
                "Beachten Sie etwaige Aufbewahrungspflichten."
            ),
            confirm_text="Loeschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._service.delete_avv(avv.id)
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

    def _list_customers(self) -> list[tuple[str, str]]:
        """``(subject_id, name)`` aller KUNDE-Subjekte (fuer den Upload-Picker)."""
        if self._subject_store is None:
            return []
        try:
            return [
                (s.subject_id, s.name)
                for s in self._subject_store.list_all()
                if s.kind is SubjectKind.KUNDE
            ]
        except Exception:  # noqa: BLE001 — Cross-DB-Store-Grenze, fail-soft
            _log.exception("Kundenliste konnte nicht geladen werden")
            return []

    def _subject_name_map(self) -> dict[str, str]:
        """BATCH-Aufloesung subject_id -> Name (ein list_all, kein N+1)."""
        return {sid: name for sid, name in self._list_customers()}

    def _reload(self) -> None:
        avvs = self._service.list_all()
        self._avvs = avvs
        name_map = self._subject_name_map()

        self._table.setRowCount(len(avvs))
        for row, avv in enumerate(avvs):
            self._set_row(row, avv, name_map.get(avv.subject_id, "?"))
        self._empty_hint.setVisible(len(avvs) == 0)
        self._table.setVisible(len(avvs) > 0)
        self._table.clearSelection()
        self._open_btn.setEnabled(False)
        self._checklist_btn.setEnabled(False)
        self._delete_btn.setEnabled(False)

        # Renewal einmal berechnen und an Banner + Emit weiterreichen (Perf:
        # genau ein list_all oben, kein erneuter DB-Read).
        expiring = self._service.list_expiring(
            within_days=RENEWAL_WARNING_DAYS_DEFAULT,
            include_overdue=True,
            docs=avvs,
        )
        self._update_banner(expiring)
        try:
            self._service.emit_renewal_findings(
                subject_name_lookup=name_map, expiring=expiring
            )
        except Exception:  # noqa: BLE001 — Hook darf den Tab nie crashen
            _log.exception("CustomerAvvTabView: emit_renewal_findings fehlgeschlagen")

    def _set_row(self, row: int, avv: CustomerAvvDocument, customer_name: str) -> None:
        name_item = QTableWidgetItem(customer_name)
        name_item.setData(Qt.ItemDataRole.UserRole, avv.id)
        self._table.setItem(row, 0, name_item)

        self._table.setItem(row, 1, QTableWidgetItem(avv.original_filename))
        self._table.setItem(
            row, 2, QTableWidgetItem(avv.valid_until.strftime("%Y-%m-%d"))
        )

        renewal = avv.renewal_status()
        renewal_item = QTableWidgetItem(_RENEWAL_LABEL[renewal])
        renewal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, 3, renewal_item)

        self._table.setItem(row, 4, QTableWidgetItem(avv.status.value.upper()))

    def _selected_avv(self) -> CustomerAvvDocument | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        if 0 <= idx < len(self._avvs):
            return self._avvs[idx]
        return None

    def _update_banner(self, expiring: list) -> None:  # noqa: ANN001
        if not expiring:
            self._banner.setText(
                "Alle Kunden-AVVs laufen noch laenger als "
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
            self._service.purge_open_temp()
        except Exception:  # noqa: BLE001 — Teardown darf nie crashen
            _log.exception("CustomerAvvTabView: purge_open_temp fehlgeschlagen")
        super().closeEvent(event)
