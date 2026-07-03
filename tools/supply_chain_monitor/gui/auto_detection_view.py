"""
auto_detection_view — Auto-Detection-Tab im Supply-Chain-Monitor.

Iter 2b:

- Domain-Eingabe (Komma-getrennt) + "Detection starten"-Button.
- Suggestions-Tabelle mit Confidence-Badge und Quellen-Breakdown.
- Pro Suggestion: Aktionen *Uebernehmen* / *Verwerfen* / *Vertagen*.
- Button "Catalog verwalten" oeffnet:class:`CatalogManagementDialog`.

Threading: Iter 2b laeuft die Detection im UI-Thread mit Wait-Cursor.
Bei langsamen Netzwerk-Pfaden (Cert-Scans, >5s) ist QThread ein
Follow-up-Thema in Iter 2c+.

Schichtzugehoerigkeit: gui/ — darf application + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.supply_chain_monitor.application.detection_service import DetectionService
from tools.supply_chain_monitor.domain.models import (
    DETECTION_SOURCE_WEIGHTS,
    DetectionConfidence,
    DetectionSource,
    VendorSuggestion,
)
from tools.supply_chain_monitor.gui.catalog_management_dialog import (
    CatalogManagementDialog,
)

_log = get_logger(__name__)

_HEADERS: list[str] = [
    "Vendor",
    "Kategorie",
    "Confidence",
    "Quellen",
    "Letzte Detection",
]

_CONFIDENCE_LABEL: dict[DetectionConfidence, str] = {
    DetectionConfidence.HIGH: "HOCH",
    DetectionConfidence.MEDIUM: "MITTEL",
    DetectionConfidence.LOW: "NIEDRIG",
}

_SOURCE_SHORT: dict[DetectionSource, str] = {
    DetectionSource.INSTALLED_APP: "Apps",
    DetectionSource.MX_LOOKUP: "MX",
    DetectionSource.CERT_ISSUER: "Cert",
}


class AutoDetectionView(QWidget):
    """Auto-Detection-Tab — Detection-Run + Suggestions-Tabelle.

    Signals:
        vendor_accepted: emittiert, wenn der User eine Suggestion in einen
            Vendor uebernommen hat. Das umgebende Widget kann darauf den
            Vendoren-Tab refreshen.
    """

    vendor_accepted = Signal()

    def __init__(
        self,
        service: DetectionService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or DetectionService()
        self._build_ui()
        self._reload_suggestions()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        info = QLabel(
            "Erkennt Vendoren ueber drei Quellen: lokal installierte Software, "
            "MX-Records einer Domain (DNS-Lookup) und das TLS-Zertifikat einer "
            "Domain. Geben Sie Ihre Kanzlei-Domain ein (z. B. 'kanzlei.de') — "
            "optional weitere Domains komma-getrennt — und starten Sie die Detection."
        )
        info.setWordWrap(True)
        info.setObjectName("AutoDetectionInfo")
        layout.addWidget(info)

        # Domain-Input-Zeile
        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Domains:"))
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText(
            "kanzlei.de, partner-mandant.de  (komma-getrennt — leer = nur Installed-Apps)"
        )
        input_row.addWidget(self._domain_input, stretch=1)
        self._run_btn = QPushButton("Detection starten")
        self._run_btn.setObjectName("AutoDetectionRunButton")
        self._run_btn.clicked.connect(self._on_run_detection)
        input_row.addWidget(self._run_btn)
        self._catalog_btn = QPushButton("Catalog verwalten")
        self._catalog_btn.clicked.connect(self._on_open_catalog)
        input_row.addWidget(self._catalog_btn)
        layout.addLayout(input_row)

        # Suggestions-Tabelle
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
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=1)

        # Action-Buttons
        action_row = QHBoxLayout()
        action_row.addStretch(1)
        self._accept_btn = QPushButton("Als Vendor uebernehmen")
        self._accept_btn.setObjectName("AutoDetectionAcceptButton")
        self._accept_btn.setEnabled(False)
        self._accept_btn.clicked.connect(self._on_accept)
        action_row.addWidget(self._accept_btn)
        self._defer_btn = QPushButton("Vertagen")
        self._defer_btn.setEnabled(False)
        self._defer_btn.clicked.connect(self._on_defer)
        action_row.addWidget(self._defer_btn)
        self._reject_btn = QPushButton("Verwerfen")
        self._reject_btn.setObjectName("AutoDetectionRejectButton")
        self._reject_btn.setEnabled(False)
        self._reject_btn.clicked.connect(self._on_reject)
        action_row.addWidget(self._reject_btn)
        layout.addLayout(action_row)

        self._empty_hint = QLabel(
            "Keine offenen Detection-Vorschlaege. Starten Sie oben eine Detection."
        )
        self._empty_hint.setObjectName("AutoDetectionEmptyHint")
        self._empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty_hint)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_run_detection(self) -> None:
        domains = _split_csv(self._domain_input.text())
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        self._run_btn.setEnabled(False)
        try:
            summary = self._service.run_detection(domains)
        except Exception as exc:  # noqa: BLE001
            _log.exception("Detection-Run fehlgeschlagen")
            FinlaiInfoDialog(
                title="Detection fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        finally:
            QApplication.restoreOverrideCursor()
            self._run_btn.setEnabled(True)
        self._show_detection_summary(summary)
        self._reload_suggestions()

    def _show_detection_summary(self, summary) -> None:  # noqa: ANN001 — DetectionSummary
        """Zeigt das Detection-Ergebnis in einem Theme-konformen Dialog.

        Statt:class:`QMessageBox.information` (OS-natives blaues Icon,
        fixed-width-Text) nutzen wir den FINLAI-Info-Dialog — damit das
        Popup im FINLAI-Dark-Theme integriert wirkt.
        """
        message = (
            f"Installed-Apps: {summary.installed_apps_count}\n"
            f"MX-Lookup: {summary.mx_lookup_count}\n"
            f"Cert-Issuer: {summary.cert_issuer_count}\n"
            f"Gesamt: {summary.total_count}"
        )
        FinlaiInfoDialog(
            title="Detection abgeschlossen",
            message=message,
            icon_name=Icons.INFO,
            parent=self,
        ).exec()

    def _on_open_catalog(self) -> None:
        dialog = CatalogManagementDialog(parent=self)
        dialog.exec()
        # Catalog-Aenderungen koennen frische Suggestions ergeben; Reload.
        self._reload_suggestions()

    def _on_accept(self) -> None:
        suggestion = self._selected_suggestion()
        if suggestion is None or suggestion.catalog_entry.id is None:
            return
        try:
            self._service.accept_suggestion(suggestion.catalog_entry.id)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Uebernahme fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self.vendor_accepted.emit()
        self._reload_suggestions()

    def _on_defer(self) -> None:
        suggestion = self._selected_suggestion()
        if suggestion is None or suggestion.catalog_entry.id is None:
            return
        self._service.defer_suggestion(suggestion.catalog_entry.id)
        self._reload_suggestions()

    def _on_reject(self) -> None:
        suggestion = self._selected_suggestion()
        if suggestion is None or suggestion.catalog_entry.id is None:
            return
        dlg = FinlaiConfirmDialog(
            title="Vorschlag verwerfen",
            message=(
                f"Den Vorschlag '{suggestion.catalog_entry.canonical_name}' "
                "endgueltig verwerfen? Er wird bei zukuenftigen Detection-Runs "
                "nicht erneut vorgeschlagen."
            ),
            confirm_text="Verwerfen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._service.reject_suggestion(suggestion.catalog_entry.id)
        self._reload_suggestions()

    def _on_selection_changed(self) -> None:
        has_selection = bool(self._table.selectionModel().selectedRows())
        self._accept_btn.setEnabled(has_selection)
        self._defer_btn.setEnabled(has_selection)
        self._reject_btn.setEnabled(has_selection)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def _reload_suggestions(self) -> None:
        self._suggestions: list[VendorSuggestion] = self._service.list_suggestions()
        self._table.setRowCount(len(self._suggestions))
        for row, sug in enumerate(self._suggestions):
            self._set_row(row, sug)
        self._empty_hint.setVisible(len(self._suggestions) == 0)
        self._table.setVisible(len(self._suggestions) > 0)
        self._table.clearSelection()
        self._accept_btn.setEnabled(False)
        self._defer_btn.setEnabled(False)
        self._reject_btn.setEnabled(False)

    def _set_row(self, row: int, sug: VendorSuggestion) -> None:
        name_item = QTableWidgetItem(sug.catalog_entry.canonical_name)
        name_item.setData(Qt.ItemDataRole.UserRole, sug.catalog_entry.id)
        self._table.setItem(row, 0, name_item)

        category_item = QTableWidgetItem(_humanize_category(sug.catalog_entry))
        self._table.setItem(row, 1, category_item)

        confidence_text = (
            f"{_CONFIDENCE_LABEL[sug.confidence]} ({sug.source_points})"
        )
        confidence_item = QTableWidgetItem(confidence_text)
        confidence_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._table.setItem(row, 2, confidence_item)

        sources_text = _format_sources_breakdown(sug)
        self._table.setItem(row, 3, QTableWidgetItem(sources_text))

        # last_detected_at ist aware-UTC -> fuer die Anzeige in die lokale
        # Wandzeit des Nutzers konvertieren: zeigte vorher roh UTC).
        last_seen_text = sug.last_detected_at.astimezone().strftime("%Y-%m-%d %H:%M")
        self._table.setItem(row, 4, QTableWidgetItem(last_seen_text))

    def _selected_suggestion(self) -> VendorSuggestion | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        if 0 <= row < len(self._suggestions):
            return self._suggestions[row]
        return None


def _split_csv(value: str) -> list[str]:
    return [part for part in (p.strip() for p in value.split(",")) if part]


def _humanize_category(entry) -> str:  # noqa: ANN001
    return entry.default_category.value.replace("_", " ").title()


def _format_sources_breakdown(suggestion: VendorSuggestion) -> str:
    """``"Cert+MX+Apps (3+2+1=6)"`` o. ae."""
    actionable = [d for d in suggestion.detections if d.is_actionable()]
    unique_sources = sorted(
        {d.source for d in actionable},
        key=lambda s: -DETECTION_SOURCE_WEIGHTS[s],
    )
    labels = "+".join(_SOURCE_SHORT[s] for s in unique_sources)
    weights = "+".join(str(DETECTION_SOURCE_WEIGHTS[s]) for s in unique_sources)
    return f"{labels}  ({weights}={suggestion.source_points})"
