"""
reports_tab_view — Reports-Tab im Supply-Chain-Monitor.

Iter 2d-ii-ii, 2026-05-15): Zwei PDF-Reports per Save-As-Dialog:

- GV.SC-Compliance-Report (NIST CSF 2.0 GV.SC + BSI OPS.2.3 + ORP.5).
- AVV-Status-Report (alle AVVs mit Renewal-Status + Art-28-Check-Quote).

Author: Patrick Riederich
Version: 0.1-ii, 2026-05-15)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.dialogs import FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.compliance_assessor import (
    ComplianceAssessor,
)
from tools.supply_chain_monitor.application.report_renderer import (
    render_avv_status_report,
    render_gvsc_compliance_report,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService

_log = get_logger(__name__)


class ReportsTabView(QWidget):
    """Reports-Tab — exportiert PDF-Reports."""

    def __init__(
        self,
        *,
        vendor_service: VendorService | None = None,
        avv_service: AvvService | None = None,
        compliance_assessor: ComplianceAssessor | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendors = vendor_service or VendorService()
        self._avvs = avv_service or AvvService()
        self._assessor = compliance_assessor or ComplianceAssessor(
            vendor_service=self._vendors,
            avv_service=self._avvs,
        )
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        info = QLabel(
            "PDF-Reports fuer Audit und Compliance. <b>GV.SC-Compliance-Report</b> "
            "mappt die aktuellen Supply-Chain-Daten gegen NIST CSF 2.0 GV.SC "
            "und BSI Grundschutz OPS.2.3 + ORP.5. <b>AVV-Status-Report</b> "
            "listet alle AVV-Dokumente mit Renewal-Status und Art-28-Check-Quote."
        )
        info.setWordWrap(True)
        info.setObjectName("ReportsTabInfo")
        layout.addWidget(info)

        # Optionaler Kundennamen-Input fuer das Deckblatt
        layout.addWidget(QLabel("Kundenname (optional, fuer Deckblatt):"))
        self._customer_input = QLineEdit()
        self._customer_input.setPlaceholderText("z. B. Kanzlei Mustermann GmbH")
        layout.addWidget(self._customer_input)

        layout.addSpacing(8)

        self._gvsc_btn = QPushButton("GV.SC-Compliance-Report exportieren ...")
        self._gvsc_btn.setObjectName("ReportsGvscButton")
        self._gvsc_btn.clicked.connect(self._on_export_gvsc)
        layout.addWidget(self._gvsc_btn)

        self._avv_btn = QPushButton("AVV-Status-Report exportieren ...")
        self._avv_btn.setObjectName("ReportsAvvButton")
        self._avv_btn.clicked.connect(self._on_export_avv)
        layout.addWidget(self._avv_btn)

        self._status_label = QLabel("")
        self._status_label.setObjectName("ReportsStatusLabel")
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        layout.addStretch(1)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_export_gvsc(self) -> None:
        default = self._default_filename("gvsc")
        path = self._ask_save_path(default)
        if path is None:
            return
        try:
            report = self._assessor.assess_all()
            render_gvsc_compliance_report(
                path, report, customer_name=self._customer_input.text().strip()
            )
        except Exception as exc:  # noqa: BLE001 — User soll Klartext sehen
            _log.exception("GV.SC-Report-Export fehlgeschlagen")
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        self._show_success(path)

    def _on_export_avv(self) -> None:
        default = self._default_filename("avv_status")
        path = self._ask_save_path(default)
        if path is None:
            return
        try:
            render_avv_status_report(
                path,
                self._avvs,
                self._vendors,
                customer_name=self._customer_input.text().strip(),
            )
        except Exception as exc:  # noqa: BLE001
            _log.exception("AVV-Status-Report-Export fehlgeschlagen")
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return
        self._show_success(path)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    @staticmethod
    def _default_filename(kind: str) -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return f"supply_chain_{kind}_{timestamp}.pdf"

    def _ask_save_path(self, suggested_name: str) -> Path | None:
        chosen, _ = QFileDialog.getSaveFileName(
            self,
            "PDF speichern unter ...",
            str(Path.home() / suggested_name),
            "PDF-Dateien (*.pdf);;Alle Dateien (*)",
        )
        if not chosen:
            return None
        path = Path(chosen)
        if path.suffix.lower() != ".pdf":
            path = path.with_suffix(".pdf")
        return path

    def _show_success(self, path: Path) -> None:
        self._status_label.setText(
            f"PDF erstellt: <b>{path.name}</b> ({path.stat().st_size} Bytes) "
            f"unter <i>{path.parent}</i>."
        )
        self._status_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
