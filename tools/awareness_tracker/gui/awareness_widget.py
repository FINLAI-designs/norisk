"""
awareness_widget — Hauptansicht des Awareness-Trackers.

Iteration 3a: 3 Tabs (Mitarbeiter funktional,
Schulungen + Phishing als Placeholder).

Iteration 3b: Schulungen-Tab voll funktional —
TrainingFormDialog (Add/Edit/Delete), Renewal-Banner-Card, CSV-Import-
Menue (Mitarbeiter + Schulungen), Bulk-ICS-Export aller Renewals.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.2
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import (
    FinlaiConfirmDialog,
    FinlaiInfoDialog,
    FinlaiSuccessDialog,
)
from core.icons import Icons
from core.logger import get_logger
from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.application.ics_exporter import (
    IcsExportError,
    export_renewals_to_ics,
)
from tools.awareness_tracker.domain.models import (
    Employee,
    Training,
    TrainingType,
    ValidityStatus,
)
from tools.awareness_tracker.gui.csv_import_dialog import (
    CsvImportDialog,
    CsvImportMode,
)
from tools.awareness_tracker.gui.employee_form_dialog import (
    EmployeeFormDialog,
)
from tools.awareness_tracker.gui.human_risk_gauge import HumanRiskGauge
from tools.awareness_tracker.gui.phishing_sim_widget import (
    PhishingSimWidget,
)
from tools.awareness_tracker.gui.renewal_banner import RenewalBanner
from tools.awareness_tracker.gui.training_form_dialog import (
    TrainingFormDialog,
)

_log = get_logger(__name__)

_INFO_TEXT = (
    "Dokumentiere Mitarbeiter-Schulungen (DSGVO, IT-Sicherheit, "
    "Phishing-Awareness, Incident-Response, Berufsrecht) und Phishing-"
    "Simulations-Kampagnen. Dieses Inventar belegt die Awareness- und "
    "Schulungs-Pflichten nach NIST CSF PR.AT, NIS2 Art. 21(2)(g) und "
    "DSGVO Art. 39 Abs. 1 lit. b."
)

_EMPLOYEE_HEADERS: list[str] = [
    "Name",
    "Rolle",
    "Abteilung",
    "Status",
    "Notizen",
]

_TRAINING_HEADERS: list[str] = [
    "Mitarbeiter",
    "Typ",
    "Titel",
    "Abgeschlossen",
    "Gueltig bis",
    "Status",
    "Anbieter",
]

_TYPE_DISPLAY: dict[TrainingType, str] = {
    TrainingType.DSGVO_BASICS: "DSGVO-Grundlagen",
    TrainingType.IT_SECURITY: "IT-Sicherheit",
    TrainingType.PHISHING_AWARENESS: "Phishing-Awareness",
    TrainingType.INCIDENT_RESPONSE: "Incident-Response",
    TrainingType.COMPLIANCE_BRAO: "Berufsrecht",
    TrainingType.CUSTOM: "Custom",
}

_STATUS_DISPLAY: dict[ValidityStatus, str] = {
    ValidityStatus.VALID: "Aktuell",
    ValidityStatus.EXPIRING_SOON: "Laeuft aus",
    ValidityStatus.EXPIRED: "Abgelaufen",
    ValidityStatus.PERMANENT: "Permanent",
}

# Filter-Combo-Werte fuer den Status-Filter im Schulungen-Tab.
_STATUS_FILTER_ALL: str = "__all__"
_STATUS_FILTER_RENEWAL: str = "__renewal__"


class AwarenessWidget(QWidget):
    """Hauptansicht des Awareness-Trackers."""

    def __init__(
        self,
        service: AwarenessService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or AwarenessService()
        self._build_ui()
        self._reload_employees()
        self._reload_trainings()
        self._reload_human_risk()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("Awareness-Tracker")
        title.setObjectName("AwarenessTitle")
        layout.addWidget(title)

        info = QLabel(_INFO_TEXT)
        info.setObjectName("AwarenessInfo")
        info.setWordWrap(True)
        layout.addWidget(info)

        layout.addWidget(self._build_overview())

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_employees_tab(), "Mitarbeiter")
        self._tabs.addTab(self._build_trainings_tab(), "Schulungen")
        self._phishing_widget = PhishingSimWidget(service=self._service, parent=self)
        self._tabs.addTab(
            self._wrap_with_margins(self._phishing_widget),
            "Phishing-Simulationen",
        )
        # Score-Uebersicht nach jedem Tab-Wechsel auffrischen (faengt Edits
        # in allen drei Tabs inkl. Phishing-Simulationen ab).
        self._tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self._tabs, stretch=1)

    @staticmethod
    def _wrap_with_margins(inner: QWidget) -> QWidget:
        """Tab-Container mit denselben 20px-Margins wie die anderen Tabs."""
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(20, 20, 20, 20)
        host_layout.setSpacing(12)
        host_layout.addWidget(inner)
        return host

    # ------------------------------------------------------------------
    # Human-Risk-Score-Uebersicht (IA-Welle 2)
    # ------------------------------------------------------------------

    def _build_overview(self) -> QWidget:
        """Baut die Human-Risk-Score-Uebersicht (Gauge + Kennzahlen)."""
        t = theme.get()
        frame = QFrame()
        frame.setObjectName("AwarenessOverview")
        frame.setStyleSheet(
            f"#AwarenessOverview {{ background-color: {t.CARD_BG};"
            f" border: 1px solid {t.BORDER}; border-radius: 8px; }}"
        )
        outer = QHBoxLayout(frame)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(20)

        self._risk_gauge = HumanRiskGauge()
        self._risk_gauge.clicked.connect(self._on_risk_gauge_clicked)
        outer.addWidget(self._risk_gauge, 0, Qt.AlignmentFlag.AlignVCenter)

        right = QVBoxLayout()
        right.setSpacing(6)

        heading = QLabel("Human-Risk-Score")
        heading.setObjectName("AwarenessOverviewHeading")
        heading.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: 15px; font-weight: bold;"
        )
        right.addWidget(heading)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(4)
        self._lbl_report = self._metric_row(grid, 0, "Melderate")
        self._lbl_click = self._metric_row(grid, 1, "Klickrate")
        self._lbl_training = self._metric_row(grid, 2, "Schulungs-Aktualitaet")
        # "Klick-Trend" (nicht "Trend"): der Wert ist das Klickraten-Delta,
        # NICHT der Gesamt-Score-Trend — sonst irrefuehrend (Review P1).
        self._lbl_trend = self._metric_row(grid, 3, "Klick-Trend")
        right.addLayout(grid)

        self._lbl_hint = QLabel("")
        self._lbl_hint.setObjectName("AwarenessOverviewHint")
        self._lbl_hint.setWordWrap(True)
        self._lbl_hint.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: 11px; font-style: italic;"
        )
        self._lbl_hint.setVisible(False)
        right.addWidget(self._lbl_hint)

        right.addStretch()
        outer.addLayout(right, 1)
        return frame

    def _metric_row(self, grid: QGridLayout, row: int, label: str) -> QLabel:
        """Fuegt eine 'Label: Wert'-Zeile ins Grid; gibt das Wert-Label zurueck."""
        t = theme.get()
        name = QLabel(f"{label}:")
        name.setStyleSheet(f"color: {t.TEXT_DIM};")
        value = QLabel("—")
        value.setStyleSheet(f"color: {t.TEXT_MAIN}; font-weight: bold;")
        grid.addWidget(name, row, 0, Qt.AlignmentFlag.AlignLeft)
        grid.addWidget(value, row, 1, Qt.AlignmentFlag.AlignLeft)
        return value

    def _on_risk_gauge_clicked(self) -> None:
        """Klick auf den Gauge -> Phishing-Tab als Detail-Drilldown."""
        # Tab-Reihenfolge: 0 Mitarbeiter, 1 Schulungen, 2 Phishing.
        self._tabs.setCurrentIndex(2)

    def _on_tab_changed(self, _index: int) -> None:
        """Aktualisiert die Score-Uebersicht beim Tab-Wechsel (nach Edits)."""
        self._reload_human_risk()

    def _reload_human_risk(self) -> None:
        """Berechnet den Human-Risk-Score neu und aktualisiert die Uebersicht.

        Fail-soft: ein Fehler in der Berechnung (z. B. DB-Problem) darf das
        Awareness-Tab NICHT reissen (Praezedenz: t.GRADE_D-Crash, Commit
        01ee921). Stattdessen Gauge leeren + dezenter Hinweis.
        """
        try:
            risk = self._service.compute_human_risk_score()
        except Exception:  # noqa: BLE001 — fail-soft, Tab darf nicht abstuerzen
            _log.exception("Human-Risk-Score-Berechnung fehlgeschlagen")
            self._risk_gauge.set_score(None)
            for lbl in (
                self._lbl_report,
                self._lbl_click,
                self._lbl_training,
                self._lbl_trend,
            ):
                lbl.setText("—")
            self._lbl_hint.setText("Score derzeit nicht verfuegbar.")
            self._lbl_hint.setVisible(True)
            return

        if not risk.has_any_data:
            self._risk_gauge.set_score(None)
            for lbl in (
                self._lbl_report,
                self._lbl_click,
                self._lbl_training,
                self._lbl_trend,
            ):
                lbl.setText("—")
            self._lbl_hint.setText(
                "Noch keine Daten — erfasse Mitarbeiter, Schulungen und "
                "Phishing-Simulationen, um den Score zu sehen."
            )
            self._lbl_hint.setVisible(True)
            return

        self._risk_gauge.set_score(risk.score, risk.band)
        if risk.has_phishing_data:
            self._lbl_report.setText(f"{risk.report_rate:.0f} %")
            self._lbl_click.setText(f"{risk.click_rate:.0f} %")
        else:
            self._lbl_report.setText("—")
            self._lbl_click.setText("—")
        self._lbl_training.setText(f"{risk.training_completion:.0f} %")
        self._lbl_trend.setText(risk.trend_label)

        if risk.has_phishing_data:
            self._lbl_hint.setVisible(False)
        else:
            self._lbl_hint.setText(
                "Noch keine Phishing-Simulationen erfasst — der Score "
                "basiert allein auf der Schulungs-Aktualitaet."
            )
            self._lbl_hint.setVisible(True)

    # ------------------------------------------------------------------
    # Mitarbeiter-Tab
    # ------------------------------------------------------------------

    def _build_employees_tab(self) -> QWidget:
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(12)

        button_row = QHBoxLayout()
        self._add_employee_btn = QPushButton("Mitarbeiter hinzufuegen")
        self._add_employee_btn.setObjectName("AwarenessAddButton")
        self._add_employee_btn.clicked.connect(self._on_add_employee_clicked)
        button_row.addWidget(self._add_employee_btn)

        self._edit_employee_btn = QPushButton("Bearbeiten")
        self._edit_employee_btn.setObjectName("AwarenessEditButton")
        self._edit_employee_btn.setEnabled(False)
        self._edit_employee_btn.clicked.connect(self._on_edit_employee_clicked)
        button_row.addWidget(self._edit_employee_btn)

        self._delete_employee_btn = QPushButton("Loeschen")
        self._delete_employee_btn.setObjectName("AwarenessDeleteButton")
        self._delete_employee_btn.setEnabled(False)
        self._delete_employee_btn.clicked.connect(self._on_delete_employee_clicked)
        button_row.addWidget(self._delete_employee_btn)

        button_row.addStretch(1)

        self._csv_import_btn = QPushButton("CSV importieren ▼")
        self._csv_import_btn.setObjectName("AwarenessCsvImportButton")
        csv_menu = QMenu(self._csv_import_btn)
        csv_menu.addAction(
            "Mitarbeiter importieren...",
            lambda: self._on_csv_import_clicked(CsvImportMode.EMPLOYEES),
        )
        csv_menu.addAction(
            "Schulungen importieren...",
            lambda: self._on_csv_import_clicked(CsvImportMode.TRAININGS),
        )
        self._csv_import_btn.setMenu(csv_menu)
        button_row.addWidget(self._csv_import_btn)

        host_layout.addLayout(button_row)

        self._employee_table = QTableWidget(0, len(_EMPLOYEE_HEADERS))
        self._employee_table.setHorizontalHeaderLabels(_EMPLOYEE_HEADERS)
        self._employee_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._employee_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._employee_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._employee_table.setAlternatingRowColors(True)
        self._employee_table.verticalHeader().setVisible(False)
        header = self._employee_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._employee_table.itemSelectionChanged.connect(
            self._on_employee_selection_changed
        )
        host_layout.addWidget(self._employee_table, stretch=1)

        self._employee_empty_hint = QLabel(
            "Noch keine Mitarbeiter erfasst — lege ueber den Button "
            "oben einen ersten Eintrag an."
        )
        self._employee_empty_hint.setObjectName("AwarenessEmptyHint")
        self._employee_empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        host_layout.addWidget(self._employee_empty_hint)

        return host

    # ------------------------------------------------------------------
    # Schulungen-Tab
    # ------------------------------------------------------------------

    def _build_trainings_tab(self) -> QWidget:
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(12)

        self._renewal_banner = RenewalBanner(parent=host)
        self._renewal_banner.show_renewals_clicked.connect(
            self._on_show_renewals_clicked
        )
        self._renewal_banner.export_ics_clicked.connect(self._on_export_ics_clicked)
        host_layout.addWidget(self._renewal_banner)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        filter_row.addWidget(QLabel("Mitarbeiter:"))
        self._employee_filter = QComboBox()
        self._employee_filter.setObjectName("AwarenessEmployeeFilter")
        self._employee_filter.addItem("Alle Mitarbeiter", userData=None)
        self._employee_filter.currentIndexChanged.connect(self._reload_trainings)
        filter_row.addWidget(self._employee_filter)

        filter_row.addSpacing(16)
        filter_row.addWidget(QLabel("Status:"))
        self._status_filter = QComboBox()
        self._status_filter.setObjectName("AwarenessStatusFilter")
        self._status_filter.addItem("Alle", userData=_STATUS_FILTER_ALL)
        self._status_filter.addItem(
            "Nur Renewal (abgelaufen + auslaufend)",
            userData=_STATUS_FILTER_RENEWAL,
        )
        for status in ValidityStatus:
            self._status_filter.addItem(_STATUS_DISPLAY[status], userData=status.value)
        self._status_filter.currentIndexChanged.connect(self._reload_trainings)
        filter_row.addWidget(self._status_filter)

        filter_row.addStretch(1)

        self._add_training_btn = QPushButton("Schulung hinzufuegen")
        self._add_training_btn.setObjectName("AwarenessAddTrainingButton")
        self._add_training_btn.clicked.connect(self._on_add_training_clicked)
        filter_row.addWidget(self._add_training_btn)

        self._edit_training_btn = QPushButton("Bearbeiten")
        self._edit_training_btn.setObjectName("AwarenessEditTrainingButton")
        self._edit_training_btn.setEnabled(False)
        self._edit_training_btn.clicked.connect(self._on_edit_training_clicked)
        filter_row.addWidget(self._edit_training_btn)

        self._delete_training_btn = QPushButton("Loeschen")
        self._delete_training_btn.setObjectName("AwarenessDeleteTrainingButton")
        self._delete_training_btn.setEnabled(False)
        self._delete_training_btn.clicked.connect(self._on_delete_training_clicked)
        filter_row.addWidget(self._delete_training_btn)

        host_layout.addLayout(filter_row)

        self._training_table = QTableWidget(0, len(_TRAINING_HEADERS))
        self._training_table.setHorizontalHeaderLabels(_TRAINING_HEADERS)
        self._training_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._training_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._training_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._training_table.setAlternatingRowColors(True)
        self._training_table.verticalHeader().setVisible(False)
        t_header = self._training_table.horizontalHeader()
        t_header.setStretchLastSection(True)
        for col in range(len(_TRAINING_HEADERS) - 1):
            t_header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._training_table.itemSelectionChanged.connect(
            self._on_training_selection_changed
        )
        host_layout.addWidget(self._training_table, stretch=1)

        self._training_empty_hint = QLabel(
            "Noch keine Schulungen erfasst. Lege eine ueber den Button "
            "oben rechts an — oder importiere via CSV."
        )
        self._training_empty_hint.setObjectName("AwarenessEmptyHint")
        self._training_empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        host_layout.addWidget(self._training_empty_hint)

        return host

    @staticmethod
    def _build_placeholder_tab(text: str) -> QWidget:
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(20, 20, 20, 20)
        label = QLabel(text)
        label.setObjectName("AwarenessPlaceholder")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        host_layout.addWidget(label, stretch=1)
        return host

    # ------------------------------------------------------------------
    # Mitarbeiter-Slots
    # ------------------------------------------------------------------

    def _on_add_employee_clicked(self) -> None:
        dialog = EmployeeFormDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            new_employee = dialog.collected_employee()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.add_employee(
                full_name=new_employee.full_name,
                email=new_employee.email,
                role=new_employee.role,
                department=new_employee.department,
                is_active=new_employee.is_active,
                notes=new_employee.notes,
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload_employees()
        self._reload_trainings()

    def _on_edit_employee_clicked(self) -> None:
        employee = self._selected_employee()
        if employee is None:
            return
        dialog = EmployeeFormDialog(parent=self, employee=employee)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected_employee()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.update_employee(updated)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Aktualisierung fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload_employees()
        self._reload_trainings()

    def _on_delete_employee_clicked(self) -> None:
        employee = self._selected_employee()
        if employee is None or employee.id is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Mitarbeiter loeschen",
            message=(
                f"Den Mitarbeiter '{employee.full_name}' samt allen Schulungen "
                f"wirklich loeschen?"
            ),
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        if not self._service.delete_employee(employee.id):
            FinlaiInfoDialog(
                title="Loeschen fehlgeschlagen",
                message=f"Der Mitarbeiter mit ID {employee.id} wurde nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
        self._reload_employees()
        self._reload_trainings()

    def _on_employee_selection_changed(self) -> None:
        has_selection = bool(self._employee_table.selectionModel().selectedRows())
        self._edit_employee_btn.setEnabled(has_selection)
        self._delete_employee_btn.setEnabled(has_selection)

    def _on_csv_import_clicked(self, mode: CsvImportMode) -> None:
        dialog = CsvImportDialog(mode=mode, service=self._service, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            # User hat abgebrochen oder Import-Lauf hatte Errors — Dialog
            # zeigt die Details schon an, kein weiterer Hinweis hier.
            return
        result = dialog.last_result()
        if result is not None:
            FinlaiSuccessDialog(
                title="Import abgeschlossen",
                message=(
                    f"{result.added_count} Eintraege importiert, "
                    f"{result.skipped_count} uebersprungen."
                ),
                parent=self,
            ).exec()
        self._reload_employees()
        self._reload_trainings()

    # ------------------------------------------------------------------
    # Schulungs-Slots
    # ------------------------------------------------------------------

    def _on_add_training_clicked(self) -> None:
        employees = self._service.list_employees(include_inactive=False)
        if not employees:
            FinlaiInfoDialog(
                title="Kein Mitarbeiter angelegt",
                message=(
                    "Bitte zuerst mindestens einen aktiven Mitarbeiter im "
                    "Mitarbeiter-Tab anlegen."
                ),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        dialog = TrainingFormDialog(parent=self, employees=employees)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            new_training = dialog.collected_training()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.add_training(
                employee_id=new_training.employee_id,
                training_type=new_training.training_type,
                title=new_training.title,
                completed_at=new_training.completed_at,
                valid_until=new_training.valid_until,
                provider=new_training.provider,
                custom_type_label=new_training.custom_type_label,
                notes=new_training.notes,
            )
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload_trainings()

    def _on_edit_training_clicked(self) -> None:
        training = self._selected_training()
        if training is None:
            return
        employees = self._service.list_employees(include_inactive=True)
        dialog = TrainingFormDialog(parent=self, employees=employees, training=training)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.collected_training()
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Eingabe ungueltig",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        try:
            self._service.update_training(updated)
        except ValueError as exc:
            FinlaiInfoDialog(
                title="Aktualisierung fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._reload_trainings()

    def _on_delete_training_clicked(self) -> None:
        training = self._selected_training()
        if training is None or training.id is None:
            return
        confirm = FinlaiConfirmDialog(
            title="Schulung loeschen",
            message=f"Die Schulung '{training.title}' wirklich loeschen?",
            confirm_text="Loeschen",
            parent=self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        if not self._service.delete_training(training.id):
            FinlaiInfoDialog(
                title="Loeschen fehlgeschlagen",
                message=f"Die Schulung mit ID {training.id} wurde nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
        self._reload_trainings()

    def _on_training_selection_changed(self) -> None:
        has_selection = bool(self._training_table.selectionModel().selectedRows())
        self._edit_training_btn.setEnabled(has_selection)
        self._delete_training_btn.setEnabled(has_selection)

    def _on_show_renewals_clicked(self) -> None:
        # Filter auf "Renewal" stellen + auf den Schulungen-Tab wechseln.
        idx = self._status_filter.findData(_STATUS_FILTER_RENEWAL)
        if idx >= 0:
            self._status_filter.setCurrentIndex(idx)
        self._tabs.setCurrentIndex(1)  # Schulungen-Tab

    def _on_export_ics_clicked(self) -> None:
        due = self._service.list_trainings_due_soon()
        if not due:
            FinlaiInfoDialog(
                title="Keine Renewals",
                message=(
                    "Aktuell sind keine Schulungen abgelaufen oder kurz "
                    "vor Ablauf — kein Export noetig."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        employee_names = self._service.employee_lookup()
        try:
            ics_text = export_renewals_to_ics(due, employee_names=employee_names)
        except IcsExportError as exc:
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=str(exc),
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        path_str, _filter = QFileDialog.getSaveFileName(
            self,
            "Renewal-Termine als ICS speichern",
            "renewal_reminder.ics",
            "iCalendar-Dateien (*.ics);;Alle Dateien (*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        try:
            path.write_text(ics_text, encoding="utf-8")
        except OSError as exc:
            FinlaiInfoDialog(
                title="Speichern fehlgeschlagen",
                message=f"Datei konnte nicht geschrieben werden: {exc}",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        FinlaiSuccessDialog(
            title="ICS exportiert",
            message=f"{len(due)} Renewal-Termine wurden exportiert.",
            file_path=str(path),
            parent=self,
        ).exec()

    # ------------------------------------------------------------------
    # Reload + Render
    # ------------------------------------------------------------------

    def _reload_employees(self) -> None:
        employees = self._service.list_employees(include_inactive=True)
        self._employee_table.setRowCount(len(employees))
        for row, employee in enumerate(employees):
            self._set_employee_row(row, employee)
        self._employee_empty_hint.setVisible(len(employees) == 0)
        self._employee_table.setVisible(len(employees) > 0)
        self._employee_table.clearSelection()
        self._edit_employee_btn.setEnabled(False)
        self._delete_employee_btn.setEnabled(False)
        # Filter-Combo neu aufbauen ohne den aktuellen Filter zu verlieren.
        previous = self._employee_filter.currentData()
        self._employee_filter.blockSignals(True)
        self._employee_filter.clear()
        self._employee_filter.addItem("Alle Mitarbeiter", userData=None)
        for emp in employees:
            self._employee_filter.addItem(emp.full_name, userData=emp.id)
        if previous is not None:
            idx = self._employee_filter.findData(previous)
            if idx >= 0:
                self._employee_filter.setCurrentIndex(idx)
        self._employee_filter.blockSignals(False)

    def _set_employee_row(self, row: int, employee: Employee) -> None:
        name_item = QTableWidgetItem(employee.full_name)
        name_item.setData(Qt.ItemDataRole.UserRole, employee.id)
        self._employee_table.setItem(row, 0, name_item)
        self._employee_table.setItem(row, 1, QTableWidgetItem(employee.role or "—"))
        self._employee_table.setItem(
            row, 2, QTableWidgetItem(employee.department or "—")
        )
        status_item = QTableWidgetItem("Aktiv" if employee.is_active else "Inaktiv")
        status_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        self._employee_table.setItem(row, 3, status_item)
        notes_preview = employee.notes.splitlines()[0] if employee.notes else ""
        if len(notes_preview) > 120:
            notes_preview = notes_preview[:117] + "..."
        self._employee_table.setItem(row, 4, QTableWidgetItem(notes_preview))

    def _selected_employee(self) -> Employee | None:
        rows = self._employee_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._employee_table.item(rows[0].row(), 0)
        if item is None:
            return None
        employee_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(employee_id, int):
            return None
        return self._service.get_employee(employee_id)

    def _reload_trainings(self) -> None:
        all_trainings = self._service.list_trainings()
        # Renewal-Banner bekommt IMMER die volle Liste — er rechnet selbst.
        self._renewal_banner.update_from(all_trainings)

        filtered = self._apply_training_filters(all_trainings)
        self._training_table.setRowCount(len(filtered))
        employee_names = self._service.employee_lookup()
        for row, training in enumerate(filtered):
            self._set_training_row(row, training, employee_names)
        self._training_empty_hint.setVisible(len(filtered) == 0)
        self._training_table.setVisible(len(filtered) > 0)
        self._training_table.clearSelection()
        self._edit_training_btn.setEnabled(False)
        self._delete_training_btn.setEnabled(False)

    def _apply_training_filters(self, trainings: list[Training]) -> list[Training]:
        emp_filter = self._employee_filter.currentData()
        status_filter = self._status_filter.currentData()
        result: list[Training] = []
        now = datetime.now(UTC)
        for training in trainings:
            if isinstance(emp_filter, int) and training.employee_id != emp_filter:
                continue
            if status_filter == _STATUS_FILTER_ALL:
                result.append(training)
                continue
            status = training.validity_status(now=now)
            if status_filter == _STATUS_FILTER_RENEWAL:
                if status in (
                    ValidityStatus.EXPIRED,
                    ValidityStatus.EXPIRING_SOON,
                ):
                    result.append(training)
                continue
            if isinstance(status_filter, str) and status.value == status_filter:
                result.append(training)
        return result

    def _set_training_row(
        self,
        row: int,
        training: Training,
        employee_names: dict[int, str],
    ) -> None:
        emp_label = employee_names.get(
            training.employee_id, f"Mitarbeiter #{training.employee_id}"
        )
        name_item = QTableWidgetItem(emp_label)
        name_item.setData(Qt.ItemDataRole.UserRole, training.id)
        self._training_table.setItem(row, 0, name_item)

        type_label = _TYPE_DISPLAY.get(
            training.training_type, training.training_type.value
        )
        if training.training_type is TrainingType.CUSTOM and training.custom_type_label:
            type_label = training.custom_type_label
        self._training_table.setItem(row, 1, QTableWidgetItem(type_label))

        self._training_table.setItem(row, 2, QTableWidgetItem(training.title))
        self._training_table.setItem(
            row,
            3,
            QTableWidgetItem(training.completed_at.strftime("%Y-%m-%d")),
        )
        valid_until_text = (
            training.valid_until.strftime("%Y-%m-%d")
            if training.valid_until is not None
            else "—"
        )
        self._training_table.setItem(row, 4, QTableWidgetItem(valid_until_text))

        status = training.validity_status()
        status_item = QTableWidgetItem(_STATUS_DISPLAY[status])
        status_item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
        # ObjectName-Selector als Stylable-Property fuer Theming
        # (QSS: ``QTableWidget::item[status="expired"] { color: red; }``).
        status_item.setData(Qt.ItemDataRole.UserRole + 1, status.value)
        self._training_table.setItem(row, 5, status_item)

        self._training_table.setItem(row, 6, QTableWidgetItem(training.provider or "—"))

    def _selected_training(self) -> Training | None:
        rows = self._training_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._training_table.item(rows[0].row(), 0)
        if item is None:
            return None
        training_id = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(training_id, int):
            return None
        return self._service.get_training(training_id)
