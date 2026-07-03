"""
phishing_sim_form_dialog — Modaler Add-/Edit-Dialog fuer
Phishing-Sim-Kampagnen.

Iteration 3c: Form mit Kampagnen-Name, Anbieter-Combo
(8 Standard-Vendoren + CUSTOM), Run-Date-Picker, Target/Click/Report-
SpinBoxes, Training-assigned-Checkbox, Notizen.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tools.awareness_tracker.domain.models import (
    MAX_CAMPAIGN_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_VENDOR_LABEL_LENGTH,
    PhishingSimEvent,
    PhishingSimVendor,
)

_VENDOR_ORDER: tuple[PhishingSimVendor, ...] = (
    PhishingSimVendor.KNOWBE4,
    PhishingSimVendor.COFENSE,
    PhishingSimVendor.SOSAFE,
    PhishingSimVendor.PROOFPOINT,
    PhishingSimVendor.HOXHUNT,
    PhishingSimVendor.PHISHME,
    PhishingSimVendor.INTERN,
    PhishingSimVendor.CUSTOM,
)

_VENDOR_DISPLAY: dict[PhishingSimVendor, str] = {
    PhishingSimVendor.KNOWBE4: "KnowBe4",
    PhishingSimVendor.COFENSE: "Cofense (PhishMe)",
    PhishingSimVendor.SOSAFE: "SoSafe",
    PhishingSimVendor.PROOFPOINT: "Proofpoint",
    PhishingSimVendor.HOXHUNT: "Hoxhunt",
    PhishingSimVendor.PHISHME: "PhishMe (Standalone)",
    PhishingSimVendor.INTERN: "Intern / Eigene Kampagne",
    PhishingSimVendor.CUSTOM: "Custom-Anbieter",
}


class PhishingSimFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer eine:class:`PhishingSimEvent`."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        event: PhishingSimEvent | None = None,
    ) -> None:
        super().__init__(parent)
        self._editing_event = event
        self.setWindowTitle(
            "Phishing-Sim bearbeiten" if event else "Phishing-Sim hinzufuegen"
        )
        self.setMinimumWidth(480)
        self._build_ui()
        if event is not None:
            self._populate_from(event)
        else:
            self._update_custom_label_visible()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setMaxLength(MAX_CAMPAIGN_NAME_LENGTH)
        self._name_input.setPlaceholderText("z. B. Q2-2026 Spear-Phishing-Welle")
        self._name_input.setObjectName("PhishingSimNameInput")
        form.addRow("Kampagnen-Name", self._name_input)

        self._vendor_combo = QComboBox()
        self._vendor_combo.setObjectName("PhishingSimVendorCombo")
        for vendor in _VENDOR_ORDER:
            self._vendor_combo.addItem(_VENDOR_DISPLAY[vendor], userData=vendor)
        self._vendor_combo.currentIndexChanged.connect(
            self._update_custom_label_visible
        )
        form.addRow("Anbieter", self._vendor_combo)

        self._custom_label_input = QLineEdit()
        self._custom_label_input.setMaxLength(MAX_VENDOR_LABEL_LENGTH)
        self._custom_label_input.setPlaceholderText(
            "Pflicht bei Custom-Anbieter"
        )
        self._custom_label_input.setObjectName("PhishingSimCustomLabelInput")
        form.addRow("Anbieter-Name (Custom)", self._custom_label_input)

        self._run_date = QDateEdit()
        self._run_date.setCalendarPopup(True)
        self._run_date.setDisplayFormat("yyyy-MM-dd")
        self._run_date.setDate(QDate.currentDate())
        # keine Spinbox-Pfeile (Datumswahl ueber den Kalender-Popup,
        # wie dialog-skill/ RPO-RTO).
        self._run_date.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self._run_date.setObjectName("PhishingSimRunDate")
        form.addRow("Durchfuehrungs-Datum", self._run_date)

        self._target_spin = QSpinBox()
        self._target_spin.setRange(1, 10_000)
        self._target_spin.setValue(10)
        self._target_spin.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self._target_spin.setObjectName("PhishingSimTargetSpin")
        form.addRow("Angeschriebene Mitarbeiter", self._target_spin)

        self._click_spin = QSpinBox()
        self._click_spin.setRange(0, 10_000)
        self._click_spin.setValue(0)
        self._click_spin.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self._click_spin.setObjectName("PhishingSimClickSpin")
        form.addRow("Klicks auf Phishing-Link", self._click_spin)

        self._report_spin = QSpinBox()
        self._report_spin.setRange(0, 10_000)
        self._report_spin.setValue(0)
        self._report_spin.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self._report_spin.setObjectName("PhishingSimReportSpin")
        form.addRow("Meldungen via Report-Button", self._report_spin)

        self._training_checkbox = QCheckBox(
            "Click-Mitarbeiter wurden nachgeschult"
        )
        self._training_checkbox.setObjectName("PhishingSimTrainingCheckbox")
        form.addRow("Follow-up", self._training_checkbox)

        self._notes_input = QTextEdit()
        self._notes_input.setMinimumHeight(60)
        self._notes_input.setObjectName("PhishingSimNotesInput")
        form.addRow("Notizen", self._notes_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(
            "Abbrechen"
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _current_vendor(self) -> PhishingSimVendor:
        data = self._vendor_combo.currentData()
        if isinstance(data, PhishingSimVendor):
            return data
        return PhishingSimVendor.CUSTOM

    def _update_custom_label_visible(self) -> None:
        is_custom = self._current_vendor() is PhishingSimVendor.CUSTOM
        self._custom_label_input.setEnabled(is_custom)
        if not is_custom:
            self._custom_label_input.clear()

    def _populate_from(self, event: PhishingSimEvent) -> None:
        self._name_input.setText(event.name)
        for idx in range(self._vendor_combo.count()):
            if self._vendor_combo.itemData(idx) is event.vendor:
                self._vendor_combo.setCurrentIndex(idx)
                break
        self._custom_label_input.setText(event.custom_vendor_label)
        self._update_custom_label_visible()
        self._run_date.setDate(
            QDate(event.run_date.year, event.run_date.month, event.run_date.day)
        )
        # Reihenfolge wichtig: target zuerst, dann clicks/reports (sonst
        # clamped die SpinBox-Validierung beim Re-Populate).
        self._target_spin.setValue(int(event.target_count))
        self._click_spin.setValue(int(event.click_count))
        self._report_spin.setValue(int(event.report_count))
        self._training_checkbox.setChecked(event.training_assigned)
        self._notes_input.setPlainText(event.notes)

    def collected_event(self) -> PhishingSimEvent:
        """Liefert ein:class:`PhishingSimEvent` aus den Form-Werten.

        Raises:
            ValueError: Wenn die Domain-Validierung in
:class:`PhishingSimEvent.__post_init__` schlaegt
                (z. B. ``click_count > target_count``).
        """
        notes = self._notes_input.toPlainText().strip()
        if len(notes) > MAX_NOTES_LENGTH:
            notes = notes[:MAX_NOTES_LENGTH]
        existing = self._editing_event
        run_date = _qdate_to_dt(self._run_date.date())
        return PhishingSimEvent(
            id=existing.id if existing is not None else None,
            name=self._name_input.text(),
            vendor=self._current_vendor(),
            run_date=run_date,
            target_count=int(self._target_spin.value()),
            click_count=int(self._click_spin.value()),
            report_count=int(self._report_spin.value()),
            training_assigned=self._training_checkbox.isChecked(),
            custom_vendor_label=self._custom_label_input.text(),
            notes=notes,
            created_at=(
                existing.created_at if existing is not None else run_date
            ),
        )


def _qdate_to_dt(qdate: QDate) -> datetime:
    return datetime(
        qdate.year(),
        qdate.month(),
        qdate.day(),
        tzinfo=UTC,
    )


__all__ = ["PhishingSimFormDialog", "Qt"]
