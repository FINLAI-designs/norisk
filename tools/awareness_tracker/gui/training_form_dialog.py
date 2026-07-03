"""
training_form_dialog — Modaler Add-/Edit-Dialog fuer Schulungen.

Iteration 3b: Form mit Mitarbeiter-Auswahl,
Schulungs-Typ, Titel, Abschluss-Datum, optionalem Ablauf-Datum,
Anbieter, Custom-Type-Label (bei CUSTOM), Notizen.

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
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tools.awareness_tracker.domain.models import (
    MAX_CUSTOM_TYPE_LABEL_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_PROVIDER_LENGTH,
    MAX_TITLE_LENGTH,
    Employee,
    Training,
    TrainingType,
)

# Anzeige-Reihenfolge in der Combo (Standard-Schulungen zuerst, CUSTOM zuletzt).
_TYPE_ORDER: tuple[TrainingType, ...] = (
    TrainingType.DSGVO_BASICS,
    TrainingType.IT_SECURITY,
    TrainingType.PHISHING_AWARENESS,
    TrainingType.INCIDENT_RESPONSE,
    TrainingType.COMPLIANCE_BRAO,
    TrainingType.CUSTOM,
)

_TYPE_DISPLAY: dict[TrainingType, str] = {
    TrainingType.DSGVO_BASICS: "DSGVO-Grundlagen",
    TrainingType.IT_SECURITY: "IT-Sicherheit",
    TrainingType.PHISHING_AWARENESS: "Phishing-Awareness",
    TrainingType.INCIDENT_RESPONSE: "Incident-Response",
    TrainingType.COMPLIANCE_BRAO: "Berufsrecht (BRAO/RAO/Verschwiegenheit)",
    TrainingType.CUSTOM: "Custom-Schulung",
}


class TrainingFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer einen:class:`Training`.

    Benutzung::

        dialog = TrainingFormDialog(parent=self, employees=service.list_employees)
        if dialog.exec == QDialog.DialogCode.Accepted:
            training = dialog.collected_training
...

    Wenn ``training`` uebergeben wird, ist es ein Edit-Dialog — der
    Mitarbeiter ist dann fix (kein Mitarbeiter-Wechsel; Verschieben einer
    Schulung waere semantisch falsch).
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        employees: list[Employee],
        training: Training | None = None,
    ) -> None:
        super().__init__(parent)
        self._employees = [e for e in employees if e.id is not None]
        self._editing_training = training
        self.setWindowTitle(
            "Schulung bearbeiten" if training else "Schulung hinzufuegen"
        )
        self.setMinimumWidth(460)
        self._build_ui()
        if training is not None:
            self._populate_from(training)
        else:
            self._update_custom_label_visible()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._form = form

        self._employee_combo = QComboBox()
        self._employee_combo.setObjectName("TrainingEmployeeCombo")
        for emp in self._employees:
            self._employee_combo.addItem(emp.full_name, userData=emp.id)
        form.addRow("Mitarbeiter", self._employee_combo)

        self._type_combo = QComboBox()
        self._type_combo.setObjectName("TrainingTypeCombo")
        for training_type in _TYPE_ORDER:
            self._type_combo.addItem(
                _TYPE_DISPLAY[training_type], userData=training_type
            )
        self._type_combo.currentIndexChanged.connect(
            self._update_custom_label_visible
        )
        form.addRow("Typ", self._type_combo)

        self._custom_label_input = QLineEdit()
        self._custom_label_input.setMaxLength(MAX_CUSTOM_TYPE_LABEL_LENGTH)
        self._custom_label_input.setPlaceholderText(
            "Pflicht bei Custom-Schulung"
        )
        self._custom_label_input.setObjectName("TrainingCustomLabelInput")
        self._custom_label_row_label = "Custom-Label"
        form.addRow(self._custom_label_row_label, self._custom_label_input)

        self._title_input = QLineEdit()
        self._title_input.setMaxLength(MAX_TITLE_LENGTH)
        self._title_input.setPlaceholderText(
            "z. B. DSGVO-Auffrischung Q2 2026"
        )
        self._title_input.setObjectName("TrainingTitleInput")
        form.addRow("Titel", self._title_input)

        self._completed_date = QDateEdit()
        self._completed_date.setCalendarPopup(True)
        self._completed_date.setDisplayFormat("yyyy-MM-dd")
        self._completed_date.setDate(QDate.currentDate())
        # keine Spinbox-Pfeile (Datumswahl ueber den Kalender-Popup).
        self._completed_date.setButtonSymbols(
            QAbstractSpinBox.ButtonSymbols.NoButtons
        )
        self._completed_date.setObjectName("TrainingCompletedDate")
        form.addRow("Abgeschlossen am", self._completed_date)

        self._has_validity_checkbox = QCheckBox("Schulung ist befristet")
        self._has_validity_checkbox.setChecked(False)
        self._has_validity_checkbox.toggled.connect(
            self._on_has_validity_toggled
        )
        self._has_validity_checkbox.setObjectName("TrainingHasValidityCheckbox")
        form.addRow("Gueltigkeit", self._has_validity_checkbox)

        self._valid_until_date = QDateEdit()
        self._valid_until_date.setCalendarPopup(True)
        self._valid_until_date.setDisplayFormat("yyyy-MM-dd")
        self._valid_until_date.setDate(QDate.currentDate().addYears(2))
        self._valid_until_date.setEnabled(False)
        # keine Spinbox-Pfeile (Datumswahl ueber den Kalender-Popup).
        self._valid_until_date.setButtonSymbols(
            QAbstractSpinBox.ButtonSymbols.NoButtons
        )
        self._valid_until_date.setObjectName("TrainingValidUntilDate")
        form.addRow("Gueltig bis", self._valid_until_date)

        self._provider_input = QLineEdit()
        self._provider_input.setMaxLength(MAX_PROVIDER_LENGTH)
        self._provider_input.setPlaceholderText(
            "Optional, z. B. DATEV-Akademie"
        )
        self._provider_input.setObjectName("TrainingProviderInput")
        form.addRow("Anbieter", self._provider_input)

        self._notes_input = QTextEdit()
        self._notes_input.setMinimumHeight(60)
        self._notes_input.setObjectName("TrainingNotesInput")
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

    def _on_has_validity_toggled(self, checked: bool) -> None:
        self._valid_until_date.setEnabled(checked)

    def _update_custom_label_visible(self) -> None:
        is_custom = self._current_training_type() is TrainingType.CUSTOM
        # Die Custom-Label-Zeile NUR bei Typ "Custom" zeigen — vorher blieb sie
        # immer sichtbar, nur ausgegraut (setEnabled), was wie ein kaputtes,
        # nicht ausfuellbares Feld wirkte (Patrick-Live-Test 2026-06-25). Jetzt
        # Feld + Form-Label aus-/einblenden, sodass es bei Custom klar nutzbar ist.
        self._custom_label_input.setVisible(is_custom)
        row_label = self._form.labelForField(self._custom_label_input)
        if row_label is not None:
            row_label.setVisible(is_custom)
        self._custom_label_input.setEnabled(is_custom)
        if not is_custom:
            self._custom_label_input.clear()

    def _populate_from(self, training: Training) -> None:
        # Mitarbeiter-Combo auf die Training-employee_id setzen (Edit-Modus
        # erlaubt keinen Wechsel — wir disabled die Combo).
        for idx in range(self._employee_combo.count()):
            if self._employee_combo.itemData(idx) == training.employee_id:
                self._employee_combo.setCurrentIndex(idx)
                break
        self._employee_combo.setEnabled(False)

        for idx in range(self._type_combo.count()):
            if self._type_combo.itemData(idx) is training.training_type:
                self._type_combo.setCurrentIndex(idx)
                break
        self._custom_label_input.setText(training.custom_type_label)
        self._update_custom_label_visible()

        self._title_input.setText(training.title)
        self._completed_date.setDate(
            QDate(
                training.completed_at.year,
                training.completed_at.month,
                training.completed_at.day,
            )
        )
        has_validity = training.valid_until is not None
        self._has_validity_checkbox.setChecked(has_validity)
        if training.valid_until is not None:
            self._valid_until_date.setDate(
                QDate(
                    training.valid_until.year,
                    training.valid_until.month,
                    training.valid_until.day,
                )
            )
        self._provider_input.setText(training.provider)
        self._notes_input.setPlainText(training.notes)

    def _current_training_type(self) -> TrainingType:
        data = self._type_combo.currentData()
        if isinstance(data, TrainingType):
            return data
        return TrainingType.CUSTOM

    def collected_training(self) -> Training:
        """Liefert ein:class:`Training` aus den eingegebenen Werten.

        Im Add-Modus mit ``id=None``, im Edit-Modus mit der ID des Originals.

        Raises:
            ValueError: Wenn die Domain-Validierung in
:class:`Training.__post_init__` schlaegt (z. B. CUSTOM ohne Label).
        """
        notes = self._notes_input.toPlainText().strip()
        if len(notes) > MAX_NOTES_LENGTH:
            notes = notes[:MAX_NOTES_LENGTH]
        employee_id = self._employee_combo.currentData()
        if not isinstance(employee_id, int):
            raise ValueError(
                "Bitte einen Mitarbeiter auswaehlen (keine Auswahl moeglich)."
            )
        completed_at = _qdate_to_dt(self._completed_date.date())
        valid_until = (
            _qdate_to_dt(self._valid_until_date.date())
            if self._has_validity_checkbox.isChecked()
            else None
        )
        existing = self._editing_training
        return Training(
            id=existing.id if existing is not None else None,
            employee_id=employee_id,
            training_type=self._current_training_type(),
            title=self._title_input.text(),
            completed_at=completed_at,
            valid_until=valid_until,
            provider=self._provider_input.text(),
            custom_type_label=self._custom_label_input.text(),
            notes=notes,
            created_at=existing.created_at if existing is not None else completed_at,
        )


def _qdate_to_dt(qdate: QDate) -> datetime:
    """Wandelt ein:class:`QDate` in einen UTC-Mitternachts-Stamp."""
    return datetime(
        qdate.year(),
        qdate.month(),
        qdate.day(),
        tzinfo=UTC,
    )


# Re-Export der gemeinsam genutzten Konstanten (sonst muessten Tests
# beide Module importieren).
__all__ = ["TrainingFormDialog", "Qt"]
