"""
employee_form_dialog — Modaler Add-/Edit-Dialog fuer Mitarbeiter.

Iteration 3a: Minimal-Form mit Name + E-Mail + Rolle + Abteilung
+ Aktiv-Flag + Notizen. Schulungs-Tracking (Forms fuer Training-Entitaeten)
folgt in 3b.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tools.awareness_tracker.domain.models import (
    MAX_DEPARTMENT_LENGTH,
    MAX_EMAIL_LENGTH,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_ROLE_LENGTH,
    Employee,
)


class EmployeeFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer einen:class:`Employee`.

    Benutzung::

        dialog = EmployeeFormDialog(parent=self)
        if dialog.exec == QDialog.DialogCode.Accepted:
            employee = dialog.collected_employee
...

    Im Edit-Modus wird ein bestehender:class:`Employee` uebergeben — der
    Dialog fuellt die Felder vor und liefert nach Accept das aktualisierte
    Dataclass-Objekt (mit erhaltener ID, neuer ``updated_at``).
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        employee: Employee | None = None,
    ) -> None:
        super().__init__(parent)
        self._editing_employee = employee
        self.setWindowTitle(
            "Mitarbeiter bearbeiten" if employee else "Mitarbeiter hinzufuegen"
        )
        self.setMinimumWidth(420)
        self._build_ui()
        if employee is not None:
            self._populate_from(employee)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setMaxLength(MAX_NAME_LENGTH)
        self._name_input.setPlaceholderText("z. B. Anna Schmidt")
        self._name_input.setObjectName("AwarenessNameInput")
        form.addRow("Name", self._name_input)

        self._email_input = QLineEdit()
        self._email_input.setMaxLength(MAX_EMAIL_LENGTH)
        self._email_input.setPlaceholderText("optional")
        self._email_input.setObjectName("AwarenessEmailInput")
        form.addRow("E-Mail", self._email_input)

        self._role_input = QLineEdit()
        self._role_input.setMaxLength(MAX_ROLE_LENGTH)
        self._role_input.setPlaceholderText("z. B. Anwaltsfachangestellte")
        self._role_input.setObjectName("AwarenessRoleInput")
        form.addRow("Rolle", self._role_input)

        self._department_input = QLineEdit()
        self._department_input.setMaxLength(MAX_DEPARTMENT_LENGTH)
        self._department_input.setPlaceholderText("z. B. Backoffice, Standort Linz")
        self._department_input.setObjectName("AwarenessDepartmentInput")
        form.addRow("Abteilung", self._department_input)

        self._active_checkbox = QCheckBox("Aktiver Mitarbeiter")
        self._active_checkbox.setChecked(True)
        self._active_checkbox.setObjectName("AwarenessActiveCheckbox")
        form.addRow("Status", self._active_checkbox)

        self._notes_input = QTextEdit()
        self._notes_input.setObjectName("AwarenessNotesInput")
        self._notes_input.setPlaceholderText(
            "Optionale Notizen — werden verschluesselt gespeichert."
        )
        self._notes_input.setMinimumHeight(80)
        form.addRow("Notizen", self._notes_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate_from(self, employee: Employee) -> None:
        self._name_input.setText(employee.full_name)
        self._email_input.setText(employee.email)
        self._role_input.setText(employee.role)
        self._department_input.setText(employee.department)
        self._active_checkbox.setChecked(employee.is_active)
        self._notes_input.setPlainText(employee.notes)

    def collected_employee(self) -> Employee:
        """Liefert einen:class:`Employee` aus den eingegebenen Werten.

        Im Add-Modus mit ``id=None``, im Edit-Modus mit der ID des
        Original-Employees (created_at bleibt erhalten, updated_at wird
        spaeter vom Repository gesetzt).

        Raises:
            ValueError: Wenn die Domain-Validierung in
:class:`Employee.__post_init__` schlaegt.
        """
        notes = self._notes_input.toPlainText().strip()
        if len(notes) > MAX_NOTES_LENGTH:
            notes = notes[:MAX_NOTES_LENGTH]
        existing = self._editing_employee
        return Employee(
            id=existing.id if existing is not None else None,
            full_name=self._name_input.text(),
            email=self._email_input.text(),
            role=self._role_input.text(),
            department=self._department_input.text(),
            is_active=self._active_checkbox.isChecked(),
            notes=notes,
            created_at=existing.created_at if existing is not None else _now_utc(),
            updated_at=_now_utc(),
        )


def _now_utc():  # pragma: no cover — trivialer Stamp-Helper
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC)
