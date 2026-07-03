"""
customer_form_dialog — Modaler Add-/Edit-Dialog fuer einen KUNDEN (Subject/KUNDE).

Gegenstueck zu:class:`VendorFormDialog` fuer die Kunden-Seite: erfasst
Firmenname (Pflicht) + Stammdaten (Branche/Groesse/Ansprechpartner). Die Anlage
laeuft ueber den ``SubjectStore``-Port (``find_or_create_client`` +
``update_stammdaten``) — der Dialog liefert nur die Werte.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1 (IA-Umbau, 2026-06-30)
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

_MAX_NAME_LENGTH = 200


@dataclass(frozen=True)
class CustomerFormValues:
    """Eingesammelte Form-Werte fuer einen Kunden."""

    name: str
    branche: str
    groesse: str
    contact: str


class CustomerFormDialog(QDialog):
    """Add-/Edit-Dialog fuer einen Kunden (Subject/KUNDE)."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        name: str = "",
        branche: str = "",
        groesse: str = "",
        contact: str = "",
        editing: bool = False,
    ) -> None:
        super().__init__(parent)
        self._editing = editing
        self.setWindowTitle("Kunde bearbeiten" if editing else "Kunde hinzufuegen")
        self.setMinimumWidth(420)
        self._build_ui(name, branche, groesse, contact)

    def _build_ui(
        self, name: str, branche: str, groesse: str, contact: str
    ) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit(name)
        self._name_input.setMaxLength(_MAX_NAME_LENGTH)
        self._name_input.setPlaceholderText("Firmenname des Kunden")
        # Im Edit-Modus bleibt der Name fix (Identitaet ueber subject_id), damit
        # die Namensaufloesung in Audit/Score stabil bleibt.
        self._name_input.setReadOnly(self._editing)
        self._name_input.textChanged.connect(self._update_ok_state)
        form.addRow("Firmenname", self._name_input)

        self._branche_input = QLineEdit(branche)
        self._branche_input.setPlaceholderText("z. B. Steuerberatung, Handel ...")
        form.addRow("Branche", self._branche_input)

        self._groesse_input = QLineEdit(groesse)
        self._groesse_input.setPlaceholderText("z. B. 1-10 / 11-50 Mitarbeiter")
        form.addRow("Groesse", self._groesse_input)

        self._contact_input = QLineEdit(contact)
        self._contact_input.setPlaceholderText("Ansprechpartner (optional)")
        form.addRow("Ansprechpartner", self._contact_input)

        layout.addLayout(form)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        self._buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)
        self._update_ok_state()

    def _update_ok_state(self) -> None:
        ok = bool(self._name_input.text().strip())
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    def collected_values(self) -> CustomerFormValues:
        """Liefert die getrimmten Form-Werte."""
        return CustomerFormValues(
            name=self._name_input.text().strip(),
            branche=self._branche_input.text().strip(),
            groesse=self._groesse_input.text().strip(),
            contact=self._contact_input.text().strip(),
        )
