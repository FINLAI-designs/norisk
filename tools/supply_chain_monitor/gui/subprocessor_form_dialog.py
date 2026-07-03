"""
subprocessor_form_dialog — Add/Edit eines:class:`Subprocessor`.

Iter 2c-ii.

Author: Patrick Riederich
Version: 0.1-ii, 2026-05-15)
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tools.supply_chain_monitor.domain.models import (
    MAX_NOTES_LENGTH,
    Subprocessor,
    VendorCategory,
)

_CATEGORY_LABELS: dict[VendorCategory, str] = {
    VendorCategory.KANZLEISOFTWARE: "Kanzlei-Software",
    VendorCategory.CLOUD: "Cloud / SaaS",
    VendorCategory.MSP: "IT-Dienstleister / MSP",
    VendorCategory.KOMMUNIKATION: "Kommunikation",
    VendorCategory.SPEZIAL: "Spezial / Sonstige",
}


class SubprocessorFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer einen Sub-Auftragnehmer."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        subprocessor: Subprocessor | None = None,
    ) -> None:
        super().__init__(parent)
        self._editing = subprocessor
        self.setWindowTitle(
            "Sub-Auftragnehmer bearbeiten"
            if subprocessor
            else "Sub-Auftragnehmer hinzufuegen"
        )
        self.setMinimumWidth(440)
        self._build_ui()
        if subprocessor is not None:
            self._populate_from(subprocessor)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("z. B. Amazon Web Services, T-Systems")
        form.addRow("Name", self._name_input)

        self._country_input = QLineEdit()
        self._country_input.setPlaceholderText("ISO-2 (z. B. US, DE, IE)")
        self._country_input.setMaxLength(2)
        form.addRow("Land (ISO-2)", self._country_input)

        self._category_combo = QComboBox()
        for category, label in _CATEGORY_LABELS.items():
            self._category_combo.addItem(label, category)
        form.addRow("Kategorie", self._category_combo)

        self._notes_input = QTextEdit()
        self._notes_input.setAcceptRichText(False)
        self._notes_input.setPlaceholderText(
            "Optional: Anwendungsbereich, Risiko-Hinweise, weitere Details "
            "(max. 2000 Zeichen)."
        )
        form.addRow("Notizen", self._notes_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate_from(self, sub: Subprocessor) -> None:
        self._name_input.setText(sub.name)
        self._country_input.setText(sub.country)
        idx = self._category_combo.findData(sub.category)
        if idx >= 0:
            self._category_combo.setCurrentIndex(idx)
        self._notes_input.setPlainText(sub.notes)

    def _on_accept(self) -> None:
        if not self._name_input.text().strip():
            self._name_input.setFocus()
            return
        if len(self._country_input.text().strip()) != 2:
            self._country_input.setFocus()
            return
        if len(self._notes_input.toPlainText()) > MAX_NOTES_LENGTH:
            self._notes_input.setFocus()
            return
        self.accept()

    def collected(self) -> Subprocessor:
        category = self._category_combo.currentData()
        if not isinstance(category, VendorCategory):
            category = VendorCategory.SPEZIAL

        if self._editing is not None:
            return Subprocessor(
                id=self._editing.id,
                name=self._name_input.text(),
                country=self._country_input.text(),
                category=category,
                notes=self._notes_input.toPlainText(),
                created_at=self._editing.created_at,
                updated_at=self._editing.updated_at,
            )

        return Subprocessor(
            id=None,
            name=self._name_input.text(),
            country=self._country_input.text(),
            category=category,
            notes=self._notes_input.toPlainText(),
        )
