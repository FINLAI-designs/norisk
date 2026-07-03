"""
vendor_form_dialog — Modaler Add-/Edit-Dialog fuer Vendor-Eintraege.

Iteration 2a: Minimal-Form mit Name + Kategorie + Kritikalitaet
+ Notes. Detection-Quellen (z. B. Auto-Vorschlag aus Installed-Apps) und
AVV-Stammdaten kommen in 2b/2c.

Author: Patrick Riederich
Version: 0.1
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
    MAX_CRITICALITY,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MIN_CRITICALITY,
    Vendor,
    VendorCategory,
)

_CATEGORY_LABELS: dict[VendorCategory, str] = {
    VendorCategory.KANZLEISOFTWARE: "Kanzlei-Software",
    VendorCategory.CLOUD: "Cloud / SaaS",
    VendorCategory.MSP: "IT-Dienstleister / MSP",
    VendorCategory.KOMMUNIKATION: "Kommunikation",
    VendorCategory.SPEZIAL: "Spezial / Sonstige",
}

# Aussagekraeftige Labels statt nackter Zahlen — orientiert sich am
# BSI 200-3-Schadenshoehen-Vokabular und passt damit zu den Risiko-Matrix-
# Skala-Begriffen aus (`risk_entities.RiskImpact`).
_CRITICALITY_LABELS: dict[int, str] = {
    1: "1 — niedrig (kein Geschaeftsimpact)",
    2: "2 — begrenzt (Workarounds moeglich)",
    3: "3 — mittel (spuerbarer Impact)",
    4: "4 — hoch (Mandantenarbeit gestoert)",
    5: "5 — sehr hoch (Mandantenarbeit unmoeglich)",
}


class VendorFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer einen Vendor.

    Benutzung::

        dialog = VendorFormDialog(parent=self)
        if dialog.exec == QDialog.DialogCode.Accepted:
            data = dialog.collected_vendor
...

    Im Edit-Modus wird ein bestehender:class:`Vendor` uebergeben — der
    Dialog fuellt die Felder vor und liefert nach Accept das aktualisierte
    Dataclass-Objekt (mit erhaltener ID).
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        vendor: Vendor | None = None,
    ) -> None:
        super().__init__(parent)
        self._editing_vendor = vendor
        self.setWindowTitle("Vendor bearbeiten" if vendor else "Vendor hinzufuegen")
        self.setMinimumWidth(420)
        self._build_ui()
        if vendor is not None:
            self._populate_from(vendor)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setMaxLength(MAX_NAME_LENGTH)
        self._name_input.setPlaceholderText("z. B. DATEV, Microsoft 365, ...")
        form.addRow("Name", self._name_input)

        self._category_combo = QComboBox()
        for category, label in _CATEGORY_LABELS.items():
            self._category_combo.addItem(label, category)
        form.addRow("Kategorie", self._category_combo)

        self._criticality_combo = QComboBox()
        self._criticality_combo.setObjectName("VendorCriticalityCombo")
        for score in range(MIN_CRITICALITY, MAX_CRITICALITY + 1):
            self._criticality_combo.addItem(_CRITICALITY_LABELS[score], score)
        # Default-Auswahl: Mittel (Score 3).
        default_idx = self._criticality_combo.findData(3)
        if default_idx >= 0:
            self._criticality_combo.setCurrentIndex(default_idx)
        self._criticality_combo.setToolTip(
            "BSI-200-3-Schadenshoehen-Skala — 1 niedrig bis 5 sehr hoch."
        )
        form.addRow("Kritikalitaet", self._criticality_combo)

        self._notes_input = QTextEdit()
        self._notes_input.setAcceptRichText(False)
        self._notes_input.setPlaceholderText(
            "Optional: Anwendungsbereich, Ansprechpartner, Kontextnotizen "
            "(max. 2000 Zeichen)"
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

    def _populate_from(self, vendor: Vendor) -> None:
        self._name_input.setText(vendor.name)
        idx = self._category_combo.findData(vendor.category)
        if idx >= 0:
            self._category_combo.setCurrentIndex(idx)
        crit_idx = self._criticality_combo.findData(vendor.criticality_score)
        if crit_idx >= 0:
            self._criticality_combo.setCurrentIndex(crit_idx)
        self._notes_input.setPlainText(vendor.notes)

    def _on_accept(self) -> None:
        # Domain-Validierung im Vendor-Konstruktor — verlassen wir uns hier nicht
        # auf doppelte GUI-Validierung; nur Klartext-Kurzcheck.
        if not self._name_input.text().strip():
            self._name_input.setFocus()
            return
        if len(self._notes_input.toPlainText()) > MAX_NOTES_LENGTH:
            self._notes_input.setFocus()
            return
        self.accept()

    def collected_vendor(self) -> Vendor:
        """Konstruiert das:class:`Vendor`-Objekt aus den Form-Werten.

        Im Edit-Modus bleiben ``id`` und ``created_at`` des Original-Vendors
        erhalten; ``updated_at`` wird vom Repository neu gesetzt.

        Raises:
            ValueError: Wenn die Form-Werte gegen die Domain-Regeln verstossen.
        """
        category = self._category_combo.currentData()
        if not isinstance(category, VendorCategory):
            category = VendorCategory.SPEZIAL

        if self._editing_vendor is not None:
            return Vendor(
                id=self._editing_vendor.id,
                name=self._name_input.text(),
                category=category,
                criticality_score=int(self._criticality_combo.currentData() or 3),
                notes=self._notes_input.toPlainText(),
                created_at=self._editing_vendor.created_at,
                updated_at=self._editing_vendor.updated_at,
            )

        return Vendor(
            id=None,
            name=self._name_input.text(),
            category=category,
            criticality_score=int(self._criticality_combo.currentData() or 3),
            notes=self._notes_input.toPlainText(),
        )
