"""
catalog_entry_form_dialog — Add/Edit eines:class:`VendorCatalogEntry`.

Iter 2b: Modaler Dialog mit Feldern fuer alle drei
Pattern-Listen (App / MX / Cert). Pattern werden als kommagetrennte Strings
eingegeben — Normalisierung uebernimmt der Domain-Layer.

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
    MAX_NOTES_LENGTH,
    VendorCatalogEntry,
    VendorCategory,
)

_CATEGORY_LABELS: dict[VendorCategory, str] = {
    VendorCategory.KANZLEISOFTWARE: "Kanzlei-Software",
    VendorCategory.CLOUD: "Cloud / SaaS",
    VendorCategory.MSP: "IT-Dienstleister / MSP",
    VendorCategory.KOMMUNIKATION: "Kommunikation",
    VendorCategory.SPEZIAL: "Spezial / Sonstige",
}


class CatalogEntryFormDialog(QDialog):
    """Modaler Add-/Edit-Dialog fuer einen Catalog-Eintrag."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        entry: VendorCatalogEntry | None = None,
    ) -> None:
        super().__init__(parent)
        self._editing = entry
        self.setWindowTitle(
            "Catalog-Eintrag bearbeiten" if entry else "Catalog-Eintrag hinzufuegen"
        )
        self.setMinimumWidth(520)
        self._build_ui()
        if entry is not None:
            self._populate_from(entry)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("z. B. Microsoft, DATEV, Hetzner, ...")
        form.addRow("Kanonischer Name", self._name_input)

        self._category_combo = QComboBox()
        for category, label in _CATEGORY_LABELS.items():
            self._category_combo.addItem(label, category)
        form.addRow("Default-Kategorie", self._category_combo)

        self._aliases_input = QLineEdit()
        self._aliases_input.setPlaceholderText(
            "Komma-getrennt, optional. Beispiel: msft, microsoft 365, office 365"
        )
        form.addRow("Aliasse", self._aliases_input)

        self._apps_input = QLineEdit()
        self._apps_input.setPlaceholderText(
            "Komma-getrennt. Substring-Match gegen Installed-App-Namen "
            "(case-insensitive). Beispiel: microsoft, onedrive"
        )
        form.addRow("App-Patterns", self._apps_input)

        self._mx_input = QLineEdit()
        self._mx_input.setPlaceholderText(
            "Komma-getrennt. Substring-Match gegen MX-Hostnames. "
            "Beispiel: protection.outlook.com"
        )
        form.addRow("MX-Patterns", self._mx_input)

        self._cert_input = QLineEdit()
        self._cert_input.setPlaceholderText(
            "Komma-getrennt. Substring-Match gegen Cert-Issuer-CN/O. "
            "Beispiel: microsoft, azure tls"
        )
        form.addRow("Cert-Patterns", self._cert_input)

        self._notes_input = QTextEdit()
        self._notes_input.setAcceptRichText(False)
        self._notes_input.setPlaceholderText(
            "Optionale Notizen zum Vendor (max. 2000 Zeichen)."
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

    def _populate_from(self, entry: VendorCatalogEntry) -> None:
        self._name_input.setText(entry.canonical_name)
        idx = self._category_combo.findData(entry.default_category)
        if idx >= 0:
            self._category_combo.setCurrentIndex(idx)
        self._aliases_input.setText(", ".join(entry.aliases))
        self._apps_input.setText(", ".join(entry.app_name_patterns))
        self._mx_input.setText(", ".join(entry.mx_hostname_patterns))
        self._cert_input.setText(", ".join(entry.cert_issuer_patterns))
        self._notes_input.setPlainText(entry.notes)

    def _on_accept(self) -> None:
        if not self._name_input.text().strip():
            self._name_input.setFocus()
            return
        if len(self._notes_input.toPlainText()) > MAX_NOTES_LENGTH:
            self._notes_input.setFocus()
            return
        self.accept()

    def collected_entry(self) -> VendorCatalogEntry:
        """Konstruiert den:class:`VendorCatalogEntry` aus den Form-Werten.

        Pattern-Listen werden aus dem komma-getrennten Input gewonnen;
        die Normalisierung (lowercase + trim + dedup) macht der Domain-Layer
        in:meth:`VendorCatalogEntry.__post_init__`.
        """
        category = self._category_combo.currentData()
        if not isinstance(category, VendorCategory):
            category = VendorCategory.SPEZIAL

        aliases = _split_csv(self._aliases_input.text())
        apps = _split_csv(self._apps_input.text())
        mx = _split_csv(self._mx_input.text())
        cert = _split_csv(self._cert_input.text())

        if self._editing is not None:
            return VendorCatalogEntry(
                id=self._editing.id,
                canonical_name=self._name_input.text(),
                default_category=category,
                aliases=aliases,
                app_name_patterns=apps,
                mx_hostname_patterns=mx,
                cert_issuer_patterns=cert,
                notes=self._notes_input.toPlainText(),
                created_at=self._editing.created_at,
                updated_at=self._editing.updated_at,
            )

        return VendorCatalogEntry(
            id=None,
            canonical_name=self._name_input.text(),
            default_category=category,
            aliases=aliases,
            app_name_patterns=apps,
            mx_hostname_patterns=mx,
            cert_issuer_patterns=cert,
            notes=self._notes_input.toPlainText(),
        )


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part for part in (p.strip() for p in value.split(",")) if part)
