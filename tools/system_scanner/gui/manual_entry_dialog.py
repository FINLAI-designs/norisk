"""
manual_entry_dialog — Inline-Dialog zum Hinzufügen/Bearbeiten manueller
Sicherheitskomponenten-Einträge (Antivirus/Firewall/Verschlüsselung).

Kompaktes Formular mit drei Feldern: Name (Pflicht), Version (optional),
Status (Dropdown: Aktiv / Inaktiv / Unbekannt). Theme-konform.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from tools.system_scanner.domain.entities import ManualScannerEntry
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType

_CATEGORY_LABELS: dict[ComponentType, str] = {
    ComponentType.ANTIVIRUS: "Antivirus / EDR",
    ComponentType.FIREWALL: "Firewall",
    ComponentType.ENCRYPTION: "Verschlüsselung",
}

_STATUS_OPTIONS: list[tuple[ComponentStatus, str]] = [
    (ComponentStatus.ACTIVE, "Aktiv"),
    (ComponentStatus.INACTIVE, "Inaktiv"),
    (ComponentStatus.UNKNOWN, "Unbekannt"),
]

_MAX_NAME_LENGTH = 100
_MAX_VERSION_LENGTH = 50


class ManualEntryDialog(QDialog):
    """Dialog für Neuanlage oder Bearbeitung eines manuellen Eintrags.

    Args:
        category: Kategorie des Eintrags. Wird nur angezeigt, nicht editierbar.
        entry: Bei ``None`` neuer Eintrag; sonst wird das Formular vorbefüllt
            und der Titel auf "Bearbeiten" gesetzt.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        category: ComponentType,
        entry: ManualScannerEntry | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._category = category
        self._entry = entry
        self._is_edit = entry is not None

        cat_label = _CATEGORY_LABELS.get(category, category.value)
        aktion = "bearbeiten" if self._is_edit else "eintragen"
        self.setWindowTitle(f"{cat_label} manuell {aktion}")
        self.setModal(True)
        self.setMinimumWidth(420)

        self._build_ui()
        if entry is not None:
            self._prefill_from(entry)
        self._apply_style()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        cat_label = _CATEGORY_LABELS.get(self._category, self._category.value)
        title = QLabel(f"{cat_label} — manueller Eintrag")
        title.setObjectName("manual_dialog_title")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self._edit_name = QLineEdit()
        self._edit_name.setMaxLength(_MAX_NAME_LENGTH)
        self._edit_name.setPlaceholderText("z. B. Bitdefender Endpoint Security")
        form.addRow("Name*:", self._edit_name)

        self._edit_version = QLineEdit()
        self._edit_version.setMaxLength(_MAX_VERSION_LENGTH)
        self._edit_version.setPlaceholderText("z. B. 7.8.3 (optional)")
        form.addRow("Version:", self._edit_version)

        self._combo_status = QComboBox()
        for status, label in _STATUS_OPTIONS:
            self._combo_status.addItem(label, status)
        self._combo_status.setCurrentIndex(0)  # Aktiv vorausgewählt
        form.addRow("Status:", self._combo_status)

        layout.addLayout(form)

        hint = QLabel("* Pflichtfeld")
        hint.setObjectName("manual_dialog_hint")
        layout.addWidget(hint)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Ok,
            parent=self,
        )
        ok_btn = button_box.button(QDialogButtonBox.StandardButton.Ok)
        ok_btn.setText("Speichern" if self._is_edit else "Hinzufügen")
        ok_btn.setProperty("class", "primary")
        cancel_btn = button_box.button(QDialogButtonBox.StandardButton.Cancel)
        cancel_btn.setText("Abbrechen")
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self._edit_name.setFocus()

    def _prefill_from(self, entry: ManualScannerEntry) -> None:
        self._edit_name.setText(entry.name)
        self._edit_version.setText(entry.version)
        for i in range(self._combo_status.count()):
            if self._combo_status.itemData(i) == entry.status:
                self._combo_status.setCurrentIndex(i)
                break

    def _apply_style(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QLabel#manual_dialog_title {{ color: {c.ACCENT}; font-size: 14px;"
            f" font-weight: 700; background: transparent; border: none; }}"
            f"QLabel#manual_dialog_hint {{ color: {c.TEXT_DIM}; font-size: 11px;"
            f" font-style: italic; background: transparent; border: none; }}"
            f"QLabel {{ color: {c.TEXT_MAIN}; background: transparent; }}"
        )

    # ------------------------------------------------------------------
    # Accept / Result
    # ------------------------------------------------------------------

    def _on_accept(self) -> None:
        """Validiert Pflichtfelder und akzeptiert den Dialog."""
        name = self._edit_name.text().strip()
        if not name:
            self._edit_name.setFocus()
            self._edit_name.setPlaceholderText("Name ist ein Pflichtfeld")
            return
        self.accept()

    def result_entry(self) -> ManualScannerEntry:
        """Baut eine ``ManualScannerEntry`` aus den Formulareingaben.

        Bei Bearbeiten wird die bestehende ``entry_id`` beibehalten;
        Zeitstempel werden vom Repository beim ``add``/``update`` gesetzt.

        Returns:
            Neue oder aktualisierte:class:`ManualScannerEntry`.
        """
        status: ComponentStatus = self._combo_status.currentData()
        existing_id = self._entry.entry_id if self._entry is not None else None
        return ManualScannerEntry(
            entry_id=existing_id,
            category=self._category,
            name=self._edit_name.text().strip(),
            version=self._edit_version.text().strip(),
            status=status,
        )
