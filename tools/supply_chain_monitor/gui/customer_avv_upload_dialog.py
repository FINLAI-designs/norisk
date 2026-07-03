"""
customer_avv_upload_dialog — Modaler Upload-Dialog fuer einen KUNDEN-AVV.

Gegenstueck zu:class:`AvvUploadDialog`: statt einer Vendor-Auswahl waehlt der
User hier den KUNDEN (``Subject``/kind=KUNDE) — entweder einen bestehenden oder
ueber den Eintrag "Neuen Kunden anlegen..." einen neuen (Name-Eingabe). Die
eigentliche Anlage (``find_or_create_client``) uebernimmt der Tab nach dem OK.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QDate
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from tools.supply_chain_monitor.domain.models import MAX_NOTES_LENGTH

#: userData-Sentinel des "Neuen Kunden anlegen"-Combo-Eintrags.
_NEW_CUSTOMER_SENTINEL = "__new__"


class CustomerAvvUploadDialog(QDialog):
    """Dialog zur Erfassung eines neuen KUNDEN-AVV-Dokuments."""

    def __init__(
        self,
        customers: list[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        """Erstellt den Dialog.

        Args:
            customers: Liste ``(subject_id, name)`` der bekannten Kunden
                (kind=KUNDE).
            parent: Eltern-Widget.
        """
        super().__init__(parent)
        self._customers = customers
        self._selected_path: Path | None = None
        self.setWindowTitle("Kunden-AVV hochladen")
        self.setMinimumWidth(480)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        # Kunden-Auswahl (bestehend) + "Neuen Kunden anlegen..."
        self._customer_combo = QComboBox()
        for subject_id, name in self._customers:
            self._customer_combo.addItem(name, subject_id)
        self._customer_combo.addItem(
            "Neuen Kunden anlegen ...", _NEW_CUSTOMER_SENTINEL
        )
        self._customer_combo.currentIndexChanged.connect(self._on_customer_changed)
        form.addRow("Kunde", self._customer_combo)

        # Eingabe fuer den neuen Kundennamen (nur im "Neu"-Modus aktiv).
        self._new_name_input = QLineEdit()
        self._new_name_input.setPlaceholderText("Firmenname des neuen Kunden")
        self._new_name_input.textChanged.connect(self._update_ok_state)
        form.addRow("Neuer Kunde", self._new_name_input)

        # Datei-Picker
        file_row = QHBoxLayout()
        self._file_label = QLineEdit()
        self._file_label.setReadOnly(True)
        self._file_label.setPlaceholderText("PDF-Datei auswaehlen ...")
        file_row.addWidget(self._file_label, stretch=1)
        browse = QPushButton("Durchsuchen ...")
        browse.clicked.connect(self._on_browse)
        file_row.addWidget(browse)
        form.addRow("AVV-PDF", _wrap_layout(file_row))

        # Datumsfelder
        today = QDate.currentDate()
        self._valid_from = QDateEdit(today)
        self._valid_from.setCalendarPopup(True)
        self._valid_from.setDisplayFormat("yyyy-MM-dd")
        self._valid_from.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        form.addRow("Gueltig ab", self._valid_from)

        self._valid_until = QDateEdit(today.addYears(2))
        self._valid_until.setCalendarPopup(True)
        self._valid_until.setDisplayFormat("yyyy-MM-dd")
        self._valid_until.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        form.addRow("Gueltig bis", self._valid_until)

        # Notes
        self._notes_input = QTextEdit()
        self._notes_input.setAcceptRichText(False)
        self._notes_input.setPlaceholderText(
            "Optional: Bemerkungen zum Kunden-AVV (max. 2000 Zeichen)."
        )
        form.addRow("Notiz", self._notes_input)

        info = QLabel(
            "Wir sind hier Auftragsverarbeiter — die PDF dokumentiert den AVV mit "
            "diesem Kunden. Sie wird verschluesselt unter "
            "~/.finlai/avv/customers/ abgelegt; das Original bleibt erhalten."
        )
        info.setWordWrap(True)
        form.addRow(info)

        layout.addLayout(form)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        self._buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        self._buttons.accepted.connect(self._on_accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        # Initialzustand der Felder ableiten (z. B. wenn keine Kunden existieren,
        # steht der Combo direkt auf "Neuen Kunden anlegen...").
        self._on_customer_changed()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_customer_changed(self) -> None:
        self._new_name_input.setEnabled(self._is_new_customer_mode())
        self._update_ok_state()

    def _on_browse(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Kunden-AVV-PDF auswaehlen",
            str(Path.home()),
            "PDF-Dateien (*.pdf);;Alle Dateien (*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        if not path.exists() or not path.is_file():
            return
        self._selected_path = path
        self._file_label.setText(str(path))
        self._update_ok_state()

    def _on_accept(self) -> None:
        if self._selected_path is None:
            return
        if not self._has_valid_customer():
            return
        if len(self._notes_input.toPlainText()) > MAX_NOTES_LENGTH:
            self._notes_input.setFocus()
            return
        if self._valid_until.date() <= self._valid_from.date():
            self._valid_until.setFocus()
            return
        self.accept()

    def _update_ok_state(self) -> None:
        ok = self._selected_path is not None and self._has_valid_customer()
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------

    def _is_new_customer_mode(self) -> bool:
        return self._customer_combo.currentData() == _NEW_CUSTOMER_SENTINEL

    def _has_valid_customer(self) -> bool:
        if self._is_new_customer_mode():
            return bool(self._new_name_input.text().strip())
        return self._customer_combo.currentData() is not None

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def selected_subject_id(self) -> str | None:
        """Subject-ID des gewaehlten BESTEHENDEN Kunden (``None`` im Neu-Modus)."""
        if self._is_new_customer_mode():
            return None
        data = self._customer_combo.currentData()
        return data if isinstance(data, str) else None

    def new_customer_name(self) -> str:
        """Name des neu anzulegenden Kunden (leer, wenn ein Bestandskunde gewaehlt)."""
        if self._is_new_customer_mode():
            return self._new_name_input.text().strip()
        return ""

    def selected_file(self) -> Path | None:
        return self._selected_path

    def selected_valid_from(self) -> datetime:
        return _qdate_to_datetime_utc(self._valid_from.date())

    def selected_valid_until(self) -> datetime:
        return _qdate_to_datetime_utc(self._valid_until.date())

    def selected_notes(self) -> str:
        return self._notes_input.toPlainText()


def _qdate_to_datetime_utc(qd: QDate) -> datetime:
    return datetime(qd.year(), qd.month(), qd.day(), tzinfo=UTC)


def _wrap_layout(inner: QHBoxLayout) -> QWidget:
    """Hilft:meth:`QFormLayout.addRow` ein Layout statt Widget zu nehmen."""
    host = QWidget()
    host.setLayout(inner)
    return host
