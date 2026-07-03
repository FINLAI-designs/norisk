"""
avv_upload_dialog — Modaler Upload-Dialog fuer ein neues AVV.

Iter 2c-i: Minimal-Form mit Vendor-Auswahl + Datei-Picker +
Gueltigkeitsdaten + Notiz. Die Art-28-Checkliste wird vom Service mit
10 PENDING-Default-Eintraegen initialisiert; der User editiert sie
nachher im:class:`AvvDetailDialog`.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QDate, Qt
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

from tools.supply_chain_monitor.domain.models import MAX_NOTES_LENGTH, Vendor


class AvvUploadDialog(QDialog):
    """Dialog zur Erfassung eines neuen AVV-Dokuments."""

    def __init__(
        self,
        vendors: list[Vendor],
        parent: QWidget | None = None,
        *,
        preselected_vendor_id: int | None = None,
    ) -> None:
        super().__init__(parent)
        self._vendors = vendors
        self._selected_path: Path | None = None
        self.setWindowTitle("AVV hochladen")
        self.setMinimumWidth(480)
        self._build_ui()
        if preselected_vendor_id is not None:
            idx = self._vendor_combo.findData(preselected_vendor_id)
            if idx >= 0:
                self._vendor_combo.setCurrentIndex(idx)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        # Vendor-Auswahl
        self._vendor_combo = QComboBox()
        for v in self._vendors:
            label = f"{v.name} (krit. {v.criticality_score})"
            self._vendor_combo.addItem(label, v.id)
        if not self._vendors:
            self._vendor_combo.addItem("Keine Vendoren angelegt", None)
            self._vendor_combo.setEnabled(False)
        form.addRow("Vendor", self._vendor_combo)

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
        # keine Spinbox-Pfeile (Datumswahl ueber den Kalender-Popup).
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
            "Optional: Bemerkungen zum AVV (max. 2000 Zeichen)."
        )
        form.addRow("Notiz", self._notes_input)

        # Hinweis
        info = QLabel(
            "Die PDF wird nach <code>~/.finlai/avv/&lt;vendor&gt;/</code> kopiert. "
            "Das Original bleibt erhalten. Die Art-28-Checkliste kann anschliessend "
            "im Detail-Dialog editiert werden."
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
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        layout.addWidget(self._buttons)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_browse(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "AVV-PDF auswaehlen",
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
        if self._vendor_combo.currentData() is None:
            return
        if len(self._notes_input.toPlainText()) > MAX_NOTES_LENGTH:
            self._notes_input.setFocus()
            return
        if self._valid_until.date() <= self._valid_from.date():
            self._valid_until.setFocus()
            return
        self.accept()

    def _update_ok_state(self) -> None:
        ok = (
            self._selected_path is not None
            and self._vendor_combo.currentData() is not None
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def selected_vendor_id(self) -> int | None:
        data = self._vendor_combo.currentData()
        return int(data) if isinstance(data, int) else None

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


# Wir definieren ``timedelta`` import oben nicht, falls in Tests verwendet:
_ = timedelta  # silence ruff
_ = Qt  # silence ruff
