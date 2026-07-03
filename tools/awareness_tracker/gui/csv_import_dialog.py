"""
csv_import_dialog — Modaler Dialog fuer Bulk-CSV-Import.

Iteration 3b: Datei-Auswahl + Preview (UTF-8) +
Validierungs-Lauf des CSV-Importers ohne Persistierung, dann Bestaetigen
fuer den tatsaechlichen Import.

Schichtzugehoerigkeit: gui/ — darf application/ + core/ importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.icons import Icons
from core.logger import get_logger
from tools.awareness_tracker.application.awareness_service import (
    AwarenessService,
)
from tools.awareness_tracker.application.csv_importer import (
    EMPLOYEE_HEADER,
    TRAINING_HEADER,
    ImportResult,
    import_employees_from_csv,
    import_trainings_from_csv,
)

_log = get_logger(__name__)


class CsvImportMode(Enum):
    """Welche Entitaet soll importiert werden?"""

    EMPLOYEES = "employees"
    TRAININGS = "trainings"


_MODE_LABEL: dict[CsvImportMode, str] = {
    CsvImportMode.EMPLOYEES: "Mitarbeiter",
    CsvImportMode.TRAININGS: "Schulungen",
}

# Beispielzeilen pro Modus. Sie sind so gewaehlt, dass sie fehlerfrei durch
# den jeweiligen Importer laufen (Roundtrip): die Mitarbeiter-Zeilen legen
# zwei Personen an; die Schulungs-Zeilen referenzieren genau diese beiden
# Personen ueber ``employee_full_name`` + nutzen gueltige ``training_type``-
# Enum-Werte. Wer beide Vorlagen in der Reihenfolge Mitarbeiter -> Schulungen
# importiert, erhaelt ein konsistentes Beispiel-Set.
_EMPLOYEE_SAMPLE_ROWS: tuple[tuple[str, ...], ...] = (
    (
        "Anna Beispiel",
        "anna.beispiel@kanzlei.example",
        "Anwaltsfachangestellte",
        "Linz",
        "true",
        "Beispielzeile - bitte ersetzen oder loeschen",
    ),
    (
        "Bernd Muster",
        "bernd.muster@kanzlei.example",
        "IT-Verantwortlicher",
        "Linz",
        "true",
        "Beispielzeile - bitte ersetzen oder loeschen",
    ),
)

_TRAINING_SAMPLE_ROWS: tuple[tuple[str, ...], ...] = (
    (
        "Anna Beispiel",
        "dsgvo_basics",
        "DSGVO-Grundlagenschulung 2026",
        "2026-03-01",
        "2028-03-01",
        "Interne Schulung",
        "",
        "Beispielzeile - bitte ersetzen oder loeschen",
    ),
    (
        "Bernd Muster",
        "phishing_awareness",
        "Phishing-Awareness Q1",
        "2026-02-15",
        "",
        "SoSafe",
        "",
        "Beispielzeile - bitte ersetzen oder loeschen",
    ),
)


def _sample_for_mode(
    mode: CsvImportMode,
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    """Liefert ``(header, beispielzeilen)`` fuer den gewuenschten Modus.

    Args:
        mode::class:`CsvImportMode` — entscheidet ueber Mitarbeiter- oder
            Schulungs-Schema.

    Returns:
        Tuple aus Header (exakt das vom Importer akzeptierte Schema) und den
        zugehoerigen Beispielzeilen.
    """
    if mode is CsvImportMode.EMPLOYEES:
        return EMPLOYEE_HEADER, _EMPLOYEE_SAMPLE_ROWS
    return TRAINING_HEADER, _TRAINING_SAMPLE_ROWS


def build_template_csv(mode: CsvImportMode) -> str:
    """Erzeugt den Inhalt einer Muster-CSV fuer den gewuenschten Modus.

    Die erste Zeile ist exakt der vom:mod:`csv_importer` akzeptierte Header
    (``EMPLOYEE_HEADER`` bzw. ``TRAINING_HEADER``); darunter folgen ein bis
    zwei Beispielzeilen, die fehlerfrei durch den Importer laufen.

    Args:
        mode::class:`CsvImportMode` — Mitarbeiter oder Schulungen.

    Returns:
        Der vollstaendige CSV-Inhalt als String (UTF-8-tauglich, Komma-
        getrennt, ``\\r\\n``-Zeilenenden gemaess:mod:`csv`).
    """
    header, sample_rows = _sample_for_mode(mode)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in sample_rows:
        writer.writerow(row)
    return buffer.getvalue()


class CsvImportDialog(QDialog):
    """Modaler Dialog fuer CSV-Import von Mitarbeitern oder Schulungen.

    Workflow:
        1. ``__init__`` zeigt Mode-Label + "Datei waehlen"-Button.
        2. Nach Datei-Auswahl wird die Datei UTF-8-decoded eingelesen und
           der Preview-Text (max. 50 Zeilen) angezeigt.
        3. User klickt "Importieren" — der Dialog laeuft den entsprechenden
           Importer und zeigt ``added/skipped/errors`` an, dann
           ``accept``.

    Args:
        mode::class:`CsvImportMode` — entscheidet welcher Importer
                     gerufen wird.
        service::class:`AwarenessService` fuer den Import.
        parent: Optionales Parent-Widget.
    """

    def __init__(
        self,
        mode: CsvImportMode,
        service: AwarenessService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._mode = mode
        self._service = service
        self._csv_text: str | None = None
        self._csv_path: Path | None = None
        self._last_result: ImportResult | None = None
        self.setWindowTitle(f"CSV-Import: {_MODE_LABEL[mode]}")
        self.setMinimumSize(640, 480)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        header = QLabel(self._build_header_text())
        header.setObjectName("AwarenessCsvImportHeader")
        header.setWordWrap(True)
        layout.addWidget(header)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)

        self._pick_button = QPushButton("CSV-Datei waehlen...")
        self._pick_button.setObjectName("AwarenessCsvPickButton")
        self._pick_button.clicked.connect(self._on_pick_clicked)
        button_row.addWidget(self._pick_button)

        self._template_button = QPushButton("Muster-CSV speichern...")
        self._template_button.setObjectName("AwarenessCsvTemplateButton")
        self._template_button.setToolTip(
            "Speichert eine Vorlage mit korrekter Kopfzeile und "
            "Beispieldaten zum Befuellen in Excel oder einem Texteditor."
        )
        self._template_button.clicked.connect(self._on_template_clicked)
        button_row.addWidget(self._template_button)

        button_row.addStretch(1)
        layout.addLayout(button_row)

        self._discoverability_hint = QLabel(
            'Tipp: Einzelne Eintraege koennen Sie auch direkt ueber '
            '"+ hinzufuegen" anlegen.'
        )
        self._discoverability_hint.setObjectName("AwarenessCsvDiscoverHint")
        self._discoverability_hint.setWordWrap(True)
        _t = theme.get()
        self._discoverability_hint.setStyleSheet(
            f"color: {_t.TEXT_DIM}; font-size: 11px; font-style: italic;"
        )
        layout.addWidget(self._discoverability_hint)

        self._path_label = QLabel("Keine Datei ausgewaehlt.")
        self._path_label.setObjectName("AwarenessCsvPathLabel")
        layout.addWidget(self._path_label)

        self._preview = QPlainTextEdit()
        self._preview.setObjectName("AwarenessCsvPreview")
        self._preview.setReadOnly(True)
        self._preview.setPlaceholderText(
            "Hier erscheint nach der Datei-Auswahl ein Preview "
            "(max. 50 Zeilen) zur Pruefung."
        )
        layout.addWidget(self._preview, stretch=1)

        self._status_label = QLabel("")
        self._status_label.setObjectName("AwarenessCsvStatusLabel")
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(
            QDialogButtonBox.StandardButton.Cancel
        ).setText("Abbrechen")
        self._import_button = QPushButton("Importieren")
        self._import_button.setObjectName("AwarenessCsvImportButton")
        self._import_button.setEnabled(False)
        self._import_button.clicked.connect(self._on_import_clicked)
        self._buttons.addButton(
            self._import_button, QDialogButtonBox.ButtonRole.AcceptRole
        )
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    def _build_header_text(self) -> str:
        if self._mode is CsvImportMode.EMPLOYEES:
            return (
                "<b>Mitarbeiter-CSV importieren.</b><br>"
                "Erwarteter Header: "
                "<code>full_name,email,role,department,is_active,notes</code>"
                "<br>UTF-8, Komma-getrennt. Mitarbeiter mit existierendem "
                "Namen werden uebersprungen (kein Ueberschreiben)."
            )
        return (
            "<b>Schulungen-CSV importieren.</b><br>"
            "Erwarteter Header: "
            "<code>employee_full_name,training_type,title,completed_at,"
            "valid_until,provider,custom_type_label,notes</code><br>"
            "UTF-8, Komma-getrennt. Mitarbeiter muessen vorher angelegt sein "
            "(z. B. via Mitarbeiter-CSV-Import)."
        )

    def _on_pick_clicked(self) -> None:
        path_str, _filter = QFileDialog.getOpenFileName(
            self,
            "CSV-Datei waehlen",
            "",
            "CSV-Dateien (*.csv);;Alle Dateien (*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            FinlaiInfoDialog(
                title="Encoding-Fehler",
                message="Die Datei ist nicht UTF-8 encoded. Bitte als UTF-8 "
                "speichern und erneut versuchen.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        except OSError as exc:
            FinlaiInfoDialog(
                title="Datei nicht lesbar",
                message=f"Fehler beim Lesen: {exc}",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        self._csv_text = content
        self._csv_path = path
        self._path_label.setText(f"Datei: {path}")
        self._preview.setPlainText(_truncate_preview(content))
        self._status_label.setText("")
        self._import_button.setEnabled(True)

    def _on_template_clicked(self) -> None:
        default_name = (
            "mitarbeiter_vorlage.csv"
            if self._mode is CsvImportMode.EMPLOYEES
            else "schulungen_vorlage.csv"
        )
        path_str, _filter = QFileDialog.getSaveFileName(
            self,
            "Muster-CSV speichern",
            default_name,
            "CSV-Dateien (*.csv);;Alle Dateien (*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != ".csv":
            path = path.with_suffix(".csv")
        content = build_template_csv(self._mode)
        try:
            # Reines utf-8 (KEIN BOM): der Importer liest die Datei spaeter
            # mit ``encoding="utf-8"``. Eine utf-8-sig-BOM wuerde als
            # ``﻿`` am ersten Header-Namen haengenbleiben (str.strip
            # entfernt sie nicht) und die Header-Validierung brechen.
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            _log.warning("Muster-CSV konnte nicht geschrieben werden: %s", exc)
            FinlaiInfoDialog(
                title="Speichern fehlgeschlagen",
                message=f"Die Vorlage konnte nicht gespeichert werden: {exc}",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self._status_label.setText(
            f"Vorlage gespeichert: {path}. Befuellen Sie die Datei und "
            'waehlen Sie sie danach ueber "CSV-Datei waehlen..." aus.'
        )

    def _on_import_clicked(self) -> None:
        if self._csv_text is None:
            return
        importer = self._importer_for_mode()
        result = importer(self._csv_text, self._service)
        self._last_result = result
        self._show_result(result)
        if result.success and not result.errors:
            self.accept()

    def _importer_for_mode(self) -> Callable[..., ImportResult]:
        if self._mode is CsvImportMode.EMPLOYEES:
            return import_employees_from_csv
        return import_trainings_from_csv

    def _show_result(self, result: ImportResult) -> None:
        parts = [
            f"<b>Hinzugefuegt:</b> {result.added_count}",
            f"<b>Uebersprungen (Duplikate):</b> {result.skipped_count}",
            f"<b>Fehler:</b> {len(result.errors)}",
        ]
        text = " · ".join(parts)
        if result.errors:
            preview = "<br>".join(
                f"  Zeile {n}: {msg}" for n, msg in result.errors[:5]
            )
            if len(result.errors) > 5:
                preview += f"<br>  ... und {len(result.errors) - 5} weitere."
            text += "<br><br><b>Fehler-Details:</b><br>" + preview
        self._status_label.setText(text)

    def last_result(self) -> ImportResult | None:
        """Liefert das letzte:class:`ImportResult` (oder ``None``)."""
        return self._last_result


def _truncate_preview(content: str, max_lines: int = 50) -> str:
    lines = content.splitlines()
    if len(lines) <= max_lines:
        return content
    head = "\n".join(lines[:max_lines])
    return (
        f"{head}\n\n... ({len(lines) - max_lines} weitere Zeilen "
        "im Preview ausgeblendet, werden aber importiert)"
    )


__all__ = ["CsvImportDialog", "CsvImportMode", "Qt", "build_template_csv"]
