"""
export_actions — GUI-Hilfsfunktionen für den einheitlichen Export-Workflow.

Kapselt den wiederkehrenden Ablauf:
  1. QFileDialog.getSaveFileName → Benutzer wählt Speicherort
  2. Exporter-Methode aufrufen
  3. FinlaiSuccessDialog mit "Öffnen"-Button anzeigen

Schichtzugehörigkeit: core/ — darf PySide6 importieren.
Nur aus gui/-Modulen aufrufen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFileDialog, QWidget

from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.export.base_exporter import BaseExporter
from core.icons import Icons
from core.logger import get_logger

if TYPE_CHECKING:
    pass

log = get_logger(__name__)


def _timestamp() -> str:
    """Gibt einen kompakten Zeitstempel zurück.

    Returns:
        String im Format YYYYMMDD_HHMM.
    """
    return datetime.now().strftime("%Y%m%d_%H%M")


def run_json_export(
    exporter: BaseExporter,
    data: object,
    parent: QWidget | None = None,
) -> bool:
    """Öffnet Speicherdialog, exportiert JSON, zeigt Erfolgsdialog.

    Args:
        exporter: Tool-spezifischer Exporter.
        data: Zu exportierendes Datenobjekt.
        parent: Eltern-Widget für den Dialog.

    Returns:
        True wenn Export erfolgreich, False wenn abgebrochen oder Fehler.
    """
    stem = f"{exporter.default_filename_stem}_{_timestamp()}"
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "JSON exportieren",
        f"{stem}.json",
        "JSON-Dateien (*.json)",
    )
    if not path:
        return False
    try:
        ok = exporter.export_json(data, path)
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        log.warning("JSON-Export fehlgeschlagen: %s", exc)
        FinlaiInfoDialog(
            title="Export fehlgeschlagen",
            message=f"JSON-Export fehlgeschlagen:\n{exc}",
            icon_name=Icons.ERROR,
            parent=parent,
        ).exec()
        return False
    if ok:
        FinlaiSuccessDialog(
            "JSON exportiert",
            f"{_format_count(data)} exportiert.",
            file_path=path,
            parent=parent,
        ).exec()
    return ok


def run_xlsx_export(
    exporter: BaseExporter,
    data: object,
    parent: QWidget | None = None,
) -> bool:
    """Öffnet Speicherdialog, exportiert XLSX, zeigt Erfolgsdialog.

    Args:
        exporter: Tool-spezifischer Exporter.
        data: Zu exportierendes Datenobjekt.
        parent: Eltern-Widget für den Dialog.

    Returns:
        True wenn Export erfolgreich, False wenn abgebrochen oder Fehler.
    """
    stem = f"{exporter.default_filename_stem}_{_timestamp()}"
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "Excel exportieren",
        f"{stem}.xlsx",
        "Excel-Dateien (*.xlsx)",
    )
    if not path:
        return False
    try:
        ok = exporter.export_xlsx(data, path)
    except (OSError, RuntimeError, ValueError, ImportError) as exc:
        log.warning("XLSX-Export fehlgeschlagen: %s", exc)
        FinlaiInfoDialog(
            title="Export fehlgeschlagen",
            message=f"Excel-Export fehlgeschlagen:\n{exc}",
            icon_name=Icons.ERROR,
            parent=parent,
        ).exec()
        return False
    if ok:
        FinlaiSuccessDialog(
            "Excel exportiert",
            f"{_format_count(data)} exportiert.",
            file_path=path,
            parent=parent,
        ).exec()
    return ok


def run_pdf_export(
    exporter: BaseExporter,
    data: object,
    parent: QWidget | None = None,
    title: str = "",
    subtitle: str = "",
) -> bool:
    """Öffnet Speicherdialog, exportiert PDF, zeigt Erfolgsdialog.

    Args:
        exporter: Tool-spezifischer Exporter.
        data: Zu exportierendes Datenobjekt.
        parent: Eltern-Widget für den Dialog.
        title: Optionaler Report-Titel.
        subtitle: Optionaler Report-Untertitel.

    Returns:
        True wenn Export erfolgreich, False wenn abgebrochen oder Fehler.
    """
    stem = f"{exporter.default_filename_stem}_{_timestamp()}"
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "PDF exportieren",
        f"{stem}.pdf",
        "PDF-Dateien (*.pdf)",
    )
    if not path:
        return False
    try:
        ok = exporter.export_pdf(data, path, title=title, subtitle=subtitle)
    except ImportError:
        FinlaiInfoDialog(
            title="reportlab fehlt",
            message="PDF-Export erfordert reportlab:\npip install reportlab pillow",
            icon_name=Icons.WARNING,
            parent=parent,
        ).exec()
        return False
    except (OSError, RuntimeError, ValueError) as exc:
        log.warning("PDF-Export fehlgeschlagen: %s", exc)
        FinlaiInfoDialog(
            title="Export fehlgeschlagen",
            message=f"PDF-Export fehlgeschlagen:\n{exc}",
            icon_name=Icons.ERROR,
            parent=parent,
        ).exec()
        return False
    if ok:
        FinlaiSuccessDialog(
            "PDF exportiert",
            f"{_format_count(data)} exportiert.",
            file_path=path,
            parent=parent,
        ).exec()
    return ok


def _format_count(data: object) -> str:
    """Gibt eine kurze Mengenangabe für den Erfolgsdialog zurück.

    Args:
        data: Datenobjekt — Liste oder einzelnes Objekt.

    Returns:
        Beschreibender String wie "12 Einträge" oder "1 Ergebnis".
    """
    if isinstance(data, list):
        n = len(data)
        return f"{n} {'Einträge' if n != 1 else 'Eintrag'}"
    return "Ergebnis"
