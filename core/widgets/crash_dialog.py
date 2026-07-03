"""
crash_dialog — Modaler Dialog fuer unbehandelte Exceptions / Qt-Fatal-
Messages.

Zeigt dem User:
  * Fehlertyp + Kurzmeldung
  * Button "Logs oeffnen" (Explorer/Finder im logs/-Verzeichnis)
  * Button "Diagnose-Bundle exportieren" (ZIP mit Log + System-Info,
    ohne PII)
  * "OK"-Button schliesst den Dialog (App laeuft weiter wenn moeglich)

Patrick-Pflicht: kein PowerShell-Graben mehr, der externe User sieht
dass etwas passiert ist und kann selbststaendig das Log abrufen.

Schichtzugehoerigkeit: ``core/widgets/`` — kein Tool-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.crash_handler import (
    export_diagnose_bundle,
    open_current_log_file,
    open_log_directory,
)
from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.icons import Icons
from core.logger import get_logger

log = get_logger(__name__)


class CrashDialog(QDialog):
    """Modaler Dialog fuer Crash-Reports.

    Args:
        title: Dialog-Titel (z. B. ``"Unbehandelter Fehler: ValueError"``).
        message: Kurzbeschreibung des Fehlers (max 2-3 Saetze).
        parent: Eltern-Widget (typisch das MainWindow).
    """

    def __init__(
        self,
        title: str,
        message: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.setModal(True)
        self._build_ui(message)

    def _build_ui(self, message: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        intro = QLabel(
            "Es ist ein Fehler aufgetreten. NoRisk versucht weiter zu "
            "laufen.\nDie Log-Datei enthält die Diagnose-Informationen."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        detail = QLabel(message)
        detail.setWordWrap(True)
        detail.setObjectName("CrashDialogDetail")
        detail.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        detail.setStyleSheet(
            "QLabel#CrashDialogDetail {"
            " font-family: 'Consolas', monospace; font-size: 11px;"
            " padding: 8px; border-radius: 4px;"
            " background-color: rgba(128, 128, 128, 0.1); }"
        )
        layout.addWidget(detail)

        # Action-Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        btn_log_dir = QPushButton("Logs-Ordner öffnen")
        btn_log_dir.clicked.connect(self._open_logs)
        btn_row.addWidget(btn_log_dir)

        btn_log_file = QPushButton("Heutiges Log öffnen")
        btn_log_file.clicked.connect(self._open_current_log)
        btn_row.addWidget(btn_log_file)

        btn_export = QPushButton("Diagnose-Bundle exportieren …")
        btn_export.clicked.connect(self._export_bundle)
        btn_row.addWidget(btn_export)

        btn_row.addStretch()

        btn_ok = QPushButton("Schließen")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)

        layout.addLayout(btn_row)

    def _open_logs(self) -> None:
        if not open_log_directory():
            FinlaiInfoDialog(
                title="Logs-Ordner",
                message="Der Logs-Ordner konnte nicht geöffnet werden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()

    def _open_current_log(self) -> None:
        if not open_current_log_file():
            FinlaiInfoDialog(
                title="Heutiges Log",
                message="Die Log-Datei konnte nicht geöffnet werden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()

    def _export_bundle(self) -> None:
        default = str(Path.home() / "NoRisk_Diagnose.zip")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Diagnose-Bundle speichern",
            default,
            "ZIP-Archiv (*.zip)",
        )
        if not path:
            return
        try:
            export_diagnose_bundle(Path(path))
            FinlaiSuccessDialog(
                title="Diagnose-Bundle",
                message=(
                    "Diagnose-Bundle wurde gespeichert.\n\n"
                    "Bitte an support@finlai.eu senden."
                ),
                file_path=str(path),
                parent=self,
            ).exec()
        except OSError as exc:
            log.error("Diagnose-Bundle-Export fehlgeschlagen: %s", exc)
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=f"Konnte das Bundle nicht erstellen:\n{exc}",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()


def show_crash_dialog(title: str, message: str, parent: QWidget | None = None) -> None:
    """Convenience-Funktion: erstellt + zeigt einen Crash-Dialog.

    Wird typisch als ``_DIALOG_TRIGGER`` an:func:`core.crash_handler.
    set_dialog_trigger` uebergeben.
    """
    dlg = CrashDialog(title, message, parent=parent)
    dlg.exec()


__all__ = ["CrashDialog", "show_crash_dialog"]
