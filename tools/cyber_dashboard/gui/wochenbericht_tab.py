"""
wochenbericht_tab — Wochenbericht PDF-Export Tab für das Cyberrisiko-Dashboard.

Ermöglicht das Erstellen eines PDF-Wochenberichts mit KI-Briefing,
kritischen CVEs und wichtigsten Meldungen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.application.export_service import ExportService

log = get_logger(__name__)


class _ExportThread(QThread):
    """Erstellt den PDF-Wochenbericht im Hintergrund.

    Signals:
        ergebnis: Emittiert True wenn PDF erfolgreich erstellt, sonst False.
    """

    ergebnis: Signal = Signal(bool)

    def __init__(
        self,
        service: DashboardService,
        briefing: dict | None,
        ausgabe_pfad: Path,
    ) -> None:
        """Initialisiert den Export-Thread.

        Args:
            service: DashboardService-Instanz für Meldungen und CVEs.
            briefing: KI-Briefing Dict oder None.
            ausgabe_pfad: Zielpfad für die PDF-Datei.
        """
        super().__init__()
        self._service = service
        self._briefing = briefing
        self._ausgabe_pfad = ausgabe_pfad

    def run(self) -> None:
        """Lädt Daten und erstellt den PDF-Bericht."""
        try:
            meldungen = self._service.lade_meldungen()
            cves = self._service.lade_cves_gefiltert(limit=50)
            svc = ExportService()
            ok = svc.erstelle_wochenbericht(
                meldungen=meldungen,
                cves=cves,
                briefing=self._briefing,
                ausgabe_pfad=self._ausgabe_pfad,
            )
            self.ergebnis.emit(ok)
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread Catch-All, fail-safe Error-Signal
            log.error("Export-Thread fehlgeschlagen: %s", exc)
            self.ergebnis.emit(False)


class WochenberichtTab(QWidget):
    """Wochenbericht-Tab — erstellt PDF-Berichte mit reportlab.

    Zeigt Pfad-Eingabe, Browse-Button und Export-Schaltfläche.
    Nach erfolgreichem Export kann die Datei direkt geöffnet werden.

    Args:
        service: DashboardService-Instanz.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        service: DashboardService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Wochenbericht-Tab."""
        super().__init__(parent)
        self._service = service
        self._thread: _ExportThread | None = None
        self._briefing: dict | None = None
        self._letzter_pfad: Path | None = None
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt das Tab-Layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(12)

        # Titel
        lbl_titel = QLabel("Wochenbericht PDF-Export")
        lbl_titel.setStyleSheet("font-size: 14px; font-weight: bold;")
        root.addWidget(lbl_titel)

        # Beschreibung
        lbl_info = QLabel(
            "Erstellt einen professionellen PDF-Wochenbericht mit KI-Briefing,\n"
            "kritischen CVEs und wichtigsten Sicherheitsmeldungen."
        )
        lbl_info.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 11px;")
        root.addWidget(lbl_info)

        # Pfad-Eingabe
        pfad_layout = QHBoxLayout()
        pfad_layout.setSpacing(6)

        pfad_layout.addWidget(QLabel("Speicherpfad:"))

        self._input_pfad = QLineEdit()
        self._input_pfad.setPlaceholderText("Zielpfad für die PDF-Datei …")
        pfad_layout.addWidget(self._input_pfad)

        self._btn_browse = QPushButton("Durchsuchen")
        self._btn_browse.setMinimumHeight(36)
        self._btn_browse.clicked.connect(self._pfad_auswaehlen)
        pfad_layout.addWidget(self._btn_browse)

        root.addLayout(pfad_layout)

        # Export-Button und Status
        export_layout = QHBoxLayout()

        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet("font-size: 11px;")
        export_layout.addWidget(self._lbl_status)
        export_layout.addStretch()

        self._btn_exportieren = QPushButton("Wochenbericht erstellen")
        self._btn_exportieren.setMinimumHeight(36)
        self._btn_exportieren.setStyleSheet("font-weight: bold; padding: 0 16px;")
        self._btn_exportieren.clicked.connect(self._exportieren)
        export_layout.addWidget(self._btn_exportieren)

        root.addLayout(export_layout)

        # Öffnen-Button (zunächst versteckt)
        self._btn_oeffnen = QPushButton("PDF öffnen")
        self._btn_oeffnen.setMinimumHeight(36)
        self._btn_oeffnen.setVisible(False)
        self._btn_oeffnen.clicked.connect(self._pdf_oeffnen)
        root.addWidget(self._btn_oeffnen)

        root.addStretch()

    def briefing_setzen(self, briefing: dict | None) -> None:
        """Setzt das aktuelle KI-Briefing für den Bericht.

        Args:
            briefing: KI-Briefing Dict oder None.
        """
        self._briefing = briefing

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------

    def _pfad_auswaehlen(self) -> None:
        """Öffnet einen Datei-Dialog zur Pfad-Auswahl."""
        from datetime import datetime  # noqa: PLC0415

        vorschlag = f"cyberrisiko_bericht_KW{datetime.now().isocalendar()[1]}.pdf"
        pfad, _ = QFileDialog.getSaveFileName(
            self,
            "Wochenbericht speichern",
            vorschlag,
            "PDF-Dateien (*.pdf)",
        )
        if pfad:
            self._input_pfad.setText(pfad)

    def _exportieren(self) -> None:
        """Startet die PDF-Erstellung im Hintergrund-Thread."""
        if self._thread and self._thread.isRunning():
            return

        pfad_text = self._input_pfad.text().strip()
        if not pfad_text:
            self._lbl_status.setText("[WARN] Bitte Speicherpfad angeben")
            return

        ausgabe_pfad = Path(pfad_text)
        if ausgabe_pfad.suffix.lower() != ".pdf":
            ausgabe_pfad = ausgabe_pfad.with_suffix(".pdf")
            self._input_pfad.setText(str(ausgabe_pfad))

        self._btn_exportieren.setEnabled(False)
        self._btn_oeffnen.setVisible(False)
        self._lbl_status.setText("Lädt… Erstelle PDF …")
        self._letzter_pfad = ausgabe_pfad

        self._thread = _ExportThread(self._service, self._briefing, ausgabe_pfad)
        self._thread.ergebnis.connect(self._export_fertig)
        self._thread.start()

    @Slot(bool)
    def _export_fertig(self, ok: bool) -> None:
        """Zeigt das Ergebnis des PDF-Exports an.

        Args:
            ok: True wenn PDF erfolgreich erstellt wurde.
        """
        self._btn_exportieren.setEnabled(True)
        if ok and self._letzter_pfad:
            self._lbl_status.setText(f"OK — PDF erstellt: {self._letzter_pfad.name}")
            self._lbl_status.setStyleSheet(
                f"color: {theme.get().SUCCESS}; font-size: 11px;"
            )
            self._btn_oeffnen.setVisible(True)
        else:
            self._lbl_status.setText(
                "FEHLER — PDF-Export fehlgeschlagen — ist reportlab installiert?"
            )
            self._lbl_status.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 11px;"
            )

    def _pdf_oeffnen(self) -> None:
        """Öffnet das zuletzt erstellte PDF mit dem Standard-Viewer."""
        if self._letzter_pfad and self._letzter_pfad.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._letzter_pfad)))

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QLineEdit {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
        )
