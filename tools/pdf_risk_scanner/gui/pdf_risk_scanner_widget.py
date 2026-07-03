"""pdf_risk_scanner_widget — GUI für den PDF-Risk-Scanner.

Erlaubt Drag&Drop oder Datei-Auswahl mehrerer PDFs, führt den
Deep-Scan im Hintergrund-Thread aus und zeigt die Ergebnisse in einer
Tabelle mit Detail-Panel für die erkannten Threats.

Schichtzugehörigkeit: gui/ — keine Geschäftslogik, nur UI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.security.validation_report import Severity, Threat
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.pdf_risk_scanner.application.scan_service import PdfScanService
from tools.pdf_risk_scanner.domain.models import PdfScanResult, ScanStatus

_STATUS_FARBE: dict[ScanStatus, str] = {
    ScanStatus.SAFE: theme.SEVERITY_SIGNAL_OK,
    ScanStatus.WARN: theme.SEVERITY_SIGNAL_MEDIUM,
    ScanStatus.BLOCK: theme.SEVERITY_SIGNAL_CRITICAL,
}

_STATUS_LABEL: dict[ScanStatus, str] = {
    ScanStatus.SAFE: "Sicher",
    ScanStatus.WARN: "Warnung",
    ScanStatus.BLOCK: "Blockiert",
}

# noqa: domain-pdf-severity-variant — Severity.LOW (#88aadd) und Severity.HIGH
# (#ff8844) sind Email/PDF-Risk-Varianten der Signal-Palette. Bewusst beibehalten.
_SEVERITY_FARBE: dict[Severity, str] = {
    Severity.INFO: theme.SEVERITY_SIGNAL_INFO,
    Severity.LOW: "#88aadd",  # noqa: domain-pdf-severity-low
    Severity.MEDIUM: theme.SEVERITY_SIGNAL_MEDIUM,
    Severity.HIGH: "#ff8844",  # noqa: domain-pdf-severity-high
    Severity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
}


class _ScanWorker(QObject):
    """Führt PDF-Scans im Hintergrund aus."""

    fortschritt = Signal(int, int, str)
    ergebnis = Signal(object)
    alle_fertig = Signal()
    fehler = Signal(str, str)

    def __init__(self, service: PdfScanService, pfade: list[Path]) -> None:
        super().__init__()
        self._service = service
        self._pfade = pfade

    @Slot()
    def run(self) -> None:
        """Arbeitet die Scan-Warteschlange sequentiell ab."""
        total = len(self._pfade)
        for index, pfad in enumerate(self._pfade, start=1):
            self.fortschritt.emit(index, total, pfad.name)
            try:
                result = self._service.scan(pfad)
            except (FileNotFoundError, ValueError) as exc:
                self.fehler.emit(pfad.name, str(exc))
                continue
            self.ergebnis.emit(result)
        self.alle_fertig.emit()


class PdfRiskScannerWidget(QWidget):
    """Haupt-Widget des PDF-Risk-Scanners."""

    def __init__(
        self,
        service: PdfScanService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._thread: QThread | None = None
        self._worker: _ScanWorker | None = None
        self._ergebnisse: list[PdfScanResult] = []
        self.setAcceptDrops(True)
        self._build_ui()
        theme.register_listener(self.apply_theme)

    def _build_ui(self) -> None:
        """Baut die gesamte Oberfläche auf."""
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(0)

        titel = QLabel("PDF Risk Scanner")
        titel.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-bottom: 4px;"
        )
        root.addWidget(titel)

        untertitel = QLabel(
            "Prüft PDF-Dokumente auf JavaScript, Auto-Actions, Launch-Befehle,"
            " eingebettete Dateien und Typ-Spoofing."
        )
        untertitel.setWordWrap(True)
        untertitel.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
            f" margin-bottom: 8px;"
        )
        root.addWidget(untertitel)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {c.ACCENT}; margin: 8px 0 16px 0;")
        root.addWidget(sep)

        _hc = HelpRegistry.get("pdf_risk_scanner")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        root.addWidget(self._build_drop_zone())
        root.addSpacing(8)
        root.addWidget(self._build_aktions_leiste())
        root.addSpacing(8)

        # kanonischer FinlaiProgressBar
        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        root.addWidget(self._progress)
        root.addSpacing(4)

        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-family: 'Raleway';"
        )
        root.addWidget(self._lbl_status)
        root.addSpacing(8)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._build_tabelle())
        splitter.addWidget(self._build_details_panel())
        splitter.setSizes([320, 220])
        root.addWidget(splitter)

    def _build_drop_zone(self) -> QWidget:
        """Baut die Drag&Drop-Zone mit "Dateien auswählen"-Button."""
        c = theme.get()
        self._drop_zone = QFrame()
        self._drop_zone.setFixedHeight(88)
        self._drop_zone.setStyleSheet(
            f"QFrame {{ background: {c.BG_INPUT}; border: 2px dashed {c.BORDER};"
            f" border-radius: 6px; }}"
        )
        layout = QHBoxLayout(self._drop_zone)
        layout.setContentsMargins(16, 8, 16, 8)

        hinweis = QLabel(
            "Findet JavaScript, Auto-Aktionen (/OpenAction), Launch-Befehle, "
            "eingebettete Dateien und Typ-Spoofing.\n"
            "PDF-Dateien hier ablegen oder auswählen — mehrere möglich."
        )
        hinweis.setWordWrap(True)
        hinweis.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
            f" background: transparent; border: none;"
        )
        layout.addWidget(hinweis, stretch=1)

        self._btn_waehlen = QPushButton("Dateien auswählen")
        self._btn_waehlen.setIcon(get_icon(Icons.UPLOAD))
        self._btn_waehlen.setFixedHeight(34)
        self._btn_waehlen.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" font-weight: bold; border: none; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DARK}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK};"
            f" padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; }}"
        )
        self._btn_waehlen.clicked.connect(self._on_dateien_waehlen)
        layout.addWidget(self._btn_waehlen)

        _tip_scan = self._help_tip("btn_scan")
        if _tip_scan:
            layout.addWidget(HelpButton(_tip_scan))
        return self._drop_zone

    def _build_aktions_leiste(self) -> QWidget:
        """Leiste mit "Liste leeren"-Aktion."""
        c = theme.get()
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addStretch()

        self._btn_leeren = QPushButton("Liste leeren")
        self._btn_leeren.setIcon(get_icon(Icons.DELETE_SWEEP))
        self._btn_leeren.setEnabled(False)
        self._btn_leeren.setFixedHeight(34)
        self._btn_leeren.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )
        self._btn_leeren.clicked.connect(self._on_leeren)
        layout.addWidget(self._btn_leeren)
        return row

    def _build_tabelle(self) -> QWidget:
        """Baut die Ergebnis-Tabelle."""
        c = theme.get()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tabelle = QTableWidget()
        self._tabelle.setColumnCount(5)
        self._tabelle.setHorizontalHeaderLabels(
            ["Datei", "Status", "Score", "Threats", "Dauer"]
        )
        self._tabelle.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._tabelle.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tabelle.setAlternatingRowColors(True)
        self._tabelle.verticalHeader().setVisible(False)
        self._tabelle.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._tabelle.setColumnWidth(1, 100)
        self._tabelle.setColumnWidth(2, 70)
        self._tabelle.setColumnWidth(3, 90)
        self._tabelle.setColumnWidth(4, 80)
        self._tabelle.setStyleSheet(
            f"QTableWidget {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" gridline-color: {c.BORDER}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; }}"
            f"QTableWidget::item:selected {{ background: {c.ACCENT_DARK};"
            f" color: {c.TEXT_MAIN}; }}"
            f"QTableWidget::item:selected:alternate {{ background: {c.ACCENT_DARK};"
            f" color: {c.TEXT_MAIN}; }}"
            f"QHeaderView::section {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: none; border-bottom: 1px solid {c.ACCENT_LINE}; padding: 4px 8px; }}"
            f"QTableWidget::item:alternate {{ background: {c.BG_DARK}; }}"
        )
        self._tabelle.selectionModel().selectionChanged.connect(self._on_auswahl)
        layout.addWidget(self._tabelle)
        return container

    def _build_details_panel(self) -> QWidget:
        """Detail-Panel für die Threats der ausgewählten Zeile."""
        c = theme.get()
        container = QWidget()
        container.setStyleSheet(
            f"background: {c.BG_INPUT}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px;"
        )
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Erkannte Risiken")
        hdr.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 12px;"
            f" font-weight: bold; background: transparent; border: none;"
        )
        hdr_row.addWidget(hdr)
        _tip_js = self._help_tip("result_js")
        if _tip_js:
            hdr_row.addWidget(HelpButton(_tip_js))
        hdr_row.addStretch()
        layout.addLayout(hdr_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self._details_inner = QWidget()
        self._details_inner.setStyleSheet("background: transparent;")
        self._details_layout = QVBoxLayout(self._details_inner)
        self._details_layout.setContentsMargins(0, 0, 0, 0)
        self._details_layout.setSpacing(4)
        self._details_layout.addStretch()
        scroll.setWidget(self._details_inner)
        layout.addWidget(scroll)
        return container

    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("pdf_risk_scanner")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "pdf_risk_scanner", parent=self.window()
        )
        dlg.show()

    def apply_theme(self) -> None:
        """Aktualisiert das Stylesheet bei Theme-Wechsel."""
        layout = self.layout()
        if layout is not None:
            QWidget().setLayout(layout)
        self._thread = None
        self._worker = None
        self._build_ui()
        self._aktualisiere_tabelle()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        """Akzeptiert Drag-Events, die mindestens ein PDF enthalten."""
        if event.mimeData().hasUrls() and any(
            url.toLocalFile().lower().endswith(".pdf")
            for url in event.mimeData().urls()
        ):
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        """Startet den Scan aller abgelegten PDF-Dateien."""
        pfade = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.toLocalFile().lower().endswith(".pdf")
        ]
        if pfade:
            event.acceptProposedAction()
            self._starte_scan(pfade)
        else:
            event.ignore()

    def _on_dateien_waehlen(self) -> None:
        """Öffnet einen Datei-Dialog zur PDF-Auswahl."""
        pfade_str, _ = QFileDialog.getOpenFileNames(
            self,
            "PDF-Dateien auswählen",
            "",
            "PDF-Dateien (*.pdf)",
        )
        if pfade_str:
            self._starte_scan([Path(p) for p in pfade_str])

    def _on_leeren(self) -> None:
        """Leert die Ergebnisliste."""
        self._ergebnisse.clear()
        self._aktualisiere_tabelle()
        self._zeige_details(None)
        self._btn_leeren.setEnabled(False)
        self._lbl_status.setText("")

    def _starte_scan(self, pfade: list[Path]) -> None:
        """Startet den Scan im Hintergrund-Thread."""
        if self._thread and self._thread.isRunning():
            return

        self._btn_waehlen.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setRange(0, len(pfade))
        self._progress.setValue(0)

        self._thread = QThread(self)
        self._worker = _ScanWorker(self._service, pfade)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.fortschritt.connect(self._on_fortschritt)
        self._worker.ergebnis.connect(self._on_ergebnis)
        self._worker.fehler.connect(self._on_fehler)
        self._worker.alle_fertig.connect(self._on_alle_fertig)
        self._worker.alle_fertig.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start()

    @Slot(int, int, str)
    def _on_fortschritt(self, current: int, total: int, name: str) -> None:
        """Aktualisiert die Fortschritts-Anzeige."""
        self._progress.setRange(0, total)
        self._progress.setValue(current)
        self._lbl_status.setText(f"Scanne: {name} ({current}/{total})")

    @Slot(object)
    def _on_ergebnis(self, result: PdfScanResult) -> None:
        """Nimmt ein Einzel-Ergebnis entgegen und aktualisiert die Tabelle."""
        self._ergebnisse.append(result)
        self._aktualisiere_tabelle()

    @Slot(str, str)
    def _on_fehler(self, dateiname: str, msg: str) -> None:
        """Meldet einen Scan-Fehler in der Status-Zeile."""
        self._lbl_status.setText(f"Fehler bei {dateiname}: {msg}")

    @Slot()
    def _on_alle_fertig(self) -> None:
        """Schließt die Scan-Session ab."""
        self._progress.setVisible(False)
        self._btn_waehlen.setEnabled(True)
        self._btn_leeren.setEnabled(bool(self._ergebnisse))
        block = sum(1 for r in self._ergebnisse if r.status is ScanStatus.BLOCK)
        warn = sum(1 for r in self._ergebnisse if r.status is ScanStatus.WARN)
        self._lbl_status.setText(
            f"Fertig — {len(self._ergebnisse)} Dateien, {block} blockiert, {warn} Warnungen"
        )

    def _aktualisiere_tabelle(self) -> None:
        """Füllt die Ergebnis-Tabelle."""
        self._tabelle.setRowCount(len(self._ergebnisse))
        for row, result in enumerate(self._ergebnisse):
            farbe = QColor(
                _STATUS_FARBE.get(result.status, theme.SEVERITY_SIGNAL_INFO)
            )
            werte = [
                result.path.name,
                _STATUS_LABEL.get(result.status, "—"),
                str(result.report.risk_score),
                str(len(result.report.threats)),
                f"{result.duration_ms:.0f} ms",
            ]
            for col, text in enumerate(werte):
                item = QTableWidgetItem(text)
                if col == 1:
                    item.setForeground(farbe)
                self._tabelle.setItem(row, col, item)

    def _on_auswahl(self) -> None:
        """Zeigt die Threats der ausgewählten Zeile im Detail-Panel."""
        rows = self._tabelle.selectionModel().selectedRows()
        if not rows:
            self._zeige_details(None)
            return
        row = rows[0].row()
        if row < len(self._ergebnisse):
            self._zeige_details(self._ergebnisse[row])

    def _zeige_details(self, result: PdfScanResult | None) -> None:
        """Befüllt das Detail-Panel mit den erkannten Threats."""
        c = theme.get()
        while self._details_layout.count() > 1:
            item = self._details_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        if result is None:
            return

        if not result.report.threats:
            lbl = QLabel("Keine Auffälligkeiten erkannt.")
            lbl.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_DIM};"
                f" background: transparent; border: none;"
            )
            self._details_layout.insertWidget(self._details_layout.count() - 1, lbl)
            return

        for threat in result.report.threats:
            self._details_layout.insertWidget(
                self._details_layout.count() - 1, self._threat_zeile(threat)
            )

    def _threat_zeile(self, threat: Threat) -> QWidget:
        """Rendert eine einzelne Threat-Zeile im Detail-Panel."""
        c = theme.get()
        farbe = _SEVERITY_FARBE.get(threat.severity, c.TEXT_MAIN)
        lbl = QLabel(
            f"<b style='color:{farbe};'>[{threat.severity.value}]</b> "
            f"<b>{threat.code}</b> — {threat.message}"
        )
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
            f" background: transparent; border: none;"
        )
        return lbl
