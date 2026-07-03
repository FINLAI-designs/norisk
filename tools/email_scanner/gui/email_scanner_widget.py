"""email_scanner_widget — Haupt-Widget des E-Mail-Anhang-Scanners.

Erlaubt Drag&Drop oder Datei-Auswahl mehrerer ``.eml``/``.msg``-Dateien,
führt die Scans im Hintergrund-Thread aus und zeigt:

    * Aggregat-Tabelle (eine Zeile je gescannter Mail)
    * Detail-Panel mit Meta-Header, Plaintext-Body, HTML-Quelltext
    * Anhang-Liste mit Threats + "Hash kopieren" / "In Quarantäne
      speichern"

HTML wird **nie** gerendert — Spec-Vorgabe.

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
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.email_scanner.application.scan_service import EmailScannerService
from tools.email_scanner.domain.models import (
    AttachmentReport,
    MailReport,
    MailScanStatus,
)
from tools.email_scanner.gui.attachment_list_view import AttachmentListView
from tools.email_scanner.gui.mail_detail_view import MailDetailView

_log = get_logger(__name__)

_STATUS_FARBE: dict[MailScanStatus, str] = {
    MailScanStatus.SAFE: theme.SEVERITY_SIGNAL_OK,
    MailScanStatus.WARN: theme.SEVERITY_SIGNAL_MEDIUM,
    MailScanStatus.BLOCK: theme.SEVERITY_SIGNAL_CRITICAL,
}

_STATUS_LABEL: dict[MailScanStatus, str] = {
    MailScanStatus.SAFE: "Sicher",
    MailScanStatus.WARN: "Warnung",
    MailScanStatus.BLOCK: "Blockiert",
}

_MAIL_SUFFIXES = {".eml", ".msg"}


class _ScanWorker(QObject):
    """Führt Mail-Scans im Hintergrund aus."""

    fortschritt = Signal(int, int, str)
    ergebnis = Signal(object)
    alle_fertig = Signal()

    def __init__(self, service: EmailScannerService, pfade: list[Path]) -> None:
        super().__init__()
        self._service = service
        self._pfade = pfade

    @Slot()
    def run(self) -> None:
        """Scant alle übergebenen Mails sequentiell."""
        total = len(self._pfade)
        for index, pfad in enumerate(self._pfade, start=1):
            self.fortschritt.emit(index, total, pfad.name)
            report = self._service.scan(pfad)
            self.ergebnis.emit(report)
        self.alle_fertig.emit()


class EmailScannerWidget(QWidget):
    """Haupt-Widget des E-Mail-Anhang-Scanners."""

    def __init__(
        self,
        service: EmailScannerService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._thread: QThread | None = None
        self._worker: _ScanWorker | None = None
        self._ergebnisse: list[MailReport] = []
        self.setAcceptDrops(True)
        self._build_ui()
        theme.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(0)

        titel = QLabel("E-Mail-Anhang-Scanner")
        titel.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {c.ACCENT}; margin-bottom: 4px;"
        )
        root.addWidget(titel)

        untertitel = QLabel(
            "Prüft .eml- und .msg-Mails auf gefährliche Anhänge (PDF-JavaScript,"
            " XLSX-Makros, Trojan-Source-Unicode, Typ-Spoofing). HTML-Bodies"
            " werden nie gerendert."
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

        _hc = HelpRegistry.get("email_scanner")
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

        outer_splitter = QSplitter(Qt.Orientation.Vertical)
        outer_splitter.addWidget(self._build_tabelle())

        detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._detail = MailDetailView()
        detail_splitter.addWidget(self._detail)
        self._attachments = AttachmentListView(
            quarantine_callback=self._on_quarantine,
            status_callback=self._set_status,
        )
        detail_splitter.addWidget(self._attachments)
        detail_splitter.setSizes([500, 320])

        outer_splitter.addWidget(detail_splitter)
        outer_splitter.setSizes([280, 320])
        root.addWidget(outer_splitter, stretch=1)

    def _build_drop_zone(self) -> QWidget:
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
            "Prüft E-Mail-Anhänge auf Office-Makros, PDF-JavaScript, "
            "Typ-Spoofing und verdächtige Dateitypen.\n"
            "Mail-Dateien (.eml, .msg) hier ablegen oder auswählen — mehrere möglich."
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
        self._btn_waehlen.setStyleSheet(self._btn_primary_stylesheet())
        self._btn_waehlen.clicked.connect(self._on_dateien_waehlen)
        layout.addWidget(self._btn_waehlen)

        _tip = self._help_tip("btn_scan_file")
        if _tip:
            layout.addWidget(HelpButton(_tip))
        return self._drop_zone

    def _build_aktions_leiste(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addStretch()

        self._btn_leeren = QPushButton("Liste leeren")
        self._btn_leeren.setIcon(get_icon(Icons.DELETE_SWEEP))
        self._btn_leeren.setEnabled(False)
        self._btn_leeren.setFixedHeight(34)
        self._btn_leeren.setStyleSheet(self._btn_ghost_stylesheet())
        self._btn_leeren.clicked.connect(self._on_leeren)
        layout.addWidget(self._btn_leeren)

        _tip_warn = self._help_tip("result_warnings")
        if _tip_warn:
            layout.addWidget(HelpButton(_tip_warn))
        return row

    def _build_tabelle(self) -> QWidget:
        c = theme.get()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tabelle = QTableWidget()
        self._tabelle.setColumnCount(6)
        self._tabelle.setHorizontalHeaderLabels(
            ["Datei", "Betreff", "Von", "Status", "Anhänge", "Score"]
        )
        self._tabelle.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._tabelle.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tabelle.setAlternatingRowColors(True)
        self._tabelle.verticalHeader().setVisible(False)
        header = self._tabelle.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tabelle.setColumnWidth(3, 100)
        self._tabelle.setColumnWidth(4, 80)
        self._tabelle.setColumnWidth(5, 70)
        self._tabelle.setStyleSheet(
            f"QTableWidget {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" gridline-color: {c.BORDER}; border: 1px solid {c.BORDER};"
            f" border-radius: 4px; }}"
            f"QTableWidget::item:selected {{ background: {c.ACCENT_DARK};"
            f" color: {c.TEXT_MAIN}; }}"
            f"QHeaderView::section {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: none; border-bottom: 1px solid {c.ACCENT_LINE}; padding: 4px 8px; }}"
            f"QTableWidget::item:alternate {{ background: {c.BG_DARK}; }}"
        )
        self._tabelle.selectionModel().selectionChanged.connect(self._on_auswahl)
        layout.addWidget(self._tabelle)
        return container

    def _btn_primary_stylesheet(self) -> str:
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" font-weight: bold; border: none; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DARK}; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; }}"
        )

    def _btn_ghost_stylesheet(self) -> str:
        c = theme.get()
        return (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )

    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("email_scanner")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "email_scanner", parent=self.window()
        )
        dlg.show()

    def apply_theme(self) -> None:
        layout = self.layout()
        if layout is not None:
            QWidget().setLayout(layout)
        self._thread = None
        self._worker = None
        self._build_ui()
        self._aktualisiere_tabelle()

    # ------------------------------------------------------------------
    # Drag & Drop + Datei-Dialog
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls() and any(
            Path(url.toLocalFile()).suffix.lower() in _MAIL_SUFFIXES
            for url in event.mimeData().urls()
        ):
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        pfade = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if Path(url.toLocalFile()).suffix.lower() in _MAIL_SUFFIXES
        ]
        if pfade:
            event.acceptProposedAction()
            self._starte_scan(pfade)
        else:
            event.ignore()

    def _on_dateien_waehlen(self) -> None:
        pfade_str, _ = QFileDialog.getOpenFileNames(
            self,
            "Mail-Dateien auswählen",
            "",
            "Mail-Dateien (*.eml *.msg)",
        )
        if pfade_str:
            self._starte_scan([Path(p) for p in pfade_str])

    def _on_leeren(self) -> None:
        self._ergebnisse.clear()
        self._aktualisiere_tabelle()
        self._detail.zeige(None)
        self._attachments.zeige([])
        self._btn_leeren.setEnabled(False)
        self._set_status("")

    # ------------------------------------------------------------------
    # Scan-Lebenszyklus
    # ------------------------------------------------------------------

    def _starte_scan(self, pfade: list[Path]) -> None:
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
        self._worker.alle_fertig.connect(self._on_alle_fertig)
        self._worker.alle_fertig.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start()

    @Slot(int, int, str)
    def _on_fortschritt(self, current: int, total: int, name: str) -> None:
        self._progress.setRange(0, total)
        self._progress.setValue(current)
        self._set_status(f"Scanne: {name} ({current}/{total})")

    @Slot(object)
    def _on_ergebnis(self, report: MailReport) -> None:
        self._ergebnisse.append(report)
        try:
            self._service.speichere_report(report)
        except Exception as exc:  # noqa: BLE001 — UI-Fluss darf nicht brechen
            _log.warning("Konnte Mail-Report nicht persistieren: %s", exc)
        self._aktualisiere_tabelle()

    @Slot()
    def _on_alle_fertig(self) -> None:
        self._progress.setVisible(False)
        self._btn_waehlen.setEnabled(True)
        self._btn_leeren.setEnabled(bool(self._ergebnisse))
        block = sum(1 for r in self._ergebnisse if r.status is MailScanStatus.BLOCK)
        warn = sum(1 for r in self._ergebnisse if r.status is MailScanStatus.WARN)
        self._set_status(
            f"Fertig — {len(self._ergebnisse)} Mails, {block} blockiert, {warn} Warnungen"
        )

    # ------------------------------------------------------------------
    # Tabelle / Auswahl
    # ------------------------------------------------------------------

    def _aktualisiere_tabelle(self) -> None:
        self._tabelle.setRowCount(len(self._ergebnisse))
        for row, report in enumerate(self._ergebnisse):
            datei = Path(report.source_path).name
            subject = report.mail.subject if report.mail else "(nicht lesbar)"
            von = report.mail.from_addr if report.mail else "—"
            status = _STATUS_LABEL.get(report.status, "—")
            farbe = QColor(
                _STATUS_FARBE.get(report.status, theme.SEVERITY_SIGNAL_INFO)
            )
            anhaenge = len(report.attachment_reports)
            werte = [
                datei,
                subject,
                von,
                status,
                str(anhaenge),
                str(report.risk_score),
            ]
            for col, text in enumerate(werte):
                item = QTableWidgetItem(text)
                if col == 3:
                    item.setForeground(farbe)
                self._tabelle.setItem(row, col, item)

    def _on_auswahl(self) -> None:
        rows = self._tabelle.selectionModel().selectedRows()
        if not rows:
            self._detail.zeige(None)
            self._attachments.zeige([])
            return
        row = rows[0].row()
        if 0 <= row < len(self._ergebnisse):
            report = self._ergebnisse[row]
            self._detail.zeige(report)
            self._attachments.zeige(report.attachment_reports)

    # ------------------------------------------------------------------
    # Quarantäne + Status
    # ------------------------------------------------------------------

    def _on_quarantine(self, report: AttachmentReport) -> None:
        try:
            sha = self._service.quarantaene_speichern(report)
            self._set_status(
                f"{report.attachment.filename} in Quarantäne gesichert (SHA-256 {sha[:12]}…)."
            )
        except Exception as exc:  # noqa: BLE001 — Nutzer-Feedback wichtiger
            _log.warning("Quarantäne-Speichern fehlgeschlagen: %s", exc)
            self._set_status(f"Fehler: {exc}")

    def _set_status(self, text: str) -> None:
        self._lbl_status.setText(text)
