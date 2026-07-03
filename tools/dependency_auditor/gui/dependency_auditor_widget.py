"""
dependency_auditor_widget — PySide6 Haupt-Widget fuer den Dependency-Auditor.

Bietet zwei Audit-Modi:
  1. Self-Audit: prueft FINLAIs eigene requirements.txt per Klick
  2. Datei-Audit: Benutzer waehlt eine beliebige requirements.txt

Verarbeitungsablauf:
  - Audit laeuft in _AuditWorker (QThread) → UI blockiert nie
  - Fortschrittsanzeige mit aktuellem Package-Namen
  - Ergebnis-Anzeige via QTreeWidget (Schwachstellen, klappbar nach Severity)
  - Unpinned-Dependencies separat aufgelistet
  - OSV-Links per QDesktopServices.openUrl oeffenbar

Schichtzugehoerigkeit: gui/ — keine Geschaeftslogik, nur UI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.escape import escape_html
from core.export import export_actions
from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.dependency_auditor.application.audit_service import AuditService
from tools.dependency_auditor.application.dep_exporter import DepExporter
from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    VulnSeverity,
)

# ---------------------------------------------------------------------------
# Severity-Farben (Theme-unabhaengige Signalfarben)
# ---------------------------------------------------------------------------

_SEV_COLORS: dict[str, str] = {
    VulnSeverity.CRITICAL.value: theme.SEVERITY_DEEP_CRITICAL,
    VulnSeverity.HIGH.value: theme.SEVERITY_DEEP_HIGH,
    VulnSeverity.MEDIUM.value: theme.SEVERITY_DEEP_MEDIUM,
    VulnSeverity.LOW.value: theme.SEVERITY_DEEP_LOW,
}

_SEV_ICONS: dict[str, str] = {
    VulnSeverity.CRITICAL.value: "KRIT",
    VulnSeverity.HIGH.value: "HOCH",
    VulnSeverity.MEDIUM.value: "MITTEL",
    VulnSeverity.LOW.value: "NIEDRIG",
}


# ---------------------------------------------------------------------------
# Audit-Worker (QThread)
# ---------------------------------------------------------------------------


class _AuditWorker(QObject):
    """Fuehrt den Audit im Hintergrund-Thread aus.

    Signals:
        progress(aktuell, gesamt, pkg): Fortschritts-Update.
        finished(result): Audit abgeschlossen.
        error(message): Kritischer Fehler.
    """

    progress = Signal(int, int, str)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, service: AuditService, file_path: str | None) -> None:
        """Initialisiert den Worker.

        Args:
            service: AuditService-Instanz.
            file_path: Pfad zur Eingabe-Datei oder None fuer Self-Audit.
        """
        super().__init__()
        self._service = service
        self._file_path = file_path

    @Slot()
    def run(self) -> None:
        """Fuehrt den Audit aus und emittiert finished."""

        def _progress(aktuell: int, gesamt: int, pkg: str) -> None:
            self.progress.emit(aktuell, gesamt, pkg)

        try:
            if self._file_path is None:
                result = self._service.audit_self(_progress)
            else:
                # audit_file erkennt Format automatisch (.txt/.json/.xlsx/.pdf)
                result = self._service.audit_file(self._file_path, _progress)
            self.finished.emit(result)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class DependencyAuditorWidget(QWidget):
    """Haupt-Widget fuer den Dependency-Auditor.

    Attributes:
        _service: AuditService-Instanz.
        _file_path: Aktuell ausgewaehlte requirements.txt oder None.
        _thread: Aktiver QThread waehrend eines Audits.
        _worker: Aktiver _AuditWorker.
    """

    def __init__(
        self,
        service: AuditService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            service: Vollstaendig konfigurierter AuditService.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        self._file_path: str | None = None
        self._thread: QThread | None = None
        self._worker: _AuditWorker | None = None
        self._last_result: DependencyAuditResult | None = None
        self._exporter = DepExporter()
        self._build_ui()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das vollstaendige UI."""
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # Titel
        title = QLabel("Dependency-Auditor")
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {t.ACCENT};")
        root.addWidget(title)

        _hc = HelpRegistry.get("dependency_auditor")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # Anleitung
        anleitung = QLabel(
            "Prüft Python-Abhängigkeiten auf bekannte Sicherheitslücken (CVEs) "
            "via OSV-Datenbank (osv.dev).\n"
            "Self-Audit: analysiert FINLAI selbst.  |  "
            "Datei öffnen: requirements.txt, JSON, Excel oder PDF importieren.\n\n"
            "Unterstützte Formate:\n"
            "  .txt / .pip  →  requirements.txt  (requests==2.31.0, flask>=2.0)\n"
            '  .json        →  [{"name": "requests", "version": "2.31.0"}, ...]\n'
            "  .xlsx        →  Excel mit Spalten Name + Version\n"
            "  .pdf         →  Maschinenlesbares PDF mit requirements-Format"
        )
        anleitung.setWordWrap(True)
        anleitung.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: 11px; padding: 4px 0;"
            f" font-family: 'Cascadia Code', 'Consolas', monospace;"
        )
        root.addWidget(anleitung)

        # Aktionsleiste
        root.addLayout(self._build_action_bar())

        # Datei-Label
        self._lbl_file = QLabel("Keine Datei ausgewaehlt")
        self._lbl_file.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 11px;")
        self._lbl_file.setWordWrap(True)
        root.addWidget(self._lbl_file)

        # Status-Label
        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(f"color: {t.TEXT_MAIN};")
        root.addWidget(self._lbl_status)

        # Audit-Button + Fortschritt
        btn_row = QHBoxLayout()
        self._btn_audit = QPushButton("Audit starten")
        self._btn_audit.setIcon(get_icon(Icons.SCAN))
        self._btn_audit.setEnabled(False)
        self._btn_audit.clicked.connect(self._on_audit_clicked)
        self._btn_audit.setStyleSheet(self._btn_style())
        btn_row.addWidget(self._btn_audit)
        _tip_audit = self._help_tip("btn_audit")
        if _tip_audit:
            btn_row.addWidget(HelpButton(_tip_audit))
        btn_row.addStretch()
        root.addLayout(btn_row)

        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        self._progress.setTextVisible(True)
        root.addWidget(self._progress)

        self._lbl_progress = QLabel("")
        self._lbl_progress.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 11px;")
        self._lbl_progress.setVisible(False)
        root.addWidget(self._lbl_progress)

        # Ergebnis-Bereich (Splitter: Zusammenfassung + Schwachstellen-Tree)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        self._summary_widget = self._build_summary_panel()
        splitter.addWidget(self._summary_widget)

        self._tree = self._build_vuln_tree()
        splitter.addWidget(self._tree)
        splitter.setSizes([120, 500])

        root.addWidget(splitter, stretch=1)

        # Export-Buttons
        root.addLayout(self._build_export_bar())

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("dependency_auditor")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "dependency_auditor", parent=self.window()
        )
        dlg.show()

    def _build_action_bar(self) -> QHBoxLayout:
        """Erstellt die Aktionsleiste mit Self-Audit- und Datei-Buttons.

        Returns:
            HBoxLayout mit den Schaltflaechen.
        """
        bar = QHBoxLayout()
        bar.setSpacing(8)

        btn_self = QPushButton("FINLAI Self-Audit")
        btn_self.setIcon(get_icon(Icons.DEPENDENCY))
        btn_self.setToolTip("Prueft FINLAIs eigene requirements.txt auf Schwachstellen")
        btn_self.clicked.connect(self._on_self_audit)
        btn_self.setStyleSheet(self._btn_style(accent=True))
        bar.addWidget(btn_self)

        btn_file = QPushButton("Datei öffnen…")
        btn_file.setIcon(get_icon(Icons.UPLOAD))
        btn_file.setToolTip(
            "Datei auswählen: requirements.txt, JSON, Excel (.xlsx) oder PDF"
        )
        btn_file.clicked.connect(self._on_choose_file)
        btn_file.setStyleSheet(self._btn_style())
        bar.addWidget(btn_file)

        bar.addStretch()
        return bar

    def _build_summary_panel(self) -> QWidget:
        """Erstellt das Zusammenfassungs-Panel (Severity-Zaehler).

        Returns:
            QWidget mit den Severity-Labels.
        """
        t = theme.get()
        panel = QWidget()
        panel.setStyleSheet(
            f"background-color: {t.CARD_BG}; border-radius: 6px;"
            f" border: 1px solid {t.BORDER};"
        )
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(20)

        panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        panel.setFixedHeight(55)

        self._lbl_critical = self._make_sev_label(
            "KRIT", "Kritisch", "0", theme.SEVERITY_DEEP_CRITICAL
        )
        self._lbl_high = self._make_sev_label(
            "HOCH", "Hoch", "0", theme.SEVERITY_DEEP_HIGH
        )
        self._lbl_medium = self._make_sev_label(
            "MITTEL", "Mittel", "0", theme.SEVERITY_DEEP_MEDIUM
        )
        self._lbl_low = self._make_sev_label(
            "NIEDRIG", "Niedrig", "0", theme.SEVERITY_DEEP_LOW
        )
        self._lbl_ok = self._make_sev_label("OK", "OK", "0", t.SUCCESS)
        self._lbl_unpinned = self._make_sev_label("[!]", "Unpinned", "0", t.WARNING)
        # eigene Kategorie — Advisories ohne moeglichen Versionsabgleich.
        self._lbl_unverified = self._make_sev_label(
            "[?]", "Version unbekannt", "0", t.WARNING
        )

        for lbl in (
            self._lbl_critical,
            self._lbl_high,
            self._lbl_medium,
            self._lbl_low,
            self._lbl_ok,
            self._lbl_unpinned,
            self._lbl_unverified,
        ):
            layout.addWidget(lbl)

        layout.addStretch()
        return panel

    def _make_sev_label(self, icon: str, text: str, count: str, color: str) -> QLabel:
        """Erzeugt ein Severity-Zaehler-Label.

        Args:
            icon: Emoji-Icon.
            text: Bezeichnung.
            count: Initialer Zaehler-String.
            color: Textfarbe.

        Returns:
            Formatiertes QLabel.
        """
        lbl = QLabel(f"{icon} {count} {text}")
        lbl.setStyleSheet(f"color: {color}; font-size: 13px; border: none;")
        return lbl

    def _build_vuln_tree(self) -> QTreeWidget:
        """Erstellt den QTreeWidget fuer Schwachstellen-Details.

        Returns:
            Konfigurierter QTreeWidget.
        """
        t = theme.get()
        tree = QTreeWidget()
        tree.setHeaderLabels(
            ["Severity / Package", "Advisory-ID", "Betroffene Versionen", "Fix"]
        )
        tree.setColumnWidth(0, 300)
        tree.setColumnWidth(1, 180)
        tree.setColumnWidth(2, 180)
        tree.setColumnWidth(3, 100)
        tree.setAlternatingRowColors(True)
        tree.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {t.CARD_BG};
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                border-radius: 4px;
                font-size: 12px;
            }}
            QTreeWidget::item:selected {{
                background-color: {t.ACCENT};
                color: {t.BG_MAIN};
            }}
            QHeaderView::section {{
                background-color: {t.BG_DARK};
                color: {t.TEXT_MAIN};
                border: 1px solid {t.BORDER};
                padding: 4px;
            }}
            """
        )
        tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        return tree

    def _build_export_bar(self) -> QHBoxLayout:
        """Erstellt die Export-Schaltflaechen-Leiste.

        Returns:
            HBoxLayout mit Export-Buttons.
        """
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._btn_copy = QPushButton("Clipboard")
        self._btn_copy.setIcon(get_icon(Icons.COPY))
        self._btn_copy.setEnabled(False)
        self._btn_copy.clicked.connect(self._on_copy_clipboard)
        self._btn_copy.setStyleSheet(self._btn_style())
        bar.addWidget(self._btn_copy)

        _tip_export = self._help_tip("btn_export_json")
        if _tip_export:
            bar.addWidget(HelpButton(_tip_export))

        bar.addStretch()

        self._btn_export_json = QPushButton("JSON")
        self._btn_export_json.setIcon(get_icon(Icons.DATA_OBJECT))
        self._btn_export_json.setToolTip("Als JSON exportieren")
        self._btn_export_json.setEnabled(False)
        self._btn_export_json.setStyleSheet(self._btn_style())
        self._btn_export_json.clicked.connect(self._on_export_json)
        bar.addWidget(self._btn_export_json)

        self._btn_export_xlsx = QPushButton("Excel")
        self._btn_export_xlsx.setIcon(get_icon(Icons.TABLE_VIEW))
        self._btn_export_xlsx.setToolTip("Als Excel-Datei exportieren")
        self._btn_export_xlsx.setEnabled(False)
        self._btn_export_xlsx.setStyleSheet(self._btn_style())
        self._btn_export_xlsx.clicked.connect(self._on_export_xlsx)
        bar.addWidget(self._btn_export_xlsx)

        self._btn_export_pdf = QPushButton("PDF")
        self._btn_export_pdf.setIcon(get_icon(Icons.PDF))
        self._btn_export_pdf.setToolTip("Als PDF-Report exportieren")
        self._btn_export_pdf.setEnabled(False)
        self._btn_export_pdf.setStyleSheet(self._btn_style())
        self._btn_export_pdf.clicked.connect(self._on_export_pdf)
        bar.addWidget(self._btn_export_pdf)

        return bar

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_self_audit(self) -> None:
        """Startet den Self-Audit (FINLAIs eigene requirements.txt)."""
        self._file_path = None
        self._lbl_file.setText("FINLAI — requirements.txt (Projektroot)")
        self._btn_audit.setEnabled(True)
        self._lbl_status.setText("OK — FINLAI requirements.txt ausgewaehlt")
        self._on_audit_clicked()

    @Slot()
    def _on_choose_file(self) -> None:
        """Oeffnet einen Dateiauswahl-Dialog (txt/json/xlsx/pdf)."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Dependency-Datei auswählen",
            "",
            "Alle unterstützten Formate (*.txt *.pip *.json *.xlsx *.pdf);;"
            "Requirements-Dateien (*.txt *.pip);;"
            "JSON-Dateien (*.json);;"
            "Excel-Dateien (*.xlsx);;"
            "PDF-Dateien (*.pdf);;"
            "Alle Dateien (*)",
        )
        if path:
            self._file_path = path
            self._lbl_file.setText(f"Datei: {path}")
            self._btn_audit.setEnabled(True)
            self._lbl_status.setText(
                "OK — Datei ausgewählt — Audit starten um zu analysieren"
            )

    @Slot()
    def _on_audit_clicked(self) -> None:
        """Startet den Audit-Worker im Hintergrund-Thread."""
        if self._thread is not None and self._thread.isRunning():
            return

        if not external_fetches_allowed():
            self._lbl_status.setText(OFFLINE_HINT)
            return

        self._btn_audit.setEnabled(False)
        self._btn_copy.setEnabled(False)
        self._btn_export_json.setEnabled(False)
        self._btn_export_xlsx.setEnabled(False)
        self._btn_export_pdf.setEnabled(False)
        self._tree.clear()
        self._reset_summary()

        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._lbl_progress.setVisible(True)
        self._lbl_status.setText("Lädt… Audit laeuft...")

        self._thread = QThread(self)
        self._worker = _AuditWorker(self._service, self._file_path)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_audit_finished)
        self._worker.error.connect(self._on_audit_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._on_thread_finished)

        self._thread.start()

    @Slot(int, int, str)
    def _on_progress(self, current: int, total: int, pkg: str) -> None:
        """Aktualisiert Fortschrittsanzeige.

        Args:
            current: Aktueller Fortschritts-Zaehler.
            total: Gesamtzahl der Packages.
            pkg: Name des aktuell geprueften Packages.
        """
        self._progress.setMaximum(total)
        self._progress.setValue(current)
        self._progress.setFormat(f"{current}/{total}")
        self._lbl_progress.setText(f"Pruefe: {pkg}")

    @Slot(object)
    def _on_audit_finished(self, result: DependencyAuditResult) -> None:
        """Zeigt das Audit-Ergebnis an.

        Args:
            result: Vollstaendiges DependencyAuditResult.
        """
        self._progress.setVisible(False)
        self._lbl_progress.setVisible(False)
        self._btn_audit.setEnabled(True)
        self._btn_copy.setEnabled(True)
        self._last_result = result
        has_data = not result.error
        self._btn_export_json.setEnabled(has_data)
        self._btn_export_xlsx.setEnabled(has_data)
        self._btn_export_pdf.setEnabled(has_data)

        if result.error:
            self._lbl_status.setText(f"FEHLER: {result.error}")
            return

        self._populate_summary(result)
        self._populate_tree(result)

        total_v = result.total_vulnerabilities
        total_d = result.total_dependencies
        unpinned = len(result.unpinned_dependencies)
        unverified = result.unverified_count()
        status = (
            f"OK — {total_d} Dependencies geprueft — "
            f"{total_v} Schwachstellen gefunden — "
            f"{unpinned} unpinned"
        )
        if unverified:
            status += f" — {unverified} ohne Versionsabgleich"
        self._lbl_status.setText(status)

    @Slot(str)
    def _on_audit_error(self, message: str) -> None:
        """Zeigt eine kritische Fehlermeldung an.

        Args:
            message: Fehlerbeschreibung.
        """
        self._progress.setVisible(False)
        self._lbl_progress.setVisible(False)
        self._btn_audit.setEnabled(True)
        self._lbl_status.setText(f"FEHLER — Kritischer Fehler: {message}")

    @Slot()
    def _on_thread_finished(self) -> None:
        """Thread ist fertig — Referenz aufräumen."""
        self._thread = None
        self._worker = None

    @Slot(object, int)
    def _on_item_double_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Oeffnet OSV-Link bei Doppelklick auf ein Vulnerability-Item.

        Args:
            item: Geklicktes Tree-Item.
            _column: Ignoriert.
        """
        from PySide6.QtCore import QUrl

        url = item.data(0, Qt.ItemDataRole.UserRole)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    @Slot()
    def _on_copy_clipboard(self) -> None:
        """Kopiert eine Text-Zusammenfassung in die Zwischenablage."""
        from PySide6.QtWidgets import QApplication

        lines = []
        root_count = self._tree.topLevelItemCount()
        for i in range(root_count):
            top = self._tree.topLevelItem(i)
            if top is None:
                continue
            lines.append(top.text(0))
            for j in range(top.childCount()):
                child = top.child(j)
                if child is None:
                    continue
                lines.append(
                    f"  {child.text(0)} | {child.text(1)} | Fix: {child.text(3)}"
                )

        text = "\n".join(lines)
        if text:
            QApplication.clipboard().setText(text)
            self._lbl_status.setText("In Zwischenablage kopiert")

    @Slot()
    def _on_export_json(self) -> None:
        """Exportiert das letzte Audit-Ergebnis als JSON."""
        if self._last_result:
            export_actions.run_json_export(self._exporter, self._last_result, self)

    @Slot()
    def _on_export_xlsx(self) -> None:
        """Exportiert das letzte Audit-Ergebnis als Excel-Datei."""
        if self._last_result:
            export_actions.run_xlsx_export(self._exporter, self._last_result, self)

    @Slot()
    def _on_export_pdf(self) -> None:
        """Exportiert das letzte Audit-Ergebnis als PDF-Report."""
        if self._last_result:
            export_actions.run_pdf_export(self._exporter, self._last_result, self)

    # ------------------------------------------------------------------
    # UI-Aktualisierung
    # ------------------------------------------------------------------

    def _reset_summary(self) -> None:
        """Setzt alle Severity-Zaehler auf 0 zurueck."""
        self._lbl_critical.setText("KRIT 0 Kritisch")
        self._lbl_high.setText("HOCH 0 Hoch")
        self._lbl_medium.setText("MITTEL 0 Mittel")
        self._lbl_low.setText("NIEDRIG 0 Niedrig")
        self._lbl_ok.setText("OK 0 OK")
        self._lbl_unpinned.setText("[!] 0 Unpinned")
        self._lbl_unverified.setText("[?] 0 Version unbekannt")

    def _populate_summary(self, result: DependencyAuditResult) -> None:
        """Aktualisiert die Severity-Zaehler mit dem Audit-Ergebnis.

        Args:
            result: Abgeschlossenes DependencyAuditResult.
        """
        # Pakete ohne verifizierbare Version sind NICHT „OK" —
        # sie haben offene Advisories, nur ohne moeglichen Abgleich.
        ok_count = max(
            0,
            result.total_dependencies
            - result.total_vulnerabilities
            - len(result.unverified_dependencies),
        )
        self._lbl_critical.setText(f"KRIT {result.critical_count()} Kritisch")
        self._lbl_high.setText(f"HOCH {result.high_count()} Hoch")
        self._lbl_medium.setText(f"MITTEL {result.medium_count()} Mittel")
        self._lbl_low.setText(f"NIEDRIG {result.low_count()} Niedrig")
        self._lbl_ok.setText(f"OK {ok_count} OK")
        self._lbl_unpinned.setText(f"[!] {len(result.unpinned_dependencies)} Unpinned")
        self._lbl_unverified.setText(
            f"[?] {result.unverified_count()} Version unbekannt"
        )

    def _populate_tree(self, result: DependencyAuditResult) -> None:
        """Befuellt den QTreeWidget mit Schwachstellen und Unpinned-Infos.

        Gruppiert nach Severity (Top-Level-Items), darunter die einzelnen
        Vulnerabilities. Anschliessend Unpinned-Abschnitt.

        Args:
            result: Abgeschlossenes DependencyAuditResult.
        """
        self._tree.clear()

        # Schwachstellen gruppiert nach Severity
        by_severity: dict[str, list] = {}
        for vuln in result.vulnerabilities:
            by_severity.setdefault(vuln.severity.value, []).append(vuln)

        sev_order = [s.value for s in VulnSeverity]
        for sev_value in sev_order:
            vulns = by_severity.get(sev_value, [])
            if not vulns:
                continue
            color = _SEV_COLORS.get(sev_value, theme.DARK_TEXT_ON_ACCENT)
            icon = _SEV_ICONS.get(sev_value, "•")

            top = QTreeWidgetItem(
                [f"{icon} {sev_value} — {len(vulns)} Schwachstelle(n)", "", "", ""]
            )
            top.setForeground(0, _qcolor(color))
            self._tree.addTopLevelItem(top)

            for vuln in vulns:
                child = QTreeWidgetItem(
                    [
                        f"  {vuln.package_name}",
                        vuln.vuln_id,
                        vuln.affected_versions,
                        vuln.fixed_version or "kein Fix",
                    ]
                )
                # R22/: Tooltip ist Auto-RichText — OSV-Summary
                # ist untrusted und wird an der Render-Stelle escaped.
                child.setToolTip(1, escape_html(vuln.summary))
                child.setData(0, Qt.ItemDataRole.UserRole, vuln.url)
                child.setForeground(1, _qcolor(color))
                top.addChild(child)

            top.setExpanded(True)

        # „Version unbekannt"-Abschnitt — Advisories ohne moeglichen
        # Versionsabgleich. Bewusst KEINE Severity-Farben/Gruppen: das sind
        # unbestaetigte Befunde, keine CRITICAL/HIGH-Zeilen.
        if result.unverified_vulnerabilities:
            t = theme.get()
            top_unverified = QTreeWidgetItem(
                [
                    f"[?] VERSION UNBEKANNT — "
                    f"{len(result.unverified_vulnerabilities)} Advisory(s) — "
                    f"Abgleich nicht möglich",
                    "",
                    "",
                    "",
                ]
            )
            top_unverified.setForeground(0, _qcolor(t.WARNING))
            self._tree.addTopLevelItem(top_unverified)

            for vuln in result.unverified_vulnerabilities:
                child = QTreeWidgetItem(
                    [
                        f"  {vuln.package_name}",
                        vuln.vuln_id,
                        vuln.affected_versions,
                        vuln.fixed_version or "kein Fix",
                    ]
                )
                # R22/: untrusted Summary escapen (Auto-RichText).
                child.setToolTip(1, escape_html(vuln.summary))
                child.setData(0, Qt.ItemDataRole.UserRole, vuln.url)
                child.setForeground(0, _qcolor(t.TEXT_DIM))
                child.setForeground(1, _qcolor(t.TEXT_DIM))
                top_unverified.addChild(child)

            top_unverified.setExpanded(False)

        # Unpinned-Abschnitt
        if result.unpinned_dependencies:
            t = theme.get()
            top_unpinned = QTreeWidgetItem(
                [
                    f"[!] UNPINNED — {len(result.unpinned_dependencies)} Package(s)",
                    "",
                    "",
                    "",
                ]
            )
            top_unpinned.setForeground(0, _qcolor(t.WARNING))
            self._tree.addTopLevelItem(top_unpinned)

            for dep in result.unpinned_dependencies:
                child = QTreeWidgetItem(
                    [f"  {dep.name}", "", dep.version_spec or "(keine Angabe)", ""]
                )
                child.setForeground(0, _qcolor(t.WARNING))
                top_unpinned.addChild(child)

            top_unpinned.setExpanded(True)

        if (
            not result.vulnerabilities
            and not result.unverified_vulnerabilities
            and not result.unpinned_dependencies
        ):
            top_ok = QTreeWidgetItem(["OK — Keine Schwachstellen gefunden", "", "", ""])
            top_ok.setForeground(0, _qcolor(theme.get().SUCCESS))
            self._tree.addTopLevelItem(top_ok)

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def _btn_style(accent: bool = False) -> str:
        """Gibt das Stylesheet fuer Buttons zurueck.

        Args:
            accent: True fuer Akzentfarbe (hervorgehobene Aktionen).

        Returns:
            CSS-Stylesheet-String.
        """
        t = theme.get()
        bg = t.ACCENT if accent else t.BG_BUTTON
        text = t.BG_MAIN if accent else t.TEXT_MAIN
        return (
            f"QPushButton {{"
            f"  background-color: {bg}; color: {text};"
            f"  border: 1px solid {t.BORDER}; border-radius: 4px;"
            f"  padding: 6px 14px; font-size: 12px;"
            f"}}"
            f"QPushButton:hover {{"
            f"  background-color: {t.ACCENT}; color: {t.BG_MAIN};"
            f"}}"
            f"QPushButton:disabled {{"
            f"  background-color: {t.BG_BUTTON_DISABLED};"
            f"  color: {t.TEXT_BUTTON_DISABLED};"
            f"  border-color: {t.BORDER_BUTTON_DISABLED};"
            f"}}"
        )


# ---------------------------------------------------------------------------
# Hilfsfunktion
# ---------------------------------------------------------------------------


def _qcolor(hex_color: str):
    """Konvertiert einen Hex-Farbstring in ein QColor-Objekt.

    Args:
        hex_color: Hex-Farbwert (z. B. ``"#d32f2f"``).

    Returns:
        QColor-Instanz.
    """
    from PySide6.QtGui import QColor

    return QColor(hex_color)
