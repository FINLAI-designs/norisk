"""
api_security_widget — PySide6-GUI fuer den API Security Analyzer.

Zwei Tabs:
    [🔍 Neuer Scan] — URL-Eingabe, Scan starten, Findings, Export
    [📋 Verlauf] — Scan-History, Trend, URL-Filter, Details, Vergleich

Der Scan laeuft in einem QThread (_ScanThread). Alle UI-Updates
erfolgen ueber Qt-Signals (thread-safe).

Sicherheitsdesign:
    - URL-Eingabe wird vor dem Scan von ScannerService.run_scan validiert
    - Kein direkter Netzwerkzugriff im GUI-Thread
    - Export-Pfad ueber QFileDialog (kein freies Text-Input)
    - Loeschen mit Bestaetgungs-Dialog

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog, FinlaiInfoDialog
from core.export import export_actions
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.api_security.application.api_exporter import ApiExporter
from tools.api_security.application.scanner_service import (
    ScannerService,
    create_default_scanner_service,
)
from tools.api_security.domain.models import (
    AuthType,
    Finding,
    OWASPCategory,
    ScanLauf,
    ScanResult,
    ScanTarget,
    Severity,
)

_log = get_logger(__name__)

# Farbzuordnung Schweregrad → Hex — konsistent mit FINLAI Severity-Signal-Palette
_SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: theme.SEVERITY_SIGNAL_CRITICAL,
    Severity.HIGH: theme.SEVERITY_SIGNAL_HIGH,
    Severity.MEDIUM: theme.SEVERITY_SIGNAL_MEDIUM,
    Severity.LOW: theme.SEVERITY_SIGNAL_LOW,
    Severity.INFO: theme.SEVERITY_SIGNAL_INFO,
}

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Stack-Indizes im Neuer-Scan-Tab AP6: Empty-State + Ergebnis-Seite)
_STACK_EMPTY = 0  # Anleitung vor dem ersten Scan
_STACK_RESULTS = 1  # Ergebnis-Kopfzeile (KPI + Export) + Splitter


def _worst_sev_color(severity_summary: dict[str, int]) -> str:
    """Gibt die Farbe des schlimmsten Schweregrades im Summary zurueck."""
    for sev in _SEV_ORDER:
        if severity_summary.get(sev.value, 0) > 0:
            return _SEV_COLORS[sev]
    return theme.DARK_TEXT_DISABLED  # Fallback: gedämpftes Grau (#4A4E5C)


def _format_dt(iso_str: str) -> str:
    """Formatiert einen ISO-8601-String als 'TT.MM.JJJJ HH:MM'."""
    if not iso_str:
        return "–"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return iso_str[:16]


# ---------------------------------------------------------------------------
# Hintergrund-Thread
# ---------------------------------------------------------------------------


class _ScanThread(QThread):
    """Fuehrt den API-Scan im Hintergrund aus."""

    scan_finished: Signal = Signal(object)  # ScanResult
    scan_error: Signal = Signal(str)  # Fehlermeldung

    def __init__(self, service: ScannerService, target: ScanTarget) -> None:
        super().__init__()
        self._service = service
        self._target = target

    def run(self) -> None:
        try:
            result = self._service.run_scan(self._target)
            self.scan_finished.emit(result)
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread Catch-All, fail-safe Error-Signal
            _log.error("_ScanThread: %s", exc)
            self.scan_error.emit(str(exc))


# ---------------------------------------------------------------------------
# Trend-Widget (QPainter-basierte horizontale Balken)
# ---------------------------------------------------------------------------


class _TrendWidget(QWidget):
    """Zeigt horizontale Balken fuer die letzten N Scans (Findings-Anzahl).

    Balkenfarbe = schlimmster Schweregrad des Scans.
    Balkenbreite proportional zur Findings-Anzahl.
    """

    _ROW_H = 22
    _LABEL_W = 44
    _COUNT_W = 48
    _PADDING = 8

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scans: list[ScanLauf] = []
        self.setMinimumHeight(40)

    def update_scans(self, scans: list[ScanLauf]) -> None:
        """Aktualisiert die angezeigten Scans."""
        self._scans = scans[:10]
        h = max(40, len(self._scans) * self._ROW_H + self._PADDING * 2)
        self.setFixedHeight(h)
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        if not self._scans:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        max_count = max((s.findings_count for s in self._scans), default=1) or 1
        bar_area = w - self._LABEL_W - self._COUNT_W - self._PADDING * 3

        y = self._PADDING
        for scan in self._scans:
            label = _format_dt(scan.scan_start)[:5]  # "TT.MM"
            color = _worst_sev_color(scan.severity_summary)
            bar_w = max(4, int(scan.findings_count / max_count * bar_area))

            # Balken
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(
                self._LABEL_W + self._PADDING,
                y + 3,
                bar_w,
                self._ROW_H - 6,
                3,
                3,
            )

            # Datum-Label links
            painter.setPen(QColor("#aaaaaa"))  # noqa: hellgrau ohne Theme-Pendant — TODO Sprint 2: ggf. theme.DARK_TEXT_SECONDARY
            painter.drawText(
                0,
                y,
                self._LABEL_W,
                self._ROW_H,
                int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight),
                label,
            )

            # Anzahl rechts
            painter.drawText(
                self._LABEL_W + self._PADDING + bar_area + self._PADDING,
                y,
                self._COUNT_W,
                self._ROW_H,
                int(Qt.AlignmentFlag.AlignVCenter),
                str(scan.findings_count),
            )

            y += self._ROW_H

        painter.end()


# ---------------------------------------------------------------------------
# Detail-Dialog: vollstaendige Findings eines ScanLaufs
# ---------------------------------------------------------------------------


class _ScanDetailDialog(QDialog):
    """Zeigt alle Findings eines gespeicherten ScanLaufs."""

    def __init__(self, lauf: ScanLauf, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Details — {lauf.target_url}")
        self.resize(820, 520)
        self._lauf = lauf
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        info = QLabel(
            f"URL: {self._lauf.target_url}   |   "
            f"Scan: {_format_dt(self._lauf.scan_start)}   |   "
            f"Findings: {self._lauf.findings_count}   |   "
            f"Dauer: {self._lauf.dauer_sekunden():.1f}s"
        )
        info.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 13px;")
        layout.addWidget(info)

        tree = QTreeWidget()
        tree.setHeaderLabels(["Schweregrad", "Code", "Titel", "OWASP", "Empfehlung"])
        _hdr = tree.header()
        _hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        _hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        _hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        _hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        _hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        _populate_findings_tree(tree, self._lauf.findings)
        layout.addWidget(tree)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.button(QDialogButtonBox.StandardButton.Close).setText("Schliessen")
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ---------------------------------------------------------------------------
# Vergleichs-Dialog: Diff zweier ScanLaufe
# ---------------------------------------------------------------------------


class _ScanVergleichDialog(QDialog):
    """Zeigt den Diff zwischen zwei Scan-Laeufen."""

    def __init__(
        self,
        diff: dict[str, list[Finding]],
        aktuell: ScanLauf,
        vorherig: ScanLauf,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scan-Vergleich")
        self.resize(860, 580)
        self._diff = diff
        self._aktuell = aktuell
        self._vorherig = vorherig
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        header = QLabel(
            f"Vergleich: {_format_dt(self._aktuell.scan_start)} vs. "
            f"{_format_dt(self._vorherig.scan_start)}"
        )
        header.setStyleSheet("font-weight: bold; font-size: 13px;")
        layout.addWidget(header)

        # Zahlen-Zusammenfassung
        summary = QLabel(
            f"{len(self._diff['neu'])} neu   "
            f"{len(self._diff['behoben'])} behoben   "
            f"{len(self._diff['bestehend'])} unveraendert"
        )
        summary.setStyleSheet("font-size: 13px; padding: 4px 0;")
        layout.addWidget(summary)

        tabs = QTabWidget()

        # Neue Findings (gruen)
        neu_tree = QTreeWidget()
        neu_tree.setHeaderLabels(["Schweregrad", "Code", "Titel", "OWASP"])
        _populate_findings_tree(neu_tree, self._diff["neu"], "#00aa44")  # noqa: domain-diff-new-green
        tabs.addTab(neu_tree, get_icon(Icons.ADD), f"Neu ({len(self._diff['neu'])})")

        # Behobene Findings (rot/durchgestrichen)
        beh_tree = QTreeWidget()
        beh_tree.setHeaderLabels(["Schweregrad", "Code", "Titel", "OWASP"])
        _populate_findings_tree(beh_tree, self._diff["behoben"], theme.SEVERITY_SIGNAL_INFO)
        tabs.addTab(
            beh_tree,
            get_icon(Icons.CHECK_CIRCLE),
            f"Behoben ({len(self._diff['behoben'])})",
        )

        # Bestehende Findings
        best_tree = QTreeWidget()
        best_tree.setHeaderLabels(["Schweregrad", "Code", "Titel", "OWASP"])
        _populate_findings_tree(best_tree, self._diff["bestehend"])
        tabs.addTab(
            best_tree,
            get_icon(Icons.REFRESH),
            f"Unveraendert ({len(self._diff['bestehend'])})",
        )

        layout.addWidget(tabs)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.button(QDialogButtonBox.StandardButton.Close).setText("Schliessen")
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ---------------------------------------------------------------------------
# Shared Hilfsfunktion: Findings-Baum befuellen
# ---------------------------------------------------------------------------


def _populate_findings_tree(
    tree: QTreeWidget,
    findings: list[Finding],
    override_color: str | None = None,
) -> None:
    """Befuellt einen QTreeWidget mit Finding-Objekten."""
    tree.clear()
    for f in sorted(findings, key=lambda x: x.severity.sort_order()):
        color = override_color or _SEV_COLORS.get(f.severity, "#aaaaaa")  # noqa: hellgrau ohne Theme-Pendant
        rem = (f.remediation[:80] + "…") if len(f.remediation) > 80 else f.remediation
        item = QTreeWidgetItem(
            [f.severity.label(), f.code, f.title, f.owasp.value, rem]
        )
        for col in range(5):
            item.setForeground(col, QColor(color))
        item.setToolTip(2, f.description)
        item.setToolTip(4, f.remediation)
        if f.detail:
            item.setToolTip(1, f"Detail: {f.detail}")
        tree.addTopLevelItem(item)


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class ApiSecurityWidget(QWidget):
    """Haupt-Widget des API Security Analyzers (Etappe 2: + Verlauf)."""

    def __init__(
        self,
        service: ScannerService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            service: Vorkonfigurierter ScannerService (per DI von tool.py).
                     Wird ein Fallback ohne Repository erstellt wenn None.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)

        if service is None:
            service = create_default_scanner_service()
        self._service = service
        self._result: ScanResult | None = None
        self._scan_thread: _ScanThread | None = None
        self._exporter = ApiExporter(self._service)

        self._build_ui()

    # ------------------------------------------------------------------
    # Cross-Tool-Deep-Link (Sprint S3d)
    # ------------------------------------------------------------------

    def apply_navigation(self, **kwargs: object) -> None:
        """Empfangs-Pattern fuer ``MainWindow.navigate_to(..., url=...)``.

        Erkannte kwargs:
            ``url`` -- URL fuer einen neuen Scan vorausfuellen.

        Andere kwargs werden ignoriert (forward-kompatibel).
        """
        url = kwargs.get("url")
        if url is None:
            return
        text = str(url).strip()
        if not text:
            return
        self._url_input.setText(text)
        # Cursor in das URL-Feld setzen, damit der User direkt auf Enter
        # druecken kann statt erst klicken zu muessen.
        self._url_input.setFocus()

    # ------------------------------------------------------------------
    # D2 — leichter Quer-Link auf das verwandte Werkzeug
    # ------------------------------------------------------------------
    def _build_verwandt_zeile(self) -> QWidget:
        """Dezente „Verwandt:"-Zeile mit Sprung zum Zertifikats-Monitor (D2).

        Returns:
            Ein schlankes Widget mit einem klickbaren Link-Label.
        """
        c = theme
        row = QWidget()
        layout = QHBoxLayout(row)
        # 12px Abstand nach unten — sonst klebt die "Verwandt:"-Zeile
        # direkt an der Tab-Leiste (root.setSpacing == 0).
        layout.setContentsMargins(12, 4, 12, 12)
        layout.setSpacing(0)
        link = QLabel(
            f"Verwandt: <a href='#' style='color:{c.ACCENT}; "
            "text-decoration:none;'>Zertifikats-Monitor &rarr;</a>"
        )
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setToolTip("Zertifikats-Monitor öffnen (verwandtes Werkzeug)")
        link.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        link.linkActivated.connect(self._open_cert_monitor)
        layout.addWidget(link)
        layout.addStretch()
        return row

    @Slot()
    def _open_cert_monitor(self) -> None:
        """Springt ins ``cert_monitor``-Tool (D2). Graceful, nie crashend."""
        window = self.window()
        navigate = getattr(window, "navigate_to", None)
        if not callable(navigate):
            return
        try:
            navigate("cert_monitor")
        except Exception:  # noqa: BLE001 -- Navigation darf nie crashen
            pass

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das Tab-Layout."""
        c = theme
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        _hc = HelpRegistry.get("api_security")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # D2 (leichter Quer-Link, KEIN Merge): dezenter Hinweis auf das
        # verwandte Werkzeug (Zertifikats-Monitor). Beide prüfen Endpunkt-
        # Sicherheit aus unterschiedlichen Blickwinkeln.
        root.addWidget(self._build_verwandt_zeile())

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 1px solid {c.BORDER}; }}"
            f"QTabBar::tab {{ background: {c.CARD_BG}; color: {c.TEXT_DIM};"
            f" padding: 8px 16px; border: none;"
            f" border-bottom: 2px solid transparent; font-size: 13px; }}"
            f"QTabBar::tab:selected {{ background: {c.BG_MAIN}; color: {c.ACCENT};"
            f" border-bottom: 2px solid {c.ACCENT}; font-weight: 600; }}"
            f"QTabBar::tab:hover:!selected {{ background: {c.ACCENT_DIM};"
            f" color: {c.TEXT_MAIN}; border-bottom: 2px solid {c.BORDER}; }}"
        )

        # Tab 1: Neuer Scan (bestehende Funktionalitaet)
        self._scan_tab = self._build_scan_tab()
        self._tabs.addTab(self._scan_tab, get_icon(Icons.SCAN), "Neuer Scan")

        # Tab 2: Verlauf
        self._verlauf_tab = self._build_verlauf_tab()
        self._tabs.addTab(self._verlauf_tab, get_icon(Icons.SCHEDULE), "Verlauf")

        root.addWidget(self._tabs)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("api_security")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "api_security", parent=self.window()
        )
        dlg.show()

    def _build_scan_tab(self) -> QWidget:
        """Erstellt den Neuer-Scan-Tab mit URL-Eingabe und Findings."""
        c = theme
        tab = QWidget()
        root = QVBoxLayout(tab)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        url_label = QLabel("API-URL:")
        url_label.setStyleSheet(f"color: {c.TEXT_MAIN}; font-weight: bold;")
        toolbar.addWidget(url_label)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://api.example.com/v1")
        self._url_input.setMinimumWidth(350)
        self._url_input.setStyleSheet(
            f"background: {c.BG_INPUT}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px;"
        )
        toolbar.addWidget(self._url_input, stretch=1)

        self._scan_btn = QPushButton("Scan starten")
        self._scan_btn.setIcon(get_icon(Icons.SCAN))
        self._scan_btn.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK}; font-weight: bold;"
            f" border: none; border-radius: 4px; padding: 6px 16px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DARK}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK};"
            f" padding-top: 7px; padding-bottom: 5px; }}"
        )
        self._scan_btn.clicked.connect(self._on_scan_clicked)
        toolbar.addWidget(self._scan_btn)

        _tip_scan = self._help_tip("btn_scan")
        if _tip_scan:
            toolbar.addWidget(HelpButton(_tip_scan))

        self._active_checks_cb = QCheckBox("Aktive Prüfungen")
        self._active_checks_cb.setToolTip(
            "Aktive Prüfungen (10–14): HTTP-Methoden, Content-Type, Auth-Bypass, "
            "Request-Size-Limits, Verbose Errors.\n"
            "Sendet zusätzliche Requests an das Ziel (opt-in)."
        )
        self._active_checks_cb.setStyleSheet(
            f"QCheckBox {{ color: {c.TEXT_MAIN}; spacing: 6px; }}"
            f"QCheckBox::indicator {{ width: 16px; height: 16px;"
            f" border: 2px solid {c.ACCENT}; border-radius: 3px;"
            f" background-color: {c.BG_INPUT}; }}"
            f"QCheckBox::indicator:hover {{ border-color: {theme.DARK_TEXT_ON_ACCENT}; }}"
            f"QCheckBox::indicator:checked {{ background-color: {c.ACCENT};"
            f" border-color: {c.ACCENT}; }}"
        )
        toolbar.addWidget(self._active_checks_cb)

        root.addLayout(toolbar)

        # AP6: Stack — Index 0 = Empty-State, Index 1 = Ergebnis-Seite
        self._scan_stack = QStackedWidget()
        self._scan_stack.addWidget(self._build_empty_state())

        # Ergebnis-Seite: Kopfzeile (KPI links, Export rechts) + Splitter
        result_page = QWidget()
        result_layout = QVBoxLayout(result_page)
        result_layout.setContentsMargins(0, 0, 0, 0)
        result_layout.setSpacing(8)

        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        self._kpi_label = QLabel()
        self._kpi_label.setTextFormat(Qt.TextFormat.RichText)
        self._kpi_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
        )
        header_row.addWidget(self._kpi_label)
        header_row.addStretch()

        # R26: Export-Buttons tragen ihr eigenes vollstaendiges Stylesheet
        # (alle 4 States) — unabhaengig von Container-Kaskaden.
        _export_btn_style = (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 6px 12px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )

        self._json_btn = QPushButton("JSON")
        self._json_btn.setIcon(get_icon(Icons.DATA_OBJECT))
        self._json_btn.setToolTip("Als JSON exportieren")
        self._json_btn.setEnabled(False)
        self._json_btn.setStyleSheet(_export_btn_style)
        self._json_btn.clicked.connect(self._on_export_json)
        header_row.addWidget(self._json_btn)

        self._xlsx_btn = QPushButton("Excel")
        self._xlsx_btn.setIcon(get_icon(Icons.TABLE_VIEW))
        self._xlsx_btn.setToolTip("Als Excel-Datei exportieren")
        self._xlsx_btn.setEnabled(False)
        self._xlsx_btn.setStyleSheet(_export_btn_style)
        self._xlsx_btn.clicked.connect(self._on_export_xlsx)
        header_row.addWidget(self._xlsx_btn)

        self._pdf_btn = QPushButton("PDF")
        self._pdf_btn.setIcon(get_icon(Icons.PDF))
        self._pdf_btn.setToolTip("Als PDF-Report exportieren")
        self._pdf_btn.setEnabled(False)
        self._pdf_btn.setStyleSheet(_export_btn_style)
        self._pdf_btn.clicked.connect(self._on_export_pdf)
        header_row.addWidget(self._pdf_btn)

        result_layout.addLayout(header_row)

        # Splitter: OWASP-Uebersicht | Befunde
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._owasp_tree = QTreeWidget()
        self._owasp_tree.setHeaderLabels(["OWASP Kategorie", "Befunde"])
        _owasp_hdr = self._owasp_tree.header()
        _owasp_hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        _owasp_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._owasp_tree.setStyleSheet(
            f"background: {c.CARD_BG}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.BORDER};"
        )
        self._owasp_tree.itemClicked.connect(self._on_owasp_selected)
        splitter.addWidget(self._owasp_tree)

        self._findings_tree = QTreeWidget()
        self._findings_tree.setHeaderLabels(
            ["Schweregrad", "Code", "Titel", "OWASP", "Empfehlung"]
        )
        _findings_hdr = self._findings_tree.header()
        _findings_hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        _findings_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        _findings_hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        _findings_hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        _findings_hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._findings_tree.setStyleSheet(
            f"background: {c.CARD_BG}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.BORDER};"
        )
        splitter.addWidget(self._findings_tree)
        splitter.setSizes([320, 680])

        result_layout.addWidget(splitter, stretch=1)
        self._scan_stack.addWidget(result_page)
        self._scan_stack.setCurrentIndex(_STACK_EMPTY)

        root.addWidget(self._scan_stack, stretch=1)

        # Fortschrittsbalken + Status: kanonischer FinlaiProgressBar)
        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        self._status_label = QLabel("Bereit \u2014 API-URL eingeben und Scan starten.")
        # Fehlertexte echoen die getippte URL (untrusted) \u2014 nie als
        # Auto-RichText rendern (R22-Review).
        self._status_label.setTextFormat(Qt.TextFormat.PlainText)
        self._status_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        root.addWidget(self._status_label)

        return tab

    def _build_empty_state(self) -> QWidget:
        """Erstellt den Empty-State des Neuer-Scan-Tabs AP6).

        Erklaert vor dem ersten Scan den Nutzen (OWASP API Security Top 10),
        fuehrt durch die 1-2-3-Schritte und blendet -- falls vorhanden -- den
        letzten gespeicherten Scan ein, damit bisheriger Wert sichtbar bleibt.

        Returns:
            Widget mit zentrierten Anleitungs-Labels.
        """
        c = theme
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(6)
        layout.addStretch(1)

        titel = QLabel("Noch kein Scan in dieser Sitzung.")
        titel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        titel.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 15px;"
            f" font-weight: bold;"
        )
        layout.addWidget(titel)

        # Wert-Erklaerung: macht den Nutzen sofort verstaendlich.
        erklaerung = QLabel(
            "Der API-Scanner prueft deine API gegen die OWASP API Security "
            "Top 10 \u2014 etwa fehlerhafte Authentifizierung, unzureichende "
            "Objekt-Zugriffsrechte (BOLA) und uebermaessige Datenrueckgabe \u2014 "
            "und liefert je Befund eine konkrete Empfehlung."
        )
        erklaerung.setAlignment(Qt.AlignmentFlag.AlignCenter)
        erklaerung.setWordWrap(True)
        erklaerung.setMaximumWidth(560)
        erklaerung.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
        )
        layout.addWidget(erklaerung, alignment=Qt.AlignmentFlag.AlignCenter)

        for text in (
            "1. Gib oben die API-URL ein",
            "2. Klicke auf 'Scan starten'",
            "3. Die Befunde erscheinen hier",
        ):
            label = QLabel(text)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setWordWrap(True)
            label.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
            )
            layout.addWidget(label)

        # Letzter gespeicherter Scan: bisherigen Wert sichtbar machen.
        letzter = self._letzter_scan_hinweis()
        if letzter:
            hint = QLabel(letzter)
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hint.setWordWrap(True)
            hint.setStyleSheet(
                f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 12px;"
            )
            layout.addWidget(hint)

        layout.addStretch(1)
        return page

    def _letzter_scan_hinweis(self) -> str:
        """Liefert einen Kurzhinweis auf den letzten gespeicherten Scan.

        Returns:
            Hinweistext, oder leerer String wenn kein Verlauf existiert.
        """
        try:
            letzte = self._service.lade_verlauf(limit=1)
        except Exception:  # noqa: BLE001 -- Empty-State darf nie crashen
            return ""
        if not letzte:
            return ""
        s = letzte[0]
        return (
            f"Zuletzt geprueft: {_format_dt(s.scan_start)} \u2014 "
            f"{s.findings_count} Befunde (siehe Tab Verlauf)"
        )

    def _update_kpi_label(self, result: ScanResult) -> None:
        """Aktualisiert die KPI-Zeile der Ergebnis-Kopfzeile AP6).

        Zeigt "X kritisch \u00b7 Y hoch \u00b7 Z mittel" in den Severity-Signalfarben,
        bei null Befunden eine positive Bestaetigung.

        Args:
            result: ScanResult, aus dessen Findings die Zaehler berechnet werden.
        """
        c = theme
        if not result.findings:
            self._kpi_label.setText(
                f"<span style='color: {c.SUCCESS};'>Keine Befunde \u2014 gut so.</span>"
            )
            return

        kritisch = result.critical_count()
        hoch = result.high_count()
        mittel = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
        trenner = f"<span style='color: {c.TEXT_DIM};'> \u00b7 </span>"
        self._kpi_label.setText(
            f"<span style='color: {_SEV_COLORS[Severity.CRITICAL]};'>"
            f"{kritisch} kritisch</span>"
            f"{trenner}"
            f"<span style='color: {_SEV_COLORS[Severity.HIGH]};'>{hoch} hoch</span>"
            f"{trenner}"
            f"<span style='color: {_SEV_COLORS[Severity.MEDIUM]};'>{mittel} mittel</span>"
        )

    def _build_verlauf_tab(self) -> QWidget:
        """Erstellt den Verlaufs-Tab mit Trend, Liste und Aktions-Buttons."""
        c = theme
        tab = QWidget()
        root = QVBoxLayout(tab)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # URL-Filter + Refresh
        filter_row = QHBoxLayout()
        filter_row.addWidget(
            QLabel(
                "URL-Filter:", styleSheet=f"color: {c.TEXT_MAIN}; font-weight: bold;"
            )
        )
        self._url_filter = QComboBox()
        self._url_filter.addItem("Alle URLs")
        self._url_filter.setMinimumWidth(300)
        self._url_filter.currentTextChanged.connect(self._on_url_filter_changed)
        filter_row.addWidget(self._url_filter, stretch=1)

        refresh_btn = QPushButton("Aktualisieren")
        refresh_btn.setIcon(get_icon(Icons.REFRESH))
        refresh_btn.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 12px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; padding-top: 6px; padding-bottom: 4px; }}"
        )
        refresh_btn.clicked.connect(self._aktualisiere_verlauf)
        filter_row.addWidget(refresh_btn)
        root.addLayout(filter_row)

        # Trend-Balken
        trend_label = QLabel(
            "\u2500\u2500\u2500 Trend (letzte 10 Scans) \u2500\u2500\u2500"
        )
        trend_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        root.addWidget(trend_label)

        self._trend_widget = _TrendWidget()
        self._trend_widget.setStyleSheet(
            f"background: {c.CARD_BG}; border-radius: 4px;"
        )
        root.addWidget(self._trend_widget)

        # Scan-Liste
        list_label = QLabel("\u2500\u2500\u2500 Scan-Liste \u2500\u2500\u2500")
        list_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 13px;")
        root.addWidget(list_label)

        self._verlauf_tree = QTreeWidget()
        self._verlauf_tree.setHeaderLabels(
            ["Datum", "URL", "K", "H", "M", "N", "I", "Findings", "Dauer"]
        )
        _verlauf_hdr = self._verlauf_tree.header()
        _verlauf_hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        _verlauf_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for _col in range(2, 7):
            _verlauf_hdr.setSectionResizeMode(
                _col, QHeaderView.ResizeMode.ResizeToContents
            )
        _verlauf_hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        _verlauf_hdr.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        self._verlauf_tree.setStyleSheet(
            f"background: {c.CARD_BG}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.BORDER};"
            f"QHeaderView::section {{ border-right: 1px solid {c.BORDER}; }}"
        )
        _header_tooltips = {
            2: "Kritisch — Schweregrad Critical",
            3: "Hoch — Schweregrad High",
            4: "Mittel — Schweregrad Medium",
            5: "Niedrig — Schweregrad Low",
            6: "Info — Informational",
        }
        for _col, _tip in _header_tooltips.items():
            self._verlauf_tree.headerItem().setToolTip(_col, _tip)
        self._verlauf_tree.itemSelectionChanged.connect(
            self._on_verlauf_selection_changed
        )
        root.addWidget(self._verlauf_tree, stretch=1)

        # Aktions-Buttons
        btn_row = QHBoxLayout()
        _normal_btn = (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )
        self._details_btn = QPushButton("Details")
        self._details_btn.setIcon(get_icon(Icons.INFO))
        self._details_btn.setEnabled(False)
        self._details_btn.setStyleSheet(_normal_btn)
        self._details_btn.clicked.connect(self._on_details_clicked)
        btn_row.addWidget(self._details_btn)

        self._vergleich_btn = QPushButton("Vergleichen")
        self._vergleich_btn.setIcon(get_icon(Icons.BILANZPRUEFUNG))
        self._vergleich_btn.setEnabled(False)
        self._vergleich_btn.setStyleSheet(_normal_btn)
        self._vergleich_btn.clicked.connect(self._on_vergleich_clicked)
        btn_row.addWidget(self._vergleich_btn)

        btn_row.addStretch()

        self._loeschen_btn = QPushButton("Löschen")
        self._loeschen_btn.setIcon(get_icon(Icons.DELETE))
        self._loeschen_btn.setEnabled(False)
        _c = theme
        self._loeschen_btn.setStyleSheet(
            f"QPushButton {{ background: {_c.DANGER}; color: {_c.TEXT_ON_DARK};"
            f" border: 1px solid {_c.DANGER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ border: 2px solid {_c.TEXT_ON_DARK}; }}"
            f"QPushButton:pressed {{ padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {_c.BG_BUTTON_DISABLED};"
            f" color: {_c.TEXT_BUTTON_DISABLED}; border-color: {_c.BORDER}; }}"
        )
        self._loeschen_btn.clicked.connect(self._on_loeschen_clicked)
        btn_row.addWidget(self._loeschen_btn)

        root.addLayout(btn_row)

        # Mehr laden
        self._mehr_btn = QPushButton("Mehr laden …")
        self._mehr_btn.setVisible(False)
        self._mehr_btn.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_DIM};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 12px; font-size: 13px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK}; border-color: {c.ACCENT}; }}"
        )
        self._mehr_btn.clicked.connect(self._lade_mehr)
        root.addWidget(self._mehr_btn)

        # Interner Verlauf-State
        self._verlauf_scans: list[ScanLauf] = []
        self._verlauf_offset = 0
        self._verlauf_page_size = 10

        # Initial laden
        self._aktualisiere_verlauf()

        return tab

    # ------------------------------------------------------------------
    # Slots — Neuer-Scan-Tab
    # ------------------------------------------------------------------

    @Slot()
    def _on_scan_clicked(self) -> None:
        """Startet den Scan-Thread."""
        url = self._url_input.text().strip()
        if not url:
            self._status_label.setText("Bitte eine API-URL eingeben.")
            return

        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url
            self._url_input.setText(url)

        target = ScanTarget(
            url=url,
            auth_type=AuthType.NONE,
            active_checks=self._active_checks_cb.isChecked(),
        )

        self._scan_btn.setEnabled(False)
        self._json_btn.setEnabled(False)
        self._xlsx_btn.setEnabled(False)
        self._pdf_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText(f"Scanne {url} \u2026")
        self._owasp_tree.clear()
        self._findings_tree.clear()
        # AP6 Review-P2: KPI des VORHERIGEN Scans nicht stehen lassen \u2014
        # schlaegt der Folge-Scan fehl, wuerde die alte Zeile sonst Befunde
        # behaupten, die nirgends mehr sichtbar sind.
        self._kpi_label.clear()

        self._scan_thread = _ScanThread(self._service, target)
        self._scan_thread.scan_finished.connect(self._on_scan_finished)
        self._scan_thread.scan_error.connect(self._on_scan_error)
        self._scan_thread.start()

    @Slot(object)
    def _on_scan_finished(self, result: ScanResult) -> None:
        """Empfaengt das ScanResult und aktualisiert die UI."""
        self._result = result
        self._progress.setVisible(False)
        self._scan_btn.setEnabled(True)

        if result.error:
            # AP6: Bei Scan-Fehler nicht auf die Ergebnis-Seite schalten.
            self._status_label.setText(f"Fehler: {result.error}")
            return

        self._populate_owasp_tree(result)
        _populate_findings_tree(self._findings_tree, result.findings_by_severity())

        # AP6: Erst nach erfolgreichem Scan Ergebnis-Seite zeigen
        # (auch bei 0 Findings — die Trees zeigen dann das echte Ergebnis).
        self._update_kpi_label(result)
        self._scan_stack.setCurrentIndex(_STACK_RESULTS)

        self._json_btn.setEnabled(True)
        self._xlsx_btn.setEnabled(True)
        self._pdf_btn.setEnabled(True)

        self._status_label.setText(
            f"Scan abgeschlossen \u2014 {len(result.findings)} Befunde | "
            f"Risikoscore: {result.risk_score()}/100 | "
            f"Dauer: {result.duration_ms} ms | "
            "\u2705 Im Verlauf gespeichert"
        )

        # Verlauf-Tab automatisch aktualisieren
        self._aktualisiere_verlauf()

    @Slot(str)
    def _on_scan_error(self, msg: str) -> None:
        """Zeigt Scan-Fehler in der Statuszeile."""
        self._progress.setVisible(False)
        self._scan_btn.setEnabled(True)
        self._status_label.setText(f"Fehler: {msg}")

    @Slot()
    def _on_export_json(self) -> None:
        """Oeffnet Speicherdialog und exportiert JSON."""
        if self._result:
            export_actions.run_json_export(self._exporter, self._result, self)

    @Slot()
    def _on_export_xlsx(self) -> None:
        """Oeffnet Speicherdialog und exportiert Excel."""
        if self._result:
            export_actions.run_xlsx_export(self._exporter, self._result, self)

    @Slot()
    def _on_export_pdf(self) -> None:
        """Oeffnet Speicherdialog und exportiert PDF."""
        if self._result:
            export_actions.run_pdf_export(self._exporter, self._result, self)

    @Slot(QTreeWidgetItem, int)
    def _on_owasp_selected(self, item: QTreeWidgetItem, _col: int) -> None:
        """Filtert Befundliste auf ausgewaehlte OWASP-Kategorie."""
        if not self._result:
            return
        category_text = item.text(0).split(" \u2013 ")[0].strip()
        try:
            cat = OWASPCategory(category_text)
            filtered = [f for f in self._result.findings if f.owasp == cat]
            _populate_findings_tree(
                self._findings_tree,
                sorted(filtered, key=lambda f: f.severity.sort_order()),
            )
        except ValueError:
            _populate_findings_tree(
                self._findings_tree, self._result.findings_by_severity()
            )

    # ------------------------------------------------------------------
    # Slots — Verlauf-Tab
    # ------------------------------------------------------------------

    @Slot()
    def _aktualisiere_verlauf(self) -> None:
        """Laedt den Scan-Verlauf neu und aktualisiert die UI."""
        self._verlauf_offset = 0
        selected_url = self._url_filter.currentText()
        url_filter = None if selected_url == "Alle URLs" else selected_url

        self._verlauf_scans = self._service.lade_verlauf(
            target_url=url_filter,
            limit=self._verlauf_page_size,
        )

        # URL-Filter befuellen (nur einmal beim ersten Laden aller URLs)
        alle_urls = self._service.lade_alle_gescannten_urls()
        current = self._url_filter.currentText()
        self._url_filter.blockSignals(True)
        self._url_filter.clear()
        self._url_filter.addItem("Alle URLs")
        for u in alle_urls:
            self._url_filter.addItem(u)
        idx = self._url_filter.findText(current)
        self._url_filter.setCurrentIndex(max(0, idx))
        self._url_filter.blockSignals(False)

        self._populate_verlauf_list(self._verlauf_scans)
        self._trend_widget.update_scans(self._verlauf_scans)
        self._mehr_btn.setVisible(len(self._verlauf_scans) >= self._verlauf_page_size)

    @Slot(str)
    def _on_url_filter_changed(self, _text: str) -> None:
        """Reagiert auf URL-Filter-Aenderung."""
        self._aktualisiere_verlauf()

    @Slot()
    def _on_verlauf_selection_changed(self) -> None:
        """Aktiviert/deaktiviert Aktions-Buttons je nach Auswahl."""
        items = self._verlauf_tree.selectedItems()
        count = len(items)
        self._details_btn.setEnabled(count == 1)
        self._loeschen_btn.setEnabled(count == 1)
        self._vergleich_btn.setEnabled(count == 2)  # noqa: PLR2004

    @Slot()
    def _on_details_clicked(self) -> None:
        """Oeffnet Detail-Dialog fuer den ausgewaehlten Scan."""
        items = self._verlauf_tree.selectedItems()
        if len(items) != 1:
            return
        lauf_id = items[0].data(0, Qt.ItemDataRole.UserRole)
        lauf = self._service.lade_lauf_details(lauf_id)
        if lauf is None:
            FinlaiInfoDialog(
                title="Fehler",
                message="Scan nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        dlg = _ScanDetailDialog(lauf, self)
        dlg.exec()

    @Slot()
    def _on_vergleich_clicked(self) -> None:
        """Vergleicht zwei ausgewaehlte Scans."""
        items = self._verlauf_tree.selectedItems()
        if len(items) != 2:  # noqa: PLR2004
            return

        # Scans laden (mit Findings)
        lauf_a = self._service.lade_lauf_details(
            items[0].data(0, Qt.ItemDataRole.UserRole)
        )
        lauf_b = self._service.lade_lauf_details(
            items[1].data(0, Qt.ItemDataRole.UserRole)
        )
        if lauf_a is None or lauf_b is None:
            FinlaiInfoDialog(
                title="Fehler",
                message="Scan(s) nicht gefunden.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return

        # Neuerer Scan = aktuell, aelterer = vorherig
        try:
            dt_a = datetime.fromisoformat(lauf_a.scan_start.replace("Z", "+00:00"))
            dt_b = datetime.fromisoformat(lauf_b.scan_start.replace("Z", "+00:00"))
            aktuell, vorherig = (lauf_a, lauf_b) if dt_a >= dt_b else (lauf_b, lauf_a)
        except ValueError:
            aktuell, vorherig = lauf_a, lauf_b

        diff = self._service.vergleiche_scans(aktuell, vorherig)
        dlg = _ScanVergleichDialog(diff, aktuell, vorherig, self)
        dlg.exec()

    @Slot()
    def _on_loeschen_clicked(self) -> None:
        """Loescht den ausgewaehlten Scan nach Bestaetigung."""
        items = self._verlauf_tree.selectedItems()
        if len(items) != 1:
            return
        lauf_id = items[0].data(0, Qt.ItemDataRole.UserRole)
        datum = items[0].text(0)
        url = items[0].text(1)

        dlg = FinlaiConfirmDialog(
            title="Scan loeschen",
            message=f"Scan vom {datum} ({url}) wirklich loeschen?\n"
            "Alle Findings werden dauerhaft entfernt.",
            confirm_text="Loeschen",
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        try:
            self._service.loesche_lauf(lauf_id)
            self._aktualisiere_verlauf()
        except (OSError, RuntimeError) as exc:
            FinlaiInfoDialog(
                title="Fehler beim Loeschen",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()

    @Slot()
    def _lade_mehr(self) -> None:
        """Laedt die naechste Seite des Verlaufs."""
        self._verlauf_offset += self._verlauf_page_size
        selected_url = self._url_filter.currentText()
        url_filter = None if selected_url == "Alle URLs" else selected_url

        weitere = self._service.lade_verlauf(
            target_url=url_filter,
            limit=self._verlauf_page_size + self._verlauf_offset,
        )
        self._verlauf_scans = weitere
        self._populate_verlauf_list(weitere)
        self._trend_widget.update_scans(weitere[:10])
        self._mehr_btn.setVisible(
            len(weitere) >= self._verlauf_page_size + self._verlauf_offset
        )

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    def _populate_verlauf_list(self, scans: list[ScanLauf]) -> None:
        """Befuellt die Verlauf-Tabelle."""
        self._verlauf_tree.clear()
        c = theme

        for scan in scans:
            k = scan.severity_summary.get(Severity.CRITICAL.value, 0)
            h = scan.severity_summary.get(Severity.HIGH.value, 0)
            m = scan.severity_summary.get(Severity.MEDIUM.value, 0)
            n = scan.severity_summary.get(Severity.LOW.value, 0)
            i = scan.severity_summary.get(Severity.INFO.value, 0)
            dauer = f"{scan.dauer_sekunden():.1f}s"

            item = QTreeWidgetItem(
                [
                    _format_dt(scan.scan_start),
                    scan.target_url,
                    str(k) if k else "–",
                    str(h) if h else "–",
                    str(m) if m else "–",
                    str(n) if n else "–",
                    str(i) if i else "–",
                    str(scan.findings_count),
                    dauer,
                ]
            )
            # UUID als UserRole fuer Detail-Abruf
            item.setData(0, Qt.ItemDataRole.UserRole, scan.id)

            # Farbe nach schlimmstem Schweregrad
            color = _worst_sev_color(scan.severity_summary)
            for col in range(9):
                item.setForeground(col, QColor(color if col < 7 else c.TEXT_MAIN))

            # Kritisch/Hoch faerben
            if k:
                item.setForeground(2, QColor(_SEV_COLORS[Severity.CRITICAL]))
            if h:
                item.setForeground(3, QColor(_SEV_COLORS[Severity.HIGH]))

            self._verlauf_tree.addTopLevelItem(item)

        # Buttons zuruecksetzen
        self._details_btn.setEnabled(False)
        self._vergleich_btn.setEnabled(False)
        self._loeschen_btn.setEnabled(False)

    def _populate_owasp_tree(self, result: ScanResult) -> None:
        """Befuellt den OWASP-Uebersichtsbaum."""
        self._owasp_tree.clear()
        by_owasp = result.findings_by_owasp()

        all_item = QTreeWidgetItem(["Alle", str(len(result.findings))])
        all_item.setForeground(0, QColor(theme.ACCENT))
        all_item.setForeground(1, QColor(theme.ACCENT))
        self._owasp_tree.addTopLevelItem(all_item)

        for cat in OWASPCategory:
            findings = by_owasp.get(cat, [])
            label = f"{cat.value} \u2013 {cat.description()}"
            count_str = str(len(findings)) if findings else "\u2013"
            item = QTreeWidgetItem([label, count_str])
            if findings:
                worst = min(findings, key=lambda f: f.severity.sort_order())
                color = _SEV_COLORS.get(worst.severity, theme.TEXT_MAIN)
                item.setForeground(0, QColor(color))
                item.setForeground(1, QColor(color))
            else:
                item.setForeground(0, QColor(theme.TEXT_DIM))
                item.setForeground(1, QColor(theme.TEXT_DIM))
            self._owasp_tree.addTopLevelItem(item)
