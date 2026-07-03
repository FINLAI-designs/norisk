"""cert_monitor_widget — GUI für den SSL/TLS-Zertifikats-Monitor.

Überwacht mehrere Domains auf Zertifikats-Ablauf, TLS-Version und
Cipher-Stärke. Scan läuft in QThread (UI blockiert nicht).

Schichtzugehörigkeit: gui/ — keine Geschäftslogik, nur UI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.export import export_actions
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.widgets.empty_state import EmptyState
from core.widgets.finlai_progress import FinlaiProgressBar
from core.widgets.tool_page import ToolPage
from tools.cert_monitor.application.cert_exporter import CertExporter
from tools.cert_monitor.application.cert_monitor_service import CertMonitorService
from tools.cert_monitor.domain.models import CertInfo, CertStatus

# ---------------------------------------------------------------------------
# Status-Farben und Icons
# ---------------------------------------------------------------------------

_STATUS_FARBE: dict[CertStatus, str] = {
    CertStatus.OK: theme.SEVERITY_SIGNAL_OK,
    CertStatus.WARNUNG: theme.SEVERITY_SIGNAL_MEDIUM,
    CertStatus.KRITISCH: theme.SEVERITY_SIGNAL_CRITICAL,
    CertStatus.FEHLER: theme.SEVERITY_SIGNAL_INFO,
    CertStatus.UNBEKANNT: "#606070",  # noqa: domain-cert-status-unknown — sichtbar dunkler als SEVERITY_SIGNAL_INFO
}

_STATUS_ICON: dict[CertStatus, str] = {
    CertStatus.OK: Icons.CHECK_CIRCLE,
    CertStatus.WARNUNG: Icons.WARNING,
    CertStatus.KRITISCH: Icons.ERROR,
    CertStatus.FEHLER: Icons.WARNING,
    CertStatus.UNBEKANNT: Icons.INFO,
}

_STATUS_LABEL: dict[CertStatus, str] = {
    CertStatus.OK: "OK",
    CertStatus.WARNUNG: "Warnung",
    CertStatus.KRITISCH: "Kritisch",
    CertStatus.FEHLER: "Fehler",
    CertStatus.UNBEKANNT: "Unbekannt",
}


# ---------------------------------------------------------------------------
# Worker-Thread
# ---------------------------------------------------------------------------


class _ScanWorker(QObject):
    """Führt Zertifikats-Scans im Hintergrund aus."""

    fortschritt = Signal(int, int, str)  # (current, total, domain)
    ergebnis = Signal(object)  # CertInfo
    alle_fertig = Signal(list)  # list[CertInfo]
    fehler = Signal(str)

    def __init__(
        self,
        service: CertMonitorService,
        domains: list[tuple[str, int]] | None = None,
    ) -> None:
        super().__init__()
        self._service = service
        self._domains = domains  # None = alle scannen

    @Slot()
    def run(self) -> None:
        """Führt die Scans aus."""
        try:
            ergebnisse = self._service.scanne_alle(
                progress_callback=lambda c, t, d: self.fortschritt.emit(c, t, d)
            )
            self.alle_fertig.emit(ergebnisse)
        except Exception as exc:
            self.fehler.emit(str(exc))


# ---------------------------------------------------------------------------
# KPI-Kachel (Hero-Strip)
# ---------------------------------------------------------------------------


class _CertKpiTile(QFrame):
    """Kompakte KPI-Kachel für die Zertifikats-Übersicht.

    Großer Zahlenwert + Titel mit farbiger Akzentlinie links. Rein
    darstellend — keine Geschäftslogik. Die Bedeutung wird über Titel
    (Text) UND Farbe vermittelt (WCAG SC 1.4.1, nicht nur Farbe).
    """

    def __init__(
        self, title: str, accent: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        c = theme.get()
        self.setObjectName("certKpiTile")
        self.setAccessibleName(title)
        # Mindesthoehe statt fixer Hoehe: die Kachel darf mit dem Strip
        # mitwachsen, statt Schrift/Abstaende einzuklemmen (Patrick-Live-Test
        # 2026-06-25, D4 — vorher fix 72px + 24px-Wert wirkte gedraengt).
        self.setMinimumHeight(88)
        self.setMinimumWidth(150)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.setStyleSheet(
            f"#certKpiTile {{ background: {c.BG_INPUT}; border: 1px solid {c.BORDER};"
            f" border-left: 3px solid {accent}; border-radius: 4px; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)

        self._value_lbl = QLabel("—")
        self._value_lbl.setStyleSheet(
            f"color: {accent}; font-family: 'Raleway'; font-size: 30px;"
            f" font-weight: bold; background: transparent; border: none;"
        )
        lay.addWidget(self._value_lbl)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
            f" background: transparent; border: none;"
        )
        lay.addWidget(title_lbl)

    def set_value(self, text: str) -> None:
        """Setzt den angezeigten Zahlenwert."""
        self._value_lbl.setText(text)


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class CertMonitorWidget(QWidget):
    """Haupt-Widget des SSL/TLS-Zertifikats-Monitors."""

    def __init__(
        self,
        service: CertMonitorService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._thread: QThread | None = None
        self._worker: _ScanWorker | None = None
        self._certs: list[CertInfo] = []
        self._exporter = CertExporter()
        self._build_ui()
        self._lade_gespeicherte_ergebnisse()
        theme.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    # Cross-Tool-Deep-Link (Sprint S3d)
    # ------------------------------------------------------------------

    def apply_navigation(self, **kwargs: object) -> None:
        """Empfangs-Pattern fuer ``MainWindow.navigate_to(..., domain=...)``.

        Erkannte kwargs:
            ``domain`` -- Domain ins Eingabefeld vorausfuellen.

        Andere kwargs werden ignoriert (forward-kompatibel).
        """
        domain = kwargs.get("domain")
        if domain is None:
            return
        text = str(domain).strip()
        if not text:
            return
        self._domain_input.setText(text)
        self._domain_input.setFocus()

    # ------------------------------------------------------------------
    # D2 — leichter Quer-Link auf das verwandte Werkzeug
    # ------------------------------------------------------------------
    def _build_verwandt_zeile(self) -> QWidget:
        """Dezente „Verwandt:"-Zeile mit Sprung zur API-Security (D2).

        Returns:
            Ein schlankes Widget mit einem klickbaren Link-Label.
        """
        c = theme.get()
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        link = QLabel(
            f"Verwandt: <a href='#' style='color:{c.ACCENT}; "
            "text-decoration:none;'>API-Security &rarr;</a>"
        )
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setToolTip("API-Security-Scanner öffnen (verwandtes Werkzeug)")
        link.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        link.linkActivated.connect(self._open_api_security)
        layout.addWidget(link)
        layout.addStretch()
        return row

    @Slot()
    def _open_api_security(self) -> None:
        """Springt ins ``api_security``-Tool (D2). Graceful, nie crashend."""
        window = self.window()
        navigate = getattr(window, "navigate_to", None)
        if not callable(navigate):
            return
        try:
            navigate("api_security")
        except Exception:  # noqa: BLE001 -- Navigation darf nie crashen
            pass

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        """Erstellt die gesamte Oberfläche."""
        c = theme.get()
        # Kopf (Titel + Akzentlinie + HelpPanel) via ToolPage AP7).
        # Die früheren expliziten addSpacing-Aufrufe ersetzt das body-
        # Spacing (8px) — versteckte Widgets (Progress) lassen so keine
        # Leerlücke mehr zurück.
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        page = ToolPage("Zertifikats-Monitor", help_key="cert_monitor")
        root.addWidget(page)

        # D2 (leichter Quer-Link, KEIN Merge): dezenter Hinweis auf das
        # verwandte Werkzeug. Beide Tools prüfen Endpunkt-Sicherheit aus
        # unterschiedlichen Blickwinkeln (TLS-Zertifikat vs. API-Härtung).
        page.body.addWidget(self._build_verwandt_zeile())

        # Domain-Hinzufügen-Zeile
        page.body.addWidget(self._build_eingabe_zeile())

        # Aktions-Leiste
        page.body.addWidget(self._build_aktions_leiste())

        # KPI-Übersicht: zeigt den Wert sofort beim Öffnen, auch ohne neuen
        # Scan — der Tab wirkte vorher leer/wertlos bis zum 1. Scan).
        self._kpi_strip = self._build_kpi_strip()
        page.body.addWidget(self._kpi_strip)

        # Fortschritts-Anzeige: kanonischer FinlaiProgressBar)
        self._progress = FinlaiProgressBar()
        self._progress.setVisible(False)
        page.body.addWidget(self._progress)

        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-family: 'Raleway';"
        )
        page.body.addWidget(self._lbl_status)

        # Splitter: Tabelle oben (Primärfläche), Details unten. Das Detail-
        # Panel startet eingeklappt und öffnet erst bei Zeilen-Selektion —
        # keine fixe Leerreserve mehr AP5c, Muster R4).
        self._splitter = QSplitter(Qt.Orientation.Vertical)
        self._splitter.addWidget(self._build_tabelle())
        self._splitter.addWidget(self._build_details_panel())
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 0)
        self._splitter.setSizes([1, 0])
        page.body.addWidget(self._splitter, stretch=1)

    def _build_eingabe_zeile(self) -> QWidget:
        """Eingabezeile zum Hinzufügen einer neuen Domain."""
        c = theme.get()
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText(
            "Domain eingeben (z.B. example.at oder example.at:8443)"
        )
        self._domain_input.setFixedHeight(34)
        self._domain_input.setStyleSheet(
            f"QLineEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px;"
            f" font-family: 'Raleway'; }}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
        )
        self._domain_input.returnPressed.connect(self._on_hinzufuegen)
        layout.addWidget(self._domain_input, stretch=1)

        _tip_domain = self._help_tip("input_domain")
        if _tip_domain:
            layout.addWidget(HelpButton(_tip_domain))

        _btn_style = (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )
        self._btn_hinzu = QPushButton("Hinzufügen")
        self._btn_hinzu.setIcon(get_icon(Icons.ADD))
        self._btn_hinzu.setFixedHeight(34)
        self._btn_hinzu.setStyleSheet(_btn_style)
        self._btn_hinzu.clicked.connect(self._on_hinzufuegen)
        layout.addWidget(self._btn_hinzu)
        return row

    def _build_aktions_leiste(self) -> QWidget:
        """Aktions-Leiste mit Scan-Button und Löschen."""
        c = theme.get()
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        _btn_style = (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )

        self._btn_scan_alle = QPushButton("Alle prüfen")
        self._btn_scan_alle.setIcon(get_icon(Icons.CERTIFICATE))
        self._btn_scan_alle.setFixedHeight(34)
        self._btn_scan_alle.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK}; font-weight: bold;"
            f" border: none; border-radius: 4px; padding: 5px 14px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DARK}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK};"
            f" padding-top: 6px; padding-bottom: 4px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; }}"
        )
        self._btn_scan_alle.clicked.connect(self._on_scan_alle)
        layout.addWidget(self._btn_scan_alle)

        layout.addStretch()

        self._btn_loeschen = QPushButton("Ausgewählte löschen")
        self._btn_loeschen.setIcon(get_icon(Icons.DELETE))
        self._btn_loeschen.setEnabled(False)
        self._btn_loeschen.setFixedHeight(34)
        # noqa: delete-button-palette — bewusst dunklere Rotabstufungen als
        # SEVERITY_SIGNAL_CRITICAL (#ff4444), passend zu Edit/Delete-Button-Pattern.
        # Vereinheitlichung in Sprint 2 zusammen mit admin_panel-Delete-Buttons.
        self._btn_loeschen.setStyleSheet(
            "QPushButton { background: #8b1a1a; color: #fff; border: 1px solid #cc2222;"  # noqa: delete-button-palette
            " border-radius: 4px; padding: 5px 14px; }"
            f"QPushButton:hover {{ background: #cc2222; border-color: {theme.SEVERITY_SIGNAL_CRITICAL}; }}"  # noqa: delete-button-palette
            "QPushButton:pressed { background: #aa1111; padding-top: 6px; padding-bottom: 4px; }"  # noqa: delete-button-palette
            "QPushButton:disabled { background: #3a1a1a; color: #555; border-color: #3a1a1a; }"  # noqa: delete-button-palette
        )
        self._btn_loeschen.clicked.connect(self._on_loeschen)
        layout.addWidget(self._btn_loeschen)

        # Export-Buttons
        self._btn_export_json = QPushButton("JSON")
        self._btn_export_json.setIcon(get_icon(Icons.DATA_OBJECT))
        self._btn_export_json.setToolTip("Als JSON exportieren")
        self._btn_export_json.setEnabled(False)
        self._btn_export_json.setFixedHeight(34)
        self._btn_export_json.setStyleSheet(_btn_style)
        self._btn_export_json.clicked.connect(self._on_export_json)
        layout.addWidget(self._btn_export_json)

        self._btn_export_xlsx = QPushButton("Excel")
        self._btn_export_xlsx.setIcon(get_icon(Icons.TABLE_VIEW))
        self._btn_export_xlsx.setToolTip("Als Excel-Datei exportieren")
        self._btn_export_xlsx.setEnabled(False)
        self._btn_export_xlsx.setFixedHeight(34)
        self._btn_export_xlsx.setStyleSheet(_btn_style)
        self._btn_export_xlsx.clicked.connect(self._on_export_xlsx)
        layout.addWidget(self._btn_export_xlsx)

        self._btn_export_pdf = QPushButton("PDF")
        self._btn_export_pdf.setIcon(get_icon(Icons.PDF))
        self._btn_export_pdf.setToolTip("Als PDF-Report exportieren")
        self._btn_export_pdf.setEnabled(False)
        self._btn_export_pdf.setFixedHeight(34)
        self._btn_export_pdf.setStyleSheet(_btn_style)
        self._btn_export_pdf.clicked.connect(self._on_export_pdf)
        layout.addWidget(self._btn_export_pdf)

        return row

    def _build_kpi_strip(self) -> QWidget:
        """Baut den KPI-Übersichts-Strip oberhalb der Tabelle.

        Zeigt die Zahl der überwachten Domains und die Verteilung nach
        Status (kritisch/Warnung/OK), damit der Wert ohne neuen Scan sofort
        sichtbar ist. Rein darstellend.
        """
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self._tile_gesamt = _CertKpiTile("Überwacht", theme.get().ACCENT)
        self._tile_kritisch = _CertKpiTile("Kritisch", theme.SEVERITY_SIGNAL_CRITICAL)
        self._tile_warnung = _CertKpiTile("Warnung", theme.SEVERITY_SIGNAL_MEDIUM)
        self._tile_ok = _CertKpiTile("OK", theme.SEVERITY_SIGNAL_OK)
        # Kacheln fuellen die Strip-Breite gleichmaessig (stretch=1) statt links
        # gedraengt mit toter Flaeche rechts (Patrick-Live-Test 2026-06-25, D4).
        for tile in (
            self._tile_gesamt,
            self._tile_kritisch,
            self._tile_warnung,
            self._tile_ok,
        ):
            layout.addWidget(tile, stretch=1)
        return row

    def _aktualisiere_kpi(self) -> None:
        """Aktualisiert den KPI-Strip aus den aktuellen Ergebnissen."""
        gesamt = len(self._certs)
        self._tile_gesamt.set_value(str(gesamt))
        self._tile_kritisch.set_value(
            str(sum(1 for c in self._certs if c.status == CertStatus.KRITISCH))
        )
        self._tile_warnung.set_value(
            str(sum(1 for c in self._certs if c.status == CertStatus.WARNUNG))
        )
        self._tile_ok.set_value(
            str(sum(1 for c in self._certs if c.status == CertStatus.OK))
        )
        # Bei 0 Domains übernimmt der Empty-State die Erklärung — Strip aus.
        self._kpi_strip.setVisible(gesamt > 0)

    def _build_tabelle(self) -> QWidget:
        """Erstellt die Domain-Übersichts-Tabelle (mit Empty-State)."""
        c = theme.get()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        # Empty-State statt leerem 5-Spalten-Raster AP5c, Muster R3).
        # Wert-erklärender Text + CTA: macht den Nutzen des Tabs auch
        # ohne Daten sofort verständlich.
        self._tabelle_empty_lbl = EmptyState(
            "Noch keine Domain in der Überwachung.\n\n"
            "Der Zertifikats-Monitor prüft deine Webadressen automatisch auf "
            "ablaufende TLS-Zertifikate, selbst-signierte Zertifikate und "
            "schwache Verschlüsselung — damit dir kein Zertifikat unbemerkt "
            "ausläuft.\n\n"
            "Füge oben eine Domain hinzu, z. B. meine-firma.at.",
            cta_text="Domain hinzufügen",
        )
        self._tabelle_empty_lbl.cta_clicked.connect(self._domain_input.setFocus)

        self._tabelle = QTableWidget()
        self._tabelle.setColumnCount(5)
        self._tabelle.setHorizontalHeaderLabels(
            ["Domain", "Gültig bis", "Tage", "TLS", "Status"]
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
        self._tabelle.setColumnWidth(1, 130)
        self._tabelle.setColumnWidth(2, 60)
        self._tabelle.setColumnWidth(3, 80)
        self._tabelle.setColumnWidth(4, 120)
        self._tabelle.setStyleSheet(
            f"QTableWidget {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" gridline-color: {c.BORDER}; border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QTableWidget::item:selected {{ background: {c.ACCENT_DARK}; color: {c.TEXT_MAIN}; }}"
            f"QTableWidget::item:selected:alternate {{ background: {c.ACCENT_DARK}; color: {c.TEXT_MAIN}; }}"
            f"QHeaderView::section {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: none; border-bottom: 1px solid {c.ACCENT_LINE}; padding: 4px 8px; }}"
            f"QTableWidget::item:alternate {{ background: {c.BG_DARK}; }}"
        )
        self._tabelle.selectionModel().selectionChanged.connect(self._on_auswahl)

        self._tabelle_stack = QStackedWidget()
        self._tabelle_stack.addWidget(self._tabelle_empty_lbl)  # Index 0
        self._tabelle_stack.addWidget(self._tabelle)  # Index 1
        layout.addWidget(self._tabelle_stack)
        return container

    def _build_details_panel(self) -> QWidget:
        """Erstellt das Detail-Panel für die ausgewählte Domain."""
        c = theme.get()
        container = QWidget()
        container.setStyleSheet(
            f"background: {c.BG_INPUT}; border: 1px solid {c.BORDER}; border-radius: 4px;"
        )
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        hdr_row = QHBoxLayout()
        hdr_row.setContentsMargins(0, 0, 0, 0)
        hdr = QLabel("Details")
        hdr.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 12px; font-weight: bold;"
            f" background: transparent; border: none;"
        )
        hdr_row.addWidget(hdr)
        _tip_expiry = self._help_tip("result_expiry")
        if _tip_expiry:
            hdr_row.addWidget(HelpButton(_tip_expiry))
        hdr_row.addStretch()
        layout.addLayout(hdr_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self._details_inner = QWidget()
        self._details_inner.setStyleSheet("background: transparent;")
        self._details_layout = QVBoxLayout(self._details_inner)
        self._details_layout.setContentsMargins(0, 0, 0, 0)
        self._details_layout.setSpacing(2)
        self._details_layout.addStretch()
        scroll.setWidget(self._details_inner)
        layout.addWidget(scroll)
        return container

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("cert_monitor")
        return hc.tooltips.get(key, "") if hc else ""

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert Farben bei Theme-Wechsel."""
        layout = self.layout()
        if layout is not None:
            QWidget().setLayout(layout)
        self._thread = None
        self._worker = None
        self._build_ui()
        self._aktualisiere_tabelle()

    # ------------------------------------------------------------------
    def _lade_gespeicherte_ergebnisse(self) -> None:
        """Lädt gespeicherte Scan-Ergebnisse aus der DB."""
        try:
            self._certs = self._service.lade_letzte_ergebnisse()
        except Exception:  # noqa: BLE001
            self._certs = []
        self._aktualisiere_tabelle()
        has_data = bool(self._certs)
        self._btn_export_json.setEnabled(has_data)
        self._btn_export_xlsx.setEnabled(has_data)
        self._btn_export_pdf.setEnabled(has_data)

    def _aktualisiere_tabelle(self) -> None:
        """Füllt die Tabelle mit den aktuellen Scan-Ergebnissen."""
        # Domains ohne Ergebnisse auch anzeigen
        domain_mit_ergebnis = {(c.domain, c.port) for c in self._certs}
        alle_domains = self._service.lade_domains()

        # Domains ohne Scan-Ergebnis als leere CertInfo einfügen
        for domain, port in alle_domains:
            if (domain, port) not in domain_mit_ergebnis:
                self._certs.append(CertInfo(domain=domain, port=port))

        # Empty-State ↔ Tabelle AP5c)
        self._tabelle_stack.setCurrentWidget(
            self._tabelle if self._certs else self._tabelle_empty_lbl
        )

        self._tabelle.setRowCount(len(self._certs))
        for row, cert in enumerate(self._certs):
            farbe = _STATUS_FARBE.get(cert.status, theme.SEVERITY_SIGNAL_INFO)
            label = _STATUS_LABEL.get(cert.status, "—")

            if cert.gueltig_bis:
                # ssl.getpeercert liefert "Oct 8 23:59:59 2025 GMT" (kein ISO-Format).
                # Mehrere Formate probieren für robuste Darstellung.
                from datetime import datetime as _dt  # noqa: PLC0415

                gueltig_bis_anzeige = cert.gueltig_bis  # Fallback: Rohstring
                for _fmt in (
                    "%b %d %H:%M:%S %Y %Z",  # "Oct 8 23:59:59 2025 GMT"
                    "%b  %d %H:%M:%S %Y %Z",  # doppeltes Leerzeichen bei einst. Tag
                    "%Y-%m-%d %H:%M:%S",  # ISO ohne TZ
                    "%Y-%m-%dT%H:%M:%S",  # ISO mit T-Trenner
                    "%Y-%m-%d",  # nur Datum
                ):
                    try:
                        _d = _dt.strptime(cert.gueltig_bis, _fmt)
                        gueltig_bis_anzeige = _d.strftime("%d.%m.%Y")
                        break
                    except ValueError:
                        continue
            else:
                gueltig_bis_anzeige = "—"

            items = [
                cert.anzeige_domain,
                gueltig_bis_anzeige,
                str(cert.tage_verbleibend) if cert.gueltig_bis else "—",
                cert.tls_version or "—",
                label,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setForeground(
                    __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(farbe)
                    if col == 4
                    else __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(
                        theme.get().TEXT_MAIN
                    )
                )
                self._tabelle.setItem(row, col, item)

        self._aktualisiere_kpi()

    # ------------------------------------------------------------------
    def _on_hinzufuegen(self) -> None:
        """Fügt die eingegebene Domain zur Überwachungsliste hinzu."""
        text = self._domain_input.text().strip()
        if not text:
            return

        domain = text
        port = 443
        if ":" in text.split("/")[-1]:
            parts = text.rsplit(":", 1)
            try:
                port = int(parts[1])
                domain = parts[0]
            except ValueError:
                pass

        try:
            self._service.domain_hinzufuegen(domain, port)
            self._domain_input.clear()
            self._lade_gespeicherte_ergebnisse()
        except Exception as exc:
            self._lbl_status.setText(f"Fehler: {exc}")

    def _on_scan_alle(self) -> None:
        """Startet den Scan aller Domains im Hintergrund."""
        if self._thread and self._thread.isRunning():
            return

        self._btn_scan_alle.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)  # Unbestimmt zu Beginn

        self._thread = QThread(self)
        self._worker = _ScanWorker(self._service)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.fortschritt.connect(self._on_fortschritt)
        self._worker.alle_fertig.connect(self._on_scan_fertig)
        self._worker.fehler.connect(self._on_scan_fehler)
        self._worker.alle_fertig.connect(self._thread.quit)
        self._worker.fehler.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start()

    @Slot(int, int, str)
    def _on_fortschritt(self, current: int, total: int, domain: str) -> None:
        """Aktualisiert den Fortschritts-Balken."""
        if total > 0:
            self._progress.setRange(0, total)
            self._progress.setValue(current)
        self._lbl_status.setText(f"Prüfe: {domain}" if domain else "")

    @Slot(list)
    def _on_scan_fertig(self, certs: list[CertInfo]) -> None:
        """Aktualisiert die Tabelle nach abgeschlossenem Scan."""
        self._certs = certs
        self._aktualisiere_tabelle()
        self._progress.setVisible(False)
        self._btn_scan_alle.setEnabled(True)
        has_data = bool(certs)
        self._btn_export_json.setEnabled(has_data)
        self._btn_export_xlsx.setEnabled(has_data)
        self._btn_export_pdf.setEnabled(has_data)
        kritisch = sum(1 for c in certs if c.status == CertStatus.KRITISCH)
        self._lbl_status.setText(
            f"Scan abgeschlossen — {len(certs)} Domains, {kritisch} kritisch"
        )

    @Slot(str)
    def _on_scan_fehler(self, msg: str) -> None:
        """Zeigt Scan-Fehler an."""
        self._progress.setVisible(False)
        self._btn_scan_alle.setEnabled(True)
        self._lbl_status.setText(f"Fehler beim Scan: {msg}")

    def _on_auswahl(self) -> None:
        """Zeigt Details der ausgewählten Zeile im Detail-Panel.

        Das Detail-Panel klappt erst bei Selektion auf und bei leerer
        Selektion wieder zu AP5c) — die Tabelle behält sonst die
        volle Höhe.
        """
        rows = self._tabelle.selectionModel().selectedRows()
        self._btn_loeschen.setEnabled(bool(rows))
        if not rows:
            self._splitter.setSizes([1, 0])
            return
        row = rows[0].row()
        if row < len(self._certs):
            self._zeige_details(self._certs[row])
            if self._splitter.sizes()[1] == 0:
                total = sum(self._splitter.sizes())
                if total < 100:
                    # Vor dem ersten Layout liefert sizes nur Platzhalter —
                    # dann mit sinnvollen Default-Höhen öffnen.
                    self._splitter.setSizes([350, 200])
                else:
                    self._splitter.setSizes([(total * 2) // 3, total // 3])

    def _on_loeschen(self) -> None:
        """Löscht die ausgewählte Domain."""
        rows = self._tabelle.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row < len(self._certs):
            cert = self._certs[row]
            self._service.domain_entfernen(cert.domain, cert.port)
            self._certs.pop(row)
            self._aktualisiere_tabelle()
            self._btn_loeschen.setEnabled(False)

    def _zeige_details(self, cert: CertInfo) -> None:
        """Befüllt das Detail-Panel mit Zertifikatsdaten."""
        c = theme.get()
        # Layout leeren
        while self._details_layout.count() > 1:
            item = self._details_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        def detail_zeile(label: str, wert: str) -> None:
            zeile = QLabel(f"<b>{label}:</b> {wert}")
            zeile.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
                f" background: transparent; border: none;"
            )
            zeile.setTextFormat(Qt.TextFormat.RichText)
            zeile.setWordWrap(True)
            self._details_layout.insertWidget(self._details_layout.count() - 1, zeile)

        detail_zeile("Domain", cert.anzeige_domain)
        if cert.aussteller:
            detail_zeile("Aussteller", cert.aussteller)
        if cert.gueltig_von:
            detail_zeile("Gültig von", cert.gueltig_von[:10])
        if cert.gueltig_bis:
            detail_zeile("Gültig bis", cert.gueltig_bis[:10])
        if cert.tls_version:
            detail_zeile("TLS-Version", cert.tls_version)
        if cert.cipher_name:
            detail_zeile("Cipher", f"{cert.cipher_name} ({cert.cipher_bits} Bit)")
        if cert.san_domains:
            detail_zeile("SAN", ", ".join(cert.san_domains[:5]))
        if cert.ist_self_signed:
            detail_zeile("Self-Signed", "Ja")
        if cert.fehler_meldung:
            detail_zeile("Fehler", cert.fehler_meldung)

        if cert.findings:
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet(f"background: {c.BORDER}; border: none;")
            self._details_layout.insertWidget(self._details_layout.count() - 1, sep)
            for finding in cert.findings:
                lbl = QLabel(finding)
                lbl.setStyleSheet(
                    f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
                    f" padding-left: 4px; background: transparent; border: none;"
                )
                lbl.setWordWrap(True)
                self._details_layout.insertWidget(self._details_layout.count() - 1, lbl)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @Slot()
    def _on_export_json(self) -> None:
        """Exportiert alle Zertifikate als JSON."""
        if self._certs:
            export_actions.run_json_export(self._exporter, self._certs, self)

    @Slot()
    def _on_export_xlsx(self) -> None:
        """Exportiert alle Zertifikate als Excel-Datei."""
        if self._certs:
            export_actions.run_xlsx_export(self._exporter, self._certs, self)

    @Slot()
    def _on_export_pdf(self) -> None:
        """Exportiert alle Zertifikate als PDF-Report."""
        if self._certs:
            export_actions.run_pdf_export(self._exporter, self._certs, self)
