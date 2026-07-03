"""
techstack_widget — Tech-Stack Monitoring als eigenständiges Tool-Widget.

Zeigt persönlichen Tech-Stack, ermöglicht Hinzufügen/Entfernen von Produkten
und startet CVE-Suche für alle aktiven Stack-Einträge via NVD API.

Zuvor als Tab 4 in:mod:`tools.cyber_dashboard.gui.dashboard_widget`; seit
2026-04-20 als self-contained Sidebar-Tool ausgegliedert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.logger import get_logger
from core.widgets.button_styles import outline_button_qss
from core.widgets.empty_state import EmptyState
from core.widgets.tool_page import ToolPage
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.domain.models import CveEintrag, TechStackEintrag

_EMPTY_STATE_TEXT = (
    "Dein Techstack ist noch leer. Füge Einträge manuell hinzu oder lade "
    "die Vorschlagsliste für österreichische Steuerkanzleien "
    "(Windows, Office, BMD, ...)."
)
_STARTER_BUTTON_TEXT = "Vorschlagsliste für österreichische Steuerkanzleien laden"

log = get_logger(__name__)


def _cve_farben() -> dict[str, tuple[str, str]]:
    """Gibt Severity-Farben (bg, text) passend zum aktiven Theme zurück."""
    c = theme.get()
    return {
        "CRITICAL": (c.SEVERITY_CRITICAL_BG, c.SEVERITY_CRITICAL_TEXT),
        "HIGH": (c.SEVERITY_HIGH_BG, c.SEVERITY_HIGH_TEXT),
        "MEDIUM": (c.SEVERITY_MEDIUM_BG, c.SEVERITY_MEDIUM_TEXT),
    }


class _StackCveThread(QThread):
    """Sucht CVEs für alle aktiven Tech-Stack-Einträge im Hintergrund.

    Signals:
        ergebnis: Emittiert die gefundenen CVE-Einträge.
        fehler: Emittiert den Exception-Typ, wenn die Suche FEHLSCHLÄGT —
            getrennt vom leeren Ergebnis, damit die GUI keinen falschen
            "Keine CVEs"-Positiv-Befund anzeigt AP5 Review-P2).
    """

    ergebnis: Signal = Signal(list)
    fehler: Signal = Signal(str)

    def __init__(self, service: DashboardService, tage: int = 30) -> None:
        """Initialisiert den Stack-CVE-Thread.

        Args:
            service: DashboardService-Instanz.
            tage: Zeitraum in Tagen für die CVE-Suche.
        """
        super().__init__()
        self._service = service
        self._tage = tage

    def run(self) -> None:
        """Führt die CVE-Suche für den gesamten Tech-Stack aus."""
        try:
            cves = self._service.suche_cves_fuer_stack(tage=self._tage)
            self.ergebnis.emit(cves)
        except Exception as exc:  # noqa: BLE001
            log.error("Stack-CVE-Thread fehlgeschlagen: %s", exc)
            self.fehler.emit(type(exc).__name__)


class TechStackWidget(QWidget):
    """Tech-Stack Monitoring Widget — verwaltet Produkte und sucht zugehörige CVEs.

    Zeigt alle Stack-Einträge, ermöglicht Hinzufügen/Entfernen,
    und startet CVE-Suche für aktive Einträge via NVD API.

    Signals:
        stack_changed: Wird emittiert nach Hinzufügen, Entfernen oder
            Starter-Stack-Import. Konsumenten (z. B. der CSAF-Advisor-
            Tab in Sprint S2c) reagieren mit einem Refresh ihrer
            Advisory-Listen.

    Args:
        service: DashboardService-Instanz.
        parent: Optionales Eltern-Widget.
    """

    # Sprint S2c: Cross-Tab-Refresh-Signal. Bewusst parameterlos —
    # Konsumenten lesen den aktuellen Stack über das Service.
    stack_changed = Signal()

    def __init__(
        self,
        service: DashboardService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Tech-Stack-Widget."""
        super().__init__(parent)
        self._service = service
        self._thread: _StackCveThread | None = None
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()
        self._stack_laden()

    def _build_ui(self) -> None:
        """Erstellt das Widget-Layout."""
        # Kopf (Titel + Akzentlinie + HelpPanel) via ToolPage — vereinheitlicht
        # den zuvor abweichenden 14px-Kopf mit 8px-Rändern AP7).
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        # Referenz behalten: techstack restylt bei apply_theme in-place
        # (kein UI-Rebuild) und muss den Seitenkopf mit-refreshen.
        self._page = ToolPage("Mein Tech-Stack", help_key="techstack")
        root.addWidget(self._page)
        body = self._page.body

        # Stack-Eingabe
        add_layout = QHBoxLayout()
        add_layout.setSpacing(6)

        self._input_name = QLineEdit()
        self._input_name.setPlaceholderText("Produktname (z.B. Apache)")
        add_layout.addWidget(self._input_name)

        self._input_version = QLineEdit()
        self._input_version.setPlaceholderText("Version (optional)")
        self._input_version.setMaximumWidth(120)
        add_layout.addWidget(self._input_version)

        self._input_kategorie = QLineEdit()
        self._input_kategorie.setPlaceholderText("Kategorie (optional)")
        self._input_kategorie.setMaximumWidth(120)
        add_layout.addWidget(self._input_kategorie)

        self._btn_hinzufuegen = QPushButton("+ Hinzufügen")
        self._btn_hinzufuegen.setMinimumHeight(36)
        self._btn_hinzufuegen.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_hinzufuegen.clicked.connect(self._eintrag_hinzufuegen)
        add_layout.addWidget(self._btn_hinzufuegen)

        _tip_add = self._help_tip("btn_add_entry")
        if _tip_add:
            add_layout.addWidget(HelpButton(_tip_add))

        self._btn_entfernen = QPushButton("Entfernen")
        self._btn_entfernen.setMinimumHeight(36)
        self._btn_entfernen.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_entfernen.clicked.connect(self._eintrag_entfernen)
        add_layout.addWidget(self._btn_entfernen)

        body.addLayout(add_layout)

        # Übernahme aus System-Scan + Patch-Monitor (Sync).
        sync_layout = QHBoxLayout()
        self._btn_sync = QPushButton("Aus System-Scan & Patch-Monitor übernehmen")
        self._btn_sync.setMinimumHeight(36)
        self._btn_sync.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_sync.clicked.connect(self._sync_uebernehmen)
        sync_layout.addWidget(
            self._btn_sync, alignment=Qt.AlignmentFlag.AlignLeft
        )
        sync_layout.addStretch()
        body.addLayout(sync_layout)

        # Empty-State-Hinweis + Starter-Button (nur sichtbar bei leerem Stack).
        self._empty_state = QWidget()
        empty_layout = QVBoxLayout(self._empty_state)
        empty_layout.setContentsMargins(0, 0, 0, 0)
        empty_layout.setSpacing(6)

        self._lbl_empty_hint = QLabel(_EMPTY_STATE_TEXT)
        self._lbl_empty_hint.setWordWrap(True)
        self._lbl_empty_hint.setStyleSheet("font-size: 12px;")
        empty_layout.addWidget(self._lbl_empty_hint)

        self._btn_starter = QPushButton(_STARTER_BUTTON_TEXT)
        self._btn_starter.setMinimumHeight(36)
        self._btn_starter.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_starter.clicked.connect(self._starter_stack_laden)
        empty_layout.addWidget(self._btn_starter, alignment=Qt.AlignmentFlag.AlignLeft)

        body.addWidget(self._empty_state)

        # Status-Meldung für Techstack-Aktionen (z.B. Starter-Import).
        self._lbl_stack_status = QLabel("")
        self._lbl_stack_status.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 11px;")
        body.addWidget(self._lbl_stack_status)

        # Stack-Tabelle — Primärfläche, skaliert mit dem Fenster AP5a:
        # der frühere 180px-Deckel quetschte den Stack, während die meist
        # leere CVE-Tabelle die untere Bildschirmhälfte bekam).
        self._stack_tabelle = QTableWidget()
        self._stack_tabelle.setColumnCount(3)
        self._stack_tabelle.setHorizontalHeaderLabels(
            ["Produkt", "Version", "Kategorie"]
        )
        self._stack_tabelle.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._stack_tabelle.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._stack_tabelle.verticalHeader().setVisible(False)

        header = self._stack_tabelle.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        # CVE-Bereich (Button-Zeile + Stacked: Empty-State | Ergebnis-Tabelle)
        cve_pane = QWidget()
        cve_pane_lyt = QVBoxLayout(cve_pane)
        cve_pane_lyt.setContentsMargins(0, 0, 0, 0)
        cve_pane_lyt.setSpacing(8)

        cve_layout = QHBoxLayout()

        self._lbl_cve_status = QLabel("")
        self._lbl_cve_status.setStyleSheet(f"color: {theme.get().TEXT_DIM}; font-size: 11px;")
        cve_layout.addWidget(self._lbl_cve_status)
        cve_layout.addStretch()

        self._btn_cve_suchen = QPushButton("CVEs für meinen Stack laden")
        self._btn_cve_suchen.setMinimumHeight(36)
        self._btn_cve_suchen.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_cve_suchen.clicked.connect(self._cves_laden)
        cve_layout.addWidget(self._btn_cve_suchen)

        _tip_cve = self._help_tip("btn_load_cves")
        if _tip_cve:
            cve_layout.addWidget(HelpButton(_tip_cve))

        cve_pane_lyt.addLayout(cve_layout)

        lbl_cve = QLabel("<b>CVEs für meinen Stack:</b>")
        cve_pane_lyt.addWidget(lbl_cve)

        # Empty-State statt leerem 6-Spalten-Raster AP5a, Muster R3).
        self._cve_empty_lbl = EmptyState(
            "Noch keine CVE-Daten geladen — klicke oben auf\n"
            "„CVEs für meinen Stack laden“."
        )

        self._cve_tabelle = QTableWidget()
        self._cve_tabelle.setColumnCount(6)
        self._cve_tabelle.setHorizontalHeaderLabels(
            ["CVE-ID", "CVSS", "Schweregrad", "Beschreibung", "KEV", "Details"]
        )
        self._cve_tabelle.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._cve_tabelle.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._cve_tabelle.verticalHeader().setVisible(False)
        self._cve_tabelle.setAlternatingRowColors(False)
        self._cve_tabelle.setSortingEnabled(True)

        cve_header = self._cve_tabelle.horizontalHeader()
        cve_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        cve_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        cve_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        cve_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        cve_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        cve_header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        self._cve_stack = QStackedWidget()
        self._cve_stack.addWidget(self._cve_empty_lbl)  # Index 0: Empty-State
        self._cve_stack.addWidget(self._cve_tabelle)  # Index 1: Daten
        cve_pane_lyt.addWidget(self._cve_stack, stretch=1)

        # Vertikaler Splitter Stack ↔ CVEs (3:2) — nutzersteuerbar,
        # beide Flächen skalieren mit dem Fenster AP5a, Muster R4).
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._stack_tabelle)
        splitter.addWidget(cve_pane)
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([300, 200])
        body.addWidget(splitter, stretch=1)

    # ------------------------------------------------------------------
    # Stack-Verwaltung
    # ------------------------------------------------------------------

    def _stack_laden(self) -> None:
        """Lädt den Tech-Stack und befüllt die Tabelle.

        Schaltet den Empty-State (Hinweistext + Starter-Button) ein wenn
        der Stack leer ist, sonst aus.
        """
        stack = self._service.lade_techstack()
        self._stack_tabelle.setRowCount(len(stack))
        for row, eintrag in enumerate(stack):
            self._stack_tabelle.setItem(row, 0, QTableWidgetItem(eintrag.name))
            self._stack_tabelle.setItem(row, 1, QTableWidgetItem(eintrag.version))
            self._stack_tabelle.setItem(row, 2, QTableWidgetItem(eintrag.kategorie))
        self._empty_state.setVisible(len(stack) == 0)

    def _starter_stack_laden(self) -> None:
        """Fügt die AT-Kanzlei-Vorschlagsliste hinzu (nur auf User-Klick).

        Nutzt die bestehende ``techstack_hinzufuegen``-Route pro Eintrag,
        damit die Repository-Dedup-Logik greift und kein bestehender
        Eintrag überschrieben wird.
        """
        starter = self._service.get_at_starter_stack()
        for eintrag in starter:
            self._service.techstack_hinzufuegen(eintrag)
        self._stack_laden()
        self._lbl_stack_status.setText(
            f"{len(starter)} Einträge aus Vorschlagsliste übernommen"
        )
        self.stack_changed.emit()

    def _eintrag_hinzufuegen(self) -> None:
        """Fügt einen neuen Eintrag zum Tech-Stack hinzu."""
        name = self._input_name.text().strip()
        if not name:
            return
        version = self._input_version.text().strip()
        kategorie = self._input_kategorie.text().strip()
        eintrag = TechStackEintrag(name=name, version=version, kategorie=kategorie)
        self._service.techstack_hinzufuegen(eintrag)
        self._input_name.clear()
        self._input_version.clear()
        self._input_kategorie.clear()
        self._stack_laden()
        self.stack_changed.emit()

    def _eintrag_entfernen(self) -> None:
        """Entfernt den ausgewählten Eintrag aus dem Tech-Stack."""
        row = self._stack_tabelle.currentRow()
        if row < 0:
            return
        item = self._stack_tabelle.item(row, 0)
        if item:
            self._service.techstack_entfernen(item.text())
            self._stack_laden()
            self.stack_changed.emit()

    def _sync_uebernehmen(self) -> None:
        """Übernimmt erkannte Produkte aus System-Scan + Patch-Monitor.

        Holt die deduplizierten Kandidaten (nur neue, noch nicht im Stack),
        zeigt sie im Vorschau-Dialog zur Kuratierung und übernimmt die
        ausgewählten Einträge inkl. CPE.
        """
        kandidaten = self._service.techstack_sync_kandidaten()
        if not kandidaten:
            self._lbl_stack_status.setText(
                "Keine neuen Produkte gefunden — lass zuerst den System-Scanner "
                "und den Patch-Monitor laufen (oder alles ist schon im Stack)."
            )
            return

        from tools.techstack.gui.techstack_import_dialog import (  # noqa: PLC0415
            TechStackImportDialog,
        )

        dlg = TechStackImportDialog(kandidaten, parent=self.window())
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        anzahl = self._service.techstack_uebernehmen(dlg.ausgewaehlte_eintraege())
        self._stack_laden()
        self._lbl_stack_status.setText(
            f"{anzahl} Eintrag(e) aus Scan & Patch-Monitor übernommen."
        )
        if anzahl:
            self.stack_changed.emit()

    # ------------------------------------------------------------------
    # CVE-Suche
    # ------------------------------------------------------------------

    def _cves_laden(self) -> None:
        """Startet die CVE-Suche für den gesamten Tech-Stack.

        Läuft auch ohne NVD-API-Key: dann werden nur die lokal im
        Patch-Monitor gematchten CVEs über die Stack-CPEs angezeigt.
        """
        if self._thread and self._thread.isRunning():
            return

        if self._service.nvd_aktiv():
            self._lbl_cve_status.setText("Suche CVEs für Stack …")
        else:
            self._lbl_cve_status.setText(
                "Kein NVD-API-Key — es werden nur lokale Patch-Monitor-Treffer "
                "(per CPE) angezeigt."
            )

        # Während der Suche keinen veralteten Hinweis stehen lassen
        # (Button ist disabled — "klicke oben" wäre irreführend).
        if self._cve_stack.currentWidget() is self._cve_empty_lbl:
            self._cve_empty_lbl.setText("CVE-Suche läuft …")

        self._btn_cve_suchen.setEnabled(False)
        self._thread = _StackCveThread(self._service, tage=30)
        self._thread.ergebnis.connect(self._cves_empfangen)
        self._thread.fehler.connect(self._cves_fehlgeschlagen)
        self._thread.start()

    @Slot(list)
    def _cves_empfangen(self, cves: list[CveEintrag]) -> None:
        """Zeigt die gefundenen CVEs in der Tabelle an.

        Args:
            cves: Gefundene CVE-Einträge für den Stack.
        """
        self._btn_cve_suchen.setEnabled(True)
        self._lbl_cve_status.setText(self._nvd_status_text(len(cves)))
        self._cve_tabelle_befuellen(cves, befund_moeglich=self._cve_befund_moeglich())

    @Slot(str)
    def _cves_fehlgeschlagen(self, exc_name: str) -> None:
        """Behandelt eine FEHLGESCHLAGENE CVE-Suche — keine Entwarnung.

        Ein Security-Tool darf einen Fehlschlag nie als "Keine CVEs
        gefunden" verkaufen AP5 Review-P2).

        Args:
            exc_name: Typname der Exception aus dem Worker-Thread.
        """
        self._btn_cve_suchen.setEnabled(True)
        self._lbl_cve_status.setText(
            f"CVE-Suche fehlgeschlagen ({exc_name}) — keine Aussage möglich."
        )
        self._cve_empty_lbl.setText(
            "CVE-Suche fehlgeschlagen — keine Aussage über deinen Stack "
            "möglich. Versuche es später erneut."
        )
        self._cve_stack.setCurrentWidget(self._cve_empty_lbl)

    def _cve_befund_moeglich(self) -> bool:
        """True, wenn ein leeres Ergebnis eine echte Entwarnung ist.

        Bei ``OFFLINE_NO_CACHE`` lagen gar keine Daten vor — dann ist
        "Keine CVEs gefunden" keine zulässige Aussage.: das Gleiche gilt
        bei offenem Circuit ohne Cache (``CIRCUIT_OPEN``) — es wurde bewusst
        NICHT abgefragt, ein leeres Ergebnis ist also keine Entwarnung.
        """
        from tools.cyber_dashboard.application.nvd_service import (  # noqa: PLC0415
            NvdStatus,
        )

        nvd = self._service.nvd_service
        if nvd is None:
            return True
        return nvd.last_status not in (
            NvdStatus.OFFLINE_NO_CACHE,
            NvdStatus.CIRCUIT_OPEN,
        )

    def _nvd_status_text(self, gefunden: int) -> str:
        """Baut eine Statuszeile aus Anzahl + NVD-Online/Offline-Metadaten.

        Greift auf:class:`NvdService` zu: bei ``ONLINE``/``CACHE_FRESH`` nur
        Treffer-Anzahl; bei ``CACHE_STALE_OFFLINE`` wird ein Offline-Hinweis
        mit Cache-Zeitstempel ergänzt; bei ``OFFLINE_NO_CACHE`` kommt eine
        klare Fehlermeldung.

        Args:
            gefunden: Anzahl gefundener CVEs.

        Returns:
            Menschenlesbarer Statustext für das Statuslabel.
        """
        from tools.cyber_dashboard.application.nvd_service import NvdStatus

        # ``nvd_service`` ist eine @property (kein Methodenaufruf) — vorher
        # fälschlich als ``nvd_service`` aufgerufen (latenter Bug, der nur
        # nie feuerte, weil _cves_laden ohne NVD-Key vorzeitig abbrach; seit
        # läuft dieser Pfad auch ohne Key).
        nvd = self._service.nvd_service
        base = f"{gefunden} CVEs für aktive Stack-Einträge gefunden"
        if nvd is None:
            return base

        status = nvd.last_status
        fetched = nvd.last_fetched_at

        if status == NvdStatus.CACHE_STALE_OFFLINE and fetched is not None:
            local = fetched.astimezone().strftime("%d.%m.%Y %H:%M")
            return (
                f"NVD nicht erreichbar — letzte bekannte Daten vom {local} "
                f"(gecached). {base}."
            )
        if status == NvdStatus.OFFLINE_NO_CACHE:
            return "NVD nicht erreichbar und kein Cache verfügbar."
        if status == NvdStatus.CIRCUIT_OPEN:
            # nach wiederholten Fehlversuchen pausieren die automatischen
            # Abrufe — klarer Handlungshinweis statt eines weiteren Timeout-Laufs.
            return (
                "NVD wiederholt nicht erreichbar — automatische Abfragen "
                "pausiert. Gültigen API-Key in den Einstellungen hinterlegen "
                "oder später erneut versuchen."
            )
        if status == NvdStatus.CACHE_FRESH and fetched is not None:
            local = fetched.astimezone().strftime("%H:%M")
            return f"{base} (Cache, {local})"
        return base

    def _cve_tabelle_befuellen(
        self, cves: list[CveEintrag], *, befund_moeglich: bool = True
    ) -> None:
        """Befüllt die CVE-Tabelle mit den übergebenen Einträgen.

        Args:
            cves: Liste der anzuzeigenden CVE-Einträge.
            befund_moeglich: False, wenn ein leeres Ergebnis KEINE
                Entwarnung ist (z.B. NVD offline ohne Cache).
        """
        # Empty-State ↔ Tabelle umschalten: ein leeres Raster füllt keine
        # halbe Bildschirmhälfte mehr AP5a). Eine Entwarnung gibt
        # es nur, wenn auch wirklich Daten vorlagen (Review-P2).
        if cves:
            self._cve_stack.setCurrentWidget(self._cve_tabelle)
        else:
            self._cve_empty_lbl.setText(
                "Keine CVEs für deinen aktiven Stack gefunden."
                if befund_moeglich
                else "Keine CVE-Daten verfügbar (NVD nicht erreichbar, kein "
                "Cache) — keine Aussage über deinen Stack möglich."
            )
            self._cve_stack.setCurrentWidget(self._cve_empty_lbl)

        self._cve_tabelle.setSortingEnabled(False)
        self._cve_tabelle.setRowCount(len(cves))

        fett = QFont()
        fett.setBold(True)

        for row, cve in enumerate(cves):
            id_text = f"[KEV] {cve.cve_id}" if cve.cisa_kev else cve.cve_id
            item_id = QTableWidgetItem(id_text)
            if cve.cisa_kev:
                item_id.setFont(fett)
            self._cve_tabelle.setItem(row, 0, item_id)

            item_cvss = QTableWidgetItem(f"{cve.cvss_score:.1f}")
            self._cve_tabelle.setItem(row, 1, item_cvss)

            self._cve_tabelle.setItem(row, 2, QTableWidgetItem(cve.schweregrad))
            self._cve_tabelle.setItem(row, 3, QTableWidgetItem(cve.beschreibung[:120]))

            item_kev = QTableWidgetItem("Ja" if cve.cisa_kev else "")
            self._cve_tabelle.setItem(row, 4, item_kev)

            bg_hex, text_hex = _cve_farben().get(cve.schweregrad.upper(), ("", ""))
            for col in range(5):
                it = self._cve_tabelle.item(row, col)
                if it:
                    if bg_hex:
                        it.setBackground(QColor(bg_hex))
                    if text_hex:
                        it.setForeground(QColor(text_hex))

            url = cve.url
            btn = QPushButton("Link")
            btn.setMinimumSize(36, 28)
            btn.setToolTip(f"NVD: {cve.cve_id}")
            btn.clicked.connect(lambda _, u=url: QDesktopServices.openUrl(QUrl(u)))
            self._cve_tabelle.setCellWidget(row, 5, btn)

        self._cve_tabelle.setSortingEnabled(True)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------

    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("techstack")
        return hc.tooltips.get(key, "") if hc else ""

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QTableWidget {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; gridline-color: {c.BORDER}; }}"
            f"QHeaderView::section {{ background-color: {c.BG_MAIN};"
            f" color: {c.TEXT_MAIN}; border: 1px solid {c.BORDER}; padding: 4px; }}"
            f"QLineEdit {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
        )
        # Buttons unter einem Container-Stylesheet brauchen ein eigenes
        # vollstaendiges Widget-Stylesheet, sonst malt Qt Border/Fill nicht
        # (Buttons wirken wie Text) und die globale Hover-color macht die
        # Schrift dunkel-auf-dunkel (R26).
        button_qss = outline_button_qss()
        for btn in (
            self._btn_hinzufuegen,
            self._btn_entfernen,
            self._btn_sync,
            self._btn_cve_suchen,
            self._btn_starter,
        ):
            btn.setStyleSheet(button_qss)
        self._page.apply_theme()
        self._cve_empty_lbl.apply_theme()
        self.refresh_severity_colors()

    def refresh_severity_colors(self) -> None:
        """Aktualisiert Severity-Hintergründe aller CVE-Tabellenzeilen.

        Wird beim Theme-Wechsel automatisch aufgerufen (via _force_repolish_recursive).
        """
        from PySide6.QtCore import Qt  # noqa: PLC0415

        farben = _cve_farben()
        for row in range(self._cve_tabelle.rowCount()):
            sg_item = self._cve_tabelle.item(row, 2)
            if sg_item is None:
                continue
            bg_hex, text_hex = farben.get(sg_item.text().upper(), ("", ""))
            for col in range(5):
                it = self._cve_tabelle.item(row, col)
                if it:
                    if bg_hex:
                        it.setBackground(QColor(bg_hex))
                    else:
                        it.setData(Qt.ItemDataRole.BackgroundRole, None)
                    if text_hex:
                        it.setForeground(QColor(text_hex))
                    else:
                        it.setData(Qt.ItemDataRole.ForegroundRole, None)
