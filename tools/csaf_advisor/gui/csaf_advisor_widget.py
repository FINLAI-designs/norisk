"""
csaf_advisor_widget — Haupt-Widget für den CSAF Advisory-Monitor.

Bietet:
  - Advisory-Liste mit Severity-Farbcodierung und Match-Badge
  - Listen-Filter: Severity, Zeitraum, Nur Matches (Provider/Quellen
    werden NICHT hier gefiltert, sondern im Zahnrad-Dialog "Provider
    verwalten" aktiviert/deaktiviert)
  - Detail-Ansicht mit allen Advisory-Feldern und externen Links
  - "Jetzt abrufen"-Button mit Worker-Thread (kein GUI-Block)
  - Provider-Settings-Dialog

Schichtzugehörigkeit: gui/ — keine Geschäftslogik, nur UI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, QThread, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTabWidget,
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
from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.gui.advisory_tree_panel import AdvisoryTreePanel
from tools.csaf_advisor.gui.detail_panel import DetailPanel
from tools.csaf_advisor.gui.fetch_worker import FetchWorker
from tools.csaf_advisor.gui.filter_panel import FilterPanel
from tools.csaf_advisor.gui.provider_dialogs import ProviderSettingsDialog
from tools.csaf_advisor.gui.system_selector_panel import SystemSelectorPanel
from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (
    ManageProfilesUseCase,
    create_default_manage_profiles_use_case,
)

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class _AdvisoriesPanel(QWidget):
    """Inhalt des "Advisories"-Tabs (Sprint S2c).

    Vor S2c war das die top-level Klasse ``CsafAdvisorWidget``; mit dem
    Tool-Merger M1 wurde sie in ein Panel umbenannt, damit der äußere
:class:`CsafAdvisorWidget` einen ``QTabWidget``-Container darstellen
    kann (Tab 1 "Inventar" — TechStack; Tab 2 "Advisories" — dieses Panel).

    Konstruktor-Signatur und alle public Methoden (``set_cve_filter``,
    ``_refresh_list``) bleiben unverändert, damit Bestands-Tests
    weiterlaufen.

    Attributes:
        _service: AdvisoryService-Instanz.
        _all_advisories: Zuletzt geladene Advisory-Liste.
        _matches_by_id: Advisory-ID → AdvisoryMatch-Mapping.
        _thread: Aktiver QThread während eines Fetches.
        _worker: Aktiver FetchWorker.
    """

    def __init__(
        self,
        service: AdvisoryService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert das Widget.

        Args:
            service: Vollständig konfigurierter AdvisoryService.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._service = service
        self._all_advisories: list[CsafAdvisory] = []
        self._matches_by_id: dict[str, AdvisoryMatch] = {}
        self._thread: QThread | None = None
        self._worker: FetchWorker | None = None
        self._cve_id_filter: str | None = None
        # Use Case kommt aus der application-Schicht (Factory
        # liefert ``None`` wenn das Repository nicht initialisierbar ist).
        self._profile_use_case: ManageProfilesUseCase | None = (
            create_default_manage_profiles_use_case()
        )
        self._build_ui()
        self._refresh_list()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das vollständige UI."""
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(8)

        # Kopfzeile
        root.addLayout(self._build_header())

        _hc = HelpRegistry.get("csaf_advisor")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # System-Selector
        self._system_panel = SystemSelectorPanel(self._service, self._profile_use_case)
        self._system_panel.inventory_changed.connect(self._refresh_list)
        root.addWidget(self._system_panel)

        # Fortschrittsanzeige: kanonischer FinlaiProgressBar)
        self._progress_bar = FinlaiProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setTextVisible(True)
        root.addWidget(self._progress_bar)

        self._lbl_progress = QLabel("")
        self._lbl_progress.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 12px;")
        self._lbl_progress.setVisible(False)
        root.addWidget(self._lbl_progress)

        # Status-Zeile
        self._lbl_status = QLabel("")
        self._lbl_status.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 12px;")
        root.addWidget(self._lbl_status)

        # Haupt-Splitter: Filter | Advisory-Liste + Detail
        outer_splitter = QSplitter(Qt.Orientation.Horizontal)
        outer_splitter.setChildrenCollapsible(False)

        # Linkes Panel: Filter
        self._filter_panel = FilterPanel()
        self._filter_panel.filters_changed.connect(self._on_filter_changed)
        outer_splitter.addWidget(self._filter_panel)

        # Rechtes Panel: Liste + Detail (vertikaler Splitter)
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.setChildrenCollapsible(False)

        self._tree = AdvisoryTreePanel()
        self._tree.advisory_selected.connect(self._on_advisory_selected)
        right_splitter.addWidget(self._tree)

        self._detail_panel = DetailPanel()
        self._detail_panel.status_message.connect(self._lbl_status.setText)
        right_splitter.addWidget(self._detail_panel)
        right_splitter.setSizes([400, 250])

        outer_splitter.addWidget(right_splitter)
        outer_splitter.setSizes([200, 750])

        root.addWidget(outer_splitter, stretch=1)

    def _build_header(self) -> QHBoxLayout:
        """Erstellt die Kopfzeile mit Titel und Action-Buttons.

        Returns:
            HBoxLayout der Kopfzeile.
        """
        t = theme.get()
        row = QHBoxLayout()
        row.setSpacing(8)

        title = QLabel("Advisory-Monitor")
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {t.ACCENT};")
        row.addWidget(title)

        row.addStretch()

        self._btn_fetch = QPushButton("Jetzt abrufen")
        self._btn_fetch.setIcon(get_icon(Icons.SYNC))
        self._btn_fetch.setToolTip(
            "CSAF Advisories von allen aktiven Providern abrufen"
        )
        self._btn_fetch.clicked.connect(self._on_fetch_clicked)
        self._btn_fetch.setStyleSheet(self._btn_style(accent=True))
        row.addWidget(self._btn_fetch)
        _tip_fetch = self._help_tip("btn_fetch")
        if _tip_fetch:
            row.addWidget(HelpButton(_tip_fetch))

        # Export-Buttons
        btn_excel = QPushButton()
        btn_excel.setIcon(get_icon(Icons.TABLE_VIEW))
        btn_excel.setToolTip("Aktuelle Ansicht als Excel (.xlsx) exportieren")
        btn_excel.clicked.connect(self._on_export_excel)
        btn_excel.setStyleSheet(self._btn_style())
        btn_excel.setFixedWidth(38)
        row.addWidget(btn_excel)

        btn_json = QPushButton()
        btn_json.setIcon(get_icon(Icons.DATA_OBJECT))
        btn_json.setToolTip("Aktuelle Ansicht als JSON exportieren")
        btn_json.clicked.connect(self._on_export_json)
        btn_json.setStyleSheet(self._btn_style())
        btn_json.setFixedWidth(38)
        row.addWidget(btn_json)

        btn_pdf = QPushButton()
        btn_pdf.setIcon(get_icon(Icons.PDF))
        btn_pdf.setToolTip("Aktuelle Ansicht als PDF exportieren")
        btn_pdf.clicked.connect(self._on_export_pdf)
        btn_pdf.setStyleSheet(self._btn_style())
        btn_pdf.setFixedWidth(38)
        row.addWidget(btn_pdf)

        btn_settings = QPushButton()
        btn_settings.setIcon(get_icon(Icons.SETTINGS))
        btn_settings.setToolTip("Provider verwalten")
        btn_settings.clicked.connect(self._on_settings_clicked)
        btn_settings.setStyleSheet(self._btn_style())
        btn_settings.setFixedWidth(38)
        row.addWidget(btn_settings)

        return row

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("csaf_advisor")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "csaf_advisor", parent=self.window()
        )
        dlg.show()

    # ------------------------------------------------------------------
    # Advisory-Liste befüllen
    # ------------------------------------------------------------------

    def _refresh_list(self) -> None:
        """Lädt Advisories und Matches aus der DB und aktualisiert die Liste."""
        days = self._filter_panel.get_days()
        self._all_advisories = self._service.list_advisories(days=days)

        matches = self._service.list_matches()
        self._matches_by_id = {m.advisory_id: m for m in matches}

        self._apply_filters()
        count = self._tree.topLevelItemCount()
        total = self._service.advisory_count()
        match_count = len(self._matches_by_id)
        self._lbl_status.setText(
            f"{count} Advisories angezeigt | {total} gesamt in DB | "
            f"{match_count} Matches"
        )

    def set_cve_filter(self, cve_id: str) -> None:
        """Öffentlicher Filter-Entry-Point (vom Dashboard genutzt).

        Args:
            cve_id: CVE-Kennung (z.B. ``"CVE-2024-1234"``). Leere Strings
                heben den Filter auf.
        """
        self._cve_id_filter = cve_id.strip() or None
        self._apply_filters()

    def _apply_filters(self) -> None:
        """Filtert die Advisory-Liste entsprechend der aktuellen Filter-Einstellungen."""
        allowed_severities = self._filter_panel.get_allowed_severities()
        only_matches = self._filter_panel.get_only_matches()

        filtered = []
        for advisory in self._all_advisories:
            if self._cve_id_filter and self._cve_id_filter not in advisory.cve_ids:
                continue
            if advisory.severity.lower() not in allowed_severities:
                continue
            if only_matches and advisory.id not in self._matches_by_id:
                continue
            filtered.append(advisory)

        self._tree.show_advisories(filtered, self._matches_by_id)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_fetch_clicked(self) -> None:
        """Startet den CSAF-Fetch im Hintergrund-Thread."""
        if self._thread is not None and self._thread.isRunning():
            return

        self._btn_fetch.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._progress_bar.setMaximum(0)  # Indeterminate
        self._lbl_progress.setVisible(True)
        self._lbl_progress.setText("Verbinde mit Providern…")
        self._lbl_status.setText("Fetch läuft…")

        self._thread = QThread(self)
        self._worker = FetchWorker(self._service, self._system_panel.get_inventory())
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_fetch_progress)
        self._worker.finished.connect(self._on_fetch_finished)
        self._worker.error.connect(self._on_fetch_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._on_thread_finished)

        self._thread.start()

    @Slot(str, int, int, str)
    def _on_fetch_progress(
        self,
        provider_name: str,
        current: int,
        total: int,
        info: str,
    ) -> None:
        """Aktualisiert die Fortschrittsanzeige.

        Args:
            provider_name: Name des aktuellen Providers.
            current: Aktueller Fortschritt.
            total: Gesamtanzahl.
            info: Zusätzliche Info (z. B. Advisory-Dateiname).
        """
        if total > 0:
            self._progress_bar.setMaximum(total)
            self._progress_bar.setValue(current)
            self._progress_bar.setFormat(f"{current}/{total}")
        self._lbl_progress.setText(f"{provider_name}: {info}")

    @Slot(int, list)
    def _on_fetch_finished(self, new_count: int, errors: list[str]) -> None:
        """Verarbeitet das Fetch-Ergebnis.

        Args:
            new_count: Anzahl neu geladener Advisories.
            errors: Liste der Fehlermeldungen.
        """
        self._progress_bar.setVisible(False)
        self._lbl_progress.setVisible(False)
        self._btn_fetch.setEnabled(True)

        if errors:
            error_summary = " | ".join(errors[:3])
            self._lbl_status.setText(
                f"Fetch abgeschlossen — {new_count} neu — Fehler: {error_summary}"
            )
        else:
            self._lbl_status.setText(
                f"Fetch abgeschlossen — {new_count} Advisories neu geladen."
            )

        self._refresh_list()

    @Slot(str)
    def _on_fetch_error(self, message: str) -> None:
        """Zeigt einen kritischen Fetch-Fehler an.

        Args:
            message: Fehlerbeschreibung.
        """
        self._progress_bar.setVisible(False)
        self._lbl_progress.setVisible(False)
        self._btn_fetch.setEnabled(True)
        self._lbl_status.setText(f"FEHLER — {message}")

    @Slot()
    def _on_thread_finished(self) -> None:
        """Bereinigt Thread-Referenzen nach Abschluss."""
        self._thread = None
        self._worker = None

    @Slot()
    def _on_filter_changed(self) -> None:
        """Reagiert auf Filteränderungen und aktualisiert die Liste."""
        days = self._filter_panel.get_days()
        self._all_advisories = self._service.list_advisories(days=days)
        self._apply_filters()

    @Slot(str)
    def _on_advisory_selected(self, advisory_id: str) -> None:
        """Zeigt Details des ausgewählten Advisory an.

        Args:
            advisory_id: Advisory-ID vom AdvisoryTreePanel-Signal,
                         leerer String wenn Selection cleared.
        """
        if not advisory_id:
            self._detail_panel.clear()
            return
        advisory = self._service.get_advisory(advisory_id)
        if advisory is None:
            self._detail_panel.clear()
            return
        self._detail_panel.show_advisory(
            advisory, match=self._matches_by_id.get(advisory.id)
        )

    @Slot()
    def _on_settings_clicked(self) -> None:
        """Öffnet den Provider-Settings-Dialog."""
        dialog = ProviderSettingsDialog(self._service, self)
        dialog.exec()
        self._refresh_list()

    # ------------------------------------------------------------------
    # Export-Slots
    # ------------------------------------------------------------------

    def _get_visible_advisories(self) -> list:
        """Gibt die aktuell sichtbaren Advisories aus dem Tree zurück."""
        result = []
        for advisory_id in self._tree.get_visible_advisory_ids():
            adv = self._service.get_advisory(advisory_id)
            if adv is not None:
                result.append(adv)
        return result

    @Slot()
    def _on_export_excel(self) -> None:
        """Exportiert die aktuelle Ansicht als Excel-Datei."""
        from datetime import date  # noqa: PLC0415

        from core.dialogs import FinlaiSuccessDialog  # noqa: PLC0415
        from tools.csaf_advisor.application.csaf_exporter import (
            export_excel,  # noqa: PLC0415
        )

        advisories = self._get_visible_advisories()
        if not advisories:
            self._lbl_status.setText("Keine Advisories zum Exportieren.")
            return

        default_name = f"CSAF_Advisories_{date.today()}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, "Excel-Export speichern", default_name, "Excel (*.xlsx)"
        )
        if not path:
            return

        try:
            export_excel(advisories, path)
            FinlaiSuccessDialog(
                title="Excel-Export erfolgreich",
                message=f"{len(advisories)} Advisories exportiert.",
                file_path=path,
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ImportError, ValueError) as exc:
            self._lbl_status.setText(f"Excel-Export fehlgeschlagen: {exc}")

    @Slot()
    def _on_export_json(self) -> None:
        """Exportiert die aktuelle Ansicht als JSON-Datei."""
        from datetime import date  # noqa: PLC0415

        from core.dialogs import FinlaiSuccessDialog  # noqa: PLC0415
        from tools.csaf_advisor.application.csaf_exporter import (
            export_json,  # noqa: PLC0415
        )

        advisories = self._get_visible_advisories()
        if not advisories:
            self._lbl_status.setText("Keine Advisories zum Exportieren.")
            return

        _allowed = self._filter_panel.get_allowed_severities()
        filter_info = {
            "days": self._filter_panel.get_days(),
            "only_matches": self._filter_panel.get_only_matches(),
            "severities": {sev: sev in _allowed for sev in ("critical", "high", "medium", "low")},
        }
        default_name = f"CSAF_Advisories_{date.today()}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "JSON-Export speichern", default_name, "JSON (*.json)"
        )
        if not path:
            return

        try:
            export_json(advisories, path, filter_info=filter_info)
            FinlaiSuccessDialog(
                title="JSON-Export erfolgreich",
                message=f"{len(advisories)} Advisories exportiert.",
                file_path=path,
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ValueError) as exc:
            self._lbl_status.setText(f"JSON-Export fehlgeschlagen: {exc}")

    @Slot()
    def _on_export_pdf(self) -> None:
        """Exportiert die aktuelle Ansicht als PDF-Report."""
        from datetime import date  # noqa: PLC0415

        from core.dialogs import FinlaiSuccessDialog  # noqa: PLC0415
        from tools.csaf_advisor.application.csaf_exporter import (
            export_pdf,  # noqa: PLC0415
        )

        advisories = self._get_visible_advisories()
        if not advisories:
            self._lbl_status.setText("Keine Advisories zum Exportieren.")
            return

        default_name = f"CSAF_Advisory_Report_{date.today()}.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "PDF-Report speichern", default_name, "PDF (*.pdf)"
        )
        if not path:
            return

        try:
            export_pdf(advisories, path)
            FinlaiSuccessDialog(
                title="PDF-Report erfolgreich gespeichert",
                message=f"{len(advisories)} Advisories exportiert.",
                file_path=path,
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ImportError, ValueError) as exc:
            self._lbl_status.setText(f"PDF-Export fehlgeschlagen: {exc}")

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def _btn_style(accent: bool = False) -> str:
        """Gibt das Stylesheet für Buttons zurück.

        Args:
            accent: True für Akzentfarbe.

        Returns:
            CSS-Stylesheet-String.
        """
        t = theme.get()
        bg = t.ACCENT if accent else t.BG_BUTTON
        text = t.BG_MAIN if accent else t.TEXT_MAIN
        return (
            f"QPushButton {{ background-color: {bg}; color: {text};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 6px 14px; font-size: 13px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN}; }}"
            f"QPushButton:disabled {{ background-color: {t.BG_BUTTON_DISABLED};"
            f" color: {t.TEXT_BUTTON_DISABLED}; border-color: {t.BORDER_BUTTON_DISABLED}; }}"
        )


# ---------------------------------------------------------------------------
# CsafAdvisorWidget — Tab-Container (Sprint S2c, Tool-Merger M1)
# ---------------------------------------------------------------------------


class CsafAdvisorWidget(QWidget):
    """Top-level CSAF-Advisor-Widget mit zwei Tabs.

    Tabs:
      1. **Tech-Stack** — das vollwertige Tech-Stack-Tool
         (:class:`tools.techstack.gui.techstack_widget.TechStackWidget`),
         eingebettet via injizierter Factory (gui↛tool).:
         Der frühere read-only „Inventar"-Tab (D4) wird durch den echten
         Editor ersetzt; der eigenständige Sidebar-Eintrag „Tech-Stack"
         entfällt — der einzige Tech-Stack-Editor lebt jetzt hier. Da es
         keinen zweiten Schreibpfad mehr gibt (kein Sidebar-Tool), bleibt
         die D4-Invariante „genau EIN Editor" erfüllt.
      2. **Advisories** — die bestehende:class:`_AdvisoriesPanel`-UI
         (frueher direkt ``CsafAdvisorWidget``).

    Public API:
      -:meth:`set_cve_filter` — von ``core.navigation_mixin``
        gerufen, wenn der User auf eine CVE im cyber_dashboard klickt.
        Wechselt automatisch in den Advisories-Tab und delegiert.
      -:meth:`shutdown` — App-Lifecycle-Hook (closeEvent-Sweep); reicht
        den Teardown an die Sub-Tab-Widgets durch.

    Args:
        service: AdvisoryService-Instanz (wird in den Advisories-Tab
            durchgereicht).
        techstack_factory: ``(parent) -> QWidget``-Factory für das
            Tech-Stack-Widget. Aus dem Composition-Root injiziert
            (``tools.csaf_advisor.tool``), damit die GUI kein Tool-Plugin
            importiert (gleiche DI wie der file_scanner-Container).
            ``None`` → Fallback-Hinweis im Tech-Stack-Tab.
        parent: Optionales Eltern-Widget.
    """

    # Tab-Indizes als Konstanten — damit ``set_cve_filter`` den
    # Advisories-Tab direkt aktivieren kann.
    _TAB_TECHSTACK = 0
    _TAB_ADVISORIES = 1

    def __init__(
        self,
        service: AdvisoryService,
        techstack_factory: Callable[[QWidget | None], QWidget] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        # Felder, die test_cve_klick.py bei einer Stub-Instanz erwartet —
        # bewusst hier instanziiert, nicht erst in ``set_cve_filter``.
        self._cve_id_filter: str | None = None
        self._advisories_panel: _AdvisoriesPanel | None = None
        self._techstack_widget: QWidget | None = None
        # Muster: Idempotenz-Guard fuer shutdown (closeEvent mehrfach).
        self._shutdown_done = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._tabs = QTabWidget(self)
        outer.addWidget(self._tabs)

        # Tab 1: Tech-Stack — das echte Tool. Defensiv bauen, damit ein
        # fehlender/fehlerhafter Tech-Stack-Service nicht den Advisories-Tab
        # blockiert.
        self._tabs.addTab(
            self._build_techstack_tab(techstack_factory), "Tech-Stack"
        )

        # Tab 2: Advisories — die bestehende UI.
        self._advisories_panel = _AdvisoriesPanel(service)
        self._tabs.addTab(self._advisories_panel, "Advisories")

    # ------------------------------------------------------------------
    # Public API (delegiert an _AdvisoriesPanel)
    # ------------------------------------------------------------------

    def set_cve_filter(self, cve_id: str) -> None:
        """Setzt den CVE-Filter (interner Entry-Point + Test-Shim).

        Live-Pfad seit: Dashboard -> open_with_filter -> Router ->
        ``apply_navigation(cve_id=…)`` -> diese Methode. Body bewusst inline
        (ohne Delegation), damit der Stub-Test
        ``test_cve_klick.py::test_csaf_set_cve_filter_setzt_*`` ohne
        ``_advisories_panel`` weiterlaeuft.
        """
        self._cve_id_filter = cve_id.strip() or None
        self._apply_filters()

    def apply_navigation(self, **kwargs: object) -> None:
        """Deep-Link-Empfaenger: Filter per ``cve_id`` vorbelegen.

        Wird vom Router (``navigate_to``) nach dem Dock-Show aufgerufen, wenn
        das Dashboard einen CVE-Deep-Link ausloest. Loest den frueheren
        Sonderpfad ``if key == "csaf_advisor": set_cve_filter`` im Router ab;
        andere kwargs werden ignoriert.

        Args:
            **kwargs: Unterstuetzt ``cve_id`` (str). Leerwerte heben den
                Filter auf.
        """
        cve_id = kwargs.get("cve_id")
        if cve_id is not None:
            self.set_cve_filter(str(cve_id))

    def _apply_filters(self) -> None:
        """Delegiert den Filter an das Advisories-Panel + wechselt den Tab."""
        panel = getattr(self, "_advisories_panel", None)
        if panel is None:
            return
        panel.set_cve_filter(self._cve_id_filter or "")
        self._tabs.setCurrentIndex(self._TAB_ADVISORIES)

    # ------------------------------------------------------------------
    # Tab-Bau + Lifecycle
    # ------------------------------------------------------------------

    def _build_techstack_tab(
        self, factory: Callable[[QWidget | None], QWidget] | None
    ) -> QWidget:
        """Baut den Tech-Stack-Tab via injizierter Factory.

        Ersetzt den frueheren read-only Inventar-Tab (D4) durch das
        vollwertige Tech-Stack-Tool. Defensive: wenn die Factory fehlt oder
        scheitert (Service-/Repo-Fehler), zeigt der Tab einen knappen
        Hinweis — der Advisories-Tab bleibt nutzbar.

        Args:
            factory: ``(parent) -> QWidget`` aus dem Composition-Root, oder
                ``None`` (dann Fallback-Hinweis).

        Returns:
            Das Tech-Stack-Widget oder einen Fallback-Hinweis.
        """
        if factory is None:
            return self._make_techstack_fallback("nicht initialisiert")
        try:
            widget = factory(self)
        except Exception as exc:  # noqa: BLE001 -- Service-Init ist Dependency-Grenze
            _log.warning(
                "CsafAdvisorWidget: Tech-Stack-Tab nicht verfuegbar (%s)",
                type(exc).__name__,
            )
            return self._make_techstack_fallback(str(exc))
        self._techstack_widget = widget
        return widget

    @staticmethod
    def _make_techstack_fallback(reason: str) -> QWidget:
        """Hinweis-Block, der den Tech-Stack-Tab fuellt, wenn der Bau scheitert."""
        t = theme.get()
        wrapper = QWidget()
        lyt = QVBoxLayout(wrapper)
        lyt.setContentsMargins(24, 24, 24, 24)
        lbl = QLabel(
            "Tech-Stack-Tool nicht verfuegbar — Initialisierung fehlgeschlagen "
            f"({reason}). Die Advisories sind ueber den 'Advisories'-Tab "
            "weiterhin nutzbar."
        )
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color: {t.TEXT_DIM}; font-size: 12px;")
        lyt.addWidget(lbl)
        return wrapper

    def shutdown(self) -> None:
        """App-Lifecycle-Hook (closeEvent-Sweep): reicht Teardown an Sub-Tabs.

        Reicht ``stop_worker``/``shutdown`` duck-typed an den eingebetteten
        Tech-Stack-Tab und das Advisories-Panel durch (analog
        file_scanner-Container). Idempotent — der ``closeEvent`` kann in Qt
        mehrfach feuern.
        """
        if self._shutdown_done:
            return
        self._shutdown_done = True
        for widget in (self._techstack_widget, self._advisories_panel):
            if widget is None:
                continue
            for hook_name in ("stop_worker", "shutdown"):
                hook = getattr(widget, hook_name, None)
                if not callable(hook):
                    continue
                try:
                    hook()
                except Exception as exc:  # noqa: BLE001 -- Shutdown-Boundary
                    _log.warning(
                        "%s() fuer %s beim Shutdown fehlgeschlagen: %s",
                        hook_name,
                        type(widget).__name__,
                        exc,
                    )
