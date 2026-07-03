"""
dashboard_widget — NoRisk Gesamt-Dashboard (Phase 1).

Root-Widget mit:
- Kopfzeile: Titel + Refresh-Button + Zeitfilter (Woche/Monat/Quartal)
- Scrollbereich mit fünf klappbaren Sektionen
  1. Was hat sich geändert (offen)
  2. Score kompakt (offen)
  3. CVE-Liste + Scan-Status (offen)
  4. Score-Aufschlüsselung + Trend (zu, Phase-2-Stub)
  5. Organisatorische Sicherheit (zu, Phase-2-Stub)

- Auto-Refresh alle 2 Stunden via QTimer
- Manueller Refresh-Button
- Refresh beim Öffnen

Author: Patrick Riederich
Version: 0.1 (Phase 1)
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.logger import get_logger
from tools.norisk_dashboard.application.dashboard_aggregator import (
    DashboardAggregator,
)
from tools.norisk_dashboard.application.pdf_export_service import (
    PdfExportService,
    default_filename,
    default_output_dir,
)
from tools.norisk_dashboard.domain.models import DashboardData, TimeRange
from tools.norisk_dashboard.gui._section import _DashboardSection
from tools.norisk_dashboard.gui._time_filter import _TimeFilter
from tools.norisk_dashboard.gui.anomaly_section import AnomalySection
from tools.norisk_dashboard.gui.cert_burndown_tile import CertBurndownTile
from tools.norisk_dashboard.gui.customer_audit_card import CustomerAuditCard
from tools.norisk_dashboard.gui.cvss_percentile_widget import CvssPercentileWidget
from tools.norisk_dashboard.gui.light_siem_section import LightSiemSection
from tools.norisk_dashboard.gui.nis2_status_section import Nis2StatusSection
from tools.norisk_dashboard.gui.score_completeness_banner import (
    ScoreCompletenessBanner,
)
from tools.norisk_dashboard.gui.section_breakdown_trend import BreakdownTrendSection
from tools.norisk_dashboard.gui.section_changes import ChangesSection
from tools.norisk_dashboard.gui.section_cves_scans import CvesScansSection
from tools.norisk_dashboard.gui.section_kanban import KanbanSection
from tools.norisk_dashboard.gui.section_notes import NotesSection
from tools.norisk_dashboard.gui.section_organizational import OrganizationalSection
from tools.norisk_dashboard.gui.section_score import ScoreSection
from tools.norisk_dashboard.gui.security_cockpit_band import SecurityCockpitBand
from tools.norisk_dashboard.gui.status_tiles_section import StatusTilesSection

log = get_logger(__name__)

_AUTO_REFRESH_MS = 2 * 60 * 60 * 1000  # 2h (schwerer Aggregator)
# 3c: separater leichter Takt fuer die Home-Widgets (KiTodo/TaskSnippet/
# Activity/Quickstart/Phishing) — sie hatten im alten Mainpage-Home einen 60s-
# Timer. Stoesst NUR ``_refresh_home_widget`` an, NICHT den 2h-Aggregator.
_LIGHT_REFRESH_MS = 60 * 1000  # 60s


class _AggregateWorker(QThread):
    """Faehrt ``DashboardAggregator.aggregate`` OFF dem UI-Thread.

    Der Aggregator oeffnet beim Cockpit-Refresh ~16-25 SQLCipher-DBs
    sequentiell (Score/Scans/Org/Cert/Hardening/Audit/Completeness/SELF).
    Synchron im UI-Thread friert das beim ERSTEN Cockpit-Render — kalt, vor
    Raw-Key-Konvertierung/TTL-Cache, mit Schema-Init/Migration — ~1-2 s ein;
    der faulthandler-Watchdog meldet dann einen "Beinahe-Crash", genau
    Patricks Symptom). Der Worker liest im Hintergrund; das UI-``_apply`` (nur
    Widget-Updates) laeuft danach im Haupt-Thread. Die Aggregator-Loader oeffnen
    ihre Verbindungen erst beim Aufruf in:meth:`run` -> thread-lokal auf diesem
    Worker (gleiches Muster wie: DB-I/O nie im UI-Slot).

    Signals:
        fertig: Emittiert die fertige ``DashboardData`` bei Erfolg.
        fehlgeschlagen: Exception-Klassenname bei Fehler.
    """

    fertig: Signal = Signal(object)
    fehlgeschlagen: Signal = Signal(str)

    def __init__(
        self,
        aggregator: DashboardAggregator,
        time_range: TimeRange,
        subject_label: str,
        subject_id: str | None,
    ) -> None:
        super().__init__()
        self._aggregator = aggregator
        self._time_range = time_range
        self._subject_label = subject_label
        self._subject_id = subject_id

    def run(self) -> None:
        try:
            if self._subject_id:
                # subjekt-bewusst nur bei expliziter Auswahl.
                data = self._aggregator.aggregate(
                    self._time_range,
                    target_name=self._subject_label,
                    subject_id=self._subject_id,
                )
            else:
                data = self._aggregator.aggregate(self._time_range)
        except (
            OSError,
            RuntimeError,
            ValueError,
            KeyError,
            AttributeError,
            TypeError,
        ) as exc:
            # exc_info=True: vorher ging nur der Typname ins Log -> die
            # eigentliche Ursache eines Aggregat-Fehlers war nicht diagnostizierbar.
            log.warning(
                "Dashboard-Aggregation fehlgeschlagen: %s",
                type(exc).__name__,
                exc_info=True,
            )
            self.fehlgeschlagen.emit(type(exc).__name__)
            return
        self.fertig.emit(data)


# Haelt parentlose Aggregate-Worker am Leben, bis ``finished`` feuert — auch
# wenn das Cockpit-Widget waehrend eines laufenden Refreshs zerstoert wird
# (Dock-Wechsel, deleteLater ohne closeEvent, Tests). Ohne diese Referenz
# koennte der Python-Wrapper des laufenden QThread eingesammelt werden ->
# "QThread destroyed while running"-Teardown-Klasse). Gleiches Muster
# wie ``_ACTIVE_INGEST_WORKERS`` im Light-SIEM. Der Worker entfernt sich beim
# ``finished`` selbst wieder.
_ACTIVE_AGGREGATE_WORKERS: set[_AggregateWorker] = set()


class NoRiskDashboardWidget(QWidget):
    """Hauptwidget des NoRisk-Gesamt-Dashboards.

    Signals:
        navigate(str): Nav-Key zum Öffnen (z.B. ``"security_scoring"``
                                     bei CTA-Klick in Sektion 5).
        open_with_filter(str, object): Nav-Key zum Öffnen plus Filter-Payload
                                     (CVE-ID für ``csaf_advisor``; der frühere
                                     Heatmap-Tagesfilter ist entfernt).
    """

    navigate = Signal(str)
    open_with_filter = Signal(str, object)
    #:: feuert nach JEDEM abgeschlossenen Refresh-Zyklus (Erfolg ODER
    #: Fehler), nachdem ``_apply``/``_show_error`` lief und ein etwaiger
    #: Initial-Worker aufgeraeumt ist. Da der ERSTE (teure) Refresh asynchron im
    #: Worker laeuft, ist das das verlaessliche "fertig"-Signal (Tests warten darauf statt auf
    #: einen festen Timeout; potenzielle Consumer koennen auf frische Daten
    #: reagieren).
    refreshed = Signal()

    def __init__(
        self,
        aggregator: DashboardAggregator | None = None,
        parent: QWidget | None = None,
        export_service: PdfExportService | None = None,
        task_service: object | None = None,
        journal_service: object | None = None,
        quickstart_service: object | None = None,
        phishing_view_model: object | None = None,
        workflow_service: object | None = None,
        subject_store: object | None = None,
    ) -> None:
        """Initialisiert das Dashboard.

        Args:
            aggregator: ``DashboardAggregator``-Instanz fuer alle
                Quick-Win-/Heatmap-Daten.
            parent: Optionales Eltern-Widget.
            export_service: PDF-Exporter (DI fuer Tests).
            task_service: Sprint S4a — geteilter ``TaskService`` aus der
                Mainpage. Wenn ``None`` werden Kanban + Notizen-Sektionen
                nicht angelegt (Backwards-Compat fuer bestehende Tests).
            journal_service: Sprint S4a — geteilter ``JournalService``.
                Wird zusammen mit ``task_service`` benoetigt; leerer
                Pfad nur wenn beide ``None``.
            quickstart_service: 3c (Cockpit) — geteilter
                ``QuickstartService`` aus der Mainpage. Steuert die
                Schnellstart-Leiste oben im Cockpit. ``None`` → keine
                Schnellstart-Leiste (Backwards-Compat).
            phishing_view_model: 3c (Cockpit) — ``PhishingRadarViewModel``
                fuer den Phishing-Radar-Banner. Der Banner wird immer gebaut
                (ctor erlaubt ``None``-VM → Placeholder-Zustand).
        """
        super().__init__(parent)
        self._aggregator = aggregator or DashboardAggregator()
        self._current_range = TimeRange.WEEK
        # aktuell gewähltes Subjekt (None = "Allgemein" = bisheriger
        # target_name-Pfad mit Freshest-Fallback, unveränderter Default).
        self._current_subject_id: str | None = None
        self._current_subject_label = "Allgemein"
        self._export_service = export_service or PdfExportService()
        self._last_data: DashboardData | None = None
        self._task_service = task_service
        self._journal_service = journal_service
        self._quickstart_service = quickstart_service
        self._phishing_view_model = phishing_view_model
        # Workflow-Tab (gefuehrter Leitfaden). Service + SubjectStore
        # best-effort injiziert; fehlen sie, wird der 4. Tab einfach nicht gebaut.
        self._workflow_service = workflow_service
        self._subject_store = subject_store
        self._workflow_tab: object | None = None
        self._workflow_tab_index: int | None = None
        # laufender INITIAL-Worker (nur der erste, teure Cold-Start-Lauf
        # laeuft off-thread) + gemerkter Nachhol-Wunsch, falls waehrend des
        # Initial-Laufs ein interaktiver refresh kommt (Subjekt-/Zeitraum-Wechsel).
        self._initial_worker: _AggregateWorker | None = None
        self._pending_refresh = False

        self._build_ui()
        self._wire_auto_refresh()
        # Cockpit-Perf A: Den schweren Initial-Refresh (Aggregator mit ~25
        # SQLCipher-Oeffnungen) NICHT synchron im ctor fahren — sonst friert
        # das Fenster ~2 s ein, bevor es ueberhaupt zeichnet. Ein Kind-QTimer
        # (single-shot, 0 ms) haengt den Refresh hinter den ersten Paint in den
        # naechsten Event-Loop-Tick: Das Cockpit erscheint sofort, die
        # Aggregation laeuft danach. BEWUSST ein Kind-Timer (nicht
        # ``QTimer.singleShot(0, self.refresh)``): wird das Widget vor dem ersten
        # Tick zerstoert (schnelles Erstellen/Zerstoeren, Dock-Wechsel, Tests),
        # stirbt der Kind-Timer mit und feuert NICHT auf ein totes C++-Objekt.
        # ``_wire_auto_refresh`` (2h-Takt + leichter 60s-Takt) bleibt unberuehrt.
        self._initial_refresh_timer = QTimer(self)
        self._initial_refresh_timer.setSingleShot(True)
        # der INITIAL-Refresh laeuft jetzt zusaetzlich im Worker-Thread
        # (nicht nur deferred) — der erste, kalte Aggregat-Lauf hat die ~1-2 s
        # eingefroren. Folge-Refreshs (manuell/Subjekt/Zeitraum/2h) bleiben
        # synchron (warme Raw-Key-DBs, ~35 ms).
        self._initial_refresh_timer.timeout.connect(self._start_initial_refresh)
        self._initial_refresh_timer.start(0)

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(f"background: {c.BG_MAIN};")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        # Fehler-Banner (anfangs versteckt) macht einen fehlgeschlagenen
        # Refresh sichtbar, statt ihn stumm zu schlucken (Button wirkte sonst tot).
        self._error_banner = self._build_error_banner()
        root.addWidget(self._error_banner)

        _hc = HelpRegistry.get("norisk:dashboard")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # 2-Tab-Cockpit (Patrick): das Cockpit war auf ~3 Bildschirmseiten
        # gewachsen. Tab 1 „Überblick" = das Wichtigste auf einen Blick, Tab 2
        # „Details" = alle Detail-Sektionen. ``content``/``content_layout`` ist
        # der Überblick-Tab (bleibt Parent der unten erzeugten Widgets — Detail-
        # Sektionen werden beim Einhängen in den Details-Tab reparentet).
        overview_scroll = QScrollArea(self)
        overview_scroll.setWidgetResizable(True)
        overview_scroll.setFrameShape(QFrame.Shape.NoFrame)
        overview_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 16, 24, 24)
        content_layout.setSpacing(12)

        # 3c (Cockpit Vision B) — Begruessungs-Zeile ganz oben
        # im Content (vor Hero). Vorname aus der Session (gleiche Quelle wie das
        # HeaderWidget der Mainpage); fail-soft auf "Guten Tag!" ohne Name.
        self._greeting_label = QLabel(self._build_greeting_text(), content)
        self._greeting_label.setObjectName("CockpitGreeting")
        self._greeting_label.setTextFormat(Qt.TextFormat.PlainText)
        self._greeting_label.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 18px; font-weight: bold; "
            f"background: transparent; border: none;"
        )

        # 3c — Schnellstart-Leiste direkt nach der Begruessung.
        # Nur wenn ein QuickstartService injiziert wurde (Backwards-Compat:
        # Tests bauen das Widget ohne Services). Cross-Tool-Import lazy
        # innerhalb des Gating-Builders.
        self._quickstart_widget = None
        if self._quickstart_service is not None:
            self._quickstart_widget = self._build_quickstart_widget(content)

        # Phase 4) — Einstiegs-Cockpit: zwei getrennte
        # Score-Kacheln der EIGENEN Sicherheitslage (Selbsteinschätzung/Audit +
        # Messung/Hardening), kein Misch-Score. Ersetzt den frueheren
        # Hardening-Hero-Gauge ganz oben. Beide Kacheln zeigen IMMER SELF
        # (Hardening ist self-only §4) — unabhaengig vom
        # Subjekt-Selektor. Navigation in beide Tools.
        self._cockpit_band = SecurityCockpitBand(content)
        self._cockpit_band.open_audit.connect(
            lambda: self.navigate.emit("customer_audit")
        )
        self._cockpit_band.open_scoring.connect(
            lambda: self.navigate.emit("security_scoring")
        )

        # Folge: Kunden-Audit-Karte. Erscheint UNTER dem Einstiegs-Band,
        # sobald im Header ein Kunden-Subjekt gewählt ist und für dieses ein
        # Audit existiert (``data.customer_audit``). Sie zeigt den Audit-Score
        # DES KUNDEN — getrennt vom self-only Einstiegs-Band. Default unsichtbar.
        self._customer_audit_card = CustomerAuditCard(content)
        self._customer_audit_card.open_audit.connect(
            lambda: self.navigate.emit("customer_audit")
        )
        self._customer_audit_card.setVisible(False)

        # 3c (Cockpit) — Phishing-Radar-Banner.
        # Wird IMMER gebaut: der ctor erlaubt ``view_model=None`` (dann zeigt
        # er den Placeholder-/Empty-State). Cross-Tool-Import lazy.
        self._phishing_radar = self._build_phishing_radar(content)

        # Sektion 1 — „Was hat sich geändert".
        # Cockpit-Perf A: zugeklappt + Lazy-Factory. Das ChangesSection-Inner
        # wird erst beim Aufklappen gebaut und aus den zuletzt aggregierten
        # Daten befuellt (``_build_changes_content``). ``_apply`` ueberspringt
        # die Sektion, solange sie noch nicht gebaut ist.
        self._changes_section: ChangesSection | None = None
        self._section_1 = _DashboardSection(
            "Was hat sich geändert", expanded=False, parent=content
        )
        self._section_1.set_content_factory(self._build_changes_content)

        # Sprint S3c — Score-Vollstaendigkeits-Banner. Sitzt im Cockpit-Layout
        # 3c 1b) direkt unter der Kunden-Audit-Karte (Datenfrische
        # auf einen Blick, noch vor „Empfohlen & Dringend").
        self._completeness_banner = ScoreCompletenessBanner(content)

        # Sektion 2 mit Score-Tile + Halbkreis (S3b) + Quick-Insight-Tiles
        # (S3c W2 + W6) als horizontale Zeile.
        self._score_section = ScoreSection(content)
        self._cert_burndown_tile = CertBurndownTile(content)
        self._cert_burndown_tile.clicked.connect(
            lambda: self.navigate.emit("cert_monitor")
        )
        self._cvss_percentile_widget = CvssPercentileWidget(content)

        section_2_inner = QWidget(content)
        section_2_layout = QHBoxLayout(section_2_inner)
        section_2_layout.setContentsMargins(0, 0, 0, 0)
        section_2_layout.setSpacing(8)
        section_2_layout.addWidget(self._score_section)
        section_2_layout.addWidget(self._cert_burndown_tile)
        section_2_layout.addWidget(self._cvss_percentile_widget)
        section_2_layout.addStretch()

        self._section_2 = _DashboardSection(
            "Score kompakt", expanded=True, parent=content
        )
        self._section_2.set_content(section_2_inner)

        # Sektion 3 — CVE-Liste + Scan-Status. Cockpit-Perf A: zugeklappt +
        # Lazy-Factory (Inner erst beim Aufklappen, aus ``_last_data`` befuellt).
        self._cves_scans_section: CvesScansSection | None = None
        self._section_3 = _DashboardSection(
            "CVE-Liste + Scan-Status", expanded=False, parent=content
        )
        self._section_3.set_content_factory(self._build_cves_scans_content)

        # Sektion 4 — Score-Aufschlüsselung + Trend. Cockpit-Perf A: lazy.
        self._breakdown_trend_section: BreakdownTrendSection | None = None
        self._section_4 = _DashboardSection(
            "Score-Aufschlüsselung + Trend", expanded=False, parent=content
        )
        self._section_4.set_content_factory(self._build_breakdown_trend_content)

        # Sektion 5 — Organisatorische Sicherheit. Cockpit-Perf A: lazy.
        self._organizational_section: OrganizationalSection | None = None
        self._section_5 = _DashboardSection(
            "Organisatorische Sicherheit", expanded=False, parent=content
        )
        self._section_5.set_content_factory(self._build_organizational_content)

        # Sektion Light-SIEM: Event-Pool aus den anderen Tools.
        # Cockpit-Perf A: zugeklappt + Lazy-Factory. Der LightSiemSection-ctor
        # ruft ``reload`` (eigene DB-Reads) — er laeuft jetzt erst beim ersten
        # Aufklappen, nicht beim App-Start.
        self._light_siem_section_inner: LightSiemSection | None = None
        self._section_light_siem = _DashboardSection(
            "Light-SIEM (Event-Pool)", expanded=False, parent=content
        )
        self._section_light_siem.set_content_factory(
            self._build_light_siem_content
        )

        # Sektion Anomaly-Heuristik: Score + Findings ueber dem
        # Light-SIEM-Pool. Cockpit-Perf A: lazy (AnomalySection-ctor ruft
        # ``reload`` mit DB-Reads → erst beim Aufklappen).
        self._anomaly_section_inner: AnomalySection | None = None
        self._section_anomaly = _DashboardSection(
            "Anomalie-Heuristik (Light-SIEM)",
            expanded=False,
            parent=content,
        )
        self._section_anomaly.set_content_factory(self._build_anomaly_content)

        # NIS2-Status: Kompakte Card mit Anzahl offener Vorfaelle
        # und der kuerzesten anstehenden Frist. Klick → Tool oeffnen.
        # Cockpit-Perf A: lazy (Nis2StatusSection-ctor ruft ``refresh`` mit
        # DB-Read → erst beim Aufklappen).
        self._nis2_status_section: Nis2StatusSection | None = None
        self._section_nis2 = _DashboardSection(
            "NIS2-Incidents",
            expanded=False,
            parent=content,
        )
        self._section_nis2.set_content_factory(self._build_nis2_content)

        # Risikomatrix (Patrick): als FESTER, immer sichtbarer Block im
        # Überblick-Tab — kein zugeklapptes Accordion mehr (das war der Grund,
        # warum die Matrix „fehlte"). Inhalt (Matrix oder Empty-State) wird in
        # _refresh_risk_matrix_block aus _last_data.self_audit befüllt; reuse
        # BsiRiskMatrixWidget (Cross-Tool lazy).
        self._risk_matrix_block = self._build_risk_matrix_block()

        # Sprint S4a: Kanban + Notizen aus dem Mainpage als
        # Akkordeon-Sektionen — nur wenn Services gesetzt sind, sonst
        # bleiben die Sektionen weg (z.B. in Tests ohne Mainpage-Stack).
        # Cockpit-Perf A: Kanban + Notizen sind ohnehin zugeklappt — jetzt mit
        # Lazy-Factory, damit ihr ctor (DB-Read aus der Mainpage-DB) erst beim
        # Aufklappen laeuft. ``_apply`` ruft ``.refresh`` nur auf, wenn das
        # Inner bereits gebaut ist (None-Guard unten).
        self._kanban_section: KanbanSection | None = None
        self._notes_section: NotesSection | None = None
        self._section_kanban = None
        self._section_notes = None
        if self._task_service is not None:
            self._section_kanban = _DashboardSection(
                "Aufgaben (Kanban)", expanded=False, parent=content
            )
            self._section_kanban.set_content_factory(self._build_kanban_content)
        if self._journal_service is not None:
            self._section_notes = _DashboardSection(
                "Notizen (Tagesprotokoll)", expanded=False, parent=content
            )
            self._section_notes.set_content_factory(self._build_notes_content)

        # 3c (Cockpit) — „FINLAI empfiehlt" (KiTodoSection): kuratierte
        # Top-3 auto-KI-Todos + Evergreen-Fallback. Im alten Home stand sie
        # prominent; im verschmolzenen Cockpit blieb nur die Hero-Zahl. Nur mit
        # ``task_service`` (wie Kanban/TaskSnippet). Inhaltlich verschieden vom
        # TaskSnippet (Board-Top-N) — beide bleiben absichtlich.
        self._ki_todo_section_widget = None
        self._section_ki_todo = None
        if self._task_service is not None:
            self._ki_todo_section_widget = self._build_ki_todo_section(content)
            if self._ki_todo_section_widget is not None:
                self._section_ki_todo = _DashboardSection(
                    "FINLAI empfiehlt", expanded=True, parent=content
                )
                self._section_ki_todo.set_content(self._ki_todo_section_widget)

        # 3c (Cockpit) — Empfohlen-&-Dringend-Snippet (TaskSnippet) als
        # Akkordeon-Sektion. Nur wenn ein TaskService da ist (wie Kanban).
        # Der Board-Sprung nutzt den Deeplink-Kontrakt wie das Mainpage-
        # ``_open_board`` (open_with_filter → Kanban-Sektion aufklappen).
        self._task_snippet_widget = None
        self._section_task_snippet = None
        if self._task_service is not None:
            self._task_snippet_widget = self._build_task_snippet(content)
            if self._task_snippet_widget is not None:
                self._section_task_snippet = _DashboardSection(
                    "Empfohlen & Dringend", expanded=True, parent=content
                )
                self._section_task_snippet.set_content(self._task_snippet_widget)

        # 3c (Cockpit) — Letzte Aktivitaeten (ActivityWidget) als
        # eingeklappte Akkordeon-Sektion ganz unten. Braucht keinen Service
        # (liest direkt aus dem Audit-Log). Cockpit-Perf A: Lazy-Factory — das
        # ActivityWidget (Audit-Log-Read im ctor) entsteht erst beim
        # Aufklappen. ``_content`` parkt das gebaute Widget fuer den 60s-/Apply-
        # Refresh (``_light_home_widgets`` liest es ueber ``_section_activity``).
        self._activity_widget: QWidget | None = None
        self._section_activity = _DashboardSection(
            "Letzte Aktivitäten", expanded=False, parent=content
        )
        self._section_activity.set_content_factory(self._build_activity_content)

        # Cockpit-Inc-2: 4 At-a-glance-Status-Kacheln (Patch /
        # Netzwerk / Supply-Chain / Passwörter), je Klick-Deeplink.
        self._status_tiles = StatusTilesSection(content)
        self._status_tiles.navigate.connect(self.navigate.emit)
        self._status_tiles.open_with_filter.connect(self.open_with_filter.emit)

        # ── 3-Tab-Cockpit (Patrick-Layout) ───────────────────────────────────
        # Konstruktion (oben) und Einhängen (hier) bleiben entkoppelt, damit die
        # Ziel-Ordnung an EINER Stelle ablesbar ist. Gegatete/fehlgeschlagene
        # Sektionen sind ``None`` und werden übersprungen.
        #
        # Tab 1 „Überblick" — Empfehlungen, Phishing, eigene Sicherheitslage
        # (Scores + Status + Vollständigkeit), Risikomatrix, dringende Aufgaben.
        overview_sections = (
            self._greeting_label,        # Begrüßung (oben)
            self._quickstart_widget,     # Schnellstart (oben)
            self._section_ki_todo,       # 1. „FINLAI empfiehlt"
            self._phishing_radar,        # 2. Phishing-Radar
            self._cockpit_band,          # 3. Eigene Sicherheitslage — Score-Kacheln
            self._status_tiles,          # 3. Eigene Sicherheitslage — Status-Kacheln
            self._completeness_banner,   # 3. Eigene Sicherheitslage — Vollständigkeit
            self._risk_matrix_block,     # 4. Risikomatrix
            self._section_task_snippet,  # 5. „Empfohlen & Dringend"
            self._customer_audit_card,   # Kunden-Audit-Karte (nur bei Kunden-Subjekt)
        )
        for section in overview_sections:
            if section is not None:
                content_layout.addWidget(section)
        content_layout.addStretch()

        # Tab 2 „Details" — technische Detail-Sektionen (Lazy wie bisher).
        details_content = QWidget()
        details_layout = QVBoxLayout(details_content)
        details_layout.setContentsMargins(24, 16, 24, 24)
        details_layout.setSpacing(12)
        detail_sections = (
            self._section_light_siem,    # 1. Light-SIEM (Event-Pool)
            self._section_anomaly,       # 2. Anomalie-Heuristik
            self._section_1,             # 3. „Was hat sich geändert"
            self._section_3,             # 4. CVE-Liste + Scan-Status
            self._section_5,             # 5. Organisatorische Sicherheit
            self._section_2,             # 6. Score kompakt
            self._section_4,             # 7. Score-Aufschlüsselung + Trend
        )
        for section in detail_sections:
            if section is not None:
                details_layout.addWidget(section)
        details_layout.addStretch()

        # Tab 3 „Arbeitsbereich" — operativer Bereich (Vorfälle/Aufgaben/Notizen).
        workspace_content = QWidget()
        workspace_layout = QVBoxLayout(workspace_content)
        workspace_layout.setContentsMargins(24, 16, 24, 24)
        workspace_layout.setSpacing(12)
        workspace_sections = (
            self._section_nis2,          # 1. NIS2-Incident-Tracker
            self._section_kanban,        # 2. Aufgaben (Kanban)
            self._section_notes,         # 3. Notizen
            self._section_activity,      # Letzte Aktivitäten (unten)
        )
        for section in workspace_sections:
            if section is not None:
                workspace_layout.addWidget(section)
        workspace_layout.addStretch()

        overview_scroll.setWidget(content)
        details_scroll = self._build_tab_scroll(details_content)
        workspace_scroll = self._build_tab_scroll(workspace_content)

        # QTabWidget erbt das globale Tab-Styling aus core/theme.py (keine
        # hardcodierten Farben, R1). Default-Tab = „Überblick" (Index 0).
        self._tabs = QTabWidget(self)
        self._tabs.setObjectName("DashboardTabs")
        self._tabs.addTab(overview_scroll, "Überblick")
        self._tabs.addTab(details_scroll, "Details")
        self._tabs.addTab(workspace_scroll, "Arbeitsbereich")
        # 4. Reiter „Workflow" — gefuehrter Leitfaden. Bewusst NICHT der
        # Default-Tab (Patrick 2026-07-02): Standard bleibt „Überblick" (Index 0).
        self._build_workflow_tab()
        self._tabs.setCurrentIndex(0)
        # Arbeitsbereich-Sektionen beim ersten Öffnen des Tabs aufklappen, damit
        # Vorfälle/Board/Notizen als Inhalt sichtbar sind (DB-Read erst beim
        # Tab-Wechsel, nicht im Startup-Pfad).
        self._tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self._tabs, stretch=1)

        # Risikomatrix-Block initial befüllen (Empty-State bis _apply Daten hat).
        self._refresh_risk_matrix_block()

    # ------------------------------------------------------------------
    # 3c (Cockpit) — Komposition der einzigartigen Home-Bestandteile
    # ------------------------------------------------------------------

    @staticmethod
    def _greeting_for_hour(hour: int) -> str:
        """Tageszeit-abhaengige Anrede (gleiche Logik wie HeaderWidget._get_greeting).

        Args:
            hour: Stunde 0..23 (typisch ``datetime.now.hour``).

        Returns:
            „Guten Morgen" (<12), „Guten Tag" (<17), „Guten Abend" (<21),
            sonst „Gute Nacht".
        """
        if hour < 12:
            return "Guten Morgen"
        if hour < 17:
            return "Guten Tag"
        if hour < 21:
            return "Guten Abend"
        return "Gute Nacht"

    @staticmethod
    def _build_greeting_text() -> str:
        """Baut die Begruessungs-Zeile „{Anrede}, {Vorname}! · {Datum}".

        Die Anrede ist tageszeit-abhaengig 3c, gleiche Logik wie das
        Mainpage-``HeaderWidget``: Morgen/Tag/Abend/Nacht nach Stunde) —
        fruehere fixe „Guten Tag"-Zeile entfaellt. Vorname kommt aus der
        ``Session`` (``first_name`` → ``full_name`` → ``username``). Fail-soft:
        ohne angemeldeten User oder bei jedem Fehler bleibt es bei der reinen
        Anrede ohne Namen.

        Returns:
            Die fertige Begruessungs-Zeile (PlainText).
        """
        from datetime import datetime  # noqa: PLC0415

        _weekdays = (
            "Montag",
            "Dienstag",
            "Mittwoch",
            "Donnerstag",
            "Freitag",
            "Samstag",
            "Sonntag",
        )
        _months = (
            "Januar",
            "Februar",
            "März",
            "April",
            "Mai",
            "Juni",
            "Juli",
            "August",
            "September",
            "Oktober",
            "November",
            "Dezember",
        )
        name = ""
        try:
            from core.auth.session import Session  # noqa: PLC0415

            user = Session().current_user
            if user is not None:
                name = (
                    getattr(user, "first_name", "")
                    or getattr(user, "full_name", "")
                    or getattr(user, "username", "")
                    or ""
                )
        except Exception as exc:  # noqa: BLE001 -- Begruessung darf nie crashen
            log.info("Begruessungs-Name nicht verfuegbar: %s", type(exc).__name__)
            name = ""

        now = datetime.now()
        anrede = NoRiskDashboardWidget._greeting_for_hour(now.hour)
        datum = f"{_weekdays[now.weekday()]}, {now.day}. {_months[now.month - 1]} {now.year}"
        if name:
            return f"{anrede}, {name}!  ·  {datum}"
        return f"{anrede}!  ·  {datum}"

    def _build_quickstart_widget(self, parent: QWidget) -> QWidget | None:
        """Baut die Schnellstart-Leiste fail-soft 3c).

        ``tool_requested`` → ``self.navigate`` (Sidebar-Sprung). Cross-Tool-
        Import lazy. Returns ``None`` bei jedem Bau-Fehler, damit
        ein defektes Sub-Widget das Cockpit nicht zerreisst.
        """
        try:
            from tools.mainpage.gui.quickstart_widget import (  # noqa: PLC0415
                QuickstartWidget,
            )

            widget = QuickstartWidget(self._quickstart_service, parent)
            widget.tool_requested.connect(self.navigate.emit)
            return widget
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf das Cockpit nie crashen
            log.warning(
                "Schnellstart-Leiste nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    def _build_phishing_radar(self, parent: QWidget) -> QWidget | None:
        """Baut den Phishing-Radar-Banner fail-soft 3c).

        Der Banner wird auch ohne ViewModel gebaut (ctor erlaubt ``None``).
        Cross-Tool-Import lazy. Returns ``None`` nur, wenn schon der
        Bau scheitert.
        """
        try:
            from tools.mainpage.gui.phishing_radar_banner import (  # noqa: PLC0415
                PhishingRadarBanner,
            )

            return PhishingRadarBanner(
                view_model=self._phishing_view_model, parent=parent
            )
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf das Cockpit nie crashen
            log.warning(
                "Phishing-Radar-Banner nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    def _build_task_snippet(self, parent: QWidget) -> QWidget | None:
        """Baut das Empfohlen-&-Dringend-Snippet fail-soft 3c).

        ``board_requested`` springt analog zum Mainpage-``_open_board`` auf das
        Kanban-Board des Cockpits: ``open_with_filter("norisk:dashboard",
        "kanban")`` — die Routing-Schicht (separat) klappt darauf die
        Kanban-Sektion via ``apply_navigation(section="kanban")`` auf.
        Cross-Tool-Import lazy.
        """
        try:
            from tools.mainpage.gui.task_snippet_widget import (  # noqa: PLC0415
                TaskSnippetWidget,
            )

            widget = TaskSnippetWidget(self._task_service, parent)
            widget.board_requested.connect(
                lambda: self.open_with_filter.emit("norisk:dashboard", "kanban")
            )
            return widget
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf das Cockpit nie crashen
            log.warning(
                "Aufgaben-Snippet nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    def _build_ki_todo_section(self, parent: QWidget) -> QWidget | None:
        """Baut die „FINLAI empfiehlt"-Sektion (KiTodoSection) fail-soft 3c).

        Zeigt die Top-3 auto-KI-Todos als Karten + Evergreen-Fallback (<3 echte
        Todos). Nur sinnvoll mit ``task_service`` — der Aufrufer baut sie nur,
        wenn einer da ist. Cross-Tool-Import lazy. Falls die Sektion
        ein Navigations-Signal traegt (aktuell nicht), wird es duck-typed an die
        Cockpit-Signale gehaengt. Returns ``None`` bei jedem Bau-Fehler, damit
        ein defektes Sub-Widget das Cockpit nicht zerreisst.
        """
        try:
            from tools.mainpage.gui.ki_todo_section import (  # noqa: PLC0415
                KiTodoSection,
            )

            # Perf (Cockpit-Startup, gemessen ~46 ms): den ersten refresh
            # (DB-Query Top-3-Todos + Karten-Render) per QTimer(0) auf nach dem
            # ersten Paint verschieben -> Cockpit erscheint schneller, die
            # Empfehlungskarten fuellen sich einen Tick spaeter.
            widget = KiTodoSection(
                self._task_service, parent, defer_initial_refresh=True
            )
            # KiTodoSection traegt aktuell kein Navigations-Signal; duck-typed
            # verdrahten, falls ein spaeteres Drill-Down (Sprint S3a) eines
            # ergaenzt — fail-soft, ohne harte Kopplung an die Signatur.
            for sig_name, slot in (
                ("tool_requested", self.navigate.emit),
                ("navigate", self.navigate.emit),
            ):
                sig = getattr(widget, sig_name, None)
                if sig is not None and hasattr(sig, "connect"):
                    try:
                        sig.connect(slot)
                    except (AttributeError, TypeError):
                        pass
            return widget
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf das Cockpit nie crashen
            log.warning(
                "FINLAI-empfiehlt-Sektion nicht verfuegbar: %s",
                type(exc).__name__,
            )
            return None

    def _build_activity_widget(self, parent: QWidget) -> QWidget | None:
        """Baut die Letzte-Aktivitaeten-Karte fail-soft 3c).

        Kein Service noetig (liest direkt aus dem Audit-Log). Cross-Tool-
        Import lazy. Returns ``None`` bei Bau-Fehler.
        """
        try:
            from tools.mainpage.gui.activity_widget import (  # noqa: PLC0415
                ActivityWidget,
            )

            return ActivityWidget(parent)
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf das Cockpit nie crashen
            log.warning(
                "Aktivitaeten-Karte nicht verfuegbar: %s", type(exc).__name__
            )
            return None

    # ------------------------------------------------------------------
    # Cockpit-Perf A — Lazy-Content-Factories (Bau erst beim 1. Aufklappen)
    # ------------------------------------------------------------------

    @staticmethod
    def _lazy_empty_state(text: str) -> QWidget:
        """Empty-State-Platzhalter, wenn der Bau einer Lazy-Sektion scheitert.

        Eine Lazy-Factory MUSS immer ein Widget liefern (``set_content`` darf
        kein ``None`` bekommen). Schlaegt der eigentliche Sektions-Aufbau fehl,
        zeigt dieser gedaempfte Hinweis statt eines Crashs.

        Args:
            text: Anzuzeigender Hinweistext (Sie-Form).

        Returns:
            Ein themisiertes ``QLabel`` als Empty-State.
        """
        c = theme.get()
        label = QLabel(text)
        label.setObjectName("DashboardLazyEmptyState")
        label.setWordWrap(True)
        label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-style: italic; padding: 12px;"
        )
        return label

    def _build_changes_content(self) -> QWidget:
        """Lazy-Factory fuer „Was hat sich geändert" (Cockpit-Perf A).

        Baut die ``ChangesSection`` und befuellt sie aus dem zuletzt
        aggregierten ``_last_data`` (oder leer, wenn noch nichts geladen).
        """
        section = ChangesSection()
        self._changes_section = section
        if self._last_data is not None:
            section.update_data(
                self._last_data.changes, self._last_data.time_range
            )
        return section

    def _build_cves_scans_content(self) -> QWidget:
        """Lazy-Factory fuer „CVE-Liste + Scan-Status" (Cockpit-Perf A)."""
        section = CvesScansSection()
        section.cve_clicked.connect(self._on_cve_clicked)
        self._cves_scans_section = section
        if self._last_data is not None:
            section.update_data(self._last_data.cves, self._last_data.scans)
        return section

    def _build_breakdown_trend_content(self) -> QWidget:
        """Lazy-Factory fuer „Score-Aufschlüsselung + Trend" (Cockpit-Perf A)."""
        section = BreakdownTrendSection()
        self._breakdown_trend_section = section
        if self._last_data is not None:
            section.update_data(
                self._last_data.breakdown, self._last_data.trend
            )
        return section

    def _build_organizational_content(self) -> QWidget:
        """Lazy-Factory fuer „Organisatorische Sicherheit" (Cockpit-Perf A)."""
        section = OrganizationalSection()
        section.navigate.connect(self.navigate.emit)
        self._organizational_section = section
        if self._last_data is not None:
            section.update_data(self._last_data.org)
        return section

    def _build_light_siem_content(self) -> QWidget:
        """Lazy-Factory fuer die Light-SIEM-Sektion (Cockpit-Perf A).

        Der ``LightSiemSection``-ctor ruft ``reload`` mit eigenen DB-Reads —
        er laeuft dadurch erst beim Aufklappen, nicht beim App-Start. Self-
        loading: ``_apply`` befuellt diese Sektion nicht. fail-soft mit
        Empty-State, falls schon der ctor scheitert.
        """
        try:
            section = LightSiemSection()
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning("Light-SIEM-Sektion nicht verfuegbar: %s", type(exc).__name__)
            return self._lazy_empty_state(
                "Der Light-SIEM-Event-Pool konnte nicht geladen werden."
            )
        self._light_siem_section_inner = section
        return section

    def _build_anomaly_content(self) -> QWidget:
        """Lazy-Factory fuer die Anomalie-Heuristik-Sektion (Cockpit-Perf A).

        Der ``AnomalySection``-ctor ruft ``reload`` mit DB-Reads → erst beim
        Aufklappen. Self-loading; fail-soft mit Empty-State.
        """
        try:
            section = AnomalySection()
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning("Anomalie-Sektion nicht verfuegbar: %s", type(exc).__name__)
            return self._lazy_empty_state(
                "Die Anomalie-Heuristik konnte nicht geladen werden."
            )
        self._anomaly_section_inner = section
        return section

    def _build_nis2_content(self) -> QWidget:
        """Lazy-Factory fuer die NIS2-Status-Sektion (Cockpit-Perf A).

        Der ``Nis2StatusSection``-ctor ruft ``refresh`` mit DB-Read → erst
        beim Aufklappen. Self-loading; fail-soft mit Empty-State.
        """
        try:
            section = Nis2StatusSection()
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning("NIS2-Sektion nicht verfuegbar: %s", type(exc).__name__)
            return self._lazy_empty_state(
                "Der NIS2-Incident-Status konnte nicht geladen werden."
            )
        section.tool_requested.connect(
            lambda: self.open_with_filter.emit("customer_audit", "nis2")
        )
        self._nis2_status_section = section
        return section

    def _build_risk_matrix_content(self) -> QWidget:
        """Lazy-Factory fuer die Risikomatrix-Sektion (read-only, 2026-06-28).

        Zeigt die Risikomatrix des JUENGSTEN SELF-Audits read-only im Cockpit
        (Patrick: die Matrix soll auch ausserhalb des Wizards sichtbar sein).
        Liest die Bewertungen aus der DB (``RiskAssessmentService.load`` —
        Stand: zuletzt berechnet); Cross-Tool-Importe lazy. fail-soft
        mit Empty-State. Die ``audit_id`` kommt aus ``DashboardData.self_audit``.
        """
        self_audit = (
            self._last_data.self_audit if self._last_data is not None else None
        )
        audit_id = getattr(self_audit, "audit_id", "") if self_audit else ""
        if not audit_id:
            return self._lazy_empty_state(
                "Noch kein Selbst-Audit berechnet. Im Security-Audit ein Audit "
                "ausfüllen und berechnen — die Risikomatrix erscheint dann hier."
            )
        try:
            from tools.customer_audit.application.risk_assessment_service import (  # noqa: PLC0415
                RiskAssessmentService,
            )
            from tools.customer_audit.gui.widgets.bsi_risk_matrix_widget import (  # noqa: PLC0415
                BsiRiskMatrixWidget,
            )

            assessments = RiskAssessmentService().load(audit_id)
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning(
                "Risikomatrix-Sektion nicht verfuegbar: %s", type(exc).__name__
            )
            return self._lazy_empty_state(
                "Die Risikomatrix konnte nicht geladen werden."
            )
        if not assessments:
            return self._lazy_empty_state(
                "Für das aktuelle Audit liegen noch keine Risiko-Bewertungen vor "
                "(im Security-Audit auf „Berechnen“ klicken)."
            )
        widget = BsiRiskMatrixWidget()
        widget.set_assessments(assessments)
        return widget

    def _build_risk_matrix_block(self) -> QWidget:
        """Baut den festen Risikomatrix-Block fuer den Überblick-Tab.

        Patrick: die Matrix soll IMMER sichtbar sein (kein zugeklapptes
        Accordion). Ein betiteltes Container-Widget mit Host-Layout; der Inhalt
        (Matrix oder Empty-State) wird in:meth:`_refresh_risk_matrix_block`
        aus ``_last_data.self_audit`` befüllt — leer beim Bau (noch keine
        Daten), gefüllt nach dem ersten ``_apply``.

        Returns:
            Das Container-Widget (Überschrift + Host fuer den Matrix-Inhalt).
        """
        c = theme.get()
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        heading = QLabel("Risikomatrix (letzter Selbst-Audit)")
        heading.setObjectName("CockpitRiskMatrixHeading")
        heading.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 13px; font-weight: bold;"
        )
        layout.addWidget(heading)
        self._risk_matrix_host = QWidget()
        self._risk_matrix_host_layout = QVBoxLayout(self._risk_matrix_host)
        self._risk_matrix_host_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._risk_matrix_host)
        return block

    def _refresh_risk_matrix_block(self) -> None:
        """Befüllt den Risikomatrix-Host mit Matrix oder Empty-State neu.

        Wird im:meth:`_build_ui` (Initial-Empty-State) und am Ende von
:meth:`_apply` (nachdem ``_last_data`` gesetzt ist) aufgerufen, sodass
        die Matrix nach jedem schweren Refresh den aktuellen Stand zeigt.
        """
        layout = self._risk_matrix_host_layout
        while layout.count():
            item = layout.takeAt(0)
            old = item.widget()
            if old is not None:
                old.deleteLater()
        layout.addWidget(self._build_risk_matrix_content())

    def _build_tab_scroll(self, content: QWidget) -> QScrollArea:
        """Erzeugt einen einheitlichen Scroll-Container für einen Cockpit-Tab.

        Args:
            content: Das Inhalts-Widget, das gescrollt werden soll.

        Returns:
            Ein ``QScrollArea`` (resizable, rahmenlos, ohne horizontale
            Scrollbar) mit ``content`` als Inhalt.
        """
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        scroll.setWidget(content)
        return scroll

    def _on_tab_changed(self, index: int) -> None:
        """Klappt die Arbeitsbereich-Sektionen beim Öffnen des Tabs auf.

        NIS2/Aufgaben/Notizen sollen im Arbeitsbereich-Tab als Inhalt sichtbar
        sein, nicht als zugeklappte Header (Patrick). ``set_expanded(True)`` ist
        ein No-op, wenn die Sektion bereits offen ist — die Lazy-Factory
        (DB-Read) läuft also nur beim ersten Tab-Wechsel, nicht im Startup-Pfad.

        Args:
            index: Index des nun aktiven Tabs (2 == „Arbeitsbereich").
        """
        # Workflow-Tab beim Oeffnen (lazy) mit dem aktuellen Subjekt laden.
        if (
            self._workflow_tab_index is not None
            and index == self._workflow_tab_index
        ):
            self._load_workflow_tab()
            return
        if index != 2:
            return
        for section in (
            self._section_nis2,
            self._section_kanban,
            self._section_notes,
        ):
            if section is not None and not section.is_expanded():
                section.set_expanded(True)

    def _build_kanban_content(self) -> QWidget:
        """Lazy-Factory fuer die Kanban-Sektion (Cockpit-Perf A).

        Der ``KanbanSection``-ctor liest aus der Mainpage-DB → erst beim
        Aufklappen. fail-soft mit Empty-State.
        """
        try:
            section = KanbanSection(self._task_service)
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning("Kanban-Sektion nicht verfuegbar: %s", type(exc).__name__)
            return self._lazy_empty_state(
                "Das Aufgaben-Board konnte nicht geladen werden."
            )
        self._kanban_section = section
        return section

    def _build_notes_content(self) -> QWidget:
        """Lazy-Factory fuer die Notizen-Sektion (Cockpit-Perf A).

        Der ``NotesSection``-ctor liest aus der Mainpage-DB → erst beim
        Aufklappen. fail-soft mit Empty-State.
        """
        try:
            section = NotesSection(self._journal_service)
        except Exception as exc:  # noqa: BLE001 -- Sektion darf das Cockpit nie crashen
            log.warning("Notizen-Sektion nicht verfuegbar: %s", type(exc).__name__)
            return self._lazy_empty_state(
                "Das Tagesprotokoll konnte nicht geladen werden."
            )
        self._notes_section = section
        return section

    def _build_activity_content(self) -> QWidget:
        """Lazy-Factory fuer die „Letzte Aktivitäten"-Sektion (Cockpit-Perf A).

        Das ``ActivityWidget`` liest aus dem Audit-Log → erst beim Aufklappen.
        Das gebaute Widget wird in ``_activity_widget`` geparkt, damit der
        leichte 60s-/Apply-Refresh es danach mitnehmen kann. fail-soft mit
        Empty-State.
        """
        widget = self._build_activity_widget(self)
        if widget is None:
            return self._lazy_empty_state(
                "Die letzten Aktivitäten konnten nicht geladen werden."
            )
        self._activity_widget = widget
        return widget

    def _build_header(self) -> QWidget:
        c = theme.get()
        header = QFrame(self)
        header.setObjectName("dashboardHeader")
        header.setFixedHeight(56)
        header.setStyleSheet(
            f"#dashboardHeader {{ background: {c.BG_SIDEBAR_HEADER}; "
            f"border-bottom: 1px solid {c.BORDER}; }}"
        )
        lay = QHBoxLayout(header)
        lay.setContentsMargins(24, 8, 24, 8)
        lay.setSpacing(12)

        title = QLabel("NoRisk Dashboard", header)
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 16px; font-weight: bold;"
        )
        lay.addWidget(title)

        self._last_refresh_label = QLabel("", header)
        self._last_refresh_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        lay.addWidget(self._last_refresh_label)

        lay.addStretch()

        # Subjekt-Selektor (nur wenn Subjekte verfügbar; sonst bleibt
        # der Header wie bisher). Erbt das globale QComboBox-Theme.
        self._subject_selector = self._build_subject_selector(header)
        if self._subject_selector is not None:
            subject_label = QLabel("Subjekt:", header)
            subject_label.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 12px;")
            lay.addWidget(subject_label)
            lay.addWidget(self._subject_selector)

        self._time_filter = _TimeFilter(TimeRange.WEEK, header)
        self._time_filter.range_changed.connect(self._on_range_changed)
        lay.addWidget(self._time_filter)

        _tip_time = self._help_tip("time_filter")
        if _tip_time:
            lay.addWidget(HelpButton(_tip_time))

        self._export_btn = QPushButton("Als PDF exportieren", header)
        self._export_btn.setIcon(get_icon(Icons.PDF))
        self._export_btn.setToolTip(
            "Compliance-Report für externe Prüfer als PDF speichern"
        )
        self._export_btn.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; "
            f"padding: 4px 10px; }} "
            f"QPushButton:hover {{ border-color: {theme.DARK_ACCENT}; "
            f"color: {theme.DARK_ACCENT}; }} "
            f"QPushButton:disabled {{ color: {c.TEXT_DIM}; }}"
        )
        self._export_btn.clicked.connect(self._on_export_clicked)
        lay.addWidget(self._export_btn)

        _tip_pdf = self._help_tip("btn_export_pdf")
        if _tip_pdf:
            lay.addWidget(HelpButton(_tip_pdf))

        self._refresh_btn = QPushButton("", header)
        self._refresh_btn.setIcon(get_icon(Icons.REFRESH))
        self._refresh_btn.setFixedSize(32, 32)
        self._refresh_btn.setToolTip("Dashboard neu laden")
        self._refresh_btn.setStyleSheet(
            f"QPushButton {{ background: {c.BG_BUTTON}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px; }} "
            f"QPushButton:hover {{ border-color: {theme.DARK_ACCENT}; }}"
        )
        self._refresh_btn.clicked.connect(self.refresh)
        lay.addWidget(self._refresh_btn)

        return header

    # ------------------------------------------------------------------
    # Auto-Refresh
    # ------------------------------------------------------------------

    def _wire_auto_refresh(self) -> None:
        self._timer = QTimer(self)
        self._timer.setInterval(_AUTO_REFRESH_MS)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self._wire_light_refresh()

    def _wire_light_refresh(self) -> None:
        """Leichter 60s-Takt fuer die Home-Widgets 3c).

        Refresht NUR die leichten Home-Widgets (``_light_home_widgets``) und
        NIE den schweren 2h-Aggregator. So bleiben KiTodo/TaskSnippet/Activity/
        Quickstart/Phishing minuetlich frisch, wie im alten Mainpage-Home, ohne
        den teuren Cross-Tool-Scan-Stack jede Minute laufen zu lassen. fail-soft
        ueber ``_refresh_home_widget`` (jedes Widget einzeln gekapselt).
        """
        self._light_timer = QTimer(self)
        self._light_timer.setInterval(_LIGHT_REFRESH_MS)
        self._light_timer.timeout.connect(self._refresh_light_home_widgets)
        self._light_timer.start()

    def _refresh_light_home_widgets(self) -> None:
        """Refresht alle leichten Home-Widgets (60s-Takt 3c)."""
        for widget in self._light_home_widgets():
            self._refresh_home_widget(widget)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("norisk:dashboard")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "norisk:dashboard", parent=self.window()
        )
        dlg.show()

    # ------------------------------------------------------------------
    # Refresh-Logik
    # ------------------------------------------------------------------

    def _on_range_changed(self, tr: TimeRange) -> None:
        self._current_range = tr
        self.refresh()

    # ------------------------------------------------------------------
    # Subjekt-Selektor
    # ------------------------------------------------------------------

    def _subject_options(self) -> list[tuple[str, str]]:
        """Holt die ``(subject_id, Anzeigename)``-Paare fail-soft vom Aggregator.

        Robust gegen Aggregatoren ohne ``subjects`` (Fakes/Mocks in Tests)
        und gegen Loader-Fehler → dann leere Liste (kein Selektor).
        """
        loader = getattr(self._aggregator, "subjects", None)
        if loader is None:
            return []
        try:
            return [
                opt
                for opt in (loader() or [])
                if isinstance(opt, tuple) and len(opt) == 2
            ]
        except Exception as exc:  # noqa: BLE001 -- Mock/Loader-Fehler → kein Selektor
            log.info("Subjekt-Selektor: keine Subjekte (%s)", type(exc).__name__)
            return []

    def _build_subject_selector(self, parent: QWidget) -> QComboBox | None:
        """Baut das Subjekt-Dropdown oder ``None``, wenn es keine Subjekte gibt.

        Erster Eintrag ist immer ``"Allgemein"`` (``subject_id=None``) — der
        bisherige Default-Pfad. Erscheint nur, wenn der Store mindestens ein
        Subjekt liefert (frische Installation ohne Profile → kein Selektor).
        """
        options = self._subject_options()
        if not options:
            return None
        combo = QComboBox(parent)
        combo.setObjectName("dashboardSubjectSelector")
        combo.setToolTip("Bewertetes Subjekt wählen (eigenes System oder Kunde)")
        combo.setMinimumWidth(180)
        # Höhe an die Header-Nachbarn (_TimeFilter 28px) angleichen, damit die
        # Baseline im 56px-Header nicht verspringt.
        combo.setFixedHeight(28)
        combo.addItem("Allgemein", userData=None)
        for subject_id, label in options:
            combo.addItem(label, userData=subject_id)
        combo.currentIndexChanged.connect(self._on_subject_changed)
        return combo

    def _on_subject_changed(self, _index: int) -> None:
        """Übernimmt die Subjekt-Auswahl und lädt das Dashboard neu."""
        sid = self._subject_selector.currentData()
        self._current_subject_id = sid or None
        self._current_subject_label = self._subject_selector.currentText()
        self.refresh()
        # der Workflow-Tab spiegelt das gewaehlte Subjekt (falls sichtbar).
        if (
            self._workflow_tab is not None
            and self._workflow_tab_index is not None
            and self._tabs.currentIndex() == self._workflow_tab_index
        ):
            self._load_workflow_tab()

    def _build_error_banner(self) -> QFrame:
        """Baut das anfangs versteckte Fehler-Banner für fehlgeschlagene Refreshs.

        Returns:
            Ein verstecktes ``QFrame`` mit Warn-Icon, Meldung und
            „Erneut versuchen"-Button.
        """
        c = theme.get()
        banner = QFrame(self)
        banner.setObjectName("DashboardErrorBanner")
        banner.setVisible(False)
        lay = QHBoxLayout(banner)
        lay.setContentsMargins(24, 8, 24, 8)
        lay.setSpacing(10)

        icon = QLabel(banner)
        icon.setPixmap(get_icon(Icons.WARNING).pixmap(20, 20))
        lay.addWidget(icon)

        self._error_label = QLabel("", banner)
        self._error_label.setObjectName("DashboardErrorText")
        self._error_label.setTextFormat(Qt.TextFormat.PlainText)
        self._error_label.setWordWrap(True)
        lay.addWidget(self._error_label, 1)

        retry = QPushButton("Erneut versuchen", banner)
        retry.setObjectName("DashboardErrorRetry")
        retry.setIcon(get_icon(Icons.REFRESH))
        retry.clicked.connect(self.refresh)
        lay.addWidget(retry)

        banner.setStyleSheet(
            f"QFrame#DashboardErrorBanner {{ background: {theme.BG_PANEL_ERROR};"
            f" border: 1px solid {c.ERROR}; border-radius: 6px; }}"
            f"QLabel#DashboardErrorText {{ color: {c.TEXT_MAIN}; font-size: 13px;"
            f" background: transparent; border: none; }}"
            f"QPushButton#DashboardErrorRetry {{ background: {c.BG_BUTTON};"
            f" color: {c.TEXT_MAIN}; border: 1px solid {c.ERROR};"
            f" border-radius: 4px; padding: 4px 12px; }}"
            f"QPushButton#DashboardErrorRetry:hover {{"
            f" border-color: {theme.DARK_ACCENT}; }}"
        )
        return banner

    def apply_navigation(self, **kwargs: object) -> None:
        """Empfangs-Pattern für ``MainWindow.navigate_to(..., section=...)``.

        Erkannte kwargs AP3):
            ``section="kanban"`` — klappt die Kanban-Sektion auf, damit
            der „Alle im Board →"-Sprung vom Homescreen nicht vor einem
            zugeklappten Akkordeon endet.

        Andere kwargs werden ignoriert (forward-kompatibel).
        """
        section = kwargs.get("section")
        if (
            section == "workflow"
            and self._workflow_tab_index is not None
            and getattr(self, "_tabs", None) is not None
        ):
            self._tabs.setCurrentIndex(self._workflow_tab_index)
            return
        if section == "kanban" and getattr(self, "_section_kanban", None) is not None:
            # Kanban liegt im Arbeitsbereich-Tab (Index 2) — dorthin wechseln
            # (_on_tab_changed klappt die Sektion dann auf), sonst klappt sie im
            # inaktiven Tab auf und bleibt unsichtbar.
            if getattr(self, "_tabs", None) is not None:
                self._tabs.setCurrentIndex(2)
            self._section_kanban.set_expanded(True)

    # ------------------------------------------------------------------
    # Workflow-Tab (gefuehrter Leitfaden, 4. Reiter)
    # ------------------------------------------------------------------

    def _build_workflow_tab(self) -> None:
        """Baut den 4. Cockpit-Reiter „Workflow" (best-effort).

        Ohne ``workflow_service`` (Bau fehlgeschlagen) wird der Tab nicht
        angelegt — das restliche Cockpit bleibt unberuehrt. Der Inhalt wird erst
        beim ersten Oeffnen des Tabs geladen (:meth:`_load_workflow_tab`).
        """
        if self._workflow_service is None:
            return
        try:
            from tools.norisk_dashboard.gui.section_workflow import (
                WorkflowTabWidget,
            )

            tab = WorkflowTabWidget(self._workflow_service, self)
            tab.navigate.connect(self.navigate.emit)
            scroll = self._build_tab_scroll(tab)
            self._workflow_tab = tab
            self._workflow_tab_index = self._tabs.addTab(scroll, "Workflow")
        except Exception as exc:  # noqa: BLE001 — Tab darf das Cockpit nie crashen
            log.warning("Workflow-Tab nicht gebaut: %s", type(exc).__name__)
            self._workflow_tab = None
            self._workflow_tab_index = None

    def _load_workflow_tab(self) -> None:
        """Laedt den Workflow-Tab mit dem aktuell gewaehlten Subjekt."""
        if self._workflow_tab is None:
            return
        subject = self._resolve_workflow_subject()
        self._workflow_tab.load(subject)

    def _resolve_workflow_subject(self):  # noqa: ANN202 — Subject | None
        """Loest die Subjekt-Auswahl in ein ``Subject`` auf.

        „Allgemein" (``_current_subject_id is None``) -> eigenes System (SELF);
        ein Kunden-Subjekt -> ueber den ``SubjectStore``. ``None`` bei fehlendem
        Store/Subjekt (der Tab zeigt dann einen Hinweiszustand).
        """
        store = self._subject_store
        if store is None:
            return None
        try:
            sid = self._current_subject_id
            return store.get(sid) if sid else store.get_self()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Workflow-Subjekt nicht aufloesbar: %s", type(exc).__name__
            )
            return None

    def _show_error(self) -> None:
        """Macht einen fehlgeschlagenen Refresh im UI sichtbar."""
        self._error_label.setText(
            "Das Dashboard konnte nicht aktualisiert werden. Die zuletzt "
            "geladenen Daten bleiben sichtbar. Bitte versuchen Sie es erneut."
        )
        self._error_banner.setVisible(True)

    def _start_initial_refresh(self) -> None:
        """Initialer Cockpit-Refresh OFF dem UI-Thread.

        NUR der erste Lauf nach dem Paint laeuft im Worker — er ist der teure:
        kalt, vor der Raw-Key-Konvertierung/Schema-Init oeffnet der Aggregator
        ~16-25 SQLCipher-DBs und friert sonst ~1-2 s ein (faulthandler-Watchdog
        -> "Beinahe-Crash", genau Patricks Symptom).:meth:`refresh` (manuell/
        Subjekt/Zeitraum/2h) laeuft danach synchron — die DBs sind dann
        raw-key-warm (~2 ms/Open). Die Aggregator-Loader oeffnen ihre
        Verbindungen erst im Worker-:meth:`run` -> thread-lokal (wie).
        """
        worker = _AggregateWorker(
            self._aggregator,
            self._current_range,
            self._current_subject_label,
            self._current_subject_id,
        )
        worker.fertig.connect(self._on_initial_done)
        worker.fehlgeschlagen.connect(self._on_initial_failed)
        worker.finished.connect(self._on_initial_finished)
        _ACTIVE_AGGREGATE_WORKERS.add(worker)
        worker.finished.connect(lambda: _ACTIVE_AGGREGATE_WORKERS.discard(worker))
        self._initial_worker = worker
        worker.start()

    def _on_initial_done(self, data: DashboardData) -> None:
        """Rendert das Ergebnis des Initial-Workers im UI-Thread."""
        self._error_banner.setVisible(False)
        self._apply(data)

    def _on_initial_failed(self, _exc_name: str) -> None:
        """Macht einen fehlgeschlagenen Initial-Refresh sichtbar."""
        self._show_error()

    def _on_initial_finished(self) -> None:
        """Raeumt den Initial-Worker auf, holt einen waehrenddessen angeforderten
        (interaktiven) Refresh synchron nach und signalisiert ``refreshed``.

        ``refreshed`` feuert ERST hier (nach dem Aufraeumen), damit Wartende
        garantiert einen Zustand ohne in-flight-Worker sehen.
        """
        if self._initial_worker is not None:
            self._initial_worker.deleteLater()
            self._initial_worker = None
        if self._pending_refresh:
            self._pending_refresh = False
            self.refresh()  # synchron (warm) — emittiert refreshed selbst
        else:
            self.refreshed.emit()

    def refresh(self) -> None:
        """Lädt Daten neu und rendert alle Sektionen (synchron, interaktiv).

        Laeuft nach dem Start auf raw-key-warmen DBs (~35 ms) — ein kurzer,
        interaktiver Wait ist hier akzeptabel. Solange der teure Initial-Worker noch laeuft, wird der Wunsch nur gemerkt und nach dessen Abschluss
        nachgeholt — so rennen nie zwei Aggregat-Laeufe nebenlaeufig auf denselben
        DBs (Cold-Start-Rekey-Schutz).
        """
        if self._initial_worker is not None:
            self._pending_refresh = True
            return
        try:
            if self._current_subject_id:
                # subjekt-bewusst nur bei expliziter Auswahl.
                data = self._aggregator.aggregate(
                    self._current_range,
                    target_name=self._current_subject_label,
                    subject_id=self._current_subject_id,
                )
            else:
                data = self._aggregator.aggregate(self._current_range)
        except (
            OSError,
            RuntimeError,
            ValueError,
            KeyError,
            AttributeError,
            TypeError,
        ) as exc:
            # exc_info=True: vorher ging nur der Typname ins Log.
            log.warning(
                "Dashboard-Aggregation fehlgeschlagen: %s",
                type(exc).__name__,
                exc_info=True,
            )
            self._show_error()
            self.refreshed.emit()
            return
        self._error_banner.setVisible(False)
        self._apply(data)
        self.refreshed.emit()

    def closeEvent(self, event) -> None:  # noqa: N802, ANN001
        """Wartet kurz auf einen laufenden Initial-Worker (QThread-Teardown)."""
        worker = self._initial_worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)
        super().closeEvent(event)

    def _apply(self, data: DashboardData) -> None:
        # Cockpit-Perf A: die aggregator-gefuellten Sektionen sind lazy. Solange
        # sie zugeklappt (noch nicht gebaut) sind, ueberspringt ``_apply`` sie —
        # die Lazy-Factory befuellt sie beim Aufklappen frisch aus ``_last_data``
        # (das ganz unten gesetzt wird). Darum ueberall ein None-Guard.
        if self._changes_section is not None:
            self._changes_section.update_data(data.changes, data.time_range)
        self._completeness_banner.set_entries(data.completeness)
        # Phase 4) — Einstiegs-Band: zwei getrennte SELF-Score-
        # Kacheln (Selbsteinschätzung/Audit + Messung/Hardening), kein
        # Misch-Score. IMMER das eigene System, unabhaengig vom Subjekt-Selektor
        # (Hardening ist self-only; das SELF-Audit kommt aus ``data.self_audit``).
        self._cockpit_band.set_data(data.self_audit, data.hardening_score)
        # Folge: Kunden-Audit-Karte erscheint UNTER dem Band, sobald im
        # Header ein Kunden-Subjekt gewählt ist und für dieses ein Audit
        # vorliegt — sie zeigt den Score DES KUNDEN, getrennt vom self-only Band.
        audit = data.customer_audit
        self._customer_audit_card.set_data(audit)
        self._customer_audit_card.setVisible(audit is not None)
        #/: Die kompakte Score-Sektion (Sektion 2) zeigt den
        # kanonischen Hardening-Score des eigenen Systems — aber nur im
        # "Allgemein"-Default. Bei explizit gewaehltem Subjekt waere der
        # self-only Hardening-Score irrefuehrend (Breakdown/Trend schalten aufs
        # Subjekt um), daher dann der subjekt-bewusste ``data.score``.
        # ``previous`` auf None: kein gemischtes Delta (Legacy-previous vs.
        # Hardening-current), solange der Trend nicht aus der Hardening-History
        # aggregiert wird.
        hardening = data.hardening_score if self._current_subject_id is None else None
        score_snapshot = data.score
        if hardening is not None:
            score_snapshot = replace(
                data.score,
                current=hardening.overall_score,
                previous=None,
            )
        self._score_section.update_data(score_snapshot, data.breakdown)
        self._cert_burndown_tile.set_data(data.cert_burndown)
        self._cvss_percentile_widget.set_data(data.cvss_percentiles)
        if self._cves_scans_section is not None:
            self._cves_scans_section.update_data(data.cves, data.scans)
        if self._breakdown_trend_section is not None:
            self._breakdown_trend_section.update_data(data.breakdown, data.trend)
        if self._organizational_section is not None:
            self._organizational_section.update_data(data.org)
        # Sprint S4a — Kanban + Notizen aus der Mainpage-DB neu laden,
        # damit zwischen den Auto-Refreshes auch dort nichts veraltet.
        if self._kanban_section is not None:
            self._kanban_section.refresh()
        if self._notes_section is not None:
            self._notes_section.refresh()
        # 3c (Cockpit) — die neuen Home-Widgets haben KEINE eigenen
        # Timer mehr (anders als im Mainpage), also hier mit-refreshen. Jedes
        # einzeln gekapselt: ein Fehler in einem Glied darf den Cockpit-Refresh
        # (und die uebrigen Widgets) nicht reissen.
        for widget in self._light_home_widgets():
            self._refresh_home_widget(widget)
        self._last_data = data
        # Risikomatrix-Block (Überblick-Tab) mit dem frischen Selbst-Audit-Stand
        # neu befüllen — _last_data ist jetzt gesetzt.
        self._refresh_risk_matrix_block()
        self._last_refresh_label.setText(
            f"Zuletzt aktualisiert: {data.generated:%d.%m.%Y %H:%M}"
        )

    def _light_home_widgets(self) -> tuple[object | None, ...]:
        """Die leichten Cockpit-Home-Widgets (eine Quelle der Wahrheit 3c).

        Diese Widgets hatten im alten Mainpage-Home einen eigenen 60s-Timer;
        im Cockpit refresht sie EINMAL der schwere ``_apply`` mit UND ein
        separater leichter 60s-Timer (``_wire_light_refresh``) — OHNE den
        2h-Aggregator anzustossen. ``None`` (gegatet/nicht gebaut) wird in
        ``_refresh_home_widget`` uebersprungen.
        """
        return (
            self._greeting_label,
            self._quickstart_widget,
            self._ki_todo_section_widget,
            self._phishing_radar,
            self._task_snippet_widget,
            self._activity_widget,
        )

    def _refresh_home_widget(self, widget: object | None) -> None:
        """Refresht ein einzelnes Cockpit-Home-Widget fail-soft 3c).

        Das Begruessungs-Label (``QLabel``) hat kein ``refresh`` — fuer es
        wird der Begruessungs-Text neu gesetzt (Datum/Uhrzeit-Frische). Alle
        anderen Widgets bekommen ihr ``refresh`` aufgerufen. ``None`` (nicht
        gebautes/gegatetes Widget) wird uebersprungen. Jeder Fehler laeuft
        still ins Log, damit ein defektes Glied das Cockpit nicht reisst.

        Args:
            widget: Das zu refreshende Home-Widget oder ``None``.
        """
        if widget is None:
            return
        try:
            if widget is self._greeting_label:
                self._greeting_label.setText(self._build_greeting_text())
                return
            refresh = getattr(widget, "refresh", None)
            if callable(refresh):
                refresh()
        except Exception as exc:  # noqa: BLE001 -- ein Widget darf den Refresh nie reissen
            log.warning(
                "Cockpit-Home-Refresh fehlgeschlagen (%s): %s",
                type(widget).__name__,
                type(exc).__name__,
            )

    # ------------------------------------------------------------------
    # Klick-Weiterleitung
    # ------------------------------------------------------------------

    def _on_cve_clicked(self, cve_id: str) -> None:
        if cve_id:
            self.open_with_filter.emit("csaf_advisor", cve_id)

    # ------------------------------------------------------------------
    # PDF-Export
    # ------------------------------------------------------------------

    def _collect_compliance_rows_fail_soft(self) -> list:
        """Frische indikative Regulatorik-Befunde fuer den PDF-Report W3b).

        Laeuft synchron im bewussten Export-Klick (kurzer Haertungs-Scan). Jeder
        Fehler (Nicht-Windows, Scan-/Probe-Problem) -> leere Liste; der Report wird
        dann ohne die Regulatorik-Sektion erzeugt (fail-soft, kein Export-Abbruch).
        """
        try:
            from tools.system_scanner.application.compliance_report_service import (  # noqa: PLC0415
                collect_default_hardening_compliance,
            )

            return collect_default_hardening_compliance()
        except Exception as exc:  # noqa: BLE001 — Export darf nie am Scan scheitern
            log.warning(
                "Regulatorik-Scan fuer PDF uebersprungen: %s", type(exc).__name__
            )
            return []

    def _on_export_clicked(self) -> None:
        """Öffnet Speichern-Dialog und schreibt den Dashboard-Report als PDF."""
        data = self._last_data
        if data is None:
            FinlaiInfoDialog(
                title="Dashboard nicht bereit",
                message=(
                    "Die Dashboard-Daten wurden noch nicht geladen. "
                    "Bitte einen Moment warten und erneut versuchen."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return

        suggestion = default_output_dir() / default_filename(data.generated)
        chosen, _filter = QFileDialog.getSaveFileName(
            self,
            "NoRisk-Dashboard-Report speichern",
            str(suggestion),
            "PDF-Dokumente (*.pdf)",
        )
        if not chosen:
            return
        target_path = Path(chosen)
        if target_path.suffix.lower() != ".pdf":
            target_path = target_path.with_suffix(".pdf")

        # W3b: der frische Haertungs-Scan + PDF-Bau laeuft synchron im
        # bewussten Export-Klick -> Warte-Cursor als Feedback (sichtbarer Freeze
        # statt scheinbar toter UI). Cursor wird IMMER zurueckgesetzt (finally),
        # bevor ein Dialog erscheint.
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        error: Exception | None = None
        result = None
        try:
            compliance_rows = self._collect_compliance_rows_fail_soft()
            result = self._export_service.export(
                data=data,
                output_path=target_path,
                target_name=data.score.target or "Allgemein",
                compliance_rows=compliance_rows,
            )
        except (OSError, RuntimeError, ValueError, ImportError) as exc:
            error = exc
        finally:
            QApplication.restoreOverrideCursor()

        if error is not None:
            log.error("PDF-Export fehlgeschlagen: %s", error)
            FinlaiInfoDialog(
                title="PDF-Export fehlgeschlagen",
                message=f"Der Report konnte nicht erstellt werden:\n{error}",
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
            return

        FinlaiSuccessDialog(
            title="PDF erstellt",
            message="Der Dashboard-Report wurde gespeichert unter:",
            file_path=str(result),
            parent=self,
        ).exec()
