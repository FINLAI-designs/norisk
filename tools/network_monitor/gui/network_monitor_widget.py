"""network_monitor.gui.network_monitor_widget — Haupt-Widget des Netzwerkmonitors.

Layout::

    ┌──────────────────────────────────────────────────────────────┐
    │ Header (Titel + Icon + Export-Button) │
    ├──────────────────────────────────────────────────────────────┤
    │ BandwidthChart (2/3) │ InterfaceOverview (1/3) │
    ├─────────────────────────────┴─────────────────────────────────┤
    │ ConnectionTable │
    └──────────────────────────────────────────────────────────────┘

Single-Tenant-OSS — kein Free/Pro-Gating mehr. Alle Anteile
(Prozess-Resolution, Suspicious-Highlighting, History-Export, Per-Prozess-/
Bedrohungslisten-/Konversationen-Tabs) sind immer aktiv.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QThread, QTimer, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.help.explainable_label import ExplainableLabel
from core.help.help_panel import HelpPanel
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import ICON_SIZE_LG, Icons, get_accent_icon, get_icon
from core.logger import get_logger
from tools.network_monitor.application.monitor_service import MonitorService
from tools.network_monitor.application.threat_checker import ThreatChecker
from tools.network_monitor.domain.interfaces import (
    IConnectionRepository,
    IProcessTrafficRepository,
)
from tools.network_monitor.domain.models import (
    Anomaly,
    AnomalySeverity,
    AnomalyType,
    ConnectionInfo,
    InterfaceStats,
)

if TYPE_CHECKING:
    # NetworkMonitorWorker wird ueber den Application-Layer
    # re-exportiert, damit die GUI keinen direkten ``data/``-Import
    # mehr braucht (auch nicht im TYPE_CHECKING-Block).
    from tools.network_monitor.application.monitor_service import (
        NetworkMonitorWorker,
    )
from tools.network_monitor.gui.anomaly_alert_tab import AnomalyAlertTab
from tools.network_monitor.gui.anomaly_worker import AnomalyDetectionWorker
from tools.network_monitor.gui.bandwidth_chart import BandwidthChart
from tools.network_monitor.gui.connection_table import ConnectionTable
from tools.network_monitor.gui.conversation_tab import ConversationTab
from tools.network_monitor.gui.interface_overview import InterfaceOverview
from tools.network_monitor.gui.process_traffic_view import ProcessTrafficView
from tools.network_monitor.gui.threat_feed_worker import ThreatFeedRefreshWorker
from tools.network_monitor.gui.threat_list_tab import ThreatListTab

#: Schweregrad-Rang fuer die Auswahl der „schwersten" Anomalie (Chart-Marker).
#: Aus der Enum-Reihenfolge (LOW < MEDIUM < HIGH) abgeleitet, damit ein kuenftig
#: ergaenzter Schweregrad automatisch einen Rang bekommt — sonst faellt
#: _most_severe_type still auf Rang 0 zurueck (Review, P2).
_SEVERITY_RANK: dict[AnomalySeverity, int] = {
    sev: rank for rank, sev in enumerate(AnomalySeverity, start=1)
}


def _most_severe_type(anomalies: list[Anomaly]) -> AnomalyType | None:
    """Liefert den ``AnomalyType`` der schwersten Anomalie (oder ``None`` wenn leer)."""
    if not anomalies:
        return None
    top = max(anomalies, key=lambda a: _SEVERITY_RANK.get(a.severity, 0))
    return top.anomaly_type


class NetworkMonitorWidget(QWidget):
    """Haupt-Widget des Netzwerkmonitors.

    Args:
        repository: Optionales Connection-History-Repository. Tests können
            ein Fake übergeben.
        auto_start_worker: ``True`` (Default) startet den Worker direkt
            in ``__init__`` — passt fuer den Standalone-Modus. Sprint
            S5a: Beim Einbetten als Tab im Network-Scanner wird ``False``
            uebergeben, damit der Worker erst beim Tab-Aktivierungs-
            Wechsel startet (CPU-Schonung wenn der User auf einem
            anderen Tab arbeitet).
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        repository: IConnectionRepository | None = None,
        auto_start_worker: bool = True,
        process_traffic_repo: IProcessTrafficRepository | None = None,
    ) -> None:
        super().__init__(parent)
        self._log = get_logger(__name__)

        # Single-Tenant-OSS — kein Free/Pro-Gating mehr.
        self._repo = repository

        # Perf (Triage P0c): KEIN eager MonitorService.create_threat_checker
        # hier — das lief build_entries (Cache-load_all + ~3900 Eintraege
        # parsen, inkl. SQLCipher-PBKDF2) SYNCHRON im UI-Aufbau und fror das
        # Tab beim Oeffnen ein. Stattdessen ein leerer Checker (kein DB-Zugriff
        # im UI-Thread); der ThreatFeedRefreshWorker befuellt ihn beim sofortigen
        # ersten Refresh OFF-THREAD via _on_feed_entries_refreshed. Der Checker
        # ist ein geteiltes mutable Objekt -> der Monitor-Worker sieht die
        # nachgereichten Eintraege ohne Neustart.
        self._checker = ThreatChecker(entries=[], whitelist=[])

        self._worker: NetworkMonitorWorker | None = None
        # F-E: periodischer Anomalie-Worker + naechster Chart-Marker.
        # ``_pending_marker`` wird beim naechsten Stats-Sample EINMAL konsumiert,
        # sodass je Detektionszyklus genau ein Marker auf dem Chart erscheint
        # (statt 45 identische Marker waehrend eines Anomalie-Fensters). Der
        # Anomalie-Worker UEBERSCHREIBT den Marker zudem jeden Zyklus (~45s,
        # unabhaengig vom Stats-Worker) — er ist also nie laenger als ein Zyklus
        # alt und spiegelt stets die juengste Detektion (Review: keine
        # unbegrenzte Staleness, daher kein Zeitstempel noetig).
        self._anomaly_worker: AnomalyDetectionWorker | None = None
        self._pending_marker: AnomalyType | None = None
        # F-D: periodischer Threat-Feed-Refresh (Pro). Aktualisiert den
        # verschluesselten abuse.ch-Cache und tauscht die Checker-Eintraege atomar.
        self._feed_worker: ThreatFeedRefreshWorker | None = None

        # Sprint S1b V10: "Aktualisiert vor X s"-Vertrauens-Signal.
        # ``_last_update_at`` ist ein monotoner Zeitstempel (sekundengenau);
        # der ``_update_age_timer`` rendert jede Sekunde das Label neu.
        # Sprint S1c: Label ist ein ExplainableLabel — im Erklär-Mode
        # erscheint der Worker-Hänger-Hinweis als Tooltip.
        self._last_update_at: float | None = None
        self._update_age_label = ExplainableLabel(
            "Noch keine Daten",
            self._explain_text("last_update_label"),
        )

        self._chart = BandwidthChart()
        self._iface_panel = InterfaceOverview()
        self._conn_table = ConnectionTable(
            highlight_suspicious=True,
        )
        self._export_btn = QPushButton("Historie exportieren")
        self._export_btn.setIcon(get_icon(Icons.EXPORT))
        self._export_btn.setEnabled(True)
        self._export_btn.setToolTip("CSV-Export der 24-Stunden-Historie")
        self._export_btn.clicked.connect(self._on_export_clicked)

        # Stop-Step C: Per-Prozess-Datenverbrauch (24h) als zweiter Tab.
        self._traffic_view = ProcessTrafficView(repository=process_traffic_repo)

        # F-E: Live-Anomalie-Alerts als eigener Tab (Pro: durchsuchbare
        # Liste + Deep-Link; Free: Zaehler-Banner). Detektion liefert der Worker.
        self._alert_tab = AnomalyAlertTab()

        # F-D-GUI: Bedrohungslisten-Tab (Refresh/Whitelist → Checker).
        self._threat_list_tab = ThreatListTab()
        self._threat_list_tab.entries_refreshed.connect(
            self._on_feed_entries_refreshed
        )
        self._threat_list_tab.whitelist_changed.connect(self._on_whitelist_changed)

        # Phase 5: Konversationen-Tab (Wer-mit-Wem aus der Verbindungs-Historie).
        # Folge: den Service aus den BEREITS geoeffneten History-Repos bauen,
        # statt ConversationTab ein ZWEITES Repo-Paar oeffnen zu lassen — sonst
        # oeffnet allein der Live-Aufbau die network_monitor-DB unnoetig mehrfach
        # (Patrick-Live-Test: viele DB-Lade-Zeilen, Absturz). Fail-soft: ohne
        # geteilte Repos baut der Tab seinen Service wie bisher selbst.
        conversation_service = None
        if self._repo is not None and process_traffic_repo is not None:
            try:
                conversation_service = MonitorService.create_conversation_service(
                    repository=self._repo,
                    traffic_repository=process_traffic_repo,
                )
            except Exception as exc:  # noqa: BLE001 — fail-soft, Tab bleibt leer
                self._log.info(
                    "Konversations-Service (geteilt) nicht verfuegbar: %s",
                    type(exc).__name__,
                )
        self._conversation_tab = ConversationTab(service=conversation_service)

        self._build_layout()
        if auto_start_worker:
            self._start_worker()

        # Sprint S1b V10: 1-Sekunden-Timer aktualisiert das Alter-Label.
        # Niedrige Priorität ist nicht nötig — ``setText`` ist trivial.
        self._update_age_timer = QTimer(self)
        self._update_age_timer.setInterval(1000)
        self._update_age_timer.timeout.connect(self._refresh_update_age)
        self._update_age_timer.start()

        # closeEvent propagiert beim App-Shutdown nicht zuverlaessig durch
        # Dock-/Tool-Container — ohne aboutToQuit-Hook bleibt der Worker bis
        # zum Python-GC am Leben und Qt wirft "QThread destroyed while still
        # running" beim Beenden.
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._stop_worker)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: D401 — Qt-Override
        """Sauberer Worker-Stopp beim Schließen."""
        # _stop_worker haelt via _pause_ui_refreshers auch den Alter-Timer (1s)
        # und die Sub-View-Refresher (Konversationen/Datenverbrauch) an.
        self._stop_worker()
        super().closeEvent(event)

    def stop_worker(self) -> None:
        """Public API für den Tool-Registry-Manager (Tab-Wechsel etc.)."""
        self._stop_worker()

    def start_worker(self) -> None:
        """Public API zum Wieder-Starten des Workers nach ``stop_worker``.

        Idempotent — wenn ein Worker bereits laeuft, ist der Aufruf ein
        No-op. Sprint S5a: Network-Scanner ruft das beim Tab-Wechsel
        auf den Live-Tab auf.
        """
        if self._worker is not None:
            return
        self._start_worker()
        # die beim Tab-Verlassen angehaltenen UI-Refresher wieder aufnehmen.
        self._resume_ui_refreshers()

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        hc = HelpRegistry.get("network_monitor")
        return hc.tooltips.get(key, "") if hc else ""

    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        dlg = HelpDialog(
            initial_nav_key=nav_key or "network_monitor", parent=self.window()
        )
        dlg.show()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot(dict)
    def _on_stats_updated(self, stats: dict[str, InterfaceStats]) -> None:
        """Aktualisiert Chart (Summe über alle Interfaces) + Interface-Panel."""
        up = sum(s.upload_kbps for s in stats.values())
        down = sum(s.download_kbps for s in stats.values())
        # F-E: den seit der letzten Detektion vorgemerkten Marker EINMAL
        # konsumieren — ein Tick je Detektionszyklus statt Dauer-Markierung.
        marker = self._pending_marker
        self._pending_marker = None
        self._chart.append_sample(up, down, anomaly=marker)
        self._iface_panel.update_interfaces(stats)
        self._last_update_at = time.monotonic()

    @Slot(list)
    def _on_connections_updated(self, connections: list[ConnectionInfo]) -> None:
        """Rendert die aktualisierten Verbindungen (UI-Thread, render-only).

        Die Persistenz (``save_snapshot``) lief früher HIER im UI-Thread
        und fror die GUI bei jedem 3s-Zyklus ein (verschlüsselte DB-Öffnung +
        INSERT, ggf. Lock-Konflikt mit dem Collector-Daemon). Sie läuft jetzt im
        Worker-Thread (:class:`NetworkMonitorWorker`) — dieser Slot rendert nur
        noch die Tabelle.
        """
        self._conn_table.update_connections(connections)
        self._last_update_at = time.monotonic()

    @Slot(str)
    def _on_worker_error(self, message: str) -> None:
        """Loggt Worker-Fehler ohne UI-Spam."""
        self._log.warning("Netzwerkmonitor-Worker: %s", message)

    @Slot(list)
    def _on_anomalies_detected(self, anomalies: list[Anomaly]) -> None:
        """Speist die Alert-Liste, merkt den Chart-Marker vor + setzt den Tab-Zaehler."""
        self._alert_tab.update_anomalies(anomalies)
        self._pending_marker = _most_severe_type(anomalies)
        title = (
            f"Auffälligkeiten ({len(anomalies)})" if anomalies else "Auffälligkeiten"
        )
        self._tabs.setTabText(self._alert_tab_index, title)

    @Slot()
    def _on_export_clicked(self) -> None:
        if self._repo is None:
            # Fail-open ohne Repository (KeyManager/DB fehlt): NICHT stumm
            # zurueckkehren — sonst wirkt der Button kaputt (Patrick-Live-Test
            # 2026-06-25, D3). Sichtbare Rueckmeldung geben.
            FinlaiInfoDialog(
                title="Export nicht verfügbar",
                message=(
                    "Für diesen Tab ist keine Verbindungshistorie verfügbar "
                    "(Datenspeicher nicht erreichbar). Es kann daher nichts "
                    "exportiert werden."
                ),
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Verbindungshistorie exportieren",
            "netzwerk_historie.csv",
            "CSV-Dateien (*.csv)",
        )
        if not target:
            return
        try:
            count = MonitorService.export_history(self._repo, Path(target))
        except OSError as exc:
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=f"Datei konnte nicht geschrieben werden:\n{exc}",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        FinlaiSuccessDialog(
            title="Export abgeschlossen",
            message=f"{count} Verbindungseinträge exportiert.",
            file_path=str(target),
            parent=self,
        ).exec()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        colors = theme.get()
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addLayout(self._build_header(colors))

        _hc = HelpRegistry.get("network_monitor")
        if _hc is not None:
            self._help_panel = HelpPanel(_hc)
            self._help_panel.open_full_help.connect(self._open_help_dialog)
            root.addWidget(self._help_panel)

        # C / F-E: Live-Ansicht, Auffälligkeiten und Per-Prozess-
        # Datenverbrauch (24h) als Tabs. Der Auffälligkeiten-Titel traegt einen
        # Live-Zaehler (siehe _on_anomalies_detected).
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_live_tab(), "Live-Übersicht")
        self._alert_tab_index = self._tabs.addTab(self._alert_tab, "Auffälligkeiten")
        self._tabs.addTab(self._traffic_view, "Datenverbrauch (24 h)")
        # F-D-GUI: Bedrohungslisten-Tab nur fuer Pro (siehe __init__).
        if self._threat_list_tab is not None:
            self._tabs.addTab(self._threat_list_tab, "Bedrohungslisten")
        # Phase 5: Konversationen-Tab nur fuer Pro (siehe __init__).
        if self._conversation_tab is not None:
            self._tabs.addTab(self._conversation_tab, "Konversationen")
        root.addWidget(self._tabs, 1)

    def _build_live_tab(self) -> QWidget:
        """Baut die bisherige Live-Ansicht (Chart + Interfaces + Verbindungen)."""
        chart_row = QHBoxLayout()
        chart_row.addWidget(self._chart, 2)
        _tip_chart = self._help_tip("chart_bandwidth")
        if _tip_chart:
            chart_row.addWidget(HelpButton(_tip_chart), 0, Qt.AlignmentFlag.AlignTop)

        chart_wrapper = QWidget()
        chart_wrapper.setLayout(chart_row)

        top_row = QHBoxLayout()
        top_row.setSpacing(12)
        top_row.addWidget(chart_wrapper, 2)
        top_row.addWidget(self._iface_panel, 1)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)
        layout.addLayout(top_row, 2)

        conn_row = QHBoxLayout()
        conn_row.addWidget(self._conn_table, 1)
        _tip_table = self._help_tip("table_connections")
        if _tip_table:
            conn_row.addWidget(HelpButton(_tip_table), 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(conn_row, 3)
        return container

    def _build_header(self, colors: object) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setSpacing(10)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            get_accent_icon(Icons.NETWORK).pixmap(ICON_SIZE_LG, ICON_SIZE_LG)
        )
        layout.addWidget(icon_lbl, 0)

        # Sprint S1c: Titel als ExplainableLabel — sichtbarste
        # Pilot-Demo des Erklär-Layers.
        title = ExplainableLabel(
            "Netzwerkmonitor",
            self._explain_text("title_widget"),
        )
        title.setStyleSheet(
            f"font-size: 18px; font-weight: 600; color: {colors.ACCENT};"
        )
        layout.addWidget(title, 0)

        # Sprint S1c: Tier-Indikator (Free/Pro) ebenfalls explainable —
        # User soll im Erklär-Mode sofort verstehen, welche Features
        # gegated sind.
        subtitle = ExplainableLabel(
            "Live · 1 Sekunde Auflösung",
            self._explain_text("tier_label"),
        )
        subtitle.setStyleSheet(f"color: {colors.TEXT_DIM};")
        layout.addWidget(subtitle, 1, Qt.AlignmentFlag.AlignLeft)

        # Sprint S1b V10: "Aktualisiert vor X s" — Vertrauens-Signal
        # rechtsbündig vor dem Export-Button. Sprint S1c: Das Label ist
        # selbst ein ExplainableLabel (siehe ``__init__``), zeigt im
        # Erklär-Mode den Worker-Hänger-Hinweis als Tooltip.
        self._update_age_label.setStyleSheet(f"color: {colors.TEXT_DIM};")
        layout.addWidget(self._update_age_label, 0, Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self._export_btn, 0, Qt.AlignmentFlag.AlignRight)
        return layout

    def _explain_text(self, element_id: str) -> str:
        """Liest einen Erklär-Text aus dem HelpRegistry (Sprint S1c).

        Liefert ``""`` falls das Help-Content fehlt —:class:`ExplainableLabel`
        verträgt das (leerer Tooltip im Erklär-Mode).
        """
        hc = HelpRegistry.get("network_monitor")
        if hc is None:
            return ""
        return hc.explanations.get(element_id, "")

    @Slot()
    def _refresh_update_age(self) -> None:
        """Rendert das "Aktualisiert vor X s"-Label aus ``_last_update_at``."""
        if self._last_update_at is None:
            self._update_age_label.setText("Noch keine Daten")
            return
        age = max(0, int(time.monotonic() - self._last_update_at))
        if age == 0:
            self._update_age_label.setText("Aktualisiert gerade eben")
        elif age < 60:
            self._update_age_label.setText(f"Aktualisiert vor {age} s")
        else:
            minutes = age // 60
            self._update_age_label.setText(f"Aktualisiert vor {minutes} min")

    def _start_worker(self) -> None:
        self._log.info(
            "Live-Monitor: Worker werden gestartet — Bandbreite 1s / "
            "Verbindungen+Persistenz 3s / Anomalie / Threat-Feed."
        )
        self._worker = MonitorService.create_worker(
            threat_checker=self._checker,
            include_per_process=True,
            # Persistenz in den Worker-Thread geben (raus aus dem
            # UI-Thread-Slot, der die GUI bei jedem 3s-Zyklus einfror).
            connection_repo=self._repo,
        )
        self._worker.stats_updated.connect(self._on_stats_updated)
        self._worker.connections_updated.connect(self._on_connections_updated)
        self._worker.error_occurred.connect(self._on_worker_error)
        # LowPriority: Monitor darf niemals den UI-Thread verdrängen.
        self._worker.start(QThread.Priority.LowPriority)
        self._start_anomaly_worker()
        self._start_feed_worker()

    def _start_feed_worker(self) -> None:
        """Startet den Threat-Feed-Refresh-Worker F-D, Pro), fail-soft.

        Nur fuer Pro mit aktivem Checker: Free hat kein Highlighting. Ohne aktiven
        ``KeyManager`` (kein Collector/DB) wirft die Service-Factory einen
        ``RuntimeError`` — dann bleibt der Worker aus und der Checker arbeitet mit
        der lokalen Blocklist (kein harter Fehler).
        """
        if self._checker is None:
            return
        try:
            service = MonitorService.create_threat_feed_service()
        except Exception as exc:  # noqa: BLE001 — kein KeyManager/keine DB → fail-soft
            self._log.info("Threat-Feed-Worker nicht gestartet: %s", exc)
            return
        self._feed_worker = ThreatFeedRefreshWorker(service)
        self._feed_worker.entries_refreshed.connect(self._on_feed_entries_refreshed)
        self._feed_worker.error_occurred.connect(self._on_worker_error)
        self._feed_worker.start(QThread.Priority.LowPriority)

    def _on_feed_entries_refreshed(self, entries: list, whitelist: list) -> None:
        """Tauscht die aktualisierten Feed-/Blocklist-Eintraege in den Checker (F-D)."""
        if self._checker is not None:
            self._checker.replace_entries(entries, whitelist)
            # Diagnose: jede Verbindung wird pro Worker-Zyklus linear gegen
            # ALLE diese Eintraege geprueft (is_suspicious, O(n)) — Groessenordnung
            # sichtbar machen.
            self._log.info(
                "Live-Monitor: ThreatChecker hat %d Bedrohungs-Eintraege "
                "(Pruefung pro Verbindung im Worker-Thread).",
                len(entries),
            )

    def _on_whitelist_changed(self, whitelist: list) -> None:
        """Uebernimmt eine im Bedrohungslisten-Tab geaenderte Whitelist live (F-D-GUI).

        Nur die Whitelist wird getauscht — die (teuren) Blocklist-/Feed-Eintraege
        bleiben unangetastet (``replace_whitelist``). Greift sofort beim naechsten
        ``is_suspicious``-Read des Monitor-Workers.
        """
        if self._checker is not None:
            self._checker.replace_whitelist(whitelist)

    def _start_anomaly_worker(self) -> None:
        """Startet den periodischen Anomalie-Worker F-E), fail-soft.

        Laeuft fuer alle Tier (Free braucht den Zaehler). Ohne aktiven Collector
        bzw. KeyManager (z. B. Nicht-Windows) wirft die Service-Factory einen
        ``RuntimeError`` — dann bleibt der Worker aus und der Alert-Tab zeigt den
        ehrlichen Leer-/Voraussetzungs-Hinweis (keine harte Fehlermeldung).
        """
        try:
            service = MonitorService.create_anomaly_service()
        except Exception as exc:  # noqa: BLE001 — kein KeyManager/keine DB → fail-soft
            self._log.info("Anomalie-Worker nicht gestartet: %s", exc)
            return
        self._anomaly_worker = AnomalyDetectionWorker(service)
        self._anomaly_worker.anomalies_detected.connect(self._on_anomalies_detected)
        self._anomaly_worker.error_occurred.connect(self._on_worker_error)
        self._anomaly_worker.start(QThread.Priority.LowPriority)

    def _stop_worker(self) -> None:
        # Erst BEIDE Stop-Flags setzen, dann joinen — so wachen die Worker aus
        # ihrem ``msleep`` quasi-parallel auf (~1 statt seriell ~2 Sekunden).
        workers = [
            w
            for w in (self._worker, self._anomaly_worker, self._feed_worker)
            if w is not None
        ]
        for worker in workers:
            try:
                worker.stop()
            except RuntimeError:
                pass
        for worker in workers:
            try:
                # wait == False = Timeout (Thread laeuft noch). Loggen statt
                # still zu schlucken — sonst droht beim Shutdown die „QThread
                # destroyed while still running"-Warnung unbemerkt (Review).
                # Der Feed-Worker kann mitten in einem ~20s-Download stecken; das
                # Timeout-Log macht das diagnostizierbar (kein Crash).
                if not worker.wait(2000):
                    self._log.warning(
                        "Worker %s nicht innerhalb 2s beendet.", worker.objectName()
                    )
            except RuntimeError:
                pass
        self._worker = None
        self._anomaly_worker = None
        self._feed_worker = None
        # F-D-GUI: einen ggf. laufenden manuellen Refresh-Worker mit beenden.
        if self._threat_list_tab is not None:
            self._threat_list_tab.shutdown()
        # alle periodischen UI-Refresher anhalten (Konversationen 30s,
        # Datenverbrauch 24h-GROUP-BY 30s, Alter-Label 1s) — kein CPU/DB-I/O im
        # UI-Thread, solange der Live-Tab nicht aktiv ist (S5a-Zusage).
        self._pause_ui_refreshers()

    def _pause_ui_refreshers(self) -> None:
        """Haelt die periodischen UI-Refresher an (Teardown / Tab verlassen).

        Stoppt den 1s-Alter-Timer sowie die 30s-Auto-Refresh-Timer von
        Konversationen- und Datenverbrauch-Tab. Letzterer fuehrt sonst alle 30s
        ein 24h-GROUP-BY-Aggregat synchron im UI-Thread aus, auch wenn der
        Live-Tab gar nicht aktiv ist/ Freeze-Linie). Pendant:
:meth:`_resume_ui_refreshers`.
        """
        # Beim App-Shutdown (``aboutToQuit`` -> ``_stop_worker``) koennen die
        # C++-Timer/Sub-Views bereits zerstoert sein -> ``.stop`` wirft
        # RuntimeError. Fangen (gleiches Muster wie der Worker-Stop oben), damit
        # der Shutdown sauber bleibt.
        try:
            self._update_age_timer.stop()
            if self._conversation_tab is not None:
                self._conversation_tab.stop()
            if self._traffic_view is not None:
                self._traffic_view.stop()
        except RuntimeError:
            pass

    def _resume_ui_refreshers(self) -> None:
        """Nimmt die in:meth:`_pause_ui_refreshers` angehaltenen Refresher wieder auf.

        Wird beim Wieder-Betreten des Live-Tabs (``start_worker``) aufgerufen.
        Jeder Tab laedt beim Start sofort frisch, damit die Tabellen nach dem
        Tab-Wechsel nicht bis zu 30s veraltet stehen.
        """
        self._update_age_timer.start()
        if self._conversation_tab is not None:
            self._conversation_tab.start()
        if self._traffic_view is not None:
            self._traffic_view.start()
