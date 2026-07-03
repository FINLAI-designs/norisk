"""
mainpage_widget — Haupt-Widget des Mainpage-Dashboards.

 AP3 (2026-06-11, Homescreen-Interim Option A):

  Header-Zeile: Begruessung | Schnellstart-Leiste (oben rechts)
  ─ KI-Todo-Sektion "FINLAI empfiehlt" (Top-3; bis "Was tun?")
  ─ Hauptzone (einziges wachsendes Element):
      links Aufgaben-Snippet (Kanban-Lese-Sicht, Stretch 2)
      rechts Phishing-Radar-Karte (waechst) + Aktivitaeten (fix ~200px)

Status / 3c umgesetzt): Die Mainpage dient NICHT mehr als
eigenes Dock. Cockpit-3c ist gemergt — ihre Widgets (TaskSnippet,
Phishing-Karte, Quickstart-Leiste, kompakte Aktivitaeten) werden ins
verschmolzene Cockpit (norisk_dashboard) komponiert; dieser Layout-Glue
existiert nur noch als wiederverwendbare Widget-Quelle.

Author: Patrick Riederich
Version: 3.0 AP3)
"""

from __future__ import annotations

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

from core import theme
from core.logger import get_logger
from tools.mainpage.application.services import create_mainpage_services
from tools.mainpage.gui.activity_widget import ActivityWidget
from tools.mainpage.gui.header_widget import HeaderWidget
from tools.mainpage.gui.ki_todo_section import KiTodoSection
from tools.mainpage.gui.phishing_radar_banner import PhishingRadarBanner
from tools.mainpage.gui.phishing_radar_data import PhishingRadarViewModel
from tools.mainpage.gui.quickstart_widget import QuickstartWidget
from tools.mainpage.gui.task_snippet_widget import TaskSnippetWidget

_log = get_logger(__name__)


def _safe_dashboard_service():  # noqa: ANN202
    """Baut den ``DashboardService`` defensiv — ``None`` bei Fehler.

    Wird vom Phishing-Radar-Banner verwendet, um aus dem RSS-Cache die
    aktuellen Phishing-Warnungen aus allen Konsumenten-Quellen zu
    lesen. Wenn das Cyber-Dashboard-Tool nicht initialisiert ist
    (Stripped-Tier o.ä.), bleibt der Banner mit Placeholder-Text
    sichtbar — die Welcome-Page bricht nicht.
    """
    try:
        from tools.cyber_dashboard.application.dashboard_service import (  # noqa: PLC0415
            create_default_dashboard_service,
        )

        return create_default_dashboard_service()
    except Exception as exc:  # noqa: BLE001 -- Cross-Tool defensiv
        _log.debug(
            "DashboardService fuer Phishing-Radar nicht verfuegbar: %s",
            type(exc).__name__,
        )
        return None

# Sprint S4b — Layout-Versionierung fuer R7-Mitigation (KANBAN_NOTES).
# 2026-05-28 (Phishing-Radar-Refactor): von 2 -> 3 (PhishingRadarBanner).
# 2026-06-11 AP3): von 3 -> 4 — Option-A-Layout (Quickstart-Leiste
# oben rechts, Aufgaben-Snippet links, Phishing-Karte + Aktivitaeten
# rechts). Alte QSettings-Snapshots koennen darueber identifiziert und
# verworfen werden.
_LAYOUT_VERSION = 4


class MainpageWidget(QWidget):
    """FINLAI Mainpage — Quelle der Home-Widgets fuers verschmolzene Cockpit.

    Signals:
        tool_requested(str): Navigationsschluessel eines vom User gewaehlten
            Tools (typisch aus dem Schnellstart).
    """

    tool_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Dashboard.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._layout_version = _LAYOUT_VERSION
        t = theme.get()
        self.setStyleSheet(f"background: {t.BG_MAIN};")

        # Services (einmal erstellen, an alle Sub-Widgets weitergeben).
        # Kanban + Journal-Code wandert nach S4a ins NoRisk-Dashboard,
        # die DB (mainpage.db) bleibt aber unveraendert — beide Sichten
        # arbeiten gemeinsam darauf.: Buendel kommt aus
        # application/services, GUI sieht das Repository nicht mehr.
        services = create_mainpage_services()
        self._journal = services.journal
        self._tasks = services.tasks
        self._quickstart_service = services.quickstart

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Header-Zeile (fix 80px): Begrüßung links, Schnellstart-Leiste
        # rechts AP3, Option A — nutzt die leere rechte Hälfte der
        # Header-Zone, kostet 0px Höhe; NN/g: Quick-Links oben rechts).
        self._header = HeaderWidget(self)
        self._quickstart = QuickstartWidget(self._quickstart_service)
        self._quickstart.tool_requested.connect(self.tool_requested)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(0)
        header_row.addWidget(self._header, stretch=1)
        header_row.addWidget(self._quickstart)
        outer.addLayout(header_row)

        # Sprint S2b: "Was tun?"-Sektion mit den drei dringlichsten
        # KI-Todos. Sitzt direkt unter dem Header, damit die
        # Aktion-Karten die erste Sicht-Ebene bekommen.
        self._ki_todo_section = KiTodoSection(self._tasks, self)
        outer.addWidget(self._ki_todo_section)

        # 2026-05-28 (Phishing-Radar-Refactor, ersetzt): Banner
        # mit 2 frischesten High-Severity-Items aus allen 5 DACH-
        # Konsumenten-Quellen + Schutz-Framing-Pill + Modal-Trigger.
        # Statische Inhalte (Erkennungsmerkmale, Notfall) sind ins
        # ``PhishingInboxDialog`` umgezogen.
        self._phishing_view_model = PhishingRadarViewModel(
            dashboard_service=_safe_dashboard_service(),
            modus="easy",
        )
        self._phishing_radar = PhishingRadarBanner(
            view_model=self._phishing_view_model,
            parent=self,
        )

        # AP3 (ersetzt-Bottom-Row): Hauptzone als 2-Spalten-
        # Layout — links das Aufgaben-Snippet als EINZIGES vertikal
        # wachsendes Element (Stretch 2), rechts Phishing-Radar (wächst
        # in der Spalte) über den fix gedeckelten Aktivitäten. Aktivitäten
        # können den Restraum nie wieder fressen (Patrick-Wunsch
        # 2026-05-14 + 2026-06-11).
        main_zone = QWidget(self)
        main_zone.setStyleSheet("background: transparent;")
        mz_lyt = QHBoxLayout(main_zone)
        mz_lyt.setContentsMargins(8, 8, 8, 8)
        mz_lyt.setSpacing(12)

        self._task_snippet = TaskSnippetWidget(self._tasks)
        self._task_snippet.board_requested.connect(self._open_board)
        mz_lyt.addWidget(self._task_snippet, stretch=2)

        right_col = QVBoxLayout()
        right_col.setSpacing(12)
        right_col.addWidget(self._phishing_radar, stretch=1)

        self._activity = ActivityWidget()
        right_col.addWidget(self._activity)
        mz_lyt.addLayout(right_col, stretch=1)

        outer.addWidget(main_zone, stretch=1)

        # Auto-Refresh alle 60 Sekunden — Activity/Quickstart aus DB,
        # KI-Todo-Sektion aus mainpage.db (Kanban-DB).
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(60_000)
        self._refresh_timer.timeout.connect(self._refresh_activity)
        self._refresh_timer.start()

        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben fuer das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(f"background: {c.BG_MAIN};")

    def _refresh_activity(self) -> None:
        """Aktualisiert Aktivitaeten, Schnellstart, KI-Todos und Aufgaben.

        Jedes Widget einzeln abgesichert — ein Fehler in einem Glied darf
        die uebrigen Refreshes nicht ueberspringen (Review-F-5).
        """
        for widget in (
            self._activity,
            self._quickstart,
            self._ki_todo_section,
            self._phishing_radar,
            self._task_snippet,
        ):
            try:
                widget.refresh()
            except Exception as exc:  # noqa: BLE001 -- Refresh darf nie crashen
                _log.warning(
                    "Dashboard-Refresh fehlgeschlagen (%s): %s",
                    type(widget).__name__,
                    type(exc).__name__,
                )

    def _open_board(self) -> None:
        """Springt zum aufgeklappten Kanban-Board im NoRisk-Dashboard.

        Das ``#kanban``-Suffix sorgt dafür, dass die (per Default
        eingeklappte) Kanban-Sektion beim Ankommen offen ist — sonst
        endet der Sprung vor genau dem Akkordeon, dessen Unsichtbarkeit
        das Snippet beheben soll (Review-F-1).
        """
        self.tool_requested.emit("norisk:dashboard#kanban")

    def set_last_used(self, tool_name: str) -> None:
        """Wird aufgerufen wenn ein Tool aktiviert wird.

        Ermoeglicht kuenftige Protokollierung von Tool-Aktivierungen.

        Args:
            tool_name: Name des aktivierten Tools.
        """
        _log.debug("Tool aktiviert: %s", tool_name)
