"""
main_window — Rahmenloses Hauptfenster der FINLAI-Applikation.

Implementiert das zentrale QMainWindow ohne nativen Fensterrahmen
(FramelessWindowHint). Das Fenster enthält:

  - Einen eigenen Titelbalken (TitleBar) mit Drag-Unterstützung und
    Minimieren-/Maximieren-/Schließen-Schaltflächen.
  - Ein SidebarWidget zur Tool-Navigation (Drag-Resize via QSplitter).
  - Ein inneres QMainWindow mit QDockWidgets für die Tool-Widgets.
  - Eine Statusleiste die Live-Log-Nachrichten über StatusLogHandler /
    LogSignalEmitter empfängt und farblich nach Schweregrad darstellt.
  - Vollständige 8-Richtungs-Resize-Logik per applikationsweitem
    Event-Filter.

Typical usage::

    from core.tool_registry import ToolRegistry
    from core.main_window import MainWindow

    registry = ToolRegistry
    window = MainWindow(registry)
    window.show

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from apps.app_config import AppConfig

    # Injection-Hooks fuer das Patch-Inventory-Lifecycle. Die apps-Schicht
    # reicht die konkrete tools.patch_monitor-Impl rein -> core kennt nur die
    # Signatur und importiert tools nicht mehr zur Lade-Zeit.
    PatchInventorySetup = Callable[
        ["MainWindow"], tuple[object, object, object, object]
    ]
    PatchInventoryTeardown = Callable[[object, object], None]

from PySide6.QtCore import (
    QMetaObject,
    QPoint,
    Qt,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .auth.session import Session
from .dock_mixin import DockMixin
from .icons import Icons
from .logger import get_logger
from .navigation_mixin import NavigationMixin
from .resize_mixin import ResizeMixin
from .sidebar import (
    SIDEBAR_COLLAPSED_W,
    SidebarWidget,
)
from .theme_mixin import ThemeMixin
from .tool_registry import ToolRegistry
from .ui_settings import UISettings
from .widgets.log_handler import LogSignalEmitter, StatusLogHandler
from .widgets.neon_splitter import NeonSplitter
from .widgets.title_bar import TitleBar

_log = get_logger(__name__)

_WEBENGINE_PREWARM_DELAY_MS = (
    800  # ms nach __init__ bis QWebEngineView pre-initialisiert wird
)

# Sub-Navigation Tab-Index-Maps -- mappen Sidebar-Keys auf den Tab-Index
# innerhalb des jeweiligen Tool-Widgets. Modul-Level statt im Funktionskörper,
# damit sie nicht bei jedem Navigationsklick neu allokiert werden und an einer
# zentralen Stelle erweiterbar sind.
# ---------------------------------------------------------------------------
# Log-Bridge: emittiert ein Signal für jeden Log-Record
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TitleBar-Logo-Auflösung
# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------
class MainWindow(ResizeMixin, ThemeMixin, DockMixin, NavigationMixin, QMainWindow):
    """Rahmenloses Hauptfenster der FINLAI-Applikation (VS Code-Stil).

    Layout-Architektur::

        outer_frame (centralWidget)
        ├── TitleBar
        ├── content area
        │ └── QSplitter
        │ ├── SidebarWidget (links, feste Breite)
        │ └── _inner_main (QMainWindow, ohne Fensterrahmen)
        │ ├── centralWidget = Home / WelcomeWidget
        │ └── QDockWidgets (rechts, getabbt)
        └── QStatusBar

    Docks werden lazy erzeugt (Widget erst bei erstem Öffnen).
    Dock-Zustand wird auf ``_inner_main`` gespeichert/wiederhergestellt.

    Signals:
        tool_activated(str): Emittiert den Tool-Namen bei Aktivierung.
        logout_requested: Emittiert wenn Logout geklickt wird.
    """

    tool_activated = Signal(str)
    logout_requested = Signal()
    # Vom SecureStorage-Corruption-Observer beigebracht. Carriers
    # tragen den Pfad der korrupten Datei + optional den Backup-Pfad.
    # QueuedConnection-faehig (Slot in MainWindow): Observer feuert
    # synchron im Caller-Thread, das Signal-emit wird auf den GUI-
    # Thread gequeued, der Recovery-Dialog erscheint immer korrekt.
    secrets_corrupted = Signal(str, str)

    # Navigationsschlüssel → (Tool-Name, Dock-Titel, Material-Icon-Name)
    # Cleanup 2026-04-28: 13 tote Verweise auf FINLAI/AUTOMATE/TeachMe-Tools
    # entfernt (buchprüfung, finanzprüfung, ocr_benchmark, xml_reader, maps,
    # robotic, sftp_manager, migrationscheck, datenabgleich, ki_agenten,
    # teachings, cheatsheet, prog_teachings) -- Tools existieren in NoRisk
    # nicht.
    _NAV_TOOL_MAP: list[tuple[str, str, str, str]] = [
        ("einstellungen", "Einstellungen", "Einstellungen", Icons.SETTINGS),
        (
            "cyber_dashboard",
            "Lagebild",
            "Risikobriefing",
            Icons.SHIELD,
        ),
        # 3c 1b Vision B): ``norisk:dashboard`` (Cockpit) hat
        # KEIN eigenes Nav-Dock mehr. Das Cockpit IST das Welcome-Dock
        # (``DockMixin._build_home`` baut es dort), und sowohl der Sidebar-Key
        # ``home`` als auch Alt-Deeplinks auf ``norisk:dashboard`` werden in
        # ``NavigationMixin`` aufs Welcome-Dock geleitet — sonst entstuende ein
        # zweites Cockpit.
        ("api_security", "API Security Analyzer", "API Security Analyzer", Icons.API),
        (
            "dependency_auditor",
            "Dependency-Auditor",
            "Dependency-Auditor",
            Icons.DEPENDENCY,
        ),
        ("network_scanner", "Netzwerk-Scanner", "Netzwerk-Scanner", Icons.NETWORK_SCAN),
        (
            "cert_monitor",
            "Zertifikats-Monitor",
            "Zertifikats-Monitor",
            Icons.CERTIFICATE,
        ),
        ("password_checker", "Passwort-Checker", "Passwort-Checker", Icons.PASSWORD),
        (
            "patch_monitor",
            "Patch Monitor",
            "Patch Monitor — installierte Software + CVE-Status",
            Icons.PATCH_MONITOR,
        ),
        (
            "supply_chain_monitor",
            "Supply-Chain-Monitor",
            "Supply-Chain-Monitor — Vendor- und AVV-Inventar (NIS2 Art. 21(2)(d))",
            Icons.SUPPLY_CHAIN,
        ),
        # (Phase 3b): Datei-Scanner-Merge — email_scanner +
        # pdf_risk_scanner + document_scanner sind kein eigenes Dock mehr,
        # sondern Sub-Tabs im file_scanner-Container. Deeplink-Einstieg via
        # navigate('file_scanner', tab='email'|'pdf'|'office').
        (
            "file_scanner",
            "Datei-Scanner",
            "Datei-Scanner — E-Mail / PDF / Office",
            Icons.PDF,
        ),
        ("system_scanner", "Scan starten", "System-Scanner", Icons.SCAN),
        (
            "system_tuner",
            "System optimieren",
            "System optimieren — Datenschutz & Telemetrie",
            Icons.TUNE,
        ),
        # Bewerten-Merge — Security-Audit/Score/Awareness/NIS2 leben als
        # vier Sub-Tabs im Container „Security-Bewertung" (tools.security_assessment).
        # Die Einzel-Tools haben kein eigenes Dock mehr; der Router biegt alte
        # Deeplinks (z.B. navigate('customer_audit', tab='nis2')) per Alias auf
        # diesen Container + Sub-Tab um (core.navigation_mixin._TOOL_ALIASES).
        (
            "security_assessment",
            "Security-Bewertung",
            "Security-Bewertung",
            Icons.ASSESSMENT,
        ),
        (
            "csaf_advisor",
            "Advisory-Monitor",
            "Advisory-Monitor",
            Icons.ADVISORY_MONITOR,
        ),
        # techstack hat kein eigenes Dock mehr — es lebt als Tab im
        # Advisory-Monitor (csaf_advisor). navigate('techstack') biegt der Router
        # per Alias auf den Advisory-Monitor um (core.navigation_mixin).
        # network_monitor: kein Sidebar-Eintrag mehr (Triage P1), aber im
        # NAV-Map belassen -> navigate_to('network_monitor') aus Help-Links
        # bleibt crashsicher (der Monitor lebt als Live-Tab im network_scanner).
        (
            "network_monitor",
            "Netzwerkmonitor",
            "Netzwerkmonitor",
            Icons.NETWORK_MONITOR,
        ),
    ]

    def __init__(
        self,
        registry: ToolRegistry,
        config: AppConfig | None = None,
        *,
        patch_inventory_setup: PatchInventorySetup | None = None,
        patch_inventory_teardown: PatchInventoryTeardown | None = None,
    ) -> None:
        super().__init__()

        # (PM-PERSIST): Patch-Inventory-Worker + Scheduler. None-Defaults
        # damit closeEvent sicher ist. Setup am Ende von __init__.
        self._inv_thread: object | None = None
        self._inv_worker: object | None = None
        self._inv_scheduler: object | None = None
        self._inv_service: object | None = None
        # Referenz auf den letzten Update-Toast (haelt ihn am Leben,
        # bis er sich selbst aufraeumt).
        self._patch_update_toast: object | None = None
        # Teardown-Hook (von apps injiziert) fuer closeEvent.
        self._patch_inventory_teardown: PatchInventoryTeardown | None = (
            patch_inventory_teardown
        )

        self._config = config
        self.setWindowTitle(config.window_title if config else "FINLAI")
        # Min-Size VOR resize/setWindowFlags setzen,
        # damit Qt nicht erst eine 1000x700-Geometry probiert (die auf
        # 1920x1080-Screens mit FramelessWindowHint nicht akzeptiert wird
        # und ``QWindowsWindow::setGeometry: Unable to set...``-Warnungen
        # ausloest). Reihenfolge: minimum -> initial size -> frameless.
        self.setMinimumSize(1000, 700)
        # Default-Groesse auf den verfuegbaren Bildschirm begrenzen —
        # auf 15-Zoll-Notebooks (1366x768) darf die App nicht groesser als der
        # Screen starten (sonst Layout zu eng / Inhalte abgeschnitten). Bei
        # persistierter Geometry ueberschreibt _restore_window_geometry das.
        _scr = QApplication.primaryScreen()
        if _scr is not None:
            _avail = _scr.availableGeometry()
            self.resize(min(1920, _avail.width()), min(1080, _avail.height()))
        else:
            self.resize(1920, 1080)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        session = Session()
        self._settings = UISettings.load()

        # Persistierte Window-Geometry wiederherstellen.
        # Nach ``resize(1920, 1080)`` aber vor ``show``, damit der Wert
        # nicht durch das Default-Resize ueberschrieben wird. Validierung
        # gegen aktuelle Screen-Geometry verhindert "Fenster ausserhalb des
        # Bildschirms"-Probleme bei Monitor-Wechsel.
        self._restore_window_geometry()

        self._tools = [t for t in registry.get_all() if session.can_access_tool(t.name)]
        self._tool_map: dict[str, object] = {t.name: t for t in self._tools}
        self._docks: dict[str, QDockWidget] = {}

        # ==============================================================
        # Äußerer Rahmen (1 px Neonblau-Border)
        # ==============================================================
        outer = QWidget()
        outer.setObjectName("outer_frame")
        self._outer_frame = outer  # gespeichert für apply_theme

        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(1, 1, 1, 1)
        outer_layout.setSpacing(0)

        # Titelbalken
        self._title_bar = TitleBar(self, config)
        self._title_bar.help_requested.connect(self._open_help_dialog)
        outer_layout.addWidget(self._title_bar)

        # F1-Shortcut global
        self._help_dialog: object | None = None
        self._help_shortcut = QShortcut(QKeySequence("F1"), self)
        self._help_shortcut.activated.connect(self._open_help_dialog)

        # kein separater Akzent-Separator mehr — die 1px-Hairline
        # der TitleBar (border-bottom) trennt Titlebar und Content allein.

        # ==============================================================
        # Inhaltsbereich: Splitter(Sidebar + inner QMainWindow)
        # ==============================================================
        content = QWidget()
        content.setStyleSheet("border: none;")
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # --- Inner QMainWindow (Dock-Host) ---
        self._inner_main = QMainWindow()
        self._inner_main.setObjectName("tool_content")
        self._inner_main.setWindowFlags(Qt.WindowType.Widget)  # kein eigenes Fenster
        self._inner_main.setDockOptions(
            QMainWindow.DockOption.AnimatedDocks
            | QMainWindow.DockOption.AllowNestedDocks
            | QMainWindow.DockOption.AllowTabbedDocks
        )
        self._inner_main.setTabPosition(
            Qt.DockWidgetArea.RightDockWidgetArea,
            QTabWidget.TabPosition.North,
        )
        self._inner_main.setTabPosition(
            Qt.DockWidgetArea.LeftDockWidgetArea,
            QTabWidget.TabPosition.North,
        )
        self._inner_main.setDockNestingEnabled(True)

        # Home-Widget als central widget des inner_main
        self._build_home(session)

        # Dock-Zustand VOR _build_docks wiederherstellen, damit die
        # anschließende Tabifizierung der Tool-Docks nicht durch
        # restoreState rückgängig gemacht wird.
        self._restore_dock_state()

        # Docks erstellen und mit Home tabifizieren (lazy loading)
        self._build_docks()

        # --- Sidebar ---
        self._sidebar = SidebarWidget(
            tools=self._tools,
            session=session,
            settings=self._settings,
            groups=config.sidebar_groups if config else None,
            app_name=config.app_name if config else "FINLAI",
        )
        self._sidebar.setObjectName("sidebar")
        self._sidebar.navigate.connect(self._on_sidebar_navigate)
        self._sidebar.open_url.connect(self._on_open_url)
        self._sidebar.logout_requested.connect(self.logout_requested)
        self._sidebar.tool_open_bottom.connect(self._open_in_bottom_panel)
        self._title_bar.search_changed.connect(self._sidebar.filter_items)

        # --- Vertikaler Splitter: inner_main oben, Bottom-Panel unten ---
        self._bottom_panel = QTabWidget()
        self._bottom_panel.setTabsClosable(True)
        self._bottom_panel.tabCloseRequested.connect(self._on_bottom_tab_close)
        self._bottom_panel.setVisible(False)
        self._bottom_panel.setMinimumHeight(120)

        self._v_splitter = QSplitter(Qt.Orientation.Vertical)
        self._v_splitter.setHandleWidth(1)
        self._v_splitter.addWidget(self._inner_main)
        self._v_splitter.addWidget(self._bottom_panel)
        self._v_splitter.setCollapsible(0, False)
        self._v_splitter.setCollapsible(1, False)

        # --- Splitter (custom NeonSplitter — paintEvent statt QSS) ---
        self._splitter = NeonSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(1)
        self._splitter.addWidget(self._sidebar)
        self._splitter.addWidget(self._v_splitter)
        self._splitter.setCollapsible(0, False)
        self._splitter.setCollapsible(1, False)

        # Cursor auf dem Handle
        handle = self._splitter.handle(1)
        if handle:
            handle.setCursor(Qt.CursorShape.SplitHCursor)

        sidebar_start_w = (
            SIDEBAR_COLLAPSED_W
            if self._settings.sidebar_collapsed
            else self._settings.sidebar_width
        )
        total_w = self.width()
        self._splitter.setSizes([sidebar_start_w, max(100, total_w - sidebar_start_w)])
        self._splitter.splitterMoved.connect(self._on_splitter_moved)

        content_layout.addWidget(self._splitter)
        outer_layout.addWidget(content)

        # ==============================================================
        # Statusleiste
        # ==============================================================
        self._status_bar = QStatusBar()
        self._status_bar.setSizeGripEnabled(False)
        self._status_bar.setFixedHeight(22)

        # Soft-Grace-Banner entfällt — kein Lizenz-Server mehr.
        self._lbl_log_level = QLabel("● INFO")
        self._status_bar.addPermanentWidget(self._lbl_log_level)
        outer_layout.addWidget(self._status_bar)

        # Log-Bridge (Komposition statt Mehrfachvererbung — kein emit-Konflikt)
        self._log_emitter = LogSignalEmitter()
        self._log_handler = StatusLogHandler(self._log_emitter)
        self._log_handler.setLevel(logging.DEBUG)
        self._log_emitter.log_received.connect(self._on_log_record)
        logging.getLogger("finlai").addHandler(self._log_handler)

        self._error_reset_timer = QTimer(self)
        self._error_reset_timer.setSingleShot(True)
        self._error_reset_timer.timeout.connect(self._reset_status_indicator)

        self.setCentralWidget(outer)

        # Opakes Repaint verhindert Flackern beim Resize
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)

        # Resize-Zustand
        self._resize_dir: str = ""
        self._last_cursor_zone: str = ""
        self._resize_cursor_set: bool = False

        # Min-Size wird oben vor resize/setWindowFlags gesetzt —
        # hier ist nur noch der EventFilter-Install.
        QApplication.instance().installEventFilter(self)

        # Ctrl+K fokussiert die Titelbalken-Suchleiste
        QShortcut(
            QKeySequence("Ctrl+K"),
            self,
            activated=self._title_bar._search.setFocus,
        )

        # Ctrl+Shift+B blendet das untere Panel ein/aus
        QShortcut(
            QKeySequence("Ctrl+Shift+B"),
            self,
            activated=self._toggle_bottom_panel,
        )

        if session.is_logged_in():
            self._sidebar.set_user(session.current_user.full_name)

        # Schwebender Hilfe-Button (rechts unten, über allen anderen Widgets)
        from core.help_button import HelpButton  # noqa: PLC0415

        self._help_btn = HelpButton(self)
        self._help_btn.reposition()
        self._help_btn.show()

        # Theme-Listener: MainWindow aktualisiert outer_frame, separator,
        # inner_main und status_bar die keine eigenen Listener haben.
        theme.register_listener(self.apply_theme)

        # Initialer Theme-Durchlauf — setzt alle lokalen Stylesheets
        # (outer_frame, separator, inner_main, status_bar) auf die aktuellen
        # Theme-Farben, da ihre setStyleSheet-Aufrufe aus __init__ entfernt wurden.
        self.apply_theme()

        # Pre-Warm QWebEngineView — verhindert GL-Surface-Flicker beim ersten Öffnen
        # von Tools die QWebEngineView nutzen (z.B. CyberSec Videos).
        # Chromium-Prozess startet im Hintergrund, bevor der User das Tool öffnet.
        QTimer.singleShot(_WEBENGINE_PREWARM_DELAY_MS, self._pre_warm_webengine)

        # Lizenz-Revalidation-Worker entfällt — kein
        # Hintergrund-Heartbeat gegen den License-Server mehr (100% lokal).

        # SecureStorage-Corruption-Observer. Wenn beim ersten Read
        # ``secure_store.enc`` mit ``InvalidToken`` ablehnt (R-8 DPAPI-Drift),
        # zeigt MainWindow einen Recovery-Dialog. Observer ist Qt-frei
        # (core/security/encryption.py kennt kein PySide6), wir mappen ihn
        # auf ein Qt-Signal — ``QueuedConnection`` routet auf den GUI-Thread.
        try:
            from core.security.encryption import get_secure_storage  # noqa: PLC0415

            _ss = get_secure_storage()
            _ss.add_corruption_observer(
                lambda path, bak: self.secrets_corrupted.emit(
                    str(path), "" if bak is None else str(bak)
                )
            )
            self.secrets_corrupted.connect(self._on_secrets_corrupted)
            # Fail-closed Recovery-Pfad: wenn der Init-Fehler
            # einen Sicherheits-Indikator angeschlagen hat (DPAPI-Drift,
            # KeyManager-Korruption), wurde ``_init_error`` gesetzt. Wir
            # triggern denselben Recovery-Dialog wie bei Corruption-Read.
            if _ss.init_error is not None:
                _log.warning(
                    "SecureStorage fail-closed im Init (%s) — Recovery-Dialog wird angestossen.",
                    type(_ss.init_error).__name__,
                )
                # Pfad ist ggf. nicht angelegt — wir loggen das mit, der
                # Dialog kommt mit dem zentralen secure_store.enc-Pfad.
                from core.security.encryption import _STORE_FILE  # noqa: PLC0415

                self.secrets_corrupted.emit(str(_STORE_FILE), "")
        except Exception as exc:  # noqa: BLE001 — Observer-Setup darf App-Start nie blockieren
            _log.warning(
                "SecureStorage corruption-observer setup fehlgeschlagen: %s",
                type(exc).__name__,
            )

        # (PM-PERSIST): Patch-Inventory-Persistence-Tier-Modell.
        # Scheduler (QTimer 5min) + Worker (eigener Thread) wickeln den
        # Drei-Tier-Scan ab (Initial / Monthly-Full / Daily-Refresh). Bei
        # leerem Inventar emittiert der Scheduler ``initial_scan_due`` —
        # MainWindow zeigt dann den Erst-Scan-Dialog. ``daily_refresh_due``
        # und ``monthly_full_due`` triggern den Worker stille.
        # Setup-Hook von apps injiziert (kein core->tools-Import).
        # Guard: Erst-Scan-Dialog nur EINMAL pro Sitzung zeigen — sonst kommt er
        # bei jedem Scheduler-Tick (5 min) erneut, solange das Inventar leer ist.
        self._initial_scan_prompted = False
        if patch_inventory_setup is not None:
            (
                self._inv_thread,
                self._inv_worker,
                self._inv_scheduler,
                self._inv_service,
            ) = patch_inventory_setup(self)
            self._inv_scheduler.initial_scan_due.connect(self._on_initial_scan_due)
            self._inv_worker.full_scan_finished.connect(self._on_full_scan_finished)
            self._inv_worker.full_scan_failed.connect(self._on_full_scan_failed)
            self._inv_worker.daily_refresh_finished.connect(
                self._on_daily_refresh_finished
            )
            self._inv_worker.daily_refresh_failed.connect(
                self._on_daily_refresh_failed
            )
        else:
            # In Produktion injiziert apps immer beide Hooks. Fehlt der
            # Setup-Hook, laeuft der Patch-/CVE-Inventory-Hintergrunddienst NICHT
            # — als warning sichtbar (nicht still unter info), damit ein versehentlich
            # nicht-injizierter Sicherheitsdienst im Log auffaellt (3-Sub-Agent-Review).
            _log.warning(
                "Patch-Inventory-Hintergrunddienst nicht registriert "
                "(kein Setup-Hook injiziert) — Patch-/CVE-Monitoring inaktiv"
            )

        _log.info("MainWindow bereit (VS Code-Stil, nested QMainWindow)")

    # ==================================================================
    # Home-Widget (central widget des inner_main)
    # ==================================================================

    # ------------------------------------------------------------------
    # Zentrales Help-System (F1 + TitleBar + FloatingButton)
    # ------------------------------------------------------------------
    @Slot()
    def _open_help_dialog(self, nav_key: str | None = None) -> None:
        """Öffnet das zentrale HelpDialog — Singleton-Verhalten.

        Wenn bereits ein HelpDialog offen ist, wird es nur in den
        Vordergrund gebracht statt ein zweites Fenster zu erzeugen.

        Args:
            nav_key: Optionaler Tool-Nav-Key — Dialog springt direkt zum
                Kapitel. Standard: Willkommensseite.
        """
        from core.help.help_dialog import HelpDialog  # noqa: PLC0415

        existing = self._help_dialog
        if existing is not None and getattr(existing, "isVisible", lambda: False)():
            # (Review-P2): Auch bei einem bereits offenen Dialog den
            # Assistenz-Reiter nach vorn holen — sonst ignoriert die Wieder-
            # verwendung den umgeleiteten ki:ollama-Deeplink stillschweigend.
            if nav_key == HelpDialog.ASSISTANT_KEY:
                existing.show_assistant()
            existing.raise_()
            existing.activateWindow()
            return

        key = nav_key if isinstance(nav_key, str) else None
        self._help_dialog = HelpDialog(initial_nav_key=key, parent=self)
        self._help_dialog.show()

    # ==================================================================
    # Slot: Sidebar-Navigation
    # ==================================================================
    # Slot: Splitter-Bewegung
    # ==================================================================
    @Slot(int, int)
    def _on_splitter_moved(self, pos: int, _index: int) -> None:
        """Speichert die neue Sidebar-Breite nach Splitter-Drag.

        Args:
            pos: Neue Position des Splitter-Handle in Pixeln.
            _index: Index des bewegten Handles (nicht verwendet).
        """
        sidebar_w = self._splitter.sizes()[0]
        self._sidebar.save_width(sidebar_w)

    # ==================================================================
    # Theme live anwenden
    # ==================================================================
    # Tab-Stylesheet-Helper
    # ==================================================================

    # ==================================================================
    # closeEvent — Settings speichern
    # ==================================================================
    def closeEvent(self, event) -> None:
        """Speichert UI- und Dock-Einstellungen vor dem Schließen.

        Args:
            event: Das Qt-CloseEvent.
        """
        # Patch-Inventory-Worker + Scheduler ebenfalls stoppen,
        # bevor das Hauptfenster verschwindet. None-Guard analog oben.
        # Teardown ueber den von apps injizierten Hook.
        if (
            self._patch_inventory_teardown is not None
            and self._inv_thread is not None
            and self._inv_scheduler is not None
        ):
            self._patch_inventory_teardown(self._inv_thread, self._inv_scheduler)

        # Alle Tool-Widget-Worker explizit stoppen,
        # bevor Qt die Receiver-Widgets zerstoert. Sonst feuert z. B. der
        # NetworkMonitor-QThread nach APP_EXIT weiter und produziert
        # "QThread: Destroyed while thread is still running"-FATAL plus
        # ~10s Slot-Aufrufe ins Leere. Pattern: jedes Widget mit
        # ``stop_worker`` Public-API kriegt den Aufruf -- nicht-betroffene
        # Tools haben die Methode nicht und werden uebersprungen.
        for dock in self.findChildren(QDockWidget):
            inner = dock.widget()
            if inner is None:
                continue
            stop = getattr(inner, "stop_worker", None)
            if callable(stop):
                try:
                    stop()
                except Exception as exc:  # noqa: BLE001 -- Shutdown-Boundary
                    _log.warning(
                        "stop_worker() fuer %s beim Shutdown fehlgeschlagen: %s",
                        type(inner).__name__, exc,
                    )
            # zusaetzlich duck-typed shutdown — der file_scanner-Container
            # raeumt darueber seine genesteten Sub-Scanner ab (Quarantaene-Cleanup +
            # Worker-wait des Dokument-Scanners), die seit 3b nicht mehr als
            # Direkt-Dock leben und vom stop_worker-Sweep nicht erreicht wurden.
            # Getrennt von stop_worker: ein Widget kann beides, eines oder keines haben.
            shutdown = getattr(inner, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except Exception as exc:  # noqa: BLE001 -- Shutdown-Boundary
                    _log.warning(
                        "shutdown() fuer %s beim Shutdown fehlgeschlagen: %s",
                        type(inner).__name__, exc,
                    )

        # Window-Geometry vor save snapshotten —
        # damit ``_settings.save`` die aktuellen Werte schreibt.
        self._snapshot_window_geometry()
        self._save_dock_state()
        self._settings.save()
        _log.debug("UI- und Dock-Einstellungen gespeichert beim Schließen.")
        super().closeEvent(event)

    # ==================================================================
    # Window-Geometry-Persistenz
    # ==================================================================
    def _restore_window_geometry(self) -> None:
        """Stellt die persistierte Window-Geometry her — falls vorhanden + valid.

        ``window_width=0`` ist Sentinel fuer "keine Persistenz vorhanden"
        (Erst-Start) → Default 1920x1080 bleibt aktiv. Ansonsten werden
        Breite, Hoehe, Position und Maximized-Flag wiederhergestellt, mit
        Validierung gegen Min-Size und aktuelle Screen-Geometry.
        """
        s = self._settings
        if s.window_width <= 0 or s.window_height <= 0:
            _log.debug("Keine Window-Geometry persistiert — Default 1920x1080.")
            return

        # Min-Size respektieren (gleiche Bounds wie ``setMinimumSize`` oben).
        width = max(1000, s.window_width)
        height = max(700, s.window_height)

        # T-GUI-060: Gegen den ZIEL-Screen validieren, nicht nur
        # den Primaer-Screen. ``screenAt`` liefert den Monitor unter der
        # gespeicherten Position — auf 2./3.-Monitor-Setups ist das nicht der
        # Primaer-Screen. Vorher klemmte die Bounds-Pruefung (nur Primaer) eine
        # auf Monitor 2/3 gespeicherte Position weg → das Fenster landete immer
        # auf dem Primaer-Monitor. ``None`` = Monitor nicht mehr angeschlossen
        # → Fallback Primaer (sichtbar einklemmen).
        screen = QApplication.screenAt(QPoint(s.window_x, s.window_y))
        if screen is None:
            screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            width = min(width, avail.width())
            height = min(height, avail.height())
            if (
                s.window_x >= avail.x() - 50
                and s.window_y >= avail.y() - 50
                and s.window_x + width <= avail.right() + 50
                and s.window_y + height <= avail.bottom() + 50
            ):
                self.move(s.window_x, s.window_y)
            else:
                # Gespeicherte Position passt in keinen aktuellen Screen —
                # sichtbar oben links auf dem Ziel-/Primaer-Screen platzieren.
                self.move(avail.x(), avail.y())

        self.resize(width, height)
        if s.window_maximized:
            self.setWindowState(Qt.WindowState.WindowMaximized)
        _log.debug(
            "Window-Geometry restored: %dx%d at (%d,%d) maximized=%s",
            width, height, s.window_x, s.window_y, s.window_maximized,
        )

    def _snapshot_window_geometry(self) -> None:
        """Schreibt aktuelle Window-Geometry in self._settings (nicht persistiert).

        ``self._settings.save`` muss vom Aufrufer separat aufgerufen werden.
        Bei maximiertem Fenster wird die ``normalGeometry`` gespeichert,
        damit das De-Maximierte Fenster spaeter die richtige Groesse hat.
        """
        is_maximized = bool(self.windowState() & Qt.WindowState.WindowMaximized)
        # Bei maximized: normalGeometry gibt die "ge-restored" Groesse;
        # sonst geometry gibt die aktuelle.
        geom = self.normalGeometry() if is_maximized else self.geometry()
        self._settings.window_width = geom.width()
        self._settings.window_height = geom.height()
        self._settings.window_x = geom.x()
        self._settings.window_y = geom.y()
        self._settings.window_maximized = is_maximized

    # ==================================================================
    # (PM-PERSIST): Patch-Inventory-Slots
    # ==================================================================
    @Slot()
    def _on_initial_scan_due(self) -> None:
        """Patch-Inventar ist leer — einmalig den Erst-Vollscan anbieten.

        Vom:class:`PatchScheduler` bei JEDEM Tick (5 min) getriggert, solange
        ``service.is_inventory_empty`` ``True`` ist. Damit der Dialog nicht
        wieder und wieder erscheint, wird er via ``_initial_scan_prompted`` nur
        EINMAL pro Sitzung gezeigt (Fix der Re-Prompt-Schleife).

        Bei "Ja" navigieren wir auf den Patch-Monitor UND starten den Erst-Scan
        direkt ueber das Console-Widget (kein separater "Scan starten"-Klick
        noetig); der Scan laeuft im ScanWorker-QThread mit Live-Fortschritt, die
        GUI bleibt responsiv.
        """
        if self._initial_scan_prompted:
            return
        self._initial_scan_prompted = True

        from PySide6.QtWidgets import QDialog  # noqa: PLC0415

        from core.dialogs import FinlaiConfirmDialog  # noqa: PLC0415

        dlg = FinlaiConfirmDialog(
            title="Patch-Inventar aufbauen?",
            message=(
                "Das Patch-Inventar ist leer. Jetzt den Erst-Vollscan starten?\n\n"
                "Wir wechseln dazu auf den Patch-Monitor; der Scan laeuft dort mit "
                "Live-Fortschritt (winget + NVD-CVE-Abfrage, ca. 20 Minuten)."
            ),
            confirm_text="Scan starten",
            parent=self,
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            _log.info("Initial-Scan-Dialog: User -> Patch-Monitor + direkter Scan-Start.")
            try:
                self.navigate_to("patch_monitor")
                self._start_patch_console_scan()
            except Exception as exc:  # noqa: BLE001 — Dialog-Handler darf nie crashen
                _log.warning(
                    "Initial-Scan-Start fehlgeschlagen: %s",
                    type(exc).__name__,
                )
        else:
            _log.info("Initial-Scan vom User abgelehnt — kein erneuter Dialog.")

    def _start_patch_console_scan(self) -> None:
        """Loest den Erst-Vollscan im Patch-Monitor-Widget aus (nach "Ja").

        Ruft die public ``start_initial_scan``-Methode des Patch-Console-
        Widgets duck-typed auf — gleiches Muster wie ``stop_worker`` im
        ``closeEvent`` (kein statischer ``tools``-Import/Makro-Schichtung).
        So nutzt der Auto-Start denselben beobachtbaren ScanWorker-Pfad wie der
        "Scan starten"-Button; laeuft schon ein Scan, ist der Aufruf ein No-op.
        """
        for dock in self.findChildren(QDockWidget):
            inner = dock.widget()
            if inner is None:
                continue
            starter = getattr(inner, "start_initial_scan", None)
            if callable(starter):
                starter()
                return
        _log.warning(
            "Patch-Console ohne start_initial_scan gefunden — Auto-Scan uebersprungen."
        )

    @Slot(object)
    def _on_full_scan_finished(self, summary) -> None:
        """Vollscan abgeschlossen — kurze Status-Meldung."""
        _log.info(
            "Patch-Inventar-Vollscan abgeschlossen: items=%d updates=%d cves=%d",
            getattr(summary, "items_total", 0),
            getattr(summary, "items_with_updates", 0),
            getattr(summary, "items_with_cves", 0),
        )

    @Slot(str, str)
    def _on_full_scan_failed(self, scan_type: str, error: str) -> None:
        """Vollscan fehlgeschlagen — Log + leise weiter (Scheduler tickt erneut)."""
        _log.warning(
            "Patch-Inventar-Vollscan (%s) fehlgeschlagen: %s", scan_type, error
        )

    @Slot(object)
    def _on_daily_refresh_finished(self, summary) -> None:
        """Daily-Refresh abgeschlossen — Ansicht aktualisieren + sichtbar machen.

        Gilt fuer beide Ausloeser: den automatischen 24-h-Refresh des
        Schedulers UND den on-demand "Schnell nach Updates suchen"-Klick. Ein offenes Patch-Console-Widget wird neu geladen; werden
        Updates gefunden, macht ein Toast den Hintergrund-Check sichtbar.
        """
        items_with_updates = int(getattr(summary, "items_with_updates", 0) or 0)
        _log.info(
            "Patch-Inventar-Daily-Refresh abgeschlossen: items=%d updates=%d cves=%d",
            getattr(summary, "items_total", 0),
            items_with_updates,
            getattr(summary, "cves_refreshed", 0),
        )
        # Offenes Patch-Console-Widget aktualisieren (Tabelle + Banner +
        # Quick-Check-Button) — No-op wenn das Tool nicht geladen ist.
        self._call_patch_console("reload_after_refresh")
        # LUECKE B: Hintergrund-Check sichtbar machen, wenn es Updates gibt.
        if items_with_updates > 0:
            self._show_patch_update_toast(items_with_updates)

    @Slot(str)
    def _on_daily_refresh_failed(self, error: str) -> None:
        """Daily-Refresh fehlgeschlagen — Log + Quick-Check-Button freigeben."""
        _log.warning("Patch-Inventar-Daily-Refresh fehlgeschlagen: %s", error)
        self._call_patch_console(
            "quick_check_failed",
            "Update-Pruefung fehlgeschlagen — bitte spaeter erneut versuchen.",
        )

    @Slot()
    def _on_patch_quick_check_requested(self) -> None:
        """On-Demand-Quick-Check aus dem Patch-Monitor.

        Loest den leichten Daily-Refresh ueber den bereits am Start
        verdrahteten Worker aus (~30-60 s statt ~20 Min Vollscan).

        Der ``is_busy``-Vorab-Check ist nur ein BERATENDER Fast-Path fuer
        die UX-Rueckmeldung ("bitte warten") — er ist nicht atomar mit dem
        Set im Worker-Thread. Der AUTORITATIVE Guard gegen Doppellaeufe
        liegt in ``InventoryWorker.run_daily_refresh`` selbst (``_busy``
        wird dort serialisiert im Worker-Thread geprueft/gesetzt, da alle
        Trigger — Scheduler wie On-Demand — queued in denselben Thread
        laufen).
        """
        worker = self._inv_worker
        if worker is None:
            self._call_patch_console(
                "quick_check_failed",
                "Update-Pruefung nicht verfuegbar (Hintergrunddienst inaktiv).",
            )
            return
        if worker.is_busy():
            self._call_patch_console(
                "quick_check_failed",
                "Es laeuft bereits eine Pruefung — bitte einen Moment warten.",
            )
            return
        self._trigger_daily_refresh(worker)

    def _trigger_daily_refresh(self, worker: object) -> None:
        """Stoesst ``run_daily_refresh`` im Worker-Thread an.

        Der Worker lebt via ``moveToThread`` in einem eigenen Thread. Ein
        DIREKTER Aufruf ``worker.run_daily_refresh`` wuerde den Refresh
        (winget + ggf. NVD, ~30-60 s) im GUI-Thread ausfuehren und die UI
        einfrieren.:func:`QMetaObject.invokeMethod` mit
        ``QueuedConnection`` marshallt den Slot-Aufruf in den Worker-Thread
        — gleiches Verhalten wie die Scheduler-Signal->Slot-Verbindung.
        """
        QMetaObject.invokeMethod(
            worker,
            "run_daily_refresh",
            Qt.ConnectionType.QueuedConnection,
        )

    def _call_patch_console(self, method_name: str, *args: object) -> bool:
        """Ruft eine Methode auf dem offenen Patch-Console-Widget auf.

        Findet das Widget duck-typed ueber die Dock-Children (gleiches
        Muster wie:meth:`_start_patch_console_scan`). Nur das
        PatchConsoleWidget traegt die hier genutzten Methoden
        (``reload_after_refresh`` / ``quick_check_failed``), daher ist der
        Aufruf zielsicher.

        Args:
            method_name: Name der aufzurufenden Widget-Methode.
            *args: Argumente fuer die Methode.

        Returns:
            ``True`` wenn ein passendes Widget gefunden und aufgerufen wurde.
        """
        for dock in self.findChildren(QDockWidget):
            inner = dock.widget()
            if inner is None:
                continue
            fn = getattr(inner, method_name, None)
            if callable(fn):
                try:
                    fn(*args)
                except Exception as exc:  # noqa: BLE001 — UI-Callback darf nicht crashen
                    _log.warning(
                        "Patch-Console.%s fehlgeschlagen: %s",
                        method_name,
                        type(exc).__name__,
                    )
                return True
        return False

    def _show_patch_update_toast(self, count: int) -> None:
        """Zeigt einen Toast "N Update(s) verfuegbar", LUECKE B)."""
        from core.widgets.info_toast import InfoToast  # noqa: PLC0415

        if count == 1:
            message = "Patch-Monitor: 1 Update verfuegbar."
        else:
            message = f"Patch-Monitor: {count} Updates verfuegbar."
        # Referenz auf self halten, bis der Toast sich selbst aufraeumt.
        self._patch_update_toast = InfoToast(message, parent=self)
        self._patch_update_toast.show_toast()

    # ==================================================================
    # SecureStorage Recovery-Dialog
    # ==================================================================
    @Slot(str, str)
    def _on_secrets_corrupted(self, corrupted_path: str, backup_path: str) -> None:
        """Zeigt einen Recovery-Dialog wenn `secure_store.enc` nicht
        entschluesselbar ist.

        Typische Ursache: DPAPI-Drift nach Windows-Update / User-Profile-
        Aenderung (THREAT_MODEL R-8). Dialog informiert den User und
        zeigt den Pfad zum Backup (falls schon angelegt). Idempotent —
        Mehrfach-Aufrufe (z. B. erst beim Read mit ``backup_path=""``,
        dann nach ``_backup_corrupted_store`` mit konkretem Pfad) werden
        gegen Spam-Schutz geprueft: nur das erste Auftreten oeffnet den
        Dialog, der Backup-Pfad wird dann ergaenzt in die Statusbar.
        """
        from core.dialogs import FinlaiInfoDialog  # noqa: PLC0415
        from core.icons import Icons  # noqa: PLC0415

        # Spam-Schutz: bei mehrfach-Emit nur das erste Mal Dialog oeffnen.
        if getattr(self, "_secrets_dialog_shown", False):
            if backup_path:
                _log.info(
                    "SecureStorage-Backup gesichert als: %s", backup_path
                )
            return
        self._secrets_dialog_shown = True

        _log.warning(
            "SecureStorage-Corruption erkannt: %s (Backup: %s)",
            corrupted_path,
            backup_path or "(noch nicht angelegt)",
        )

        backup_note = (
            f"\n\nDie alte Datei wurde gesichert als:\n{backup_path}"
            if backup_path
            else "\n\nDie alte Datei wird beim naechsten Speicher-Vorgang automatisch gesichert."
        )

        FinlaiInfoDialog(
            title="Verschluesselte Daten nicht lesbar",
            message=(
                "Einige gespeicherte Werte (z. B. API-Keys) konnten nach dem "
                "letzten System-Update nicht mehr entschluesselt werden.\n\n"
                "Das ist ein bekanntes Risiko bei Windows-Profile-Aenderungen "
                "(DPAPI-Drift). Ihre Lizenz und Ihre Datenbanken sind nicht "
                "betroffen, nur lokal verschluesselte API-Keys / Tokens.\n\n"
                "Bitte tragen Sie betroffene Schluessel im Einstellungen-Tab neu ein "
                "(NVD-API-Key, HIBP-Key, etc.)."
                f"{backup_note}"
            ),
            icon_name=Icons.WARNING,
            parent=self,
        ).exec()

    def resizeEvent(self, event) -> None:
        """Repositioniert den HelpButton bei Fenster-Resize.

        Args:
            event: Das Qt-ResizeEvent.
        """
        super().resizeEvent(event)
        if hasattr(self, "_help_btn"):
            self._help_btn.reposition()

    # ==================================================================
    # Pre-Warming
    # ==================================================================

    def _pre_warm_webengine(self) -> None:
        """Pre-initialisiert QWebEngineView um GL-Surface-Flicker zu vermeiden.

        Wird einmalig _WEBENGINE_PREWARM_DELAY_MS nach dem MainWindow-Start
        aufgerufen. Die erste QWebEngineView-Instanz triggert die Chromium-
        Engine-Initialisierung im Hintergrund, sodass spätere Instanzen
        (z.B. CyberSec Videos) ohne sichtbaren Blackout geöffnet werden können.

        Die Warmup-Instanz ist 1×1 px und unsichtbar — kein visueller Effekt.
        """
        try:
            from PySide6.QtWebEngineWidgets import QWebEngineView  # noqa: PLC0415

            self._webengine_warmup = QWebEngineView()
            self._webengine_warmup.setFixedSize(1, 1)
            self._webengine_warmup.hide()
            _log.debug("QWebEngineView pre-warmed (GL-Surface bereit)")
        except ImportError:
            _log.debug("QtWebEngineWidgets nicht verfügbar — Pre-Warming übersprungen")
        except Exception as exc:  # noqa: BLE001 -- QtWebEngine GL/Chromium-Init kann beliebige OS/Treiber-Errors werfen, Pre-Warm darf nie App-Start blockieren
            _log.warning("QWebEngineView Pre-Warming fehlgeschlagen: %s", exc)

    # ==================================================================
    # Status-Anzeige
    # ==================================================================
    def _on_log_record(self, record: logging.LogRecord) -> None:
        """Aktualisiert Statusleiste bei eingehenden Log-Records.

        Args:
            record: Eingehender LogRecord.
        """
        lvl = record.levelno
        # GUI-Statuszeile nutzt record.getMessage (roh, am Formatter
        # vorbei) → vor Anzeige sanitisieren, damit kein Secret on-screen erscheint.
        from core.logger import _redact  # noqa: PLC0415

        if lvl >= logging.ERROR:
            self._lbl_log_level.setText("● ERROR")
            self._lbl_log_level.setStyleSheet(
                f"color: {theme.ERROR_RED}; padding: 0 8px; font-weight: bold;"
            )
            self._status_bar.showMessage(f"[ERROR] {_redact(record.getMessage())}", 0)
            self._status_bar.setStyleSheet(f"""
                QStatusBar {{
                    background-color: #3a1010;
                    border-top: 1px solid {theme.ERROR_RED};
                    color: {theme.get().TEXT_MAIN};
                    font-size: 11px;
                }}
            """)  # noqa: hex-color-pending — #3a1010 (Error-Statusbar-BG) ohne Theme-Pendant; ggf. Sprint 2 als BG_PANEL_ERROR_DEEP
            self._error_reset_timer.start(4000)
        elif lvl >= logging.WARNING:
            self._lbl_log_level.setText("● WARN")
            self._lbl_log_level.setStyleSheet(
                f"color: {theme.WARNING_ORANGE}; padding: 0 8px;"
            )
        elif lvl >= logging.INFO:
            self._lbl_log_level.setText("● INFO")
            self._lbl_log_level.setStyleSheet(
                f"color: {theme.get().TEXT_MAIN}; padding: 0 8px;"
            )
        else:
            self._lbl_log_level.setText("● DEBUG")
            self._lbl_log_level.setStyleSheet(
                f"color: {theme.get().TEXT_DIM}; padding: 0 8px;"
            )

    def _reset_status_indicator(self) -> None:
        """Setzt Statusleiste nach einem ERROR-Log-Eintrag zurück."""
        self._lbl_log_level.setText("● INFO")
        self._lbl_log_level.setStyleSheet(
            f"color: {theme.get().TEXT_MAIN}; padding: 0 8px;"
        )
        self._status_bar.clearMessage()
        self._status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {theme.get().BG_MAIN};
                border-top: 1px solid {theme.get().BORDER};
                color: {theme.get().TEXT_MAIN};
                font-size: 11px;
            }}
        """)

