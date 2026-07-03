"""
dock_mixin — Tool-Dock-Lifecycle + Bottom-Panel-Verwaltung fuer das MainWindow.

Sprint 7 Phase 2c: Dritter Mixin-Extract aus dem
``MainWindow``-God-Class-Refactor.

Buendelt zwei eng zusammenhaengende Verantwortlichkeiten:

1. **Tool-Docks** -- Lazy-geladene QDockWidgets pro Tool, tabifiziert
   mit dem Welcome-Dock. Build, Lifecycle, State-Save/Restore.

2. **Bottom-Panel** -- QTabWidget am unteren Bildschirmrand fuer
   sekundaere Tool-Ansichten (z. B. KI-Chat parallel zum Haupttool).

Methoden:
    _build_home(session) -- Welcome-Dock initial
    _create_dock(key, title, icon, ref)-- Lazy-loadendes Dock
    _on_dock_visible(dock, key, vis) -- Lazy-Load-Trigger
    _build_docks -- Alle Tool-Docks aufbauen
    _save_dock_state -- Dock-Layout in UISettings
    _restore_dock_state -- Dock-Layout wiederherstellen
    _open_in_bottom_panel(key) -- Tool im Bottom-Panel oeffnen
    _get_or_create_tool_widget(key) -- Widget-Factory fuer Bottom
    _get_tool_title(key) -> str -- Anzeigenamen fuer Tab
    _show_bottom_panel -- Panel einblenden
    _close_bottom_panel -- Panel ausblenden
    _toggle_bottom_panel -- Panel toggeln (Ctrl+Shift+B)
    _on_bottom_tab_close(index) -- Tab schliessen + leer? hide

State-Anforderungen (vom MainWindow.__init__ zu setzen):
    self._inner_main, self._tool_map, self._docks, self._welcome_dock,
    self._bottom_panel, self._v_splitter, self._sidebar, self._settings,
    self._NAV_TOOL_MAP (Klassen-Attribut)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtWidgets import QDockWidget, QLabel, QWidget

from core import theme
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.dock_title_bar import DockTitleBar
from core.widgets.placeholder import PlaceholderWidget

_log = get_logger(__name__)

# Aktuelle dock_state-Schema-Version. Erhoehen, wenn ein Dock entfaellt
# oder umbenannt wird (objectName-Wegfall) — dann verwirft _restore_dock_state
# den Alt-Blob einmalig, statt verwaiste objectNames zu interpretieren.
# 3c 1b: auf 2 erhoeht — das eigenstaendige ``dock_norisk:dashboard``
# entfaellt (Cockpit IST jetzt das Welcome-Dock Vision B), der
# Alt-Layout-Blob wird einmalig verworfen.
# auf 3 erhoeht — die Einzel-Docks customer_audit/nis2_incidents/
# security_scoring/awareness_tracker/techstack entfallen (Bewerten-Merge in den
# Container ``security_assessment`` + Techstack zieht in den Advisory-Monitor);
# der Alt-Layout-Blob mit den verwaisten objectNames wird einmalig verworfen.
_DOCK_STATE_VERSION = 3

# 3c 1b Vision B) — Tool-NAME-Key (``BaseTool.name``) des
# NoRisk-Cockpits im ``_tool_map``. Das Cockpit-Widget (NoRiskDashboardWidget)
# wird unter diesem Namen registriert (siehe tools/norisk_dashboard/tool.py)
# und dient als EINE Landing-Seite im Welcome-Dock — kein separates
# mainpage-„Home"-Dock und kein zweites „norisk:dashboard"-Nav-Dock mehr.
_COCKPIT_TOOL_NAME = "Übersicht"


class DockMixin:
    """Mixin: Tool-Dock-Lifecycle + Bottom-Panel-Verwaltung."""

    def _build_home(self, session) -> None:
        """Erstellt das Cockpit als erstes (Welcome-)Dock (nicht centralWidget).

 3c 1b Vision B): Das Welcome-Dock zeigt jetzt das
        **Cockpit** (``NoRiskDashboardWidget``, registriert als
        ``_COCKPIT_TOOL_NAME``) — die EINE Landing-Seite. Das frueher hier
        gebaute mainpage-„Home" entfaellt als eigenes Dock; seine
        einzigartigen Bestandteile (Begruessung/Schnellstart/Phishing/
        Aufgaben/Aktivitaeten) komponiert das Cockpit selbst.

        Das Welcome-Dock startet sichtbar und wird beim Oeffnen eines
        anderen Tools automatisch in den Hintergrund (Tab) geschoben.
        inner_main bekommt ein minimales leeres centralWidget damit
        die Dock-Area korrekt funktioniert.
        """
        # Leeres central widget -- nur Platzhalter fuer Qt-Dock-System
        empty = QWidget()
        empty.setStyleSheet(f"background: {theme.get().BG_MAIN}; border: none;")
        empty.setMaximumSize(0, 0)
        self._inner_main.setCentralWidget(empty)

        # Cockpit als Welcome-Dock erstellen. Fail-soft auf einen Placeholder,
        # wenn das Cockpit-Tool nicht freigeschaltet/registriert ist ODER wenn
        # sein eager Bau (eine Sektion-Ctor laeuft hier SYNCHRON beim App-Start,
        # anders als der lazy Tool-Dock-Pfad) eine Exception wirft. Ohne diese
        # Kapselung wuerde ein einziger fehlerhafter Sektion-Ctor die KOMPLETTE
        # App am Start verhindern (kein Welcome-Dock, kein MainWindow).
        cockpit_tool = self._tool_map.get(_COCKPIT_TOOL_NAME)
        if cockpit_tool is not None:
            try:
                home_widget = cockpit_tool.create_widget(self._inner_main)
            except Exception as exc:  # noqa: BLE001 -- App-Start darf nie am Cockpit scheitern
                _log.error(
                    "Cockpit-Bau (Welcome-Dock) fehlgeschlagen: %s — "
                    "Fallback auf ErrorPlaceholder, App startet trotzdem.",
                    exc,
                    exc_info=True,
                )
                from core.widgets.error_placeholder import ErrorPlaceholderWidget

                home_widget = ErrorPlaceholderWidget(
                    tool_title="Cockpit",
                    message="Das Cockpit konnte nicht initialisiert werden.",
                    detail=f"{type(exc).__name__}: {exc}",
                    parent=self._inner_main,
                )
        else:
            _log.warning(
                "Cockpit-Tool %r nicht im _tool_map (gegatet/umbenannt) "
                "-> Placeholder",
                _COCKPIT_TOOL_NAME,
            )
            home_widget = PlaceholderWidget("Cockpit", "Willkommen bei NoRisk")

        if hasattr(home_widget, "set_last_used"):
            self.tool_activated.connect(home_widget.set_last_used)

        # 3c: Cockpit-Deeplinks (z.B. „Alle im Board →") laufen ueber
        # navigate_to(..., section=...) -> apply_navigation, und CTA-Klicks im
        # Cockpit ueber navigate/open_with_filter. Diese Signale hier verdrahten
        # (sonst gibt es kein lazy ``_on_dock_visible`` mehr fuer das Cockpit).
        # an ``navigate_to`` haengen (NICHT ``_on_sidebar_navigate``), damit
        # Cockpit-CTAs auf alte Keys (z.B. „Zum Audit"/„Zum Scoring" ->
        # customer_audit/security_scoring) durch den Alias-Router auf den
        # Bewerten-Container + Sub-Tab umgebogen werden statt ins Leere zu laufen.
        if hasattr(home_widget, "navigate"):
            try:
                home_widget.navigate.connect(self.navigate_to)
            except (AttributeError, TypeError):
                pass
        if hasattr(home_widget, "open_with_filter"):
            try:
                home_widget.open_with_filter.connect(
                    self._on_dashboard_open_with_filter
                )
            except (AttributeError, TypeError):
                pass

        dock = QDockWidget("Cockpit", self._inner_main)
        dock.setObjectName("dock_welcome")
        dock.setWidget(home_widget)
        dock.setWindowIcon(get_icon(Icons.DASHBOARD))

        # Custom TitleBar (nur movable, kein Float/Close fuer Welcome)
        title_bar = DockTitleBar("Cockpit", dock)
        dock.setTitleBarWidget(title_bar)

        dock.setFloating(False)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.RightDockWidgetArea
            | Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.TopDockWidgetArea
            | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        dock.setStyleSheet(f"""
            QDockWidget {{
                color: {theme.get().TEXT_MAIN};
                font-family: 'Raleway'; font-size: 12px;
                border: 1px solid {theme.get().ACCENT};
                background: {theme.get().BG_MAIN};
            }}
        """)

        self._inner_main.addDockWidget(
            Qt.DockWidgetArea.RightDockWidgetArea,
            dock,
        )
        dock.show()

        self._welcome_dock = dock

    # ==================================================================
    # Dock-Aufbau (Lazy Loading)
    # ==================================================================

    def _create_dock(
        self, nav_key: str, title: str, icon: str, tool_ref: object | None = None
    ) -> QDockWidget:
        """Erstellt ein lazy-geladenes QDockWidget.

        Das eigentliche Tool-Widget wird erst beim ersten Sichtbar-
        werden erzeugt (``_on_dock_visible``).
        """
        display_title = title
        dock = QDockWidget(display_title, self._inner_main)
        dock.setObjectName(f"dock_{nav_key}")
        dock.setWindowIcon(get_icon(icon))

        # Lazy-Loading: Widget wird erst bei Sichtbarkeit erstellt
        dock._tool_ref = tool_ref  # type: ignore[attr-defined]
        dock._widget_loaded = False  # type: ignore[attr-defined]

        # Platzhalter bis zum ersten Oeffnen
        placeholder = QLabel(f"  {display_title} wird geladen …")
        placeholder.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 12px; "
            f"background: {theme.get().BG_MAIN}; border: none; padding: 20px;"
        )
        dock.setWidget(placeholder)

        # Custom TitleBar
        title_bar = DockTitleBar(display_title, dock)
        dock.setTitleBarWidget(title_bar)

        dock.setFloating(False)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.RightDockWidgetArea
            | Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.TopDockWidgetArea
            | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        dock.setStyleSheet(f"""
            QDockWidget {{
                color: {theme.get().TEXT_MAIN};
                font-family: 'Raleway'; font-size: 12px;
                border: 1px solid {theme.get().ACCENT};
                background: {theme.get().BG_MAIN};
            }}
        """)

        # Lazy-Load bei erster Sichtbarkeit
        dock.visibilityChanged.connect(
            lambda visible, d=dock, k=nav_key: self._on_dock_visible(d, k, visible)
        )

        return dock

    def _on_dock_visible(self, dock: QDockWidget, nav_key: str, visible: bool) -> None:
        """Lazy-Load: erzeugt das Tool-Widget beim ersten Sichtbarwerden."""
        if not visible:
            return
        if dock._widget_loaded:  # type: ignore[attr-defined]
            # Sidebar-Aktiv-Status synchronisieren
            self._sidebar.set_active_key(nav_key)
            return

        tool_ref = dock._tool_ref  # type: ignore[attr-defined]
        widget_class = getattr(dock, "_widget_class", None)

        try:
            if tool_ref is not None:
                _log.debug("Lazy-Load Dock-Widget (tool): %s", nav_key)
                widget = tool_ref.create_widget(dock)
            elif widget_class is not None:
                _log.debug("Lazy-Load Dock-Widget (class): %s", nav_key)
                widget = widget_class(dock)
            else:
                return
        except Exception as exc:  # noqa: BLE001 -- fail-safe UI fallback
            _log.error(
                "Widget-Erzeugung fehlgeschlagen für '%s': %s",
                nav_key,
                exc,
                exc_info=True,
            )
            from core.widgets.error_placeholder import ErrorPlaceholderWidget

            widget = ErrorPlaceholderWidget(
                tool_title=dock.windowTitle() or nav_key,
                message="Das Tool konnte nicht initialisiert werden.",
                detail=f"{type(exc).__name__}: {exc}",
                parent=dock,
            )

        dock.setWidget(widget)
        dock._widget_loaded = True  # type: ignore[attr-defined]

        # Dashboard-Signale verdrahten (NoRisk-Dashboard, optional fuer andere)
        if hasattr(widget, "navigate"):
            try:
                widget.navigate.connect(self._on_sidebar_navigate)
            except (AttributeError, TypeError):
                pass
        if hasattr(widget, "open_with_filter"):
            try:
                widget.open_with_filter.connect(self._on_dashboard_open_with_filter)
            except (AttributeError, TypeError):
                pass
        # Patch-Monitor-Quick-Check (On-Demand-Daily-Refresh) an den
        # Patch-Inventory-Worker haengen — duck-typed, nur das
        # PatchConsoleWidget traegt dieses Signal.
        if hasattr(widget, "request_quick_check"):
            try:
                widget.request_quick_check.connect(
                    self._on_patch_quick_check_requested
                )
            except (AttributeError, TypeError) as exc:
                # Schlaegt der (Same-Thread-)Connect doch fehl, bliebe der
                # Quick-Check-Button nach einem Klick dauerhaft disabled
                # (kein Callback re-aktiviert ihn) — daher sichtbar loggen
                # statt still schlucken.
                _log.warning(
                    "request_quick_check-Connect fehlgeschlagen (%s) — "
                    "Quick-Check fuer '%s' inaktiv.",
                    type(exc).__name__,
                    nav_key,
                )

        self._sidebar.set_active_key(nav_key)

    def _build_docks(self) -> None:
        """Erstellt lazy-geladene QDockWidgets und tabifiziert sie untereinander.

        Das Welcome-Dock bleibt separat und wird beim Oeffnen eines
        anderen Docks automatisch ausgeblendet.
        """
        # Alle Tool-Docks werden mit dem Welcome-Dock tabifiziert --
        # Welcome bleibt dadurch immer als erster Tab sichtbar
        # und wird beim Start explizit nach vorne gebracht.

        # Registrierte Tools
        for nav_key, tool_name, dock_title, icon in self._NAV_TOOL_MAP:
            tool_ref = self._tool_map.get(tool_name)
            if tool_ref is None:
                continue
            dock = self._create_dock(nav_key, dock_title, icon, tool_ref)
            self._docks[nav_key] = dock
            self._inner_main.addDockWidget(
                Qt.DockWidgetArea.RightDockWidgetArea,
                dock,
            )
            self._inner_main.tabifyDockWidget(self._welcome_dock, dock)
            dock.hide()

        # Das eigenstaendige Security-Chat-Dock (ki:ollama / OllamaPanel)
        # wurde entfernt. Der vereinte FINLAI-Assistent lebt jetzt als Reiter im
        # Handbuch-Dialog (core/help); Alt-Deeplinks auf "ki:ollama" leitet
        # NavigationMixin._on_sidebar_navigate dorthin um.

        # DeepL UEbersetzer wurde am 2026-05-28 entfernt —
        # NoRisk ist 100% lokal, das DeepL-Dock entfaellt damit.

        # Welcome explizit nach vorne -- Landing Page hat hoechste Prioritaet
        self._welcome_dock.show()
        self._welcome_dock.raise_()

    # ==================================================================
    # Dock-Zustand speichern / laden
    # ==================================================================

    def _save_dock_state(self) -> None:
        """Speichert die Dock-Positionen von inner_main in UISettings."""
        state = self._inner_main.saveState()
        self._settings.dock_state = state.toBase64().data().decode()

    def _restore_dock_state(self) -> None:
        """Stellt Dock-Positionen auf inner_main wieder her.

        Bei einem dock_state-Versionssprung (z.B. nis2_incidents ist kein
        eigenes Dock mehr, sondern ein Tab) wird der Alt-Blob einmalig verworfen,
        statt verwaiste ``dock_<nav_key>``-objectNames durch Qt interpretieren zu
        lassen.
        Idempotent (der naechste Start sieht die neue Version); betrifft nur eine
        Layout-Praeferenz, keine Nutzdaten.
        """
        if self._settings.dock_state_version < _DOCK_STATE_VERSION:
            self._settings.dock_state = ""
            self._settings.dock_state_version = _DOCK_STATE_VERSION
            return
        state_str = self._settings.dock_state
        if state_str:
            state = QByteArray.fromBase64(state_str.encode())
            self._inner_main.restoreState(state)
        # Freischwebend persistierte Tool-Docks zwangsweise wieder andocken:
        # ein Floating-Zustand (Absolut-Position im dock_state) ist gegen
        # Monitor-/Layout-Wechsel fragil — nach Dock/Undock, Neustart oder
        # Primaer-Monitor-Wechsel liegt die Position auf keinem sichtbaren
        # Bildschirm mehr, der Sidebar-Eintrag wirkt "tot". Floating bleibt
        # nur transienter Laufzeit-Zustand.
        all_docks = list(self._docks.values())
        welcome = getattr(self, "_welcome_dock", None)
        if welcome is not None:
            all_docks.append(welcome)
        self._redock_floating(all_docks)

    @staticmethod
    def _redock_floating(docks) -> None:
        """Dockt freischwebend wiederhergestellte Docks wieder an.

        Setzt ``setFloating(False)`` auf jedes freischwebende Dock, sodass es
        in die (immer sichtbare) Dock-Area des Hauptfensters zurueckkehrt statt
        an einer evtl. nicht mehr existierenden Absolut-Position zu haengen.

        Args:
            docks: Iterable von ``QDockWidget``.
        """
        for dock in docks:
            if dock.isFloating():
                dock.setFloating(False)

    # ==================================================================
    # Bottom-Panel
    # ==================================================================

    def _open_in_bottom_panel(self, key: str) -> None:
        """OEffnet ein Tool-Widget im unteren Panel.

        Wenn das Tool bereits als Tab vorhanden ist, wird dieser aktiviert.
        Andernfalls wird ein neuer Tab erstellt.

        Args:
            key: Navigationsschluessel des Tools.
        """
        # Tab bereits vorhanden? -> aktivieren
        for i in range(self._bottom_panel.count()):
            if self._bottom_panel.tabToolTip(i) == key:
                self._bottom_panel.setCurrentIndex(i)
                self._show_bottom_panel()
                return

        # Neues Widget erzeugen (analog zu _on_sidebar_navigate)
        widget = self._get_or_create_tool_widget(key)
        if widget is None:
            return

        title = self._get_tool_title(key)
        idx = self._bottom_panel.addTab(widget, title)
        self._bottom_panel.setTabToolTip(idx, key)
        self._bottom_panel.setCurrentIndex(idx)
        self._show_bottom_panel()

    def _get_or_create_tool_widget(self, key: str) -> QWidget | None:
        """Gibt das Widget fuer den Navigationsschluessel zurueck oder erstellt es.

        Args:
            key: Navigationsschluessel des Tools.

        Returns:
            Tool-Widget oder None wenn kein passendes Tool gefunden.
        """
        # ki:ollama wird nicht mehr als Bottom-Panel-Widget gebaut — der
        # vereinte Assistent lebt im Handbuch-Dialog (NavigationMixin leitet
        # "ki:ollama" dorthin um). ki:deepl entfernt 2026-05-28.

        # Generisches Platzhalter-Widget fuer andere Tools
        placeholder = QLabel(f"  {key} — Vorschau nicht verfügbar")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet(
            f"color: {theme.get().TEXT_DIM}; font-size: 12px; background: {theme.get().BG_MAIN};"
        )
        return placeholder

    def _get_tool_title(self, key: str) -> str:
        """Gibt einen kurzen Anzeigenamen fuer den Navigationsschluessel zurueck.

        Args:
            key: Navigationsschluessel.

        Returns:
            Anzeigenamen (max. ~20 Zeichen).
        """
        titles = {
            "cyber_dashboard": "Cyberrisiko",
            "api_security": "API-Scanner",
            "dependency_auditor": "Dep-Auditor",
            "network_scanner": "Netzwerk",
            "security_scoring": "Scoring",
        }
        return titles.get(key, key.split(":")[-1].capitalize())

    def _show_bottom_panel(self) -> None:
        """Blendet das untere Panel ein und setzt eine sinnvolle Anfangshoehe."""
        if not self._bottom_panel.isVisible():
            self._bottom_panel.setVisible(True)
            total_h = self._v_splitter.height()
            panel_h = max(200, total_h // 3)
            self._v_splitter.setSizes([total_h - panel_h, panel_h])

    def _close_bottom_panel(self) -> None:
        """Blendet das untere Panel aus."""
        self._bottom_panel.setVisible(False)

    def _toggle_bottom_panel(self) -> None:
        """Schaltet das untere Panel ein/aus (Ctrl+Shift+B)."""
        if self._bottom_panel.isVisible():
            self._close_bottom_panel()
        else:
            self._show_bottom_panel()

    def _on_bottom_tab_close(self, index: int) -> None:
        """Entfernt den Tab und blendet das Panel aus wenn keine Tabs mehr vorhanden.

        Args:
            index: Tab-Index der geschlossen werden soll.
        """
        self._bottom_panel.removeTab(index)
        if self._bottom_panel.count() == 0:
            self._close_bottom_panel()
