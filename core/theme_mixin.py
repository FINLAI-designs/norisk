"""
theme_mixin — Live-Theme-Anwendung fuer rahmenlose Hauptfenster.

Sprint 7 Phase 2b: Zweiter Mixin-Extract aus dem
``MainWindow``-God-Class-Refactor.

Buendelt die zwei zusammenhaengenden Theme-Methoden:

* ``apply_theme`` -- ist als ``theme.register_listener``-Callback
  registriert UND wird direkt vom EinstellungenTool ueber
  ``theme.apply`` aufgerufen. Aktualisiert alle Widgets mit lokalen
  Stylesheets die sonst nicht ueber den Listener-Mechanismus erreicht
  werden (outer_frame, inner_main, status_bar, alle Docks).
* ``_tabs_style`` -- gemeinsamer QSS-String fuer Tab-Widgets
  (Bottom-Panel + tabifizierte Tool-Docks).

State-Anforderungen (vom MainWindow.__init__ zu setzen):
    self._outer_frame, self._v_splitter,
    self._bottom_panel, self._inner_main, self._status_bar,
    self._lbl_log_level, self._title_bar, self._sidebar, self._docks

Da nicht alle Attribute zwingend existieren (z. B. _bottom_panel
kann fehlen wenn keine Tools im Bottom-Panel offen sind), werden
hasattr-Checks beibehalten -- defensive UI-Programming.

Tonale Schale -- Akzent-Separator entfernt,
Splitter-Handles neutral 1px mit Teal nur bei Hover.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from core import theme
from core.signals import global_signals


class ThemeMixin:
    """Mixin: Live-Theme-Anwendung fuer das MainWindow.

    Erwartet vom mixenden QMainWindow:
    - update (von QWidget vererbt)
    - die State-Felder aus dem Modul-Docstring
    """

    def _tabs_style(self) -> str:
        """Gibt den gemeinsamen QSS-String fuer Tab-Widgets zurueck.

        Erzeugt den neonblauen Trennbalken unter der Tab-Leiste und
        stylt aktive/inaktive/hover Tabs passend zum aktiven Theme.

        Returns:
            QSS-String der auf QTabWidget und QTabBar angewendet werden kann.
        """
        c = theme.get()
        return (
            f"QTabWidget::pane {{"
            f"  border: none;"
            # AP2: Struktur-Linie gedimmt — Teal voll nur am
            # aktiven Tab (Zustands-Signal, s.u.)
            f"  border-top: 1px solid {c.ACCENT_LINE};"
            f"  background-color: {c.BG_MAIN};"
            f"}}"
            f"QTabBar {{"
            f"  background-color: {c.BG_DARK};"
            f"}}"
            f"QTabBar::tab {{"
            f"  background-color: {c.BG_DARK};"
            f"  color: {c.TEXT_DIM};"
            f"  border: none;"
            f"  border-right: 1px solid {c.BORDER};"
            f"  padding: 6px 16px;"
            f"  min-width: 80px;"
            f"}}"
            f"QTabBar::tab:selected {{"
            f"  background-color: {c.BG_MAIN};"
            f"  color: {c.ACCENT};"
            f"  border-top: 2px solid {c.ACCENT};"
            f"  font-weight: bold;"
            f"}}"
            f"QTabBar::tab:hover:!selected {{"
            f"  background-color: {c.CARD_BG};"
            f"  color: {c.TEXT_MAIN};"
            f"}}"
            f"QTabBar::close-button:hover {{"
            f"  background-color: {c.DANGER};"
            f"  border-radius: 8px;"
            f"}}"
        )

    def apply_theme(self) -> None:
        """Wendet das aktuell aktive Theme live auf die gesamte App an.

        Wird als Listener registriert (theme.register_listener) und auch
        direkt von EinstellungenTool aufgerufen. Aktualisiert alle Widgets
        mit lokalen Stylesheets die sonst nicht ueber den Listener-Mechanismus
        erreicht werden (outer_frame, inner_main, status_bar).
        TitleBar und Sidebar aktualisieren sich ueber eigene Listener.
        """
        app = QApplication.instance()
        if app is None:
            return
        c = theme.get()

        # AEusserer Rahmen (1 px Akzent-Border + Hintergrund)
        if hasattr(self, "_outer_frame"):
            self._outer_frame.setStyleSheet(
                f"QWidget#outer_frame {{"
                f"  border: 1px solid {c.ACCENT};"
                f"  background-color: {c.BG_MAIN};"
                f"}}"
            )

        # Vertikaler Splitter (inner_main ↕ Bottom-Panel) — durchgehend
        # neutrale 1px-Hairline, KEIN Teal-Hover: die Teal-Hover-
        # Affordance an den duennen Trennbalken war ueberladen und wurde
        # entfernt; der Balken bleibt als BORDER-Hairline). hatte nur
        # den NeonSplitter-Griff (neon_splitter.py) entschaerft, diese
        # QSS-Hover-Regel (_v_splitter) aber uebersehen.
        if hasattr(self, "_v_splitter"):
            self._v_splitter.setStyleSheet(
                f"QSplitter::handle:horizontal {{"
                f"  background: {c.BORDER}; width: 1px;"
                f"}}"
                f"QSplitter::handle:vertical {{"
                f"  background: {c.BORDER}; height: 1px;"
                f"}}"
            )

        # Bottom-Panel QTabWidget
        if hasattr(self, "_bottom_panel"):
            self._bottom_panel.setStyleSheet(self._tabs_style())

        # Inneres QMainWindow (Dock-Host) inkl. tabifizierter Dock-Tabs
        self._inner_main.setStyleSheet(
            f"QMainWindow {{"
            f"  background: {c.BG_MAIN}; border: none;"
            f"}}"
            f"QMainWindow::separator {{"
            f"  background: {c.BORDER}; width: 2px; height: 2px;"
            f"}}"
            # kein Teal-Hover an den Dock-Trennern (gleiche
            # ueberladene Affordance wie am Splitter); Trenner bleibt BORDER.
            + self._tabs_style()
        )

        # Statusleiste
        self._status_bar.setStyleSheet(
            f"QStatusBar {{"
            f"  background-color: {c.BG_MAIN};"
            f"  border-top: 1px solid {c.BORDER};"
            f"  color: {c.TEXT_MAIN};"
            f"  font-size: 13px;"
            f"}}"
        )
        self._lbl_log_level.setStyleSheet(f"color: {c.TEXT_MAIN}; padding: 0 8px;")

        # TitleBar und Sidebar explizit aufrufen (zusaetzlich zu ihren Listenern)
        if hasattr(self, "_title_bar"):
            self._title_bar.apply_theme()
        if hasattr(self, "_sidebar"):
            self._sidebar.apply_theme()

        # Alle offenen Docks updaten (deren Toolbar-Titel + Hintergrund)
        for dock in self._docks.values():
            dock.setStyleSheet(
                f"QDockWidget {{"
                f"  background: {c.BG_MAIN};"
                f"  color: {c.TEXT_MAIN};"
                f"}}"
                f"QDockWidget::title {{"
                f"  background: {c.CARD_BG};"
                f"  color: {c.TEXT_MAIN};"
                f"  border-bottom: 1px solid {c.BORDER};"
                f"  padding: 4px 8px;"
                f"}}"
            )

        # Repaint erzwingen ohne unpolish/polish (wuerde lokale QSS ueberschreiben)
        self.update()

        # Globales Signal nach erfolgreicher Theme-Anwendung -- Tools koennen
        # subscriben (siehe core/signals.py), ohne hasattr-Workaround auf
        # MainWindow.apply_theme. Behebt Audit-Befund S2-6.
        global_signals.theme_changed.emit()
