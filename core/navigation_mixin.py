"""
navigation_mixin — Sidebar-Navigation + Tool-Routing fuer das MainWindow.

Sprint 7 Phase 2d: Mixin-Extract aus dem
``MainWindow``-God-Class-Refactor. Behandelt das Routing aller
Sidebar-Klicks zu den passenden Tool-Docks.

Public API:
    navigate_to(key) -- oeffentlicher Entry-Point fuer Tools die per
                          Navigation andere Tools oeffnen wollen
                          (Audit-Befund S2-5: ersetzt hasattr-Workaround).

Interne Slots:
    _on_sidebar_navigate(key) -- Master-Slot fuer Sidebar
    _on_dashboard_open_with_filter(k, p) -- Dashboard-Klicks mit Filter
    _get_active_widget_for(key) -- Widget-Lookup
    _on_open_url(url) -- Externe URL im Browser

State-Anforderungen (vom MainWindow.__init__ zu setzen):
    self._docks, self._welcome_dock, self.tool_activated (Signal).

Cleanup 2026-04-28: Sub-Navigation-Patterns (Cheatsheet/Teachings/
Maps/Robotic/SFTP/FinanzOnline/WichtigeLinks) wurden komplett
entfernt -- diese Tools existieren nicht in NoRisk (sie gehoeren
zu FINLAI/AUTOMATE/TeachMe). Damit entfaellt auch die deklarative
Routing-Tabelle aus Sprint 7 Phase 2e.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QDockWidget, QWidget

from core.deeplink_registry import accepted_kwargs, dashboard_filter_kwarg
from core.logger import get_logger

_log = get_logger(__name__)


# alte Einzel-Tool-Keys -> (Ziel-Key, fixer Sub-Tab | None). Der
# Bewerten-Merge (Security-Audit/Score/Awareness/NIS2 in EINEM Container
# ``security_assessment``) und der Techstack-Umzug in den Advisory-Monitor
# loesen die Einzel-Docks ab; alte Deeplinks/CTAs werden hier auf den Container
# + richtigen Sub-Tab umgebogen (analog der home/ki:ollama-Umleitung in
# ``_on_sidebar_navigate``). Fuer ``customer_audit`` bestimmt zusaetzlich das
# eingehende ``tab``-kwarg den Sub-Tab (siehe ``_CUSTOMER_AUDIT_TAB_MAP``).
_TOOL_ALIASES: dict[str, tuple[str, str | None]] = {
    "customer_audit": ("security_assessment", "audit"),
    "nis2_incidents": ("security_assessment", "nis2"),
    "security_scoring": ("security_assessment", "score"),
    "awareness_tracker": ("security_assessment", "awareness"),
    "techstack": ("csaf_advisor", None),
}

# customer_audit-Deeplink: altes ``tab``-kwarg -> Container-Sub-Tab.
_CUSTOMER_AUDIT_TAB_MAP: dict[object, str] = {
    "nis2": "nis2",
    "audits": "audit",
    "audit": "audit",
}


def _resolve_tool_alias(
    key: str, kwargs: dict[str, object]
) -> tuple[str, dict[str, object]]:
    """Loest alte Einzel-Tool-Keys auf Merge-Container/Advisory-Monitor auf.

    Nach dem Bewerten-Merge + Techstack-Umzug haben die fuenf alten Keys
    (``customer_audit``/``nis2_incidents``/``security_scoring``/
    ``awareness_tracker``/``techstack``) kein eigenes Dock mehr. Diese Funktion
    biegt ``navigate_to(<alt>,...)`` transparent auf den richtigen Container +
    Sub-Tab um, damit bestehende CTAs/Deeplinks (Cockpit-Kacheln, Dashboard-
    NIS2-Sektion, Hilfe-Links) ohne Aenderung weiterlaufen. Unbekannte Keys
    werden samt kwargs unveraendert durchgereicht.

    Bewusst modul-global (kein ``self``-Bezug): so greift die Aufloesung auch
    fuer leichtgewichtige Router-Stubs, die ``NavigationMixin`` nicht erben.

    Args:
        key: Eingehender Navigationsschluessel.
        kwargs: Eingehende Prefill-kwargs (z.B. ``tab='nis2'``).

    Returns:
        ``(aufgeloester_key, aufgeloeste_kwargs)``.
    """
    alias = _TOOL_ALIASES.get(key)
    if alias is None:
        return key, kwargs
    target_key, sub_tab = alias
    # customer_audit fuehrte ein ``tab``-kwarg ('nis2'/'audits') — auf den
    # passenden Container-Sub-Tab mappen (Default: 'audit').
    if key == "customer_audit":
        sub_tab = _CUSTOMER_AUDIT_TAB_MAP.get(kwargs.get("tab"), "audit")
    new_kwargs: dict[str, object] = {"tab": sub_tab} if sub_tab is not None else {}
    return target_key, new_kwargs


class NavigationMixin:
    """Mixin: Sidebar-Klick-Routing zu Tool-Docks (inkl. Sub-Navigation).

    Das ``_on_sidebar_navigate``-Master ist eine bewusst flache if/else-
    Kette -- nicht refactoriert in dieser Phase, der Audit-Plan sieht
    die God-Method-Verkleinerung als separaten Schritt vor.
    """

    def navigate_to(self, key: str, **kwargs: object) -> None:
        """OEffentliches API um aus Tool-Code heraus zu navigieren.

        Tools sollen NICHT mehr ``hasattr(window, "_on_sidebar_navigate")``
        machen, sondern diese Methode aufrufen. Behebt Audit-Befund S2-5
        (Layer-Verletzung via Private-Member-Zugriff).

        Sprint S3d (Cross-Tool-Deep-Links): Wenn ``kwargs`` nicht leer
        sind und das Ziel-Widget eine Methode ``apply_navigation(**kwargs)``
        besitzt, werden die Argumente nach dem Dock-Show an das Widget
        durchgereicht. Damit kann z. B. der Network-Scanner einen
        ``api_security``-Tab mit vorausgefuellter URL oeffnen, ohne dass
        ``MainWindow`` die einzelnen Tool-APIs kennen muss.

        Backwards-Compat: ``navigate_to(key)`` ohne kwargs verhaelt sich
        unveraendert wie vor S3d.

        Args:
            key: Sidebar-Navigationsschluessel (z. B. ``"password_checker"``).
            **kwargs: Optionale tool-spezifische Prefill-Parameter
                (``url``, ``domain``, ``target``,...). Werden ignoriert,
                wenn das Ziel-Widget kein ``apply_navigation`` anbietet.
        """
        # alte Einzel-Tool-Keys transparent auf den Merge-Container /
        # Advisory-Monitor + Sub-Tab umbiegen (kein eigenes Dock mehr).
        key, kwargs = _resolve_tool_alias(key, dict(kwargs))
        self._on_sidebar_navigate(key)
        if not kwargs:
            return
        widget = self._get_active_widget_for(key)
        if widget is None:
            return
        apply = getattr(widget, "apply_navigation", None)
        if apply is None or not callable(apply):
            _log.debug(
                "navigate_to(%r): Ziel-Widget hat kein apply_navigation -- "
                "kwargs %s ignoriert",
                key,
                sorted(kwargs.keys()),
            )
            return
        try:
            apply(**kwargs)
        except Exception as exc:  # noqa: BLE001 -- Empfaenger darf den Caller nie crashen
            _log.warning(
                "navigate_to(%r) apply_navigation fehlgeschlagen: %s",
                key,
                type(exc).__name__,
            )

    @Slot(str)
    def _on_sidebar_navigate(self, key: str) -> None:
        """Zeigt das passende DockWidget.

        Jeder Sidebar-Klick oeffnet ein Dock und bringt es nach vorne.
        Das Welcome-Dock wird dadurch automatisch in den Hintergrund
        (Tab-Wechsel) geschoben.

        Args:
            key: Navigationsschluessel aus dem SidebarWidget.
        """
        # Home-Button: Welcome-Dock in den Vordergrund (kein tool_activated emit).
        # 3c 1b Vision B): Das Cockpit (``norisk:dashboard``) hat
        # kein eigenes Dock mehr — es IST das Welcome-Dock. Beide Keys zeigen
        # daher dasselbe Dock; Alt-Deeplinks auf ``norisk:dashboard`` (z.B. aus
        # dem Hilfe-System oder dem Aufgaben-Snippet) landen so nicht im Leeren.
        if key in ("home", "norisk:dashboard"):
            self._welcome_dock.show()
            self._welcome_dock.raise_()
            # 3c: Cockpit-Sidebar-Eintrag nach einem Tool-Wechsel-zurueck
            # wieder aktiv markieren. Das Welcome-Dock loest (anders als Tool-
            # Docks) kein ``_on_dock_visible`` aus, das den Active-Key setzt.
            sidebar = getattr(self, "_sidebar", None)
            set_active = getattr(sidebar, "set_active_key", None)
            if callable(set_active):
                set_active("home")
            return

        # Der frühere Security-Chat (ki:ollama) ist jetzt der FINLAI-
        # Assistent-Reiter im Handbuch-Dialog — kein eigenes Dock mehr. Alt-
        # Deeplinks (z. B. Quickstart-Verlauf, der über navigate_to hier
        # einläuft) dorthin umleiten statt ins Leere zu navigieren.
        if key == "ki:ollama":
            from core.help.help_dialog import HelpDialog  # noqa: PLC0415

            self._open_help_dialog(HelpDialog.ASSISTANT_KEY)
            return

        # DockWidget anzeigen (registrierte Tools)
        if key in self._docks:
            dock = self._docks[key]
            if not dock.isVisible():
                dock.show()
            dock.raise_()
            if dock.isFloating():
                self._ensure_dock_on_screen(dock)
                dock.activateWindow()
            self.tool_activated.emit(key)
            return

        # Kein Dock und kein Sub-Routing: Tool ist nicht freigeschaltet
        # (allowed_tools) oder nicht registriert. Statt stillem Log eine
        # sichtbare Rückmeldung — ein stiller Klick wirkt wie ein toter Eintrag.
        _log.warning("Unbekannter Navigationsschlüssel: %s", key)
        self._status_bar.showMessage(
            "Dieses Modul ist derzeit nicht verfügbar — möglicherweise ist es "
            "für dein Benutzerkonto nicht freigeschaltet. Bitte wende dich "
            "an deinen Administrator.",
            6000,
        )

    @staticmethod
    def _ensure_dock_on_screen(dock: QDockWidget) -> None:
        """Holt ein freischwebendes Dock zurück auf einen sichtbaren Bildschirm.

        Ein persistiertes Dock-Layout (``ui_settings.json`` Feld ``dock_state``)
        kann ein freischwebendes Dock an einer Position wiederherstellen, die auf
        keinem aktuell angeschlossenen Monitor mehr liegt (Multi-Monitor-
        Koordinaten-Drift nach Dock/Undock, Neustart oder Primaer-Monitor-
        Wechsel). ``show``/``raise_`` machen es dann zwar sichtbar, aber
        außerhalb des sichtbaren Bereichs — der Sidebar-Eintrag wirkt „tot".
        Dieser Helper verschiebt ein solches Dock auf den Primaer-Bildschirm.

        Args:
            dock: Das freischwebende Dock, dessen Position geprüft wird.
        """
        if not dock.isFloating():
            return
        frame = dock.frameGeometry()
        on_screen = any(
            scr.availableGeometry().intersects(frame)
            for scr in QApplication.screens()
        )
        if on_screen:
            return
        target = QApplication.primaryScreen()
        if target is None:
            return
        avail = target.availableGeometry()
        dock.move(avail.x(), avail.y())

    @Slot(str, object)
    def _on_dashboard_open_with_filter(self, key: str, payload: object) -> None:
        """OEffnet ein Tool per Nav-Key mit einem Dashboard-Filter-Payload.

        Vom NoRisk-Dashboard genutzt, um per Klick auf eine CVE-Zeile den
        CSAF-Advisor mit vorausgefuelltem CVE-Filter zu oeffnen. Die Zuordnung
        Nav-Key -> Empfaenger-kwarg liegt zentral in der Deeplink-Registry statt in hart kodierten ``if key ==...``-Zweigen; die
        Filter-Uebergabe laeuft ueber den generischen ``navigate_to``-Pfad
        (Dock-Show + ``apply_navigation``).

        Der Payload-Typ wird gegen das Registry-Manifest validiert; bei
        Mismatch wird das Tool fail-safe OHNE Filter geoeffnet (kein
        ungueltiger Wert ins Ziel-Widget).

        Args:
            key: Navigationsschluessel (z.B. ``"csaf_advisor"``).
            payload: Filter-Payload fuer den registrierten kwarg (z.B. CVE-ID).
        """
        filter_kwarg = dashboard_filter_kwarg(key)
        if filter_kwarg is None:
            # Kein Filter-Contract registriert -> Tool nur oeffnen.
            self.navigate_to(key)
            return
        expected = accepted_kwargs(key).get(filter_kwarg)
        if expected is not None and not isinstance(payload, expected):
            # Payload-Typ passt nicht zum deklarierten Contract -> fail-safe.
            _log.warning(
                "Dashboard-Deeplink %r: Payload-Typ %s passt nicht zu "
                "erwartetem %s -- ohne Filter geoeffnet",
                key,
                type(payload).__name__,
                expected.__name__,
            )
            self.navigate_to(key)
            return
        self.navigate_to(key, **{filter_kwarg: payload})

    def _get_active_widget_for(self, key: str) -> QWidget | None:
        """Gibt das aktive Widget im Dock fuer ``key`` zurueck, falls vorhanden.

 3c 1b Vision B): Das Cockpit (``home`` /
        ``norisk:dashboard``) hat kein Eintrag in ``_docks`` mehr — es lebt im
        Welcome-Dock. Damit Deeplinks mit kwargs (z.B.
        ``navigate_to("norisk:dashboard", section="kanban")``) das
        ``apply_navigation`` des Cockpit-Widgets erreichen, wird fuer beide Keys
        das Welcome-Dock-Widget zurueckgegeben.
        """
        if key in ("home", "norisk:dashboard"):
            welcome = getattr(self, "_welcome_dock", None)
            return welcome.widget() if welcome is not None else None
        dock = self._docks.get(key)
        if dock is None:
            return None
        return dock.widget()

    @Slot(str)
    def _on_open_url(self, url: str) -> None:
        """OEffnet eine URL im Standardbrowser.

        Args:
            url: Die zu oeffnende URL.
        """
        QDesktopServices.openUrl(QUrl(url))
