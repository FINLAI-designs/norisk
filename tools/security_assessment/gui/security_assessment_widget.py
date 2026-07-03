"""security_assessment_widget — Container: Audit / Score / Awareness / NIS2.

Verschmilzt die vier zuvor getrennten Bewerten-Tools
(Security-Audit, Security-Score, Awareness-Tracker, NIS2-Vorfälle) in EINEN
Bereich „Security-Bewertung" mit vier Sub-Tabs — analog dem file_scanner-
Container (Refactoring-Plan §4/§8, Fortschreibung von).

Die eigentliche Komposition (Service + Repository + Sub-Widget) lebt im
Composition-Root:mod:`tools.security_assessment.tool` und wird hier als
Factory injiziert — so importiert die GUI-Schicht keine ``data``-Module
(Hexagonal-Contract gui↛data).

Sub-Tabs werden LAZY gebaut (erst beim ersten Anzeigen), weil einzelne
Sub-Tools — v. a. Security-Score — beim Aufbau viele Services instanziieren;
ein eager-Build aller vier im UI-Thread beim Öffnen würde das Fenster kurz
einfrieren (vgl. / Qt-Freeze-Lehre). Der Dock selbst ist bereits lazy
(erst beim ersten Anzeigen gebaut); danach baut nur der jeweils aktive Sub-Tab.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QTabWidget, QVBoxLayout, QWidget

from core import theme
from core.logger import get_logger

log = get_logger(__name__)

# (deeplink_key, license_feature, tool_name, tab_title, factory)
# ``factory(parent)`` baut das echte Sub-Widget; injiziert vom Composition-Root
# (tools.security_assessment.tool), damit die GUI kein data/tool importiert.
TabSpec = tuple[str, str, str, str, "Callable[[QWidget], QWidget]"]


def _placeholder(message: str) -> QWidget:
    """Erzeugt einen zentrierten Hinweis-Platzhalter im gedämpften Stil.

    Args:
        message: Anzuzeigender Text.

    Returns:
        Ein QWidget mit zentriertem, umbrechendem Label.
    """
    placeholder = QWidget()
    layout = QVBoxLayout(placeholder)
    label = QLabel(message)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setWordWrap(True)
    label.setStyleSheet(
        f"color: {theme.get().TEXT_DIM}; "
        "font-family: 'Raleway', 'Segoe UI', sans-serif; "
        "font-size: 14px; background: transparent; border: none;"
    )
    layout.addWidget(label)
    return placeholder


def _error_placeholder(tool_name: str) -> QWidget:
    """Hinweis-Platzhalter für einen nicht ladbaren Sub-Tab.

    Args:
        tool_name: Anzeigename des betroffenen Sub-Tools.

    Returns:
        Ein QWidget mit zentrierter Lade-Fehler-Meldung.
    """
    return _placeholder(
        f"„{tool_name}“ konnte nicht geladen werden.\n"
        "Bitte starten Sie die App neu. Hält der Fehler an, "
        "wenden Sie sich an den Support."
    )


class SecurityAssessmentWidget(QWidget):
    """Security-Bewertung-Container mit vier Sub-Tabs.

    Die Reihenfolge der Tabs entspricht der Reihenfolge der ``tab_specs``:
    Security-Audit · Security-Score · Awareness-Tracker · NIS2-Vorfälle.

    Sub-Tabs werden lazy gebaut.:meth:`apply_navigation` wählt einen Sub-Tab
    vor (Deeplink-Einstieg; der Router biegt die alten Einzel-Tool-Keys per
    Alias hierher um).
    """

    def __init__(
        self, tab_specs: list[TabSpec], parent: QWidget | None = None
    ) -> None:
        """Initialisiert den Container und legt die (lazy) Sub-Tabs an.

        Args:
            tab_specs: Liste der Tab-Definitionen (Deeplink-Key, Lizenz-Feature,
                Tool-Name, Tab-Titel, Factory).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._specs: list[TabSpec] = list(tab_specs)
        self._tabs = QTabWidget()
        # Muster: Idempotenz-Guard fuer shutdown (closeEvent mehrfach).
        self._shutdown_done = False
        # Deeplink-Key -> Tab-Index (entkoppelt von der Reihenfolge).
        self._tab_indices: dict[str, int] = {}
        # Tab-Index -> bereits gebautes Widget (Lazy-Cache).
        self._built: dict[int, QWidget] = {}

        for index, (deeplink_key, _feature, _tool_name, title, _factory) in enumerate(
            self._specs
        ):
            self._tabs.addTab(QWidget(), title)  # Lazy-Platzhalter
            self._tab_indices[deeplink_key] = index

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._tabs)

        self._tabs.currentChanged.connect(self._ensure_built)
        # Den initial sichtbaren Tab (Index 0) sofort bauen.
        self._ensure_built(self._tabs.currentIndex())

    def _ensure_built(self, index: int) -> None:
        """Baut den Sub-Tab beim ersten Anzeigen (lazy), fehler-sicher.

        Ersetzt den leeren Platzhalter durch das echte Sub-Widget. Schlägt die
        Factory fehl, bleibt ein Fehler-Platzhalter — kein Crash. Bereits
        gebaute Tabs werden sofort übersprungen (kein Doppel-Init).

        Args:
            index: Tab-Index (0-basiert).
        """
        if index < 0 or index >= len(self._specs) or index in self._built:
            return
        _deeplink_key, _feature, tool_name, title, factory = self._specs[index]
        try:
            widget = factory(self)
        except Exception:  # noqa: BLE001 -- Factory-Fehler darf den currentChanged-Slot nie crashen
            # Sub-Tool-Factories instanziieren Services/Repositories und koennen
            # ueber ImportError/RuntimeError/OSError hinaus auch DB-Fehler
            # (FinLaiDatabaseError erbt von Exception) o.ae. werfen — analog
            # CyberDashboardWidget._on_tab_changed: breit fangen, Platzhalter zeigen.
            log.exception(
                "Bewerten-Sub-Tool '%s' konnte nicht geladen werden.", tool_name
            )
            widget = _error_placeholder(tool_name)
        # Vor removeTab/insertTab eintragen → Re-Entrancy-Guard (insertTab löst
        # currentChanged erneut aus; der re-entrante Aufruf greift dann hier).
        self._built[index] = widget
        self._wire_cross_tab_signals(widget)
        self._tabs.removeTab(index)
        self._tabs.insertTab(index, widget, title)
        self._tabs.setCurrentIndex(index)

    def _wire_cross_tab_signals(self, widget: QWidget) -> None:
        """Verbindet bekannte Cross-Tab-Signale eines frisch gebauten Sub-Widgets.

        Das Security-Audit-Widget bietet ``nis2_requested`` (Toolbar-Button
        „NIS2-Vorfälle"); der Klick springt auf den NIS2-Geschwister-Tab — ohne
        dass das Audit-Widget den Container-Key kennen muss.

        Args:
            widget: Das gebaute Sub-Widget (Signal optional, duck-typed).
        """
        signal = getattr(widget, "nis2_requested", None)
        connect = getattr(signal, "connect", None)
        if callable(connect):
            connect(lambda: self.apply_navigation(tab="nis2"))

    def apply_navigation(self, *, tab: str | None = None, **_kwargs) -> None:
        """Deeplink-Einstieg: wählt einen Sub-Tab vor.

        Args:
            tab: Ziel-Tab. Gültig: ``'audit'`` (Security-Audit), ``'score'``
                (Security-Score), ``'awareness'`` (Awareness-Tracker),
                ``'nis2'`` (NIS2-Vorfälle). Unbekannte Werte werden ignoriert.
        """
        if tab in self._tab_indices:
            self._tabs.setCurrentIndex(self._tab_indices[tab])

    def shutdown(self) -> None:
        """App-Lifecycle-Hook (closeEvent-Sweep): reicht Teardown an Sub-Tabs.

        Reicht ``stop_worker``/``shutdown`` duck-typed an die bereits gebauten
        Sub-Tabs durch (analog file_scanner-Container). Nicht gebaute (lazy)
        oder Platzhalter-Tabs werden übersprungen. Idempotent — der
        ``closeEvent`` kann in Qt mehrfach feuern.
        """
        if self._shutdown_done:
            return
        self._shutdown_done = True
        for widget in self._built.values():
            for hook_name in ("stop_worker", "shutdown"):
                hook = getattr(widget, hook_name, None)
                if not callable(hook):
                    continue
                try:
                    hook()
                except Exception as exc:  # noqa: BLE001 -- Shutdown-Boundary
                    log.warning(
                        "%s() für %s beim Shutdown fehlgeschlagen: %s",
                        hook_name,
                        type(widget).__name__,
                        exc,
                    )
