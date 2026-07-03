"""file_scanner_widget — Container-Widget: E-Mail / PDF / Office in Sub-Tabs.

Verschmilzt die drei zuvor getrennten Datei-Scanner (E-Mail-Anhang,
PDF-Risiko, Dokument) in EIN Tool mit Sub-Tabs (Refactoring-Plan §4/§8,
 Phase 3b). Die eigentliche Komposition (Service + Repository + Sub-
Widget) lebt im Composition-Root ``tools.file_scanner.tool`` und wird hier
als Factory injiziert — so importiert die GUI-Schicht keine ``data``-Module
(Hexagonal-Contract gui↛data).

Jeder Tab wird über das jeweilige Lizenz-Feature des Sub-Scanners gegated;
schlägt der Aufbau eines Sub-Scanners fehl, zeigt der Tab einen Platzhalter
statt den Container abstürzen zu lassen (GUI-Fehlerboundary, R-Exc).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QTabWidget, QVBoxLayout, QWidget

from core import theme
from core.logger import get_logger

log = get_logger(__name__)

# (deeplink_key, license_feature, tool_name, tab_title, factory)
# ``factory(parent)`` baut das echte Sub-Widget; sie wird vom Composition-Root
# (tools.file_scanner.tool) injiziert, damit die GUI kein data importiert.
TabSpec = tuple[str, str, str, str, "Callable[[QWidget], QWidget]"]


def _placeholder(message: str) -> QWidget:
    """Erzeugt einen zentrierten Hinweis-Platzhalter im gedämpften Stil.

    Args:
        message: Anzuzeigender Text (Du-Form).

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
    """Hinweis-Platzhalter für einen lizenzierten, aber nicht ladbaren Sub-Tab.

    Args:
        tool_name: Anzeigename des betroffenen Sub-Scanners.

    Returns:
        Ein QWidget mit zentrierter Lade-Fehler-Meldung (Du-Form).
    """
    return _placeholder(
        f"„{tool_name}“ konnte nicht geladen werden.\n"
        "Bitte starte die App neu. Hält der Fehler an, "
        "wende dich an den Support."
    )


class FileScannerWidget(QWidget):
    """Datei-Scanner-Container mit Sub-Tabs (E-Mail / PDF / Office).

    Die Tab-Definitionen werden injiziert (:data:`TabSpec`); die
    Reihenfolge der Tabs entspricht der Reihenfolge der ``tab_specs``.
    """

    def __init__(
        self, tab_specs: list[TabSpec], parent: QWidget | None = None
    ) -> None:
        """Initialisiert den Container und baut die Sub-Tabs.

        Args:
            tab_specs: Liste der Tab-Definitionen (Deeplink-Key, Lizenz-Feature,
                Tool-Name, Tab-Titel, Factory).
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._tabs = QTabWidget()
        # Idempotenz-Guard fuer shutdown (closeEvent kann mehrfach feuern).
        self._shutdown_done = False
        # Deeplink-Key -> Tab-Index, dynamisch aus der Spec (entkoppelt von
        # der Reihenfolge), für apply_navigation.
        self._tab_indices: dict[str, int] = {}
        for deeplink_key, _feature, tool_name, title, factory in tab_specs:
            # _feature (license_feature) bleibt inert in der TabSpec.
            index = self._tabs.addTab(
                self._build_tab(tool_name, factory), title
            )
            self._tab_indices[deeplink_key] = index

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._tabs)

    def _build_tab(
        self, tool_name: str, factory: Callable[[QWidget], QWidget]
    ) -> QWidget:
        """Baut einen Sub-Tab fehler-sicher (kein Lizenz-Gate mehr).

        Args:
            tool_name: Anzeigename (für die Fehlermeldung).
            factory: Funktion ``(parent) -> QWidget``, die das echte Sub-Widget
                baut (aus dem Composition-Root injiziert).

        Returns:
            Das Sub-Widget oder einen Fehler-Platzhalter.
        """
        try:
            return factory(self)
        except (ImportError, RuntimeError, OSError):
            log.exception("Sub-Scanner '%s' konnte nicht geladen werden.", tool_name)
            return _error_placeholder(tool_name)

    def apply_navigation(self, *, tab: str | None = None, **_kwargs) -> None:
        """Deeplink-Einstieg: wählt einen Sub-Tab vor.

        Args:
            tab: Ziel-Tab. Gültig: ``'email'`` (E-Mail-Anhang), ``'pdf'``
                (PDF-Risiko), ``'office'`` (Dokument/Office). Unbekannte
                Werte werden ignoriert (kein Tab-Wechsel).
        """
        if tab in self._tab_indices:
            self._tabs.setCurrentIndex(self._tab_indices[tab])

    def shutdown(self) -> None:
        """App-Lifecycle-Hook: fährt alle Sub-Scanner herunter, idempotent).

        Reicht den Teardown duck-typed an die Sub-Tab-Widgets durch — so räumt
        z. B. der Dokument-Scanner seine Quarantäne auf und stoppt laufende
        ScanWorker. Vor war ``DocumentScannerWidget.shutdown`` verwaist,
        seit die Sub-Scanner im Container statt als Direkt-Dock leben und der
        ``closeEvent``-Sweep nur ``stop_worker`` auf Top-Level-Docks rief.

        Platzhalter-Tabs (Lizenz/Fehler) und Sub-Widgets ohne ``shutdown`` werden
        übersprungen. Idempotent: ein zweiter Aufruf ist ein No-op (der
        ``closeEvent`` kann in Qt mehrfach feuern).
        """
        if self._shutdown_done:
            return
        self._shutdown_done = True
        for i in range(self._tabs.count()):
            widget = self._tabs.widget(i)
            sub_shutdown = getattr(widget, "shutdown", None)
            if not callable(sub_shutdown):
                continue
            try:
                sub_shutdown()
            except Exception as exc:  # noqa: BLE001 — Shutdown-Boundary
                log.warning(
                    "shutdown() für Sub-Scanner %s fehlgeschlagen: %s",
                    type(widget).__name__,
                    exc,
                )
