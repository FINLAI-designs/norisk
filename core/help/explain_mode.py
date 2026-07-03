"""explain_mode — Erklär-Layer-Schalter, seit Facade über DisplayModeState.

Historisch eine eigene Bool-Achse („Was bedeutet das?"-Layer an/aus). Seit
 ist der Erklär-Layer **keine eigene Achse mehr**, sondern abgeleitet aus
dem globalen Einfach/Profi-Modus (:class:`core.help.display_mode_state.
DisplayModeState`):

* **EINFACH** (``DisplayMode.EASY``) → Erklär-Layer **AN** (Laienhilfe).
* **PROFI** (``DisplayMode.EXPERT``) → Erklär-Layer **AUS** (technische Volltexte,
  dafür CVE/Logs).

Entscheidung Patrick 2026-05-29 (überschreibt §9). Default ist
``EASY`` → der Erklär-Layer ist per Default sichtbar (Erst-Install = Einfach).

Diese Klasse hält die bestehende API (``is_enabled`` / ``set_enabled`` /
``toggle`` / ``mode_changed``) als dünne Facade stabil, damit
:class:`core.help.explainable_label.ExplainableLabel`, der TitleBar-Toggle und
direkt subscribierte Widgets (Netzwerk-Monitor) unverändert weiterlaufen — die
Wahrheit liegt aber in ``DisplayModeState``.

Schichtzugehörigkeit: core/ — gewollt PySide6-abhängig.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from core.exceptions import ConfigurationError
from core.help.display_mode import DisplayMode
from core.help.display_mode_state import DisplayModeState


class ExplainMode(QObject):
    """Facade über:class:`DisplayModeState` mit Bool-Semantik.

    ``is_enabled == True`` bedeutet „Erklär-Layer sichtbar" und entspricht
    ``DisplayMode.EASY``. Subscribers verbinden sich wie bisher mit
:pyattr:`mode_changed` (Bool).
    """

    mode_changed = Signal(bool)

    _instance: ExplainMode | None = None

    def __init__(self) -> None:
        """Direkter Aufruf ist verboten — nutze:meth:`instance`."""

        raise ConfigurationError(
            "ExplainMode ist ein Singleton — nutze ExplainMode.instance()."
        )

    @classmethod
    def instance(cls) -> ExplainMode:
        """Liefert die Singleton-Instanz; koppelt sie an DisplayModeState."""

        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            QObject.__init__(cls._instance)
            # Erklär-Layer-Wechsel folgt dem globalen Einfach/Profi-Wechsel.
            DisplayModeState.instance().mode_changed.connect(
                cls._instance._on_display_mode_changed
            )
        return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        """Verwirft die Singleton-Instanz — nur für Tests."""

        cls._instance = None

    def is_enabled(self) -> bool:
        """``True`` wenn der Erklär-Layer sichtbar ist (= Einfach-Modus)."""

        return DisplayModeState.instance().is_easy()

    def set_enabled(self, enabled: bool) -> None:
        """Schaltet den Erklär-Layer = setzt den Modus auf Einfach/Profi."""

        DisplayModeState.instance().set_mode(
            DisplayMode.EASY if enabled else DisplayMode.EXPERT
        )

    def toggle(self) -> None:
        """Schaltet Einfach/Profi um (TitleBar-Button)."""

        DisplayModeState.instance().toggle()

    def _on_display_mode_changed(self, mode: DisplayMode) -> None:
        """Re-emittiert den Modus-Wechsel als Bool für Bestands-Subscriber."""

        self.mode_changed.emit(mode is DisplayMode.EASY)
