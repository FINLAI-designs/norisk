"""core.help.display_mode_state — Globaler Einfach/Profi-Zustand.

Plattform-Singleton analog:class:`core.help.explain_mode.ExplainMode`, hält
aber den:class:`core.help.display_mode.DisplayMode` (EASY/EXPERT) statt eines
Bool. Persistiert ueber App-Restarts (``QSettings``) und sendet ``mode_changed``,
damit Render-Pfade (HelpPanel/HelpDialog/HelpButton) und Tool-Widgets bei einem
Wechsel neu rendern.

Default ist ``EASY`` (Erst-Install = Einfach).

Hinweis: Dieser Zustand soll den bestehenden ``ExplainMode`` perspektivisch
**subsumieren** (eine Achse Einfach/Profi statt zwei Toggles). Die genaue
Kopplung (zeigt EASY oder EXPERT den Erklaer-Layer?) ist eine offene
UX-Entscheidung und wird HIER bewusst noch NICHT verdrahtet — dieser Singleton
ist reiner, semantik-neutraler Zustandshalter. Schichtzugehoerigkeit: core/
(gewollt PySide6-abhaengig, UI-Toggle).
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QSettings, Signal

from core.exceptions import ConfigurationError
from core.help.display_mode import DisplayMode

_SETTINGS_ORG = "FINLAI"
_SETTINGS_APP = "DisplayMode"
_SETTINGS_KEY = "mode"


class DisplayModeState(QObject):
    """Singleton-QObject fuer den globalen Anzeige-Modus (Einfach/Profi).

    Subscribers verbinden sich mit:pyattr:`mode_changed` (liefert den neuen
:class:`DisplayMode`). Initialwert wird beim ersten Zugriff aus
    ``QSettings`` gelesen — Default ``EASY``.

    Beispiel::

        state = DisplayModeState.instance
        state.mode_changed.connect(widget._on_display_mode_changed)
        widget._on_display_mode_changed(state.mode) # initialer Push
...
        state.toggle # vom Einfach/Profi-Umschalter
    """

    mode_changed = Signal(object)  # DisplayMode

    _instance: DisplayModeState | None = None

    def __init__(self) -> None:
        """Direkter Aufruf ist verboten — nutze:meth:`instance`."""

        raise ConfigurationError(
            "DisplayModeState ist ein Singleton — nutze DisplayModeState.instance()."
        )

    @classmethod
    def instance(cls) -> DisplayModeState:
        """Liefert die Singleton-Instanz; legt sie beim ersten Aufruf an."""

        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            QObject.__init__(cls._instance)
            settings = QSettings(_SETTINGS_ORG, _SETTINGS_APP)
            stored = settings.value(_SETTINGS_KEY, DisplayMode.EASY.value, type=str)
            cls._instance._mode = DisplayMode.from_value(stored)  # type: ignore[attr-defined]
        return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        """Verwirft die Singleton-Instanz — nur fuer Tests."""

        cls._instance = None

    def mode(self) -> DisplayMode:
        """Aktueller Anzeige-Modus."""

        return self._mode

    def is_easy(self) -> bool:
        """``True`` wenn Einfach-Modus aktiv."""

        return self._mode is DisplayMode.EASY

    def is_expert(self) -> bool:
        """``True`` wenn Profi-Modus aktiv."""

        return self._mode is DisplayMode.EXPERT

    def set_mode(self, mode: DisplayMode) -> None:
        """Setzt den Modus + persistiert + emittiert ``mode_changed``.

        No-op bei Wert-Identitaet (kein Doppel-Signal).
        """

        if mode is self._mode:
            return
        self._mode = mode
        QSettings(_SETTINGS_ORG, _SETTINGS_APP).setValue(_SETTINGS_KEY, mode.value)
        self.mode_changed.emit(mode)

    def toggle(self) -> None:
        """Schaltet zwischen Einfach und Profi um."""

        self.set_mode(
            DisplayMode.EXPERT if self._mode is DisplayMode.EASY else DisplayMode.EASY
        )


__all__ = ["DisplayModeState"]
