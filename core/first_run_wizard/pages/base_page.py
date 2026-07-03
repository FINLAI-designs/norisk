"""Basisklasse für First-Run-Wizard-Seiten.

Jede Seite erbt von:class:`BasePage` und bekommt damit:
    * einheitliche vertikale Layout-Struktur
    * ``is_complete``-Hook, den ``wizard.py`` für die Weiter-Button-
      Aktivierung abfragt
    * ``completion_changed``-Signal, das die Seite emittiert, wenn sich
      der Abschluss-Status ändert (typ. bei Validierungsseiten).
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QVBoxLayout, QWidget


class BasePage(QWidget):
    """Abstrakte Basisklasse für alle Wizard-Seiten."""

    completion_changed = Signal(bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(32, 24, 32, 24)
        self._layout.setSpacing(16)

    def is_complete(self) -> bool:
        """Gibt True zurück, wenn „Weiter" erlaubt ist. Default: True."""
        return True

    def commit(self) -> None:
        """Wird beim Verlassen der Seite nach vorne aufgerufen.

        Default: no-op. Seiten mit persistenter Aktion (z. B.
:class:`AdminSetupPage`) überschreiben das, um ihre Daten zu
        speichern. Bei Fehlern soll eine:class:`RuntimeError` geworfen
        werden; der Wizard fängt diese und zeigt die Meldung an.
        """
        return None
