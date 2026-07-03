"""section_kanban — Wrapper-Sektion fuer das Kanban-Board (Sprint S4a).

Bettet ``TaskboardWidget`` aus ``tools.mainpage.gui.taskboard_widget`` als
Inhalt einer Dashboard-Akkordeon-Sektion ein. DB bleibt unveraendert
(``mainpage.db``); nur das Code-Ownership wandert vom Mainpage-Widget
ins NoRisk-Dashboard.

Bestehende Funktionalitaet — Drag&Drop, Bearbeiten, KI-Todo-Marker,
Urgency-Badge — bleiben unangetastet, da das Widget verbatim eingebettet
wird.

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtWidgets import QVBoxLayout, QWidget

from core.logger import get_logger
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.gui.taskboard_widget import TaskboardWidget

_log = get_logger(__name__)

_BOARD_MIN_HEIGHT = 450
"""Mindesthöhe (px) des eingebetteten Kanban-Boards im Cockpit.

Im Mainpage füllt das ``TaskboardWidget`` die ganze Seite; im Cockpit-Akkordeon
bekommt es nur seinen (kleinen) Size-Hint und die drei Spalten kollabieren auf
~eine Karte mit Scrollbar. Diese Mindesthöhe vergrößert die Board-/Spaltenhöhe
auf ca. das Dreifache (Patrick), sodass bei geöffneten Arbeitsbereich-Sektionen
mehrere Karten je Spalte sichtbar sind. Betrifft NUR die Cockpit-Einbettung —
das Mainpage-Board (nutzt ``TaskboardWidget`` direkt) bleibt unverändert.
"""


class KanbanSection(QWidget):
    """Dashboard-Sektion mit eingebettetem Kanban-Board.

    Args:
        task_service: Geteilter ``TaskService`` — gleiche Instanz wie der
            Mainpage-Eintrag, damit Add/Edit/Delete in beiden Sichten
            sofort sichtbar werden.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        task_service: TaskService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self._board = TaskboardWidget(task_service, self)
        # Cockpit-Einbettung: Board braucht eine Mindesthöhe, sonst kollabieren
        # die Spalten im Akkordeon auf ~eine Karte (siehe _BOARD_MIN_HEIGHT).
        self._board.setMinimumHeight(_BOARD_MIN_HEIGHT)
        root.addWidget(self._board)

    def refresh(self) -> None:
        """Triggert einen DB-Reload des Kanban-Boards.

        Wird vom Auto-Refresh des Dashboards aufgerufen, damit Aenderungen
        in der Mainpage (oder durch KI-Todo-Erzeugung in S2a/S2b) sichtbar
        werden, ohne dass der User das Dashboard manuell neu laedt.
        """
        try:
            self._board._refresh()  # noqa: SLF001 -- bestehende interne API
        except Exception as exc:  # noqa: BLE001 -- Refresh darf nie crashen
            _log.warning(
                "KanbanSection-Refresh fehlgeschlagen: %s", type(exc).__name__
            )
