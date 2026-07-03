"""section_notes — Wrapper-Sektion fuer das Tagesprotokoll (Sprint S4a).

Bettet ``JournalWidget`` aus ``tools.mainpage.gui.journal_widget`` als
Inhalt einer Dashboard-Akkordeon-Sektion ein. DB bleibt unveraendert
(``mainpage.db``); nur das Code-Ownership wandert.

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtWidgets import QVBoxLayout, QWidget

from core.logger import get_logger
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.gui.journal_widget import JournalWidget

_log = get_logger(__name__)


class NotesSection(QWidget):
    """Dashboard-Sektion mit eingebettetem Tagesprotokoll.

    Args:
        journal_service: Geteilter ``JournalService`` — gleiche Instanz wie
            der Mainpage-Eintrag, damit Notizen in beiden Sichten konsistent
            sind.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        journal_service: JournalService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self._journal = JournalWidget(journal_service, self)
        root.addWidget(self._journal)

    def refresh(self) -> None:
        """Triggert einen DB-Reload des Tagesprotokolls."""
        try:
            self._journal.refresh()
        except Exception as exc:  # noqa: BLE001 -- Refresh darf nie crashen
            _log.warning(
                "NotesSection-Refresh fehlgeschlagen: %s", type(exc).__name__
            )
