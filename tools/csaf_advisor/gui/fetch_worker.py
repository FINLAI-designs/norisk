"""
fetch_worker — Hintergrund-Worker fuer den CSAF-Fetch.

Sprint 6 Phase 1: Aus csaf_advisor_widget.py extrahiert.
Klassische QObject + moveToThread-Worker-Konstruktion. Wird im
Hauptwidget per QThread gestartet — kein direkter Aufruf von hier.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.application.product_matcher import SoftwareComponent


class FetchWorker(QObject):
    """Führt den CSAF-Fetch im Hintergrund-Thread aus.

    Signals:
        progress(provider_name, current, total, info): Fortschritts-Update.
        finished(new_count, errors): Fetch abgeschlossen.
        error(message): Kritischer Fehler.
    """

    progress = Signal(str, int, int, str)
    finished = Signal(int, list)
    error = Signal(str)

    def __init__(
        self,
        service: AdvisoryService,
        inventory: list[SoftwareComponent],
    ) -> None:
        """Initialisiert den Worker.

        Args:
            service: Vollständig konfigurierter AdvisoryService.
            inventory: Aktives Software-Inventar für Matching nach dem Fetch.
        """
        super().__init__()
        self._service = service
        self._inventory = inventory

    @Slot()
    def run(self) -> None:
        """Führt den Fetch aus und emittiert finished."""
        try:

            def _cb(provider_name: str, current: int, total: int, info: str) -> None:
                self.progress.emit(provider_name, current, total, info)

            new_count, errors = self._service.fetch_all_providers(progress_callback=_cb)

            # Matching nach Fetch automatisch neu berechnen
            if self._inventory:
                self._service.run_matching(self._inventory)

            self.finished.emit(new_count, errors)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
