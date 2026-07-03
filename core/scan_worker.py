"""
scan_worker — Qt-Worker fuer asynchrones Software-Inventar-Scanning.

PM-1.1b, in PM-1.7 um die volle Pipeline-Integration
erweitert. Stellt:class:`ScanWorker` bereit — eine
``QObject``-Subklasse (kein ``QThread``-Subclassing), die per
``moveToThread``-Pattern in einen Hintergrund-Thread eingehaengt
wird und dort den synchronen
:mod:`core.patch_collector`/:mod:`core.patch_service`-Code
ausfuehrt.

Pattern: ``QObject`` + ``Signal`` + ``@Slot`` im moveToThread-Aufbau
(gemeinsames Qt-Worker-Muster im Repo).

3-Wellen-Modell aus / NoRisk_PROGRESS.md::

    Welle 1 (~3 s): winget-Ergebnisse → batch_ready
    Welle 2 (~5 s): Registry-Ergaenzungen → batch_ready
    Welle 3 (8-30 s)::class:`PatchService.scan` → scan_progress
                                                    + scan_complete_with_results

Welle 3 delegiert an:class:`core.patch_service.PatchService` —
Channel-Resolver + CVE-Matcher laufen pro Item, ``scan_progress``
wird via ``progress_cb`` weitergereicht. Am Ende feuert
``scan_complete_with_results`` mit der vollen
:class:`core.patch_result.PatchScanResult`-Liste.

``batch_ready`` wird **nicht** fuer leere Listen gefeuert — wenn
``collect_winget`` leer zurueckkommt (Timeout, nicht installiert,
Format-Fehler), springt der Worker direkt zu Welle 2 ohne ein
leeres Signal-Emit. Analog fuer Welle 2.

Trigger-Verbund (typisch im Tab-Code, siehe PM-1.7
``PatchConsoleWidget``)::

    self._scan_thread = QThread(self)
    self._scan_worker = ScanWorker
    self._scan_worker.moveToThread(self._scan_thread)
    self._scan_thread.started.connect(self._scan_worker.run)
    self._scan_worker.scan_complete.connect(self._scan_thread.quit)
    self._scan_worker.scan_complete_with_results.connect(self._on_results)
    self._scan_worker.scan_progress.connect(self._on_progress)
    self._scan_worker.scan_failed.connect(self._on_failed)
    self._scan_thread.start
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from core.logger import get_logger
from core.patch_collector import collect_registry, collect_winget
from core.patch_service import PatchService

log = get_logger(__name__)


class ScanWorker(QObject):
    """Asynchroner Software-Inventar-Worker.

    Signals:
        scan_started: Lebenszyklus-Marker — Worker hat angefangen.
        batch_ready(list): Eine Welle ``SoftwareItem``-Objekte liegt
            bereit. Wird **nicht** fuer leere Listen gefeuert
            (vermeidet leere UI-Updates).
        item_enriched(object): Reserviert fuer kuenftige Per-Item-
            Streaming-Erweiterungen — wird in PM-1.7 noch nicht
            gefeuert. Die volle Liste kommt am Ende ueber
            ``scan_complete_with_results``.
        scan_progress(int, int): ``(current, total)`` waehrend Welle 3.
            Wird vom:class:`core.patch_service.PatchService`-
            ``progress_cb`` durchgereicht — pro Item ein Tick
            (1-basiert).
        scan_complete: Lebenszyklus-Marker — Worker ist fertig.
            Gegenstueck zu ``scan_started``. Wird auch nach
:meth:`cancel` emittiert (sauberer Stop, kein Abort-Signal).
            Bleibt aus Rueckwaertskompatibilitaet erhalten.
        scan_complete_with_results(list): PM-1.7-Hauptkanal — die volle
            ``list[PatchScanResult]`` aus:meth:`PatchService.scan`.
            Wird **vor** ``scan_complete`` gefeuert.
        scan_failed(str): Unerwartete Exception in:meth:`run`. Der
            Aufrufer zeigt den String und markiert den Lauf als
            fehlgeschlagen.
    """

    scan_started = Signal()
    batch_ready = Signal(list)
    item_enriched = Signal(object)  # reserviert
    scan_progress = Signal(int, int)
    scan_complete = Signal()
    scan_complete_with_results = Signal(list)  # list[PatchScanResult]
    scan_failed = Signal(str)

    def __init__(
        self,
        service: PatchService | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialisiert den Worker.

        Args:
            service: Optional injizierter:class:`PatchService` (Tests).
                Default: lazy konstruiert beim ersten:meth:`run`-Aufruf
                (vermeidet teure SQLCipher-DB-Anlage in Tests, die den
                Worker nur konstruieren).
            parent: Standard-Qt-Parent fuer Memory-Management.
        """
        super().__init__(parent)
        self._cancelled = False
        self._service = service

    @Slot()
    def cancel(self) -> None:
        """Bittet den Worker, beim naechsten Pruefpunkt aufzuhoeren.

        Setzt ein internes Flag — ``run`` prueft es zwischen den
        Wellen. Welle 3 (PatchService) ist atomar und nicht abbrechbar
        — der Cancel greift erst NACH Welle 3, sodass die UI in einem
        konsistenten Zustand zurueckkommt.
        """
        self._cancelled = True

    @Slot()
    def run(self) -> None:
        """Fuehrt einen vollstaendigen Inventar-Scan in 3 Wellen durch.

        Welle 1: ``collect_winget`` — als ``batch_ready`` feuern,
        **wenn** Items gefunden.

        Welle 2: ``collect_registry`` — gefiltert um die in Welle 1
        schon bekannten Namen (case-insensitiv). Auch hier nur feuern
        wenn nicht-leer.

        Welle 3::meth:`PatchService.scan` mit
        ``progress_cb=self.scan_progress.emit``. Der Service ruft
        intern ``collect_all`` erneut auf und sammelt also komplettes
        Inventar — Welle 1+2 dienen primaer dem progressiven UI-Feed
        ("Tabelle fuellt sich"); Welle 3 ist der eigentliche
        Resolver+CVE-Lauf.

        Am Ende: ``scan_complete_with_results(results)`` →
        ``scan_complete``. Bei Exception: ``scan_failed(msg)``.
        """
        self.scan_started.emit()
        try:
            # Welle 1: winget
            winget_items = collect_winget()
            if winget_items:
                self.batch_ready.emit(winget_items)

            # Welle 2: Registry-Ergaenzungen
            registry_items = collect_registry()
            winget_names = {i.name.lower() for i in winget_items}
            new_items = [
                i for i in registry_items if i.name.lower() not in winget_names
            ]
            if new_items:
                self.batch_ready.emit(new_items)

            if self._cancelled:
                self.scan_complete_with_results.emit([])
                self.scan_complete.emit()
                return

            # Welle 3: vollstaendige Pipeline (collect_all + Resolver + CVE)
            service = self._service if self._service is not None else PatchService()
            results = service.scan(
                progress_cb=lambda c, t: self.scan_progress.emit(c, t),
            )
            self.scan_complete_with_results.emit(results)
            self.scan_complete.emit()
        except Exception as e:
            log.exception(
                "ScanWorker.run: unerwartete Exception — Scan abgebrochen."
            )
            self.scan_failed.emit(str(e))
