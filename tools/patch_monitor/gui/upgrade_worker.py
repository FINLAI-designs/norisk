"""upgrade_worker — Qt-Worker fuer asynchrone Batch-Upgrades.

 / PM-2.x Stop-Step C. Wraps den ``BatchUpgradeService`` in einem
``QObject`` (kein ``QThread``-Subclassing), damit das aufrufende Widget
das ``moveToThread``-Pattern aus:class:`core.scan_worker.ScanWorker`
identisch wiederverwenden kann.

Signal-Kette (gefeuert in dieser Reihenfolge)::

    batch_started(total) — direkt nach run-Start
    item_started(index, total, req) — vor jedem Subprocess
    item_finished(index, total, req, result)
                                        — nach jedem Subprocess
    batch_done(summary) — am Ende ueber Erfolg / Fehler /
                                          Cancel hinweg
    batch_failed(error) — nur bei unerwarteter Exception
                                          *vor* batch_done; in dem Fall
                                          wird kein batch_done emittiert

Cancel-Pattern: ``cancel`` setzt ein internes Flag, das der
:meth:`BatchUpgradeService.upgrade_batch` zwischen Items via
``should_cancel``-Callback abfragt. Aktuelles winget-Subprocess laeuft
zu Ende (winget ist nicht stoppbar), restliche Queue wird mit
:attr:`UpgradeStatus.SKIPPED` ueberspringen.

Schicht: ``gui/`` — importiert nur ``application/`` und ``domain/``.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from core.logger import get_logger
from core.patch_upgrade import UpgradeRequest
from tools.patch_monitor.application.batch_upgrade_service import (
    BatchUpgradeService,
)

log = get_logger(__name__)


class UpgradeWorker(QObject):
    """Asynchroner Batch-Upgrade-Worker.

    Signals:
        batch_started(int): ``total`` — Anzahl der Items im Batch.
            Wird direkt zu Beginn von:meth:`run` emittiert.
        item_started(int, int, object): ``(index, total, request)`` —
            ``index`` ist 1-basiert.
        item_finished(int, int, object, object): ``(index, total,
            request, result)`` — Result-Objekt ist
:class:`core.patch_upgrade.UpgradeResult`.
        batch_done(object)::class:`BatchSummary` mit aggregierten
            Zaehlern + Pro-Item-Results.
        batch_failed(str): Unerwartete Exception. Wird nur emittiert,
            wenn der Service selbst crasht — was nicht passieren sollte,
            weil:meth:`BatchUpgradeService.upgrade_batch` Exceptions
            schluckt. Trotzdem als Safety-Net.

    Cancel:
:meth:`cancel` setzt ein Flag, das zwischen Items im Service
        abgefragt wird. Aktuelles Item laeuft fertig.
    """

    batch_started = Signal(int)
    item_started = Signal(int, int, object)
    item_finished = Signal(int, int, object, object)
    batch_done = Signal(object)
    batch_failed = Signal(str)

    def __init__(
        self,
        requests: list[UpgradeRequest],
        service: BatchUpgradeService | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialisiert den Worker.

        Args:
            requests: Die ausgewaehlten Upgrade-Aktionen in der
                gewuenschten Reihenfolge.
            service: Optional vorbereiteter:class:`BatchUpgradeService`
                (Tests injizieren Mocks). Default: lazy konstruiert beim
                ersten:meth:`run`-Aufruf.
            parent: Standard-Qt-Parent fuer Memory-Management.
        """
        super().__init__(parent)
        self._requests = list(requests)
        self._service = service
        self._cancelled = False

    @Slot()
    def cancel(self) -> None:
        """Bittet den Worker, beim naechsten Pruefpunkt aufzuhoeren.

        Der naechste Pruefpunkt liegt zwischen zwei winget-Subprocesses
        — ein laufender Install kann nicht abgebrochen werden.
        """
        self._cancelled = True
        log.info("UpgradeWorker.cancel: cancel-Flag gesetzt")

    @Slot()
    def run(self) -> None:
        """Fuehrt die Batch synchron aus und emittiert Lifecycle-Signals.

        Wird vom:class:`QThread` ueber ``thread.started`` aufgerufen.
        Garantie: emittiert genau ein ``batch_done`` ODER ein
        ``batch_failed`` — niemals beides, niemals keines.
        """
        total = len(self._requests)
        self.batch_started.emit(total)
        try:
            service = self._service or BatchUpgradeService()
            summary = service.upgrade_batch(
                self._requests,
                on_start=self._emit_item_started,
                on_finish=self._emit_item_finished,
                should_cancel=lambda: self._cancelled,
            )
            self.batch_done.emit(summary)
        except Exception as exc:  # noqa: BLE001 — Worker darf nie crashen
            log.exception("UpgradeWorker.run unerwartete Exception: %s", exc)
            self.batch_failed.emit(str(exc))

    # ------------------------------------------------------------------
    # Internals — Signal-Emit-Bridges fuer die Service-Callbacks
    # ------------------------------------------------------------------

    def _emit_item_started(
        self, index: int, total: int, request: UpgradeRequest
    ) -> None:
        self.item_started.emit(index, total, request)

    def _emit_item_finished(
        self,
        index: int,
        total: int,
        request: UpgradeRequest,
        result,  # noqa: ANN001 - UpgradeResult, ueber object-Signal
    ) -> None:
        self.item_finished.emit(index, total, request, result)


__all__ = ["UpgradeWorker"]
