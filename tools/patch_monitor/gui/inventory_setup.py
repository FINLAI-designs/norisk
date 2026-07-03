"""patch_inventory_setup — Factory + Teardown fuer den InventoryWorker-Verbund.

 Stop-Step E. Eine duenne
Schicht zwischen:class:`InventoryWorker` +:class:`PatchScheduler` und
MainWindow, die das Qt-Lifecycle (Thread + Worker + Scheduler-Verbund)
gekapselt zurueckgibt.

Begruendung der Kapselung:

* MainWindow soll **keine** Qt-Lifecycle-Details kennen.
* Tests koennen die Verdrahtung verifizieren ohne MainWindow zu
  importieren oder QApplication-Setup zu duplizieren.
* Aenderungen am Tick-Intervall oder am Worker-Pattern sind hier
  zentral.

**Schicht:** ``gui/`` — importiert ``application/`` (Service) und
``core.patch_scheduler``. Die Factory lebt bewusst neben dem Worker
(beide ``gui/``), damit MainWindow nur einen Tool-Import benoetigt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QThread

from core.logger import get_logger
from core.patch_scheduler import PatchScheduler
from tools.patch_monitor.application.patch_inventory_service import (
    PatchInventoryService,
)
from tools.patch_monitor.gui.inventory_worker import InventoryWorker

if TYPE_CHECKING:
    from PySide6.QtCore import QObject

log = get_logger(__name__)


def setup_patch_inventory(
    parent: QObject,
    *,
    service: PatchInventoryService | None = None,
    auto_start_scheduler: bool = True,
) -> tuple[QThread, InventoryWorker, PatchScheduler, PatchInventoryService]:
    """Baut den InventoryWorker + Scheduler-Verbund und startet beides.

    Reihenfolge (analog setup_revalidation):

    1. Service-Instanz (geteilt zwischen Worker und Scheduler).
    2. Thread mit Parent (bindet Lifetime an MainWindow).
    3. Worker konstruieren + ``moveToThread``.
    4. Scheduler im Hauptthread (Parent = parent).
    5. Scheduler-Signale auf Worker-Slots verdrahten —
       ``QueuedConnection`` ist auto-default weil cross-thread.
    6. Thread starten.
    7. Scheduler starten (sofortiger erster Tick).

    Args:
        parent: Qt-Parent, typischerweise das MainWindow.
        service: Optional vorbereiteter Service (Tests). Default: neu.
        auto_start_scheduler: ``False`` ueberspringt
            ``scheduler.start`` — Tests koennen ``tick_now`` manuell
            aufrufen.

    Returns:
        ``(thread, worker, scheduler, service)`` — MainWindow muss alle
        4 Referenzen halten damit nichts gargabe-collected wird.
    """
    if service is None:
        service = PatchInventoryService()

    thread = QThread(parent)
    worker = InventoryWorker(service=service)
    worker.moveToThread(thread)

    scheduler = PatchScheduler(service, parent=parent)
    # Cross-Thread Signal → Slot mit AutoConnection. Beide Slots haengen
    # an ``worker`` (QThread-Mitglied) — kein Lambda, damit Qt die
    # Verbindung sauber als ``QueuedConnection`` aufloesst und die GUI
    # waehrend des Scans nicht blockiert.
    scheduler.daily_refresh_due.connect(worker.run_daily_refresh)
    scheduler.monthly_full_due.connect(worker.run_monthly_full)
    # initial_scan_due wird vom MainWindow direkt abonniert
    # (Navigation zum Patch-Monitor + User-Klick "Scan starten").

    thread.start()
    if auto_start_scheduler:
        scheduler.start()
    log.info(
        "PatchInventory-Setup bereit (Worker-Thread + Scheduler aktiv).",
    )
    return thread, worker, scheduler, service


def teardown_patch_inventory(
    thread: QThread,
    scheduler: PatchScheduler,
) -> None:
    """Stoppt Scheduler + Worker-Thread sauber. Wird im
    MainWindow.closeEvent gerufen.

    Args:
        thread: Worker-Thread aus:func:`setup_patch_inventory`.
        scheduler: Scheduler-Instanz.
    """
    try:
        scheduler.stop()
    except Exception as exc:  # noqa: BLE001 — Teardown darf nicht crashen
        log.warning("Scheduler.stop fehlgeschlagen: %s", type(exc).__name__)
    try:
        thread.quit()
        thread.wait(2000)  # 2 s timeout
    except Exception as exc:  # noqa: BLE001
        log.warning("Thread-Teardown fehlgeschlagen: %s", type(exc).__name__)
    log.info("PatchInventory-Setup abgebaut.")


__all__ = [
    "setup_patch_inventory",
    "teardown_patch_inventory",
]
