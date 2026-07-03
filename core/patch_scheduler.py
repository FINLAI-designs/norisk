"""patch_scheduler — Tier-Trigger fuer Patch-Persistence.

 Stop-Step C. Entscheidet bei jedem Tick was zu tun ist und
emittiert ein passendes Signal — die eigentlichen Scans (full_scan /
daily_refresh) laufen ueber einen GUI-Worker, NICHT inline im
Scheduler-Tick. Damit bleibt der Scheduler-Tick selbst <1 ms (drei
DB-Reads im PatchInventoryRepository) und blockiert die UI nicht.

Tier-Logik (Prioritaet absteigend):

1. **Inventar leer** →:attr:`initial_scan_due`. Die UI zeigt einen
   Modal-Dialog "Patch-Inventar noch nicht aufgebaut — jetzt
   Initial-Scan starten?" — User-Opt-In, kein Auto-Trigger.
2. **Monthly-Full faellig** (last_full_scan_at >= 31 Tage alt) →
:attr:`monthly_full_due`. Auto-Trigger durch Worker-Start.
3. **Daily-Refresh faellig** (last_daily_refresh_at >= 24 h alt) →
:attr:`daily_refresh_due`. Auto-Trigger.

Wird Tier 2 emittiert, wird Tier 3 fuer denselben Tick uebersprungen
(Monthly-Full deckt das Daily-Refresh inhaltlich mit ab).

Pure Funktionen:func:`is_daily_refresh_due` und
:func:`is_monthly_full_due` sind ohne Qt testbar.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from core.logger import get_logger

if TYPE_CHECKING:
    # Nur Typannotation (DI-injizierter Service, ``from __future__ import
    # annotations`` aktiv) -> kein Laufzeit-Import. Hebt die core->tools-
    # Makro-Schicht-Verletzung auf.
    from tools.patch_monitor.application.patch_inventory_service import (
        PatchInventoryService,
    )

log = get_logger(__name__)

#: Default-Tick-Intervall: alle 5 Minuten. Damit reagiert der Scheduler
#: schnell genug auf "Tag-ueberschritten" (24-h-Faelligkeit) ohne
#: konstant DB-Reads zu machen.
DEFAULT_TICK_INTERVAL_MS: Final[int] = 5 * 60 * 1000

#: Wann ist ein Daily-Refresh ueberfaellig.
DEFAULT_DAILY_INTERVAL_HOURS: Final[int] = 24

#: Wann ist ein Monthly-Full ueberfaellig.
DEFAULT_MONTHLY_INTERVAL_DAYS: Final[int] = 31


# ---------------------------------------------------------------------------
# Pure-Function Helpers (Qt-frei, testbar)
# ---------------------------------------------------------------------------


def is_daily_refresh_due(
    last_daily: datetime | None,
    *,
    interval_hours: int = DEFAULT_DAILY_INTERVAL_HOURS,
    now: datetime | None = None,
) -> bool:
    """``True`` wenn ein Daily-Refresh ueberfaellig ist.

    Args:
        last_daily: Zeitpunkt des letzten erfolgreichen Daily-Refresh
            (aus:meth:`PatchInventoryService.get_last_daily_refresh_at`).
            ``None`` heisst "noch nie passiert" → faellig.
        interval_hours: Refresh-Intervall. Default 24 h.
        now: Override fuer Tests; default ``datetime.now(UTC)``.

    Returns:
        ``True`` wenn ``last_daily`` ``None`` ist ODER ``now - last_daily
        >= interval_hours``.
    """
    if last_daily is None:
        return True
    if now is None:
        now = datetime.now(UTC)
    return (now - last_daily) >= timedelta(hours=interval_hours)


def is_monthly_full_due(
    last_full: datetime | None,
    *,
    interval_days: int = DEFAULT_MONTHLY_INTERVAL_DAYS,
    now: datetime | None = None,
) -> bool:
    """``True`` wenn ein Monthly-Full-Scan ueberfaellig ist.

    Args:
        last_full: Zeitpunkt des letzten erfolgreichen Vollscans
            (aus:meth:`PatchInventoryService.get_last_full_scan_at`).
            ``None`` heisst "noch nie passiert" — wird **nicht** als
            "faellig" gewertet, weil der Initial-Scan-Pfad (Tier 1)
            das abdeckt. Saubere Trennung: Initial = User-Opt-In,
            Monthly = Auto.
        interval_days: Monthly-Intervall. Default 31 Tage.
        now: Override fuer Tests.

    Returns:
        ``False`` wenn ``last_full`` ``None`` ist (Initial-Scan deckt
        das), sonst ``True`` wenn ``now - last_full >= interval_days``.
    """
    if last_full is None:
        return False
    if now is None:
        now = datetime.now(UTC)
    return (now - last_full) >= timedelta(days=interval_days)


# ---------------------------------------------------------------------------
# Scheduler-Klasse
# ---------------------------------------------------------------------------


class PatchScheduler(QObject):
    """Tier-Trigger via QTimer.

    Signals:
        initial_scan_due:
            Inventory ist leer — UI soll Initial-Scan-Modal anzeigen.
        monthly_full_due:
            Letzter Vollscan ist >= 31 Tage her — Auto-Trigger
            Monthly-Full-Scan via GUI-Worker.
        daily_refresh_due:
            Letzter Daily-Refresh ist >= 24 h her — Auto-Trigger
            Daily-Refresh via GUI-Worker.

    Lifecycle:
:meth:`start` aktiviert den 5-min-Tick und feuert einen
        initialen Tick sofort (catch-up nach App-Restart).
:meth:`stop` deaktiviert den Timer.

    Threading: alle Signal-Emits passieren im Thread, in dem
:meth:`_on_tick` laeuft — typischerweise der Hauptthread (der
    QTimer haengt am QObject-Parent). Die Slots der GUI starten
    QThreads fuer die eigentlichen Scans.
    """

    initial_scan_due = Signal()
    monthly_full_due = Signal()
    daily_refresh_due = Signal()

    def __init__(
        self,
        service: PatchInventoryService,
        *,
        tick_interval_ms: int = DEFAULT_TICK_INTERVAL_MS,
        daily_interval_hours: int = DEFAULT_DAILY_INTERVAL_HOURS,
        monthly_interval_days: int = DEFAULT_MONTHLY_INTERVAL_DAYS,
        parent: QObject | None = None,
    ) -> None:
        """Initialisiert den Scheduler.

        Args:
            service: Geteilte:class:`PatchInventoryService`-Instanz.
                Wird fuer die "is_due"-Lookups verwendet — der Scheduler
                ruft selbst keine Service-Methoden auf die Scans
                ausloesen, das macht die GUI nach Signal-Empfang.
            tick_interval_ms: Wie oft wird gecheckt. Default 5 min.
            daily_interval_hours: Schwelle fuer Daily-Refresh.
            monthly_interval_days: Schwelle fuer Monthly-Full.
            parent: Qt-Parent fuer Memory-Management.
        """
        super().__init__(parent)
        self._service = service
        self._daily_interval_hours = daily_interval_hours
        self._monthly_interval_days = monthly_interval_days
        self._timer = QTimer(self)
        self._timer.setInterval(tick_interval_ms)
        self._timer.timeout.connect(self._on_tick)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Startet den Tick-Timer + feuert sofort einen ersten Tick.

        Sofortiger Tick ist wichtig nach App-Restart: ueber Nacht ist
        garantiert ein Daily-Refresh faellig, ohne sofortigen Tick
        wuerde der User 5 min warten bis der Patch-Monitor frische
        Daten zeigt.
        """
        self._timer.start()
        # singleShot(0) gibt der Event-Loop einen Tick um den Slot zu
        # connecten bevor _on_tick laeuft.
        QTimer.singleShot(0, self._on_tick)
        log.info(
            "PatchScheduler gestartet (tick=%d ms, daily=%d h, monthly=%d d).",
            self._timer.interval(),
            self._daily_interval_hours,
            self._monthly_interval_days,
        )

    def stop(self) -> None:
        """Stoppt den Tick-Timer."""
        self._timer.stop()
        log.info("PatchScheduler gestoppt.")

    def is_running(self) -> bool:
        """``True`` wenn der Timer aktiv ist."""
        return self._timer.isActive()

    # ------------------------------------------------------------------
    # Tick-Logik
    # ------------------------------------------------------------------

    @Slot()
    def tick_now(self) -> None:
        """Manueller Tick-Aufruf — fuer Tests und Settings-Tab-Button.

        Identisches Verhalten wie ein Timer-Tick, aber explizit
        Caller-getriggert.
        """
        self._on_tick()

    @Slot()
    def _on_tick(self) -> None:
        """Entscheidet welches Signal emittiert wird.

        Reihenfolge:
            1. Inventory leer →:attr:`initial_scan_due`.
            2. Monthly-Full faellig →:attr:`monthly_full_due`.
            3. Daily-Refresh faellig →:attr:`daily_refresh_due`.

        Garantie: pro Tick wird **maximal ein** Signal emittiert
        (Monthly schliesst Daily aus, weil Monthly inhaltlich
        Daily-Refresh-Aufgaben mitmacht).
        """
        try:
            if self._service.is_inventory_empty():
                log.info("Scheduler-Tick: Inventar leer → initial_scan_due.")
                self.initial_scan_due.emit()
                return

            last_full = self._service.get_last_full_scan_at()
            if is_monthly_full_due(
                last_full, interval_days=self._monthly_interval_days
            ):
                log.info(
                    "Scheduler-Tick: Monthly-Full faellig (last=%s) → monthly_full_due.",
                    last_full,
                )
                self.monthly_full_due.emit()
                return

            last_daily = self._service.get_last_daily_refresh_at()
            if is_daily_refresh_due(
                last_daily, interval_hours=self._daily_interval_hours
            ):
                log.info(
                    "Scheduler-Tick: Daily-Refresh faellig (last=%s) → daily_refresh_due.",
                    last_daily,
                )
                self.daily_refresh_due.emit()
                return

            log.debug(
                "Scheduler-Tick: nichts zu tun (last_full=%s, last_daily=%s).",
                last_full,
                last_daily,
            )
        except Exception as exc:  # noqa: BLE001 — Tick darf nie crashen
            log.exception(
                "PatchScheduler._on_tick: unerwartete Exception (%s) — "
                "Tick uebersprungen, Timer laeuft weiter.",
                type(exc).__name__,
            )


__all__ = [
    "DEFAULT_DAILY_INTERVAL_HOURS",
    "DEFAULT_MONTHLY_INTERVAL_DAYS",
    "DEFAULT_TICK_INTERVAL_MS",
    "PatchScheduler",
    "is_daily_refresh_due",
    "is_monthly_full_due",
]
