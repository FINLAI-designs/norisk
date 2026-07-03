"""network_monitor.gui.threat_feed_worker — periodischer Threat-Feed-Refresh F-D).

LowPriority-``QThread``, der die abuse.ch-CC0-Feeds über
:meth:`ThreatFeedService.update` aktualisiert (Netzwerk → verschlüsselter Cache)
und danach die zusammengeführten Blocklist-/Feed-/Whitelist-Einträge als
``entries_refreshed(list, list)``-Signal an die GUI emittiert. Der
:class:`ThreatChecker` tauscht sie atomar ein (``replace_entries``).

Takt: alle:data:`_REFRESH_INTERVAL_MS` (6 h). Die Service-TTL (12 h) verhindert,
dass innerhalb ihres Fensters tatsächlich neu heruntergeladen wird — ``update``
ist dann ein No-op, der Cache (und damit der Checker) bleibt gültig. Die Loop-
Granularität bleibt fein (1 s), damit:meth:`stop` zügig greift.

Thread-Sicherheit: ``update``/``build_entries`` öffnen pro Aufruf frische
``EncryptedDatabase``-Verbindungen im Worker-Thread; ``replace_entries`` ist
GIL-atomar. Der Netzwerk-Download ist der einzige lang blockierende Schritt
(Client-Timeout 20 s) — bei einem Shutdown mitten im Download kann der join
kurz über das 2-s-Fenster laufen (vom Aufrufer geloggt).

Schicht: GUI-Worker (Qt). Importiert nur den Application-``ThreatFeedService``
(gui→application), nie ``data/`` direkt.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger

if TYPE_CHECKING:
    from tools.network_monitor.application.threat_feed_service import ThreatFeedService

#: Loop-Granularität in ms — klein, damit ``stop`` nach spätestens einem Tick greift.
_TICK_MS = 1000
#: Refresh-Intervall in ms (6 h; die Service-TTL drosselt echte Downloads zusätzlich).
_REFRESH_INTERVAL_MS = 6 * 3600 * 1000
#: Anzahl Ticks zwischen zwei Refreshes (Tick 0 = sofort beim Start).
_CYCLES_PER_REFRESH = _REFRESH_INTERVAL_MS // _TICK_MS


class ThreatFeedRefreshWorker(QThread):
    """Aktualisiert periodisch die Threat-Feeds und emittiert die Merge-Einträge.

    Signals:
        entries_refreshed(list, list): (entries, whitelist) — die zusammengeführten
            (Netzwerk, Grund)-Tupel und die Whitelist-Netze für ``replace_entries``.
        error_occurred(str): Generische Fehlermeldung (geloggt, kein Roh-Exception-
            Text — R-Log).

    Args:
        service: Der:class:`ThreatFeedService` (Quellen/Cache injiziert).
    """

    entries_refreshed = Signal(list, list)
    error_occurred = Signal(str)

    def __init__(self, service: ThreatFeedService) -> None:
        super().__init__()
        self.setObjectName("ThreatFeedRefreshWorker")
        self._log = get_logger(__name__)
        self._service = service
        self._stop_flag = False

    def stop(self) -> None:
        """Setzt das Stop-Flag; nach dem nächsten ``msleep``-Tick endet ``run``."""
        self._stop_flag = True

    def run(self) -> None:  # noqa: D401 — Qt-Override
        """Refresht sofort und danach alle:data:`_REFRESH_INTERVAL_MS` neu."""
        self._stop_flag = False
        cycle = 0
        while not self._stop_flag:
            if cycle % _CYCLES_PER_REFRESH == 0:
                self._refresh_once()
            self.msleep(_TICK_MS)
            cycle += 1

    def _refresh_once(self) -> None:
        """Ein Refresh-Durchlauf: update → build_entries → emit (fail-soft).

        Aus:meth:`run` extrahiert, damit der Schritt ohne Schleife/``msleep``
        unit-testbar bleibt. Ein Fehler killt den Worker nicht — er wird geloggt
        und als ``error_occurred`` gemeldet, der Loop läuft weiter.
        """
        if self._stop_flag:
            return
        try:
            snapshot = self._service.refresh_snapshot()
            self._log.info(
                "Threat-Feeds: %d Einträge aktiv (%d Quellen aktualisiert, %d Fehler).",
                len(snapshot.entries),
                snapshot.updated_count,
                snapshot.error_count,
            )
            self.entries_refreshed.emit(snapshot.entries, snapshot.whitelist)
        except Exception as exc:  # noqa: BLE001 — Worker-Loop darf nie sterben
            self._log.warning("Threat-Feed-Refresh fehlgeschlagen: %s", exc)
            self.error_occurred.emit("Bedrohungslisten konnten nicht aktualisiert werden")


def _default_service_factory() -> ThreatFeedService:
    """Default-Factory für den One-Shot-Worker (öffnet die Feed-Cache-DB).

    Lazy import (gui→application), damit das GUI-Modul ohne aktiven ``KeyManager``
    importierbar bleibt; die DB wird erst im Worker-Thread (run) konstruiert.
    """
    from tools.network_monitor.application.monitor_service import (  # noqa: PLC0415
        MonitorService,
    )

    return MonitorService.create_threat_feed_service()


class ThreatFeedRefreshOnceWorker(QThread):
    """Einmaliger, **erzwungener** Threat-Feed-Refresh F-D-GUI).

    Hängt am „Jetzt aktualisieren"-Button des Bedrohungslisten-Tabs und führt
    genau einen ``update(force=True)`` → ``build_entries`` → ``load_whitelist``
    aus, damit der Netzwerk-Download nie den UI-Thread blockiert (frontend-design
    F3: Operationen > 1 s über QThread). Anders als der periodische
:class:`ThreatFeedRefreshWorker` ignoriert er die TTL (der Nutzer will
    bewusst frische Daten) und läuft genau einmal.

    Signals:
        refreshed(list, list, int, int): (entries, whitelist, aktualisierte
            Quellen, Quellen-Fehler) nach erfolgreichem Refresh — für den
            atomaren ``replace_entries``-Swap und die Status-Anzeige.
        failed(str): Generische, nutzerlesbare Fehlermeldung (kein Roh-Exception-
            Text — R-Log).

    Args:
        service_factory: Liefert den:class:`ThreatFeedService`. Default öffnet die
            echte Feed-Cache-DB; Tests injizieren eine Fake-Factory (keine DB/Netz).
    """

    refreshed = Signal(list, list, int, int)
    failed = Signal(str)

    def __init__(
        self, service_factory: Callable[[], ThreatFeedService] | None = None
    ) -> None:
        super().__init__()
        self.setObjectName("ThreatFeedRefreshOnceWorker")
        self._log = get_logger(__name__)
        self._service_factory = service_factory or _default_service_factory

    def run(self) -> None:  # noqa: D401 — Qt-Override
        """Baut den Service, erzwingt einen Refresh und emittiert das Ergebnis.

        Der eigentliche Download (``update``) ist nicht hart unterbrechbar (kein
        Cancel-Token im HTTP-Client). Daher wird an den natürlichen Grenzen
        (vor/nach ``update``, vor dem Emit) ``isInterruptionRequested`` geprüft —
        wurde der Tab beim Teardown weggeschaltet, bricht der Worker still ab und
        emittiert nichts mehr (kein Zugriff auf ein evtl. zerstörtes Tab-Widget).
        """
        try:
            service = self._service_factory()
        except Exception as exc:  # noqa: BLE001 — kein KeyManager/keine DB → fail-soft
            self._log.info(
                "Manueller Threat-Refresh: Dienst nicht verfügbar (%s).",
                type(exc).__name__,
            )
            self.failed.emit(
                "Bedrohungslisten konnten nicht aktualisiert werden — der "
                "Netzwerk-Collector ist nicht aktiv. Starte den Collector "
                "und versuche es erneut."
            )
            return
        if self.isInterruptionRequested():
            return
        try:
            snapshot = service.refresh_snapshot(force=True)
        except Exception as exc:  # noqa: BLE001 — Netz-/DB-Fehler abfangen
            self._log.warning("Manueller Threat-Refresh fehlgeschlagen: %s", exc)
            self.failed.emit(
                "Bedrohungslisten konnten nicht aktualisiert werden — die Quelle "
                "ist nicht erreichbar. Prüfe deine Internetverbindung."
            )
            return
        if self.isInterruptionRequested():
            return
        self.refreshed.emit(
            snapshot.entries,
            snapshot.whitelist,
            snapshot.updated_count,
            snapshot.error_count,
        )
