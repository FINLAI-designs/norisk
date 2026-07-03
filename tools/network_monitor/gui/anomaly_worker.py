"""network_monitor.gui.anomaly_worker — periodischer Anomalie-Detektions-Worker F-E).

LowPriority-``QThread``, der:meth:`AnomalyService.detect` im ~45-Sekunden-Takt
aufruft und das Ergebnis als ``anomalies_detected(list)``-Signal an die GUI
emittiert (Live-Anomalie-Alerts).

Takt 30–60 s laut SoT (Phase 3), **nicht** 5–10 s: ein ``detect``-Aufruf
feuert fuenf DB-Aggregate. Die Loop-Granularitaet bleibt fein (1 s), damit
:meth:`stop` zuegig greift; detektiert wird nur jeden N-ten Tick.

Thread-Sicherheit: ``detect`` liest die vom Collector geschriebene
``network_monitor``-DB. ``EncryptedDatabase.connection`` oeffnet pro Aufruf eine
**frische** ``sqlcipher3``-Verbindung im aufrufenden Thread — daher ist der Lese-
Zugriff aus diesem Worker-Thread unbedenklich; gleichzeitiges Schreiben des
Collectors deckt die DB-Lock-Retry-Logik ab.

Schicht: GUI-Worker (Qt). Importiert nur den Application-``AnomalyService``
(gui→application), damit — anders als beim aelteren ``data/monitor_worker`` —
keine data→application-Schichtverletzung entsteht.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger

if TYPE_CHECKING:
    from tools.network_monitor.application.anomaly_detector import AnomalyService

#: Loop-Granularitaet in ms — klein, damit ``stop`` nach spaetestens einem Tick greift.
_TICK_MS = 1000
#: Detektions-Intervall in ms (SoT Phase 3: 30–60 s LowPriority, nicht 5–10 s).
_DETECT_INTERVAL_MS = 45_000
#: Anzahl Ticks zwischen zwei Detektionen (Tick 0 = sofort beim Start).
_CYCLES_PER_DETECT = _DETECT_INTERVAL_MS // _TICK_MS


class AnomalyDetectionWorker(QThread):
    """Ruft periodisch:meth:`AnomalyService.detect` und emittiert die Anomalien.

    Signals:
        anomalies_detected(list): Liste der aktuell erkannten:class:`Anomaly`
            (auch leer — die GUI muss „0 Auffaelligkeiten" abbilden koennen).
        error_occurred(str): Beschreibung eines Detektions-/DB-Fehlers (wird
            geloggt, nicht als Dialog gespammt).

    Args:
        service: Der:class:`AnomalyService` (Repos injiziert). detect laeuft
            im Worker-Thread — die DB-Verbindungen entstehen dort.
    """

    anomalies_detected = Signal(list)
    error_occurred = Signal(str)

    def __init__(self, service: AnomalyService) -> None:
        super().__init__()
        self.setObjectName("AnomalyDetectionWorker")
        self._log = get_logger(__name__)
        self._service = service
        self._stop_flag = False

    def stop(self) -> None:
        """Setzt das Stop-Flag; nach dem naechsten ``msleep``-Tick endet ``run``."""
        self._stop_flag = True

    def run(self) -> None:  # noqa: D401 — Qt-Override
        """Detektiert sofort und danach alle:data:`_DETECT_INTERVAL_MS` neu."""
        self._stop_flag = False
        cycle = 0
        while not self._stop_flag:
            if cycle % _CYCLES_PER_DETECT == 0:
                self._detect_once()
            self.msleep(_TICK_MS)
            cycle += 1

    def _detect_once(self) -> None:
        """Ein Detektions-Durchlauf: detect → emit (fail-soft).

        Aus:meth:`run` extrahiert, damit der Schritt ohne Schleife/``msleep``
        unit-testbar bleibt. Ein Fehler killt den Worker nicht — er wird geloggt
        und als ``error_occurred`` gemeldet, der Loop laeuft weiter.
        """
        try:
            anomalies = self._service.detect()
            self.anomalies_detected.emit(anomalies)
        except Exception as exc:  # noqa: BLE001 — Worker-Loop darf nie sterben
            # Detail bleibt im lokalen Log; das Signal traegt nur eine generische
            # Meldung, damit kein evtl. datenhaltiger Roh-Exception-Text ueber die
            # Konsumenten-Senke weiterwandert (Review, Log-Sanitize-Pflicht).
            self._log.warning("Anomalie-Detektion fehlgeschlagen: %s", exc)
            self.error_occurred.emit("Anomalie-Detektion vorübergehend nicht verfügbar")
