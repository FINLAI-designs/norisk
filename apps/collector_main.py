"""apps.collector_main — headless ETW-Network-Collector B2 + Regel 5).

Eigenstaendiger, GUI-loser Einstiegspunkt fuer den Per-Prozess-Collector. Laeuft
als **geplante Aufgabe** (elevated, im User-Kontext) und schreibt alle 60s:
- Per-(Prozess, Remote-IP)-Bytes (Kernel-Network) → ``process_traffic``,
- Per-Prozess-DNS-Query-Statistik (DNS-Client, Regel 5) → ``dns_queries``.

Aufruf (Dev): ``.\\.venv\\Scripts\\python apps\\collector_main.py [--duration N]``

Architektur (Composition Root): der ETW-Subscriber (``data/``) forwardet **rohe**
Events thread-sicher in eine ``queue``; nur der Hauptthread beruehrt die (nicht
thread-safen) Aggregatoren (``application/``) und routet jedes Roh-Event ueber
die passenden Normalizer in beide Aggregatoren. So bleibt der Layer-Contract
gewahrt und die Capture race-frei — beide Provider teilen eine ETW-Session.

Bootstrap: nur ``KeyManager`` + ``set_db_app_id("norisk")`` — bewusst **ohne**
``run_bootstrap_migration`` (App-Install-Sache; die Tabellen werden frisch angelegt).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Repo-Root in sys.path injizieren (analog norisk_app.py) — die geplante Aufgabe
# ruft die Datei direkt auf, cwd ist nicht zwingend der Repo-Root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import argparse  # noqa: E402
import logging  # noqa: E402
import queue  # noqa: E402
import signal  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any  # noqa: E402

from core.logger import get_logger  # noqa: E402
from tools.network_monitor.data.dns_event_normalizer import (  # noqa: E402
    normalize_dns_event,
)
from tools.network_monitor.data.etw_event_normalizer import (  # noqa: E402
    normalize_kernel_network_event,
)
from tools.network_monitor.data.process_path_tracker import (  # noqa: E402
    ProcessPathTracker,
)

_APP_ID = "norisk"
_FLUSH_INTERVAL_S = 60.0
#: Intervall fuer Anomalie-Erkennung + KiTodo-Emit (seltener als der Flush —
#: Anomalien aendern sich nicht im Sekundentakt).
_ALERT_INTERVAL_S = 300.0
#: Sicherheitspuffer ETW-Thread → Hauptthread; bei Overflow Drop + Zaehler.
_QUEUE_MAXSIZE = 200_000
#: Max. Events pro Drain-Durchlauf (begrenzt eine einzelne Schleifeniteration).
_DRAIN_BATCH = 20_000
#: Obergrenze fuer den PID→Name-Cache (Schutz gegen unbegrenztes Wachstum).
_NAME_CACHE_MAX = 50_000

log = get_logger(__name__)


def make_name_resolver() -> Callable[[int], str]:
    """Liefert einen gecachten ``pid -> process_name``-Resolver (psutil).

    Nicht (mehr) existente PIDs → ``"–"``. Der Cache wird bei Ueberschreiten
    von:data:`_NAME_CACHE_MAX` geleert (PIDs werden wiederverwendet — ein
    gelegentlich veralteter Name ist akzeptabel, ein Leak nicht).
    """
    import psutil

    cache: dict[int, str] = {}

    def resolve(pid: int) -> str:
        cached = cache.get(pid)
        if cached is not None:
            return cached
        try:
            name = psutil.Process(pid).name()
        except (psutil.Error, OSError):
            name = "–"
        if len(cache) >= _NAME_CACHE_MAX:
            cache.clear()
        cache[pid] = name
        return name

    return resolve


def make_path_resolver(tracker: ProcessPathTracker) -> Callable[[int], str]:
    """Liefert ``pid -> image_path``: erst Kernel-Process-Map, dann psutil-Fallback.

    Der Tracker (ProcessStart-Events) deckt ab Collector-Start gestartete
    Prozesse ab; fuer bereits laufende ist ``psutil.Process(pid).exe`` der
    Fallback (gecacht). Leerer Pfad, wenn beides scheitert.
    """
    import psutil

    cache: dict[int, str] = {}

    def resolve(pid: int) -> str:
        path = tracker.resolve(pid)
        if path:
            return path
        cached = cache.get(pid)
        if cached is not None:
            return cached
        try:
            path = psutil.Process(pid).exe()
        except (psutil.Error, OSError):
            path = ""
        if len(cache) >= _NAME_CACHE_MAX:
            cache.clear()
        cache[pid] = path
        return path

    return resolve


def _bootstrap_key_manager() -> Any:
    """Initialisiert den KeyManager und setzt den DB-App-Kontext ("norisk")."""
    from core.database.db_context import set_db_app_id
    from core.database.key_manager import KeyManager
    from core.database.key_manager_context import set_active_key_manager

    km = KeyManager()
    km.initialize()
    set_active_key_manager(km)
    set_db_app_id(_APP_ID)
    return km


def _drain_queue(
    q: queue.Queue[tuple[int, dict[str, Any]]],
    traffic_aggregator: Any,
    dns_aggregator: Any,
    path_tracker: Any,
    *,
    max_items: int = _DRAIN_BATCH,
) -> int:
    """Routet bis zu ``max_items`` Roh-Events in die Aggregatoren + Pfad-Tracker.

    Jedes Roh-Event geht an beide Normalizer/Aggregatoren UND den Pfad-Tracker;
    jeder filtert selbst nach seinen Event-IDs (Kernel-Network / DNS 3006 /
    ProcessStart 1), daher ist die Mehrfach-Einspeisung unschaedlich.

    Returns:
        Anzahl verarbeiteter Events.
    """
    drained = 0
    while drained < max_items:
        try:
            event_id, raw = q.get_nowait()
        except queue.Empty:
            break
        traffic_aggregator.add_event(event_id, normalize_kernel_network_event(raw))
        dns_aggregator.add_event(event_id, normalize_dns_event(raw))
        path_tracker.add_event(event_id, raw)
        drained += 1
    return drained


def _flush(
    traffic_aggregator: Any,
    dns_aggregator: Any,
    traffic_repo: Any,
    dns_repo: Any,
    name_resolver: Callable[[int], str],
    path_resolver: Callable[[int], str],
) -> tuple[int, int]:
    """Flusht beide Aggregatoren und persistiert die Samples.

    Returns:
        ``(traffic_zeilen, dns_zeilen)``.
    """
    traffic_n = traffic_repo.save_samples(
        traffic_aggregator.flush(name_resolver, path_resolver)
    )
    dns_n = dns_repo.save_samples(dns_aggregator.flush(name_resolver))
    return traffic_n, dns_n


def run_collector(
    *, duration_s: float | None = None, flush_interval_s: float = _FLUSH_INTERVAL_S
) -> int:
    """Startet die ETW-Capture (Kernel-Network + DNS-Client) und den Persist-Loop.

    Args:
        duration_s: Laufzeit in Sekunden; ``None`` = unbegrenzt (bis Signal).
        flush_interval_s: Sekunden zwischen zwei Flush/Save-Zyklen.

    Returns:
        Exit-Code: 0 = sauber beendet, 1 = Fehler im Loop, 2 = keine Admin-Rechte.
    """
    from tools.network_monitor.application.anomaly_detector import (
        AnomalyDetector,
        AnomalyService,
    )
    from tools.network_monitor.application.dns_query_aggregator import (
        DnsQueryAggregator,
    )
    from tools.network_monitor.application.etw_traffic_aggregator import (
        EtwTrafficAggregator,
    )
    from tools.network_monitor.data.dns_query_repository import DnsQueryRepository
    from tools.network_monitor.data.etw_network_subscriber import (
        EtwNetworkSubscriber,
        is_admin,
    )
    from tools.network_monitor.data.process_traffic_repository import (
        ProcessTrafficRepository,
    )

    if not is_admin():
        log.error("Collector benoetigt Administrator-Rechte (ETW). Abbruch.")
        return 2

    km = _bootstrap_key_manager()
    traffic_aggregator = EtwTrafficAggregator()
    dns_aggregator = DnsQueryAggregator()
    traffic_repo = ProcessTrafficRepository()
    dns_repo = DnsQueryRepository()
    anomaly_service = AnomalyService(
        traffic_repo, detector=AnomalyDetector(), dns_repository=dns_repo
    )
    path_tracker = ProcessPathTracker()
    name_resolver = make_name_resolver()
    path_resolver = make_path_resolver(path_tracker)
    q: queue.Queue[tuple[int, dict[str, Any]]] = queue.Queue(maxsize=_QUEUE_MAXSIZE)
    dropped = 0

    def on_event(event_id: int, raw: dict[str, Any]) -> None:
        nonlocal dropped
        try:
            q.put_nowait((event_id, raw))
        except queue.Full:
            dropped += 1

    stop_event = threading.Event()

    def _handle_signal(signum: int, _frame: Any) -> None:
        log.info("Signal %s empfangen — Collector faehrt herunter.", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):  # nicht Hauptthread / Plattform
            pass

    # Default-Provider: Kernel-Network + DNS-Client (eine Session). KEIN
    # provider-seitiger event_id_filter (wuergt die Capture ab — Smoke 2026-05-25);
    # die Aggregatoren filtern selbst.
    subscriber = EtwNetworkSubscriber(on_event)

    deadline = None if duration_s is None else time.monotonic() + duration_s
    next_flush = time.monotonic() + flush_interval_s
    next_alert = time.monotonic() + _ALERT_INTERVAL_S
    total_events = 0
    exit_code = 0
    try:
        subscriber.start()
        log.info("Collector laeuft (Flush alle %ss).", int(flush_interval_s))
        while not stop_event.is_set():
            total_events += _drain_queue(
                q, traffic_aggregator, dns_aggregator, path_tracker
            )
            now = time.monotonic()
            if now >= next_flush:
                traffic_n, dns_n = _flush(
                    traffic_aggregator,
                    dns_aggregator,
                    traffic_repo,
                    dns_repo,
                    name_resolver,
                    path_resolver,
                )
                if dropped:
                    log.warning("ETW-Queue-Overflow: %d Events verworfen.", dropped)
                    dropped = 0
                log.info(
                    "Flush: %d Traffic + %d DNS Samples (%d Events seit Start).",
                    traffic_n,
                    dns_n,
                    total_events,
                )
                next_flush = now + flush_interval_s
            if now >= next_alert:
                try:
                    anomalies, emitted = anomaly_service.detect_and_emit()
                    if anomalies:
                        log.info(
                            "Anomalie-Check: %d erkannt, %d KiTodos emittiert.",
                            len(anomalies),
                            emitted,
                        )
                except Exception:  # noqa: BLE001 — Alert-Hook darf den Loop nicht brechen
                    log.exception("Anomalie-Check fehlgeschlagen.")
                next_alert = now + _ALERT_INTERVAL_S
            if deadline is not None and now >= deadline:
                break
            stop_event.wait(0.5)
    except Exception:  # noqa: BLE001 — Hintergrund-Dienst: Crash MUSS ins Log
        log.exception("Collector mit Fehler abgebrochen.")
        exit_code = 1
    finally:
        subscriber.stop()
        try:
            total_events += _drain_queue(
                q, traffic_aggregator, dns_aggregator, path_tracker
            )
            traffic_n, dns_n = _flush(
                traffic_aggregator,
                dns_aggregator,
                traffic_repo,
                dns_repo,
                name_resolver,
                path_resolver,
            )
            log.info(
                "Final-Flush: %d Traffic + %d DNS Samples (%d Events gesamt).",
                traffic_n,
                dns_n,
                total_events,
            )
        except Exception:  # noqa: BLE001 — Cleanup-Flush darf den Exit nicht stoppen
            log.exception("Final-Flush fehlgeschlagen.")
        try:
            km.wipe()
        except Exception:  # noqa: BLE001 — Cleanup darf nie crashen
            pass
    return exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI-Einstieg: parst Argumente und startet den Collector."""
    # Security-Gate E1 F-C-3): DLL-Suchpfad härten, BEVOR run_collector die
    # DLL-ladenden Lazy-Imports (psutil/pywintrace/win32com) anstößt — sonst könnte
    # eine in CWD/PATH platzierte Schad-DLL in den elevated Prozess geladen werden.
    from core.win_security import harden_dll_search_path  # noqa: PLC0415

    harden_dll_search_path()

    parser = argparse.ArgumentParser(
        description="NoRisk ETW-Network-Collector (T-075)."
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Laufzeit in Sekunden (Default: unbegrenzt).",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=_FLUSH_INTERVAL_S,
        help="Sekunden zwischen Flush/Save-Zyklen (Default: 60; klein fuer Smoke).",
    )
    parser.add_argument("--log-file", type=str, default=None, help="Log-Datei-Pfad.")
    parser.add_argument("--debug", action="store_true", help="Debug-Logging.")
    parser.add_argument(
        "--finlai-home",
        type=str,
        default=None,
        help=(
            "Daten-Wurzel-Override (FINLAI_HOME). Von der geplanten Aufgabe "
            "durchgereicht, damit der Collector im installierten Profil schreibt."
        ),
    )
    args = parser.parse_args(argv)

    if args.log_file:
        logging.basicConfig(
            filename=args.log_file,
            level=logging.DEBUG if args.debug else logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    if args.finlai_home:
        # MUSS vor run_collector greifen: run_collector importiert encrypted_db/
        # key_manager lazy; deren Modul-Konstanten binden finlai_dir erst dann
        # und uebernehmen damit den Override (set_finlai_home prueft _override zuerst).
        from core.finlai_paths import set_finlai_home  # noqa: PLC0415

        set_finlai_home(args.finlai_home)
        log.info("FINLAI_HOME-Override aktiv: %s", args.finlai_home)
    return run_collector(duration_s=args.duration, flush_interval_s=args.flush_interval)


if __name__ == "__main__":
    sys.exit(main())
