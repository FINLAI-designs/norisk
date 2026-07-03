"""network_monitor.data.monitor_worker — psutil-basierter QThread.

Poll-Takt getrennt nach Signal-Kosten (ab 2026-04-24):

* Bandbreiten-Stats alle 1s (billig, ``psutil.net_io_counters``)
* Verbindungsliste alle 3s (teurer, ``psutil.net_connections``)
* Prozess-Name-Cache alle 5s (``psutil.process_iter`` statt N×``psutil.Process``)

Emittiert pro Zyklus:

* ``stats_updated(dict)`` — ``{interface_name: InterfaceStats}``
* ``connections_updated(list[ConnectionInfo])``

Bei Fehlern (``psutil.AccessDenied``, ``psutil.NoSuchProcess``, generische
``OSError``) wird ``error_occurred(str)`` emittiert statt den Thread zu
beenden. Der Thread stoppt nur über ``stop`` (Flag) — niemals via
``terminate``.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import socket
import time

import psutil
from PySide6.QtCore import QThread, Signal

from core.logger import get_logger
from tools.network_monitor.application.threat_checker import ThreatChecker
from tools.network_monitor.domain.interfaces import IConnectionRepository
from tools.network_monitor.domain.models import ConnectionInfo, InterfaceStats

_STATS_INTERVAL_MS = 1000        # Bandbreite: jede Sekunde
_CONNECTIONS_INTERVAL_MS = 3000  # Verbindungstabelle: alle 3s
_PROCESS_MAP_TTL_MS = 5000       # Prozess-Map: 5s Cache
_BYTES_PER_KB = 1024.0

# Abgeleitete Zyklusraten — Loop-Takt bleibt bei _STATS_INTERVAL_MS,
# teurere Operationen laufen nur jeden N-ten Zyklus.
_CYCLES_PER_CONNECTIONS = _CONNECTIONS_INTERVAL_MS // _STATS_INTERVAL_MS


def _status_name(raw: str) -> str:
    """Normalisiert psutil-Status-Strings (z.B. ``'ESTABLISHED'``)."""
    return raw or "UNKNOWN"


def _family_is_inet(family: int) -> bool:
    """True für IPv4/IPv6-Sockets (LISTEN- und Verbindungs-Sockets)."""
    return family in (socket.AF_INET, socket.AF_INET6)


class NetworkMonitorWorker(QThread):
    """Pollt psutil und emittiert Stats + Connections auf gestaffelten Intervallen.

    Signals:
        stats_updated(dict): ``{iface_name: InterfaceStats}``.
        connections_updated(list): Liste ``ConnectionInfo``.
        error_occurred(str): Beschreibung eines psutil-/Systemfehlers.

    Args:
        threat_checker: Optionaler Checker für Suspicious-Markierung
            (Pro-Feature). Wenn ``None``, werden alle Verbindungen
            als nicht verdächtig markiert.
        include_per_process: Wenn True (Pro), wird der Prozessname je
            Verbindung über einen 5s-Cache aus ``psutil.process_iter``
            aufgelöst (kein N+1-Pattern mehr). Im Free-Modus bleibt
            ``process_name="–"`` um Overhead zu sparen.
        connection_repo: Optionales History-Repository. Ist es gesetzt,
            persistiert der Worker den Verbindungs-Snapshot SELBST im
            Worker-Thread — vorher tat das der UI-Thread-Slot und
            fror die GUI bei jedem 3s-Zyklus ein (verschlüsselte DB-Öffnung
            + INSERT). ``None`` = keine Persistenz (fail-open).
    """

    stats_updated = Signal(dict)
    connections_updated = Signal(list)
    error_occurred = Signal(str)

    def __init__(
        self,
        threat_checker: ThreatChecker | None = None,
        include_per_process: bool = False,
        connection_repo: IConnectionRepository | None = None,
    ) -> None:
        super().__init__()
        self.setObjectName("NetworkMonitorWorker")
        self._log = get_logger(__name__)
        self._checker = threat_checker
        self._include_per_process = include_per_process
        self._connection_repo = connection_repo
        self._stop_flag = False
        self._prev_counters: dict[str, psutil._common.snetio] | None = None
        self._proc_map: dict[int, str] = {}
        self._proc_map_expires_at: float = 0.0

    def stop(self) -> None:
        """Setzt das Stop-Flag. Nach dem nächsten ``msleep`` beendet sich ``run``."""
        self._stop_flag = True

    def run(self) -> None:  # noqa: D401 — Qt-Override
        """Haupt-Loop. Stats jede Sekunde, Connections alle 3 Zyklen."""
        self._stop_flag = False
        try:
            self._prev_counters = psutil.net_io_counters(pernic=True)
        except OSError as exc:
            self.error_occurred.emit(f"net_io_counters init: {exc}")
            self._prev_counters = {}

        interval_s = _STATS_INTERVAL_MS / 1000.0
        cycle = 0
        while not self._stop_flag:
            try:
                stats = self._collect_stats(interval_s)
                self.stats_updated.emit(stats)

                if cycle % _CYCLES_PER_CONNECTIONS == 0:
                    _tc0 = time.perf_counter()
                    conns = self._collect_connections()
                    # UI-Render zuerst anstossen (queued, non-blocking)…
                    self.connections_updated.emit(conns)
                    # …dann IM WORKER-THREAD persistieren: save_snapshot
                    # oeffnet die verschluesselte network_monitor-DB + INSERT.
                    # Frueher lief das im UI-Thread-Slot und fror die GUI ein
                    # (DB-Open/Lock gegen den Collector-Daemon). Hier blockiert
                    # es hoechstens den naechsten Worker-Zyklus (LowPriority).
                    self._persist_connections(conns)
                    self._log.debug(
                        "Monitor-Zyklus: %d Verbindungen erfasst + persistiert "
                        "(%.0f ms, Worker-Thread)",
                        len(conns),
                        (time.perf_counter() - _tc0) * 1000.0,
                    )
            except Exception as exc:  # noqa: BLE001 -- Worker-Loop muss bei jedem psutil/Sub-Routine-Fehler weiterlaufen
                # Einzelner Fehlzyklus darf den Worker nicht killen
                self._log.warning("NetworkMonitor-Zyklus fehlgeschlagen: %s", exc)
                self.error_occurred.emit(str(exc))
            self.msleep(_STATS_INTERVAL_MS)
            cycle += 1

    def _persist_connections(self, conns: list[ConnectionInfo]) -> None:
        """Speichert den Verbindungs-Snapshot im Worker-Thread.

        Fail-soft: ``save_snapshot`` öffnet pro Aufruf eine frische,
        thread-lokale verschlüsselte Verbindung (kein geteilter Handle), daher
        ist der Aufruf aus dem Worker-Thread sicher. Ein DB-Fehler darf den
        Worker NICHT beenden — er wird geloggt und der Loop läuft weiter.
        """
        if self._connection_repo is None:
            return
        try:
            self._connection_repo.save_snapshot(conns)
        except (OSError, RuntimeError) as exc:
            self._log.warning("Persist (Worker-Thread) fehlgeschlagen: %s", exc)

    def _collect_stats(self, interval_s: float) -> dict[str, InterfaceStats]:
        """Berechnet KB/s aus dem Delta der letzten beiden Samples."""
        now_counters = psutil.net_io_counters(pernic=True)
        prev = self._prev_counters or {}

        if_addrs = _safe_if_addrs()
        if_stats = _safe_if_stats()

        result: dict[str, InterfaceStats] = {}
        for name, curr in now_counters.items():
            old = prev.get(name)
            if old is None:
                upload_kbps = 0.0
                download_kbps = 0.0
            else:
                delta_sent = max(0, curr.bytes_sent - old.bytes_sent)
                delta_recv = max(0, curr.bytes_recv - old.bytes_recv)
                upload_kbps = (delta_sent / _BYTES_PER_KB) / max(interval_s, 0.001)
                download_kbps = (delta_recv / _BYTES_PER_KB) / max(interval_s, 0.001)

            ip, mac = _extract_addresses(if_addrs.get(name, []))
            is_up = bool(getattr(if_stats.get(name), "isup", True))

            result[name] = InterfaceStats(
                name=name,
                upload_kbps=round(upload_kbps, 2),
                download_kbps=round(download_kbps, 2),
                bytes_sent_total=curr.bytes_sent,
                bytes_recv_total=curr.bytes_recv,
                is_up=is_up,
                mac_address=mac,
                ip_address=ip,
            )
        self._prev_counters = now_counters
        return result

    def _get_process_map(self) -> dict[int, str]:
        """Liefert ``{pid: process_name}`` mit 5s-TTL-Cache.

        Ersetzt das N+1-Muster (``psutil.Process(pid).name`` pro Verbindung)
        durch einen einmaligen ``psutil.process_iter``-Scan pro TTL-Fenster.
        """
        now = time.monotonic()
        if now < self._proc_map_expires_at and self._proc_map:
            return self._proc_map

        new_map: dict[int, str] = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    pid = p.info.get("pid")
                    name = p.info.get("name") or "–"
                    if pid is not None:
                        new_map[pid] = name
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except (OSError, RuntimeError) as exc:
            self._log.warning("process_iter fehlgeschlagen: %s", exc)
            return self._proc_map

        self._proc_map = new_map
        self._proc_map_expires_at = now + _PROCESS_MAP_TTL_MS / 1000.0
        return self._proc_map

    def _collect_connections(self) -> list[ConnectionInfo]:
        """Iteriert psutil-Sockets, resolved Prozess-Namen aus Cache (Pro)."""
        conns: list[ConnectionInfo] = []
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            self.error_occurred.emit(f"net_connections: {exc}")
            return []

        proc_map = self._get_process_map() if self._include_per_process else {}

        for c in raw_conns:
            if not _family_is_inet(c.family):
                continue

            remote_ip = c.raddr.ip if c.raddr else ""
            remote_port = c.raddr.port if c.raddr else 0
            local_port = c.laddr.port if c.laddr else 0
            pid = c.pid or 0

            process_name = "–"
            if self._include_per_process and pid:
                process_name = proc_map.get(pid, "–")

            suspicious = False
            reason = ""
            if self._checker is not None and remote_ip:
                suspicious, reason = self._checker.is_suspicious(remote_ip)

            conns.append(
                ConnectionInfo(
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    local_port=local_port,
                    pid=pid,
                    process_name=process_name,
                    status=_status_name(c.status),
                    suspicious=suspicious,
                    suspicious_reason=reason,
                )
            )
        return conns


def _safe_if_addrs() -> dict:
    """psutil.net_if_addrs mit Absicherung gegen seltene OS-Fehler."""
    try:
        return psutil.net_if_addrs()
    except OSError:
        return {}


def _safe_if_stats() -> dict:
    """psutil.net_if_stats mit Absicherung."""
    try:
        return psutil.net_if_stats()
    except OSError:
        return {}


def _extract_addresses(addrs: list) -> tuple[str, str]:
    """Extrahiert (IPv4-Adresse, MAC) aus einer psutil-Adressliste."""
    ip = ""
    mac = ""
    for a in addrs:
        fam = getattr(a, "family", None)
        if fam == socket.AF_INET and not ip:
            ip = a.address or ""
        elif fam == psutil.AF_LINK and not mac:
            mac = a.address or ""
    return ip, mac
