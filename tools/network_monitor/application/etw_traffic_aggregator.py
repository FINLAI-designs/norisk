"""etw_traffic_aggregator — Kernel-Network-ETW-Events → Per-Flow-Bytes.

Reiner In-Memory-Aggregator (keine ETW-/psutil-/DB-Abhaengigkeit): der
Collector (Stop-Step B2) fuettert pro ETW-Event:meth:`add_event` und ruft pro
60s-Intervall:meth:`flush`, das die:class:`ProcessTrafficSample`-Liste fuers
Repository liefert.

Grain = ``(pid, remote_ip, remote_port, protocol)`` (Flow-artig). Damit tragen
die spaeteren Threshold-Alerts „High-Volume-Single-IP" und „Game-CDN" (D), waehrend
per-Prozess-Summen weiterhin via ``GROUP BY pid`` entstehen.

Event-ID-Mapping (per PoC 2026-05-25 gegen ``Microsoft-Windows-Kernel-Network``
verifiziert): nur die ``datasent``/``datarecv``-Events werden gezaehlt — die
TCP-„copied in protocol"-Events (18/34) werden ignoriert, sonst wuerden Bytes
doppelt gezaehlt. Bei Send liefert das Event ``daddr``/``dport``, bei Recv
``saddr``/``sport`` als Remote-Endpunkt.

Schichtzugehoerigkeit: ``application/`` — pure Logik, headless-testbar. Importiert
nur ``domain``; Prozessnamen-Aufloesung wird als Callable injiziert (kein psutil).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any, Final

from tools.network_monitor.domain.models import ProcessTrafficSample

#: ``datasent``-Events: TCPv4=10, TCPv6=26, UDPv4=42, UDPv6=58.
SEND_EVENT_IDS: Final[frozenset[int]] = frozenset({10, 26, 42, 58})
#: ``datarecv``-Events: TCPv4=11, TCPv6=27, UDPv4=43, UDPv6=59.
RECV_EVENT_IDS: Final[frozenset[int]] = frozenset({11, 27, 43, 59})
#: TCP-Event-IDs (v4+v6, send+recv) — fuer die Protokoll-Ableitung.
_TCP_EVENT_IDS: Final[frozenset[int]] = frozenset({10, 11, 26, 27})

#: Flow-Key: (pid, remote_ip, remote_port, protocol).
_Key = tuple[int, str, int, str]


def _coerce_int(value: Any) -> int | None:
    """ETW-Payload-Werte kommen als Strings — robust nach int wandeln."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


class EtwTrafficAggregator:
    """Aggregiert rohe Kernel-Network-ETW-Events zu Per-Flow-Byte-Samples."""

    def __init__(self) -> None:
        self._sent: dict[_Key, int] = defaultdict(int)
        self._recv: dict[_Key, int] = defaultdict(int)

    def add_event(self, event_id: int, payload: dict[str, Any]) -> None:
        """Verbucht ein einzelnes ETW-Event.

        Nicht-Traffic-Events (Event-ID nicht in Send/Recv) sowie Events ohne
        ``PID``/``size`` werden ignoriert. Idempotent gegen Fremdformate.

        Args:
            event_id: ETW-Event-ID (:data:`SEND_EVENT_IDS` /
:data:`RECV_EVENT_IDS`).
            payload: Event-Felder (``PID``, ``size``, ``daddr``, ``saddr``,
                ``dport``, ``sport`` …), bereits normalisiert (IP als String).
        """
        is_send = event_id in SEND_EVENT_IDS
        is_recv = event_id in RECV_EVENT_IDS
        if not (is_send or is_recv):
            return
        pid = _coerce_int(payload.get("PID") or payload.get("pid"))
        size = _coerce_int(payload.get("size") or payload.get("Size"))
        if pid is None or size is None:
            return
        if is_send:
            remote_ip = str(payload.get("daddr") or "")
            remote_port = _coerce_int(payload.get("dport")) or 0
        else:
            remote_ip = str(payload.get("saddr") or "")
            remote_port = _coerce_int(payload.get("sport")) or 0
        protocol = "TCP" if event_id in _TCP_EVENT_IDS else "UDP"
        key: _Key = (pid, remote_ip, remote_port, protocol)
        if is_send:
            self._sent[key] += size
        else:
            self._recv[key] += size

    def flush(
        self,
        name_resolver: Callable[[int], str],
        path_resolver: Callable[[int], str] | None = None,
    ) -> list[ProcessTrafficSample]:
        """Gibt die aggregierten Samples zurueck und setzt den Puffer zurueck.

        Args:
            name_resolver: ``pid -> process_name`` (Collector injiziert eine
                psutil-basierte Aufloesung; Tests ein Fake).
            path_resolver: Optional ``pid -> image_path`` (Collector injiziert
                den Kernel-Process-Pfad-Tracker; ``None`` → leerer Pfad).

        Returns:
            Ein:class:`ProcessTrafficSample` pro im Intervall aktivem Flow
            ``(pid, remote_ip, remote_port, protocol)``.
        """
        keys = set(self._sent) | set(self._recv)
        samples = [
            ProcessTrafficSample(
                pid=pid,
                process_name=name_resolver(pid),
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                bytes_sent=self._sent.get(key, 0),
                bytes_recv=self._recv.get(key, 0),
                image_path=path_resolver(pid) if path_resolver else "",
            )
            for key in keys
            for (pid, remote_ip, remote_port, protocol) in (key,)
        ]
        self._sent.clear()
        self._recv.clear()
        return samples
