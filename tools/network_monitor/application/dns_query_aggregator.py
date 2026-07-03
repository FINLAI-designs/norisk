"""dns_query_aggregator — DNS-Client-ETW-Events → Per-PID-Query-Stats Regel 5).

Reiner In-Memory-Aggregator (kein ETW/DB): der Collector fuettert pro
DNS-Event:meth:`add_event` (nur Event 3006 „DNS query is called") und ruft pro
60s-Intervall:meth:`flush`, das die:class:`~tools.network_monitor.domain.models.DnsQuerySample`-Liste
liefert.

Erfasst neben der reinen Query-Anzahl die DGA-/Tunneling-Signale (distinct
Namen, laengstes Label, hoechste Label-Entropie) — die spaetere Heuristik kann
darauf aufbauen, die Kern-Regel ist die Query-Rate (>1000/Min).

Schichtzugehoerigkeit: ``application/`` — pure Logik, importiert nur ``domain``.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Final

from tools.network_monitor.application.game_cdn import match_game_cdn
from tools.network_monitor.domain.models import DnsQuerySample

#: Event-ID „DNS query is called" (Microsoft-Windows-DNS-Client).
DNS_QUERY_EVENT_ID: Final[int] = 3006


def _shannon_entropy(text: str) -> float:
    """Shannon-Entropie (Bits/Zeichen) eines Strings; 0.0 fuer leer."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _label_features(query_name: str) -> tuple[int, float]:
    """Liefert (max Label-Laenge, max Label-Entropie) ueber alle Labels."""
    best_len = 0
    best_entropy = 0.0
    for label in query_name.split("."):
        if not label:
            continue
        best_len = max(best_len, len(label))
        best_entropy = max(best_entropy, _shannon_entropy(label))
    return best_len, best_entropy


class _Accumulator:
    __slots__ = ("count", "names", "max_len", "max_entropy", "sample", "game_cdn")

    def __init__(self) -> None:
        self.count = 0
        self.names: set[str] = set()
        self.max_len = 0
        self.max_entropy = 0.0
        self.sample = ""
        self.game_cdn = ""


class DnsQueryAggregator:
    """Aggregiert DNS-Client-Events zu Per-PID-Query-Statistiken."""

    def __init__(self) -> None:
        self._acc: dict[int, _Accumulator] = defaultdict(_Accumulator)

    def add_event(self, event_id: int, payload: dict[str, Any]) -> None:
        """Verbucht ein DNS-Query-Event (Event 3006); andere werden ignoriert.

        Args:
            event_id: ETW-Event-ID.
            payload: Normalisiert (``pid``, ``query_name``, ``query_type``).
        """
        if event_id != DNS_QUERY_EVENT_ID:
            return
        raw_pid = payload.get("pid")
        try:
            pid = int(raw_pid)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            return
        name = str(payload.get("query_name") or "")
        acc = self._acc[pid]
        acc.count += 1
        if name:
            acc.names.add(name)
            if not acc.sample:
                acc.sample = name
            length, entropy = _label_features(name)
            acc.max_len = max(acc.max_len, length)
            acc.max_entropy = max(acc.max_entropy, entropy)
            if not acc.game_cdn:
                acc.game_cdn = match_game_cdn(name)

    def flush(
        self, name_resolver: Callable[[int], str]
    ) -> list[DnsQuerySample]:
        """Gibt die Per-PID-Samples zurueck und setzt den Puffer zurueck."""
        samples = [
            DnsQuerySample(
                pid=pid,
                process_name=name_resolver(pid),
                query_count=acc.count,
                distinct_names=len(acc.names),
                max_label_len=acc.max_len,
                max_label_entropy=round(acc.max_entropy, 3),
                sample_query=acc.sample,
                game_cdn=acc.game_cdn,
            )
            for pid, acc in self._acc.items()
        ]
        self._acc.clear()
        return samples
