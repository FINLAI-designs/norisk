"""Tests fuer den DNS-Query-Aggregator Regel 5).

Query-Zaehlung, distinct-Namen, Label-Features (Laenge/Entropie),
Event-Filter, flush-Reset — pure, kein ETW.
"""

from __future__ import annotations

from tools.network_monitor.application.dns_query_aggregator import (
    DNS_QUERY_EVENT_ID,
    DnsQueryAggregator,
)


def _resolver(pid: int) -> str:
    return {1: "a.exe", 2: "b.exe"}.get(pid, "?")


class TestDnsAggregator:
    def test_zaehlt_und_distinct(self) -> None:
        agg = DnsQueryAggregator()
        for i in range(5):
            agg.add_event(DNS_QUERY_EVENT_ID, {"pid": 1, "query_name": f"s{i}.example.com"})
        s = agg.flush(_resolver)[0]
        assert s.query_count == 5
        assert s.distinct_names == 5
        assert s.process_name == "a.exe"

    def test_distinct_kleiner_als_count(self) -> None:
        agg = DnsQueryAggregator()
        for _ in range(3):
            agg.add_event(DNS_QUERY_EVENT_ID, {"pid": 1, "query_name": "same.com"})
        s = agg.flush(_resolver)[0]
        assert s.query_count == 3
        assert s.distinct_names == 1

    def test_nicht_dns_event_ignoriert(self) -> None:
        agg = DnsQueryAggregator()
        agg.add_event(10, {"pid": 1, "query_name": "x.com"})
        assert agg.flush(_resolver) == []

    def test_fehlende_pid_ignoriert(self) -> None:
        agg = DnsQueryAggregator()
        agg.add_event(DNS_QUERY_EVENT_ID, {"query_name": "x.com"})
        assert agg.flush(_resolver) == []

    def test_label_features(self) -> None:
        agg = DnsQueryAggregator()
        # Langes, hoch-entropisches Label (Tunneling-Muster).
        agg.add_event(
            DNS_QUERY_EVENT_ID,
            {"pid": 1, "query_name": "a1b2c3d4e5f6g7h8.tunnel.evil.com"},
        )
        s = agg.flush(_resolver)[0]
        assert s.max_label_len == 16  # "a1b2c3d4e5f6g7h8"
        assert s.max_label_entropy > 3.0
        assert s.sample_query == "a1b2c3d4e5f6g7h8.tunnel.evil.com"

    def test_flush_setzt_zurueck(self) -> None:
        agg = DnsQueryAggregator()
        agg.add_event(DNS_QUERY_EVENT_ID, {"pid": 1, "query_name": "x.com"})
        agg.flush(_resolver)
        assert agg.flush(_resolver) == []

    def test_game_cdn_erkannt(self) -> None:
        agg = DnsQueryAggregator()
        agg.add_event(
            DNS_QUERY_EVENT_ID, {"pid": 1, "query_name": "cdn.steamcontent.com"}
        )
        assert agg.flush(_resolver)[0].game_cdn == "Steam"

    def test_kein_game_cdn(self) -> None:
        agg = DnsQueryAggregator()
        agg.add_event(DNS_QUERY_EVENT_ID, {"pid": 1, "query_name": "example.com"})
        assert agg.flush(_resolver)[0].game_cdn == ""
