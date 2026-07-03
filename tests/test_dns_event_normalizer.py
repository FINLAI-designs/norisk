"""Tests fuer den DNS-Event-Normalizer Regel 5).

PID aus EventHeader, QueryName/QueryType, Fallbacks — admin-/ETW-frei.
"""

from __future__ import annotations

from tools.network_monitor.data.dns_event_normalizer import normalize_dns_event


class TestNormalizeDns:
    def test_pid_aus_eventheader(self) -> None:
        raw = {
            "EventHeader": {"ProcessId": 4321},
            "QueryName": "evil.example.com",
            "QueryType": 16,
        }
        assert normalize_dns_event(raw) == {
            "pid": 4321,
            "query_name": "evil.example.com",
            "query_type": 16,
        }

    def test_string_coercion(self) -> None:
        raw = {
            "EventHeader": {"ProcessId": "4321"},
            "QueryName": "x.com",
            "QueryType": "1",
        }
        out = normalize_dns_event(raw)
        assert out["pid"] == 4321
        assert out["query_type"] == 1

    def test_fehlende_pid_ausgelassen(self) -> None:
        out = normalize_dns_event({"QueryName": "x.com"})
        assert "pid" not in out
        assert out["query_name"] == "x.com"

    def test_fallback_flacher_pid(self) -> None:
        out = normalize_dns_event({"ProcessId": 7, "QueryName": "x.com"})
        assert out["pid"] == 7

    def test_leeres_event(self) -> None:
        assert normalize_dns_event({}) == {}
