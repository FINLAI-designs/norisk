"""test_etw_traffic_aggregator — Tests fuer Stop-Step B1/B2.

Pure Event→Sample-Logik (kein ETW/Admin): Send/Recv-Mapping, Flow-Grain
(pid, remote_ip, remote_port, protocol), Doppel-Count-Schutz, String-Coercion,
Protokoll-Ableitung, flush-Reset.
"""

from __future__ import annotations

from tools.network_monitor.application.etw_traffic_aggregator import (
    RECV_EVENT_IDS,
    SEND_EVENT_IDS,
    EtwTrafficAggregator,
)

# Prozessnamen-Resolver fuer Tests (kein psutil).
_NAMES = {2820: "svchost.exe", 27272: "python.exe"}


def _resolver(pid: int) -> str:
    return _NAMES.get(pid, "?")


def _send(
    pid: str | int = 27272,
    size: str | int = 100,
    daddr: str = "1.2.3.4",
    dport: str | int = 443,
) -> dict:
    return {"PID": pid, "size": size, "daddr": daddr, "dport": dport}


def _recv(
    pid: str | int = 27272,
    size: str | int = 200,
    saddr: str = "5.6.7.8",
    sport: str | int = 443,
) -> dict:
    return {"PID": pid, "size": size, "saddr": saddr, "sport": sport}


class TestAggregator:
    def test_send_event_zaehlt_bytes_sent(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100, daddr="1.2.3.4", dport=443))  # TCPv4 send
        samples = agg.flush(_resolver)
        assert len(samples) == 1
        s = samples[0]
        assert s.bytes_sent == 100
        assert s.bytes_recv == 0
        assert s.process_name == "python.exe"
        assert s.remote_ip == "1.2.3.4"  # daddr bei send
        assert s.remote_port == 443
        assert s.protocol == "TCP"

    def test_recv_event_zaehlt_bytes_recv(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(11, _recv(size=200, saddr="5.6.7.8", sport=80))  # TCPv4 recv
        s = agg.flush(_resolver)[0]
        assert s.bytes_recv == 200
        assert s.bytes_sent == 0
        assert s.remote_ip == "5.6.7.8"  # saddr bei recv
        assert s.remote_port == 80

    def test_nicht_traffic_event_wird_ignoriert(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(34, _send(size=999))  # "copied in protocol" → ignorieren
        agg.add_event(18, _send(size=999))
        assert agg.flush(_resolver) == []

    def test_string_payload_wird_coerced(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(pid="27272", size="150", dport="443"))  # Strings
        s = agg.flush(_resolver)[0]
        assert s.pid == 27272
        assert s.bytes_sent == 150
        assert s.remote_port == 443

    def test_fehlende_pid_oder_size_ignoriert(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, {"size": 100})  # kein PID
        agg.add_event(11, {"PID": 1})  # kein size
        assert agg.flush(_resolver) == []

    def test_akkumuliert_pro_flow(self) -> None:
        # Gleicher Flow (pid, ip, port, proto) → ein Sample, Bytes summiert.
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100, daddr="1.2.3.4", dport=443))
        agg.add_event(10, _send(size=50, daddr="1.2.3.4", dport=443))
        agg.add_event(11, _recv(size=200, saddr="1.2.3.4", sport=443))
        samples = agg.flush(_resolver)
        assert len(samples) == 1
        assert samples[0].bytes_sent == 150
        assert samples[0].bytes_recv == 200

    def test_unterschiedliche_ips_getrennt(self) -> None:
        # Gleicher PID, verschiedene Remote-IPs → getrennte Flows.
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100, daddr="1.2.3.4", dport=443))
        agg.add_event(10, _send(size=300, daddr="9.9.9.9", dport=443))
        by_ip = {s.remote_ip: s for s in agg.flush(_resolver)}
        assert by_ip["1.2.3.4"].bytes_sent == 100
        assert by_ip["9.9.9.9"].bytes_sent == 300

    def test_mehrere_pids_getrennt(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(42, _send(pid=27272, size=100))  # UDPv4 send
        agg.add_event(43, _recv(pid=2820, size=300))  # UDPv4 recv
        by_pid = {s.pid: s for s in agg.flush(_resolver)}
        assert by_pid[27272].bytes_sent == 100
        assert by_pid[2820].bytes_recv == 300

    def test_protokoll_aus_event_id(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=1))  # TCPv4
        agg.add_event(42, _send(daddr="9.9.9.9", size=1))  # UDPv4
        by_ip = {s.remote_ip: s.protocol for s in agg.flush(_resolver)}
        assert by_ip["1.2.3.4"] == "TCP"
        assert by_ip["9.9.9.9"] == "UDP"

    def test_flush_setzt_zurueck(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100))
        agg.flush(_resolver)
        assert agg.flush(_resolver) == []  # zweiter flush leer

    def test_send_recv_id_mengen_disjunkt(self) -> None:
        assert SEND_EVENT_IDS.isdisjoint(RECV_EVENT_IDS)

    def test_path_resolver_setzt_image_path(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100))
        s = agg.flush(_resolver, lambda pid: r"C:\Temp\x.exe")[0]
        assert s.image_path == r"C:\Temp\x.exe"

    def test_ohne_path_resolver_leerer_pfad(self) -> None:
        agg = EtwTrafficAggregator()
        agg.add_event(10, _send(size=100))
        assert agg.flush(_resolver)[0].image_path == ""
