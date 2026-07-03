"""Tests fuer den Netzwerk-Anomalie-Detektor D).

Reine Regel-Logik, kein DB/ETW: Schwellwerte, Whitelist, externe-IP-Filter,
Pfad-Heuristik, Game-CDN-Mechanik, Service-Verdrahtung (Fake-Repo).

Hinweis: getrennt von ``test_anomaly_detector.py`` (norisk_dashboard/Light-SIEM,
anderes Feature) — Dateiname bewusst ``test_network_anomaly_detector``.
"""

from __future__ import annotations

from tools.network_monitor.application.anomaly_detector import (
    DNS_QUERY_RATE_PER_MIN,
    OFFHOURS_BYTES,
    SINGLE_IP_BYTES,
    UNKNOWN_PATH_BYTES,
    VOLUME_SPIKE_BYTES,
    AnomalyDetector,
    AnomalyService,
)
from tools.network_monitor.domain.models import (
    AnomalySeverity,
    AnomalyType,
    DnsRateAggregate,
    ProcessOutbound,
    RemoteIpTraffic,
)


def _out(pid=1, name="evil.exe", sent=0, path="") -> ProcessOutbound:
    return ProcessOutbound(pid=pid, process_name=name, bytes_sent=sent, image_path=path)


def _ip(pid=1, name="evil.exe", ip="8.8.8.8", sent=0, recv=0) -> RemoteIpTraffic:
    return RemoteIpTraffic(
        pid=pid, process_name=name, remote_ip=ip, bytes_sent=sent, bytes_recv=recv
    )


class TestVolumeSpike:
    def test_ueber_schwelle_feuert(self) -> None:
        det = AnomalyDetector()
        res = det.detect_volume_spike([_out(sent=VOLUME_SPIKE_BYTES + 1)])
        assert len(res) == 1
        assert res[0].anomaly_type == AnomalyType.VOLUME_SPIKE
        assert res[0].severity == AnomalySeverity.HIGH

    def test_unter_schwelle_feuert_nicht(self) -> None:
        det = AnomalyDetector()
        assert det.detect_volume_spike([_out(sent=VOLUME_SPIKE_BYTES)]) == []

    def test_trusted_prozess_unterdrueckt(self) -> None:
        det = AnomalyDetector()
        res = det.detect_volume_spike(
            [_out(name="OneDrive.exe", sent=VOLUME_SPIKE_BYTES * 5)]
        )
        assert res == []


class TestOffHours:
    def test_feuert_medium(self) -> None:
        det = AnomalyDetector()
        res = det.detect_off_hours([_out(sent=OFFHOURS_BYTES + 1)])
        assert len(res) == 1
        assert res[0].severity == AnomalySeverity.MEDIUM


class TestUnknownPath:
    def test_temp_pfad_feuert(self) -> None:
        det = AnomalyDetector()
        res = det.detect_unknown_path(
            [
                _out(
                    sent=UNKNOWN_PATH_BYTES + 1,
                    path=r"C:\Users\x\AppData\Local\Temp\x.exe",
                )
            ]
        )
        assert len(res) == 1
        assert res[0].detail.endswith("x.exe")

    def test_leerer_pfad_dormant(self) -> None:
        # image_path noch nicht populiert → Regel bleibt still.
        det = AnomalyDetector()
        assert det.detect_unknown_path([_out(sent=UNKNOWN_PATH_BYTES * 10, path="")]) == []

    def test_normaler_pfad_feuert_nicht(self) -> None:
        det = AnomalyDetector()
        res = det.detect_unknown_path(
            [_out(sent=UNKNOWN_PATH_BYTES + 1, path=r"C:\Program Files\App\app.exe")]
        )
        assert res == []


class TestSingleIp:
    def test_externe_ip_ueber_schwelle(self) -> None:
        det = AnomalyDetector()
        res = det.detect_single_ip([_ip(ip="8.8.8.8", sent=SINGLE_IP_BYTES + 1)])
        assert len(res) == 1
        assert res[0].remote_ip == "8.8.8.8"

    def test_private_ip_ignoriert(self) -> None:
        det = AnomalyDetector()
        assert det.detect_single_ip([_ip(ip="192.168.1.5", sent=SINGLE_IP_BYTES * 2)]) == []

    def test_unter_schwelle_ignoriert(self) -> None:
        det = AnomalyDetector()
        assert det.detect_single_ip([_ip(ip="8.8.8.8", sent=SINGLE_IP_BYTES)]) == []


class TestGameCdn:
    def test_kein_game_cdn_kein_alert(self) -> None:
        det = AnomalyDetector()
        assert det.detect_game_cdn([_dns(game_cdn="")]) == []

    def test_game_cdn_match_low(self) -> None:
        det = AnomalyDetector()
        res = det.detect_game_cdn(
            [_dns(name="steam.exe", game_cdn="Steam"), _dns(name="x.exe", game_cdn="")]
        )
        assert len(res) == 1
        assert res[0].anomaly_type == AnomalyType.GAME_CDN
        assert res[0].severity == AnomalySeverity.LOW
        assert res[0].detail == "Steam"


class _FakeRepo:
    def __init__(self, outbound=None, offhours=None, per_ip=None) -> None:
        self._outbound = outbound or []
        self._offhours = offhours or []
        self._per_ip = per_ip or []

    def outbound_per_process_since(self, cutoff_ts):  # noqa: ANN001, ARG002
        return self._outbound

    def offhours_outbound_per_process(self, cutoff_ts):  # noqa: ANN001, ARG002
        return self._offhours

    def traffic_per_remote_ip_since(self, cutoff_ts):  # noqa: ANN001, ARG002
        return self._per_ip


def _dns(
    pid=1,
    name="evil.exe",
    peak=2000,
    maxlen=40,
    ent=4.2,
    sample="x.tunnel.com",
    game_cdn="",
) -> DnsRateAggregate:
    return DnsRateAggregate(
        pid=pid,
        process_name=name,
        peak_query_count=peak,
        max_label_len=maxlen,
        max_label_entropy=ent,
        sample_query=sample,
        game_cdn=game_cdn,
    )


class TestDnsTunneling:
    def test_ueber_rate_feuert_high(self) -> None:
        det = AnomalyDetector()
        res = det.detect_dns_tunneling([_dns(peak=DNS_QUERY_RATE_PER_MIN + 1)])
        assert len(res) == 1
        assert res[0].anomaly_type == AnomalyType.DNS_TUNNELING
        assert res[0].severity == AnomalySeverity.HIGH
        assert res[0].value_bytes == DNS_QUERY_RATE_PER_MIN + 1

    def test_unter_rate_feuert_nicht(self) -> None:
        det = AnomalyDetector()
        assert det.detect_dns_tunneling([_dns(peak=DNS_QUERY_RATE_PER_MIN)]) == []

    def test_trusted_unterdrueckt(self) -> None:
        det = AnomalyDetector()
        assert det.detect_dns_tunneling([_dns(name="svchost.exe", peak=9000)]) == []


class _FakeDnsRepo:
    def __init__(self, rates) -> None:  # noqa: ANN001
        self._rates = rates

    def peak_rate_per_process(self, cutoff_ts):  # noqa: ANN001, ARG002
        return self._rates


class TestAnomalyService:
    def test_detect_verdrahtet_repo_und_detektor(self) -> None:
        repo = _FakeRepo(per_ip=[_ip(ip="8.8.8.8", sent=SINGLE_IP_BYTES + 1)])
        service = AnomalyService(repo)
        res = service.detect(now=1_000_000.0)
        assert len(res) == 1
        assert res[0].anomaly_type == AnomalyType.SINGLE_IP

    def test_detect_mit_dns_repo(self) -> None:
        repo = _FakeRepo()
        dns = _FakeDnsRepo([_dns(peak=DNS_QUERY_RATE_PER_MIN + 500)])
        service = AnomalyService(repo, dns_repository=dns)
        res = service.detect(now=1_000_000.0)
        assert any(a.anomaly_type == AnomalyType.DNS_TUNNELING for a in res)

    def test_detect_ohne_dns_repo_keine_dns_anomalie(self) -> None:
        repo = _FakeRepo()
        res = AnomalyService(repo).detect(now=1_000_000.0)
        assert res == []
