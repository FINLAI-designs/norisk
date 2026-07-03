"""Tests fuer das DNS-Query-Repository Regel 5).

save + peak_rate_per_process + purge. DB-Isolation via conftest-Fixture.
"""

from __future__ import annotations

from tools.network_monitor.data.dns_query_repository import DnsQueryRepository
from tools.network_monitor.domain.models import DnsQuerySample


def _s(
    pid: int = 1,
    name: str = "a.exe",
    count: int = 10,
    distinct: int = 5,
    maxlen: int = 10,
    ent: float = 2.0,
    sample: str = "x.com",
) -> DnsQuerySample:
    return DnsQuerySample(
        pid=pid,
        process_name=name,
        query_count=count,
        distinct_names=distinct,
        max_label_len=maxlen,
        max_label_entropy=ent,
        sample_query=sample,
    )


class TestDnsQueryRepository:
    def test_save_und_peak_rate(self) -> None:
        repo = DnsQueryRepository()
        repo.save_samples([_s(pid=1, count=100)])
        repo.save_samples([_s(pid=1, count=1500)])  # Peak fuer pid 1
        repo.save_samples([_s(pid=2, count=50)])
        peaks = {r.pid: r for r in repo.peak_rate_per_process(0.0)}
        assert peaks[1].peak_query_count == 1500
        assert peaks[2].peak_query_count == 50

    def test_save_gibt_anzahl_zurueck(self) -> None:
        repo = DnsQueryRepository()
        assert repo.save_samples([_s(), _s(pid=2)]) == 2

    def test_purge(self) -> None:
        repo = DnsQueryRepository()
        repo.save_samples([_s()])
        assert repo.purge_older_than(hours=0) >= 1
        assert repo.peak_rate_per_process(0.0) == []

    def test_game_cdn_round_trip(self) -> None:
        repo = DnsQueryRepository()
        repo.save_samples(
            [
                DnsQuerySample(
                    pid=2,
                    process_name="steam.exe",
                    query_count=3,
                    distinct_names=1,
                    max_label_len=5,
                    max_label_entropy=1.0,
                    sample_query="cdn.steamcontent.com",
                    game_cdn="Steam",
                )
            ]
        )
        peaks = {r.pid: r for r in repo.peak_rate_per_process(0.0)}
        assert peaks[2].game_cdn == "Steam"
