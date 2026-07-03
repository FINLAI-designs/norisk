"""test_process_traffic_repository — Tests fuer Stop-Step A/B2.

Deckt das admin-freie Fundament ab (kein ETW noetig): Domain-Modelle +
``ProcessTrafficRepository`` (save / per-IP-Grain / 24h-Aggregat / 48h-Retention /
purge). DB-Isolation via autouse-Fixture in ``tests/conftest.py``.
"""

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError

import pytest

import tools.network_monitor.data.process_traffic_repository as repo_mod
from tools.network_monitor.data.process_traffic_repository import (
    ProcessTrafficRepository,
)
from tools.network_monitor.domain.models import (
    ProcessTrafficAggregate,
    ProcessTrafficSample,
)


def _sample(
    pid: int = 100,
    name: str = "firefox.exe",
    sent: int = 1000,
    recv: int = 2000,
    ip: str = "1.2.3.4",
    port: int = 443,
    proto: str = "TCP",
) -> ProcessTrafficSample:
    return ProcessTrafficSample(
        pid=pid,
        process_name=name,
        remote_ip=ip,
        remote_port=port,
        protocol=proto,
        bytes_sent=sent,
        bytes_recv=recv,
    )


class TestDomainModels:
    def test_sample_ist_frozen(self) -> None:
        s = _sample()
        with pytest.raises(FrozenInstanceError):
            s.pid = 7  # type: ignore[misc]

    def test_aggregate_ist_frozen(self) -> None:
        a = ProcessTrafficAggregate(
            pid=1, process_name="x", total_bytes_sent=1, total_bytes_recv=2
        )
        with pytest.raises(FrozenInstanceError):
            a.total_bytes_sent = 9  # type: ignore[misc]


class TestProcessTrafficRepository:
    def test_save_und_aggregate_summiert_pro_prozess(self) -> None:
        repo = ProcessTrafficRepository()
        repo.save_samples([_sample(sent=1000, recv=2000)])
        repo.save_samples([_sample(sent=500, recv=100)])  # gleicher pid+name
        agg = repo.aggregate_last_24h()
        assert len(agg) == 1
        assert agg[0].total_bytes_sent == 1500
        assert agg[0].total_bytes_recv == 2100

    def test_aggregate_sortiert_nach_gesamt_desc(self) -> None:
        repo = ProcessTrafficRepository()
        repo.save_samples(
            [
                _sample(pid=1, name="small.exe", sent=10, recv=10),
                _sample(pid=2, name="big.exe", sent=5000, recv=5000),
            ]
        )
        agg = repo.aggregate_last_24h()
        assert [a.process_name for a in agg] == ["big.exe", "small.exe"]

    def test_grain_pro_ip_getrennt_aber_pro_prozess_summiert(self) -> None:
        # Gleicher Prozess, zwei Remote-IPs → 2 Roh-Zeilen, aber 1 per-PID-Aggregat.
        repo = ProcessTrafficRepository()
        repo.save_samples(
            [
                _sample(pid=5, name="x.exe", sent=100, recv=0, ip="1.1.1.1"),
                _sample(pid=5, name="x.exe", sent=200, recv=0, ip="2.2.2.2"),
            ]
        )
        with repo._db.connection() as conn:
            rows = conn.execute("SELECT COUNT(*) FROM process_traffic").fetchone()[0]
        assert rows == 2  # per-(pid, ip)-Grain bewahrt
        agg = repo.aggregate_last_24h()
        assert len(agg) == 1
        assert agg[0].total_bytes_sent == 300

    def test_save_gibt_anzahl_zurueck(self) -> None:
        repo = ProcessTrafficRepository()
        assert repo.save_samples([_sample(pid=1), _sample(pid=2)]) == 2

    def test_save_leer_nur_purge(self) -> None:
        repo = ProcessTrafficRepository()
        assert repo.save_samples([]) == 0
        assert repo.aggregate_last_24h() == []

    def test_purge_older_than_loescht_alles_bei_null(self) -> None:
        repo = ProcessTrafficRepository()
        repo.save_samples([_sample()])
        assert repo.purge_older_than(hours=0) >= 1
        assert repo.aggregate_last_24h() == []

    def test_retention_purged_alte_zeile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        repo = ProcessTrafficRepository()
        # Echte Zeit VOR dem Patchen fixieren — der Patch auf repo_mod.time.time
        # wirkt global (geteiltes time-Modul), darum nicht spaeter time.time
        # im Test aufrufen.
        real_now = time.time()
        clock = [real_now - 2 * 3600]  # 2h her (noch im 24h-Fenster)
        monkeypatch.setattr(repo_mod.time, "time", lambda: clock[0])
        repo.save_samples([_sample(pid=99, name="old.exe")])
        # Uhr auf jetzt stellen; retention_hours=0 → die 2h-alte Zeile wird
        # gepurged, obwohl sie noch im 24h-Aggregat-Fenster liegt.
        clock[0] = real_now
        repo.save_samples([_sample(pid=1, name="new.exe")], retention_hours=0)
        names = [a.process_name for a in repo.aggregate_last_24h()]
        assert "old.exe" not in names
        assert "new.exe" in names


class TestDetectorQueries:
    """Query-Methoden fuer den Anomalie-Detektor D)."""

    def test_outbound_per_process_summiert_ueber_ips(self) -> None:
        repo = ProcessTrafficRepository()
        repo.save_samples(
            [
                _sample(pid=1, name="a.exe", sent=100, ip="1.1.1.1"),
                _sample(pid=1, name="a.exe", sent=200, ip="2.2.2.2"),
            ]
        )
        res = repo.outbound_per_process_since(0.0)
        assert len(res) == 1
        assert res[0].pid == 1
        assert res[0].bytes_sent == 300

    def test_outbound_traegt_image_path(self) -> None:
        # Regel-4-Datenfluss: image_path muss round-trippen.
        repo = ProcessTrafficRepository()
        repo.save_samples(
            [
                ProcessTrafficSample(
                    pid=7,
                    process_name="t.exe",
                    remote_ip="1.1.1.1",
                    remote_port=443,
                    protocol="TCP",
                    bytes_sent=50,
                    bytes_recv=0,
                    image_path=r"C:\Users\x\AppData\Local\Temp\t.exe",
                )
            ]
        )
        res = repo.outbound_per_process_since(0.0)
        assert res[0].image_path == r"C:\Users\x\AppData\Local\Temp\t.exe"

    def test_traffic_per_remote_ip_getrennt(self) -> None:
        repo = ProcessTrafficRepository()
        repo.save_samples(
            [
                _sample(pid=1, name="a.exe", sent=100, ip="1.1.1.1"),
                _sample(pid=1, name="a.exe", sent=200, ip="2.2.2.2"),
            ]
        )
        by_ip = {r.remote_ip: r for r in repo.traffic_per_remote_ip_since(0.0)}
        assert by_ip["1.1.1.1"].bytes_sent == 100
        assert by_ip["2.2.2.2"].bytes_sent == 200

    def test_offhours_filtert_nach_lokaler_stunde(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = ProcessTrafficRepository()
        # Konstruierte Lokalzeiten: 02:00 (Nacht) und 14:00 (Tag), gleicher Tag.
        night = time.mktime((2026, 5, 20, 2, 0, 0, 0, 0, -1))
        day = time.mktime((2026, 5, 20, 14, 0, 0, 0, 0, -1))
        monkeypatch.setattr(repo_mod.time, "time", lambda: night)
        repo.save_samples([_sample(pid=1, name="night.exe", sent=500)])
        monkeypatch.setattr(repo_mod.time, "time", lambda: day)
        repo.save_samples([_sample(pid=2, name="day.exe", sent=500)])
        names = {r.process_name for r in repo.offhours_outbound_per_process(0.0)}
        assert "night.exe" in names
        assert "day.exe" not in names
