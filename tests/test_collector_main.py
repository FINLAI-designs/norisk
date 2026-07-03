"""Tests fuer die testbaren Collector-Helfer B2/Regel 4/5).

Routing roher Events in Traffic- + DNS-Aggregator + Pfad-Tracker, Flush in
beide Repos (mit Pfad-Resolver), PID-Name-Resolver — ohne ETW/Admin.
``run_collector`` selbst ist nur elevated real testbar (Smoke).
"""

from __future__ import annotations

import os
import queue
from typing import Any

import apps.collector_main as collector_main
import pytest
from apps.collector_main import _drain_queue, _flush, main, make_name_resolver


class _FakeAggregator:
    """Sammelt add_event-Aufrufe; flush gibt vorbereitete Samples zurueck."""

    def __init__(self, flush_result: list[Any] | None = None) -> None:
        self.events: list[tuple[int, dict]] = []
        self._flush_result = flush_result or []

    def add_event(self, event_id: int, payload: dict) -> None:
        self.events.append((event_id, payload))

    def flush(self, name_resolver: Any, path_resolver: Any = None) -> list[Any]:  # noqa: ARG002
        return self._flush_result


class _FakePathTracker:
    def __init__(self) -> None:
        self.events: list[tuple[int, dict]] = []

    def add_event(self, event_id: int, raw: dict) -> None:
        self.events.append((event_id, raw))


class _FakeRepo:
    def __init__(self) -> None:
        self.saved: list[list[Any]] = []

    def save_samples(self, samples: list[Any]) -> int:
        self.saved.append(samples)
        return len(samples)


class TestDrainQueue:
    def test_routet_in_aggregatoren_und_tracker(self) -> None:
        q: queue.Queue = queue.Queue()
        q.put((10, {"PID": 1, "size": 100, "daddr": 67_305_985}))  # Kernel-Network
        q.put((3006, {"EventHeader": {"ProcessId": 2}, "QueryName": "x.com"}))  # DNS
        q.put((1, {"ProcessID": 9, "ImageName": r"C:\Temp\x.exe"}))  # ProcessStart
        traffic = _FakeAggregator()
        dns = _FakeAggregator()
        tracker = _FakePathTracker()
        drained = _drain_queue(q, traffic, dns, tracker)
        assert drained == 3
        # Jedes Event geht an alle drei Konsumenten (jeder filtert per ID).
        assert len(traffic.events) == 3
        assert len(dns.events) == 3
        assert len(tracker.events) == 3

    def test_leere_queue_gibt_null(self) -> None:
        assert (
            _drain_queue(
                queue.Queue(), _FakeAggregator(), _FakeAggregator(), _FakePathTracker()
            )
            == 0
        )

    def test_respektiert_max_items(self) -> None:
        q: queue.Queue = queue.Queue()
        for i in range(5):
            q.put((10, {"PID": i, "size": 1}))
        assert (
            _drain_queue(
                q,
                _FakeAggregator(),
                _FakeAggregator(),
                _FakePathTracker(),
                max_items=3,
            )
            == 3
        )
        assert q.qsize() == 2


class TestFlush:
    def test_flusht_beide_repos(self) -> None:
        traffic = _FakeAggregator(flush_result=["a", "b"])
        dns = _FakeAggregator(flush_result=["c"])
        traffic_repo = _FakeRepo()
        dns_repo = _FakeRepo()
        result = _flush(
            traffic, dns, traffic_repo, dns_repo, lambda pid: "x", lambda pid: "p"
        )
        assert result == (2, 1)
        assert traffic_repo.saved == [["a", "b"]]
        assert dns_repo.saved == [["c"]]


class TestNameResolver:
    def test_unbekannte_pid_gibt_strich(self) -> None:
        resolve = make_name_resolver()
        assert resolve(2_000_000_000) == "–"

    def test_eigener_prozess_aufloesbar_und_gecacht(self) -> None:
        resolve = make_name_resolver()
        name1 = resolve(os.getpid())
        name2 = resolve(os.getpid())
        assert name1 == name2
        assert name1 and name1 != "–"


class TestMainHardening:
    """main härtet den DLL-Suchpfad VOR run_collector (Security-Gate E1)."""

    def test_main_haertet_dll_suchpfad(self, monkeypatch) -> None:
        import core.win_security as win_security

        order: list[str] = []
        monkeypatch.setattr(
            win_security,
            "harden_dll_search_path",
            lambda: order.append("harden") or True,
        )
        monkeypatch.setattr(
            collector_main,
            "run_collector",
            lambda **_kw: order.append("run") or 0,
        )
        rc = main(["--duration", "0"])
        assert rc == 0
        # Härtung läuft vor dem (DLL-ladenden) Collector-Start.
        assert order == ["harden", "run"]


class TestAdminGate:
    """run_collector/main liefern ohne Admin-Rechte Exit 2 (Spec-Regressionskriterium).

    Build-freier Anker fuer den unprivilegierten Smoke aus F-C-2 Teil 2:
    ``norisk-collector.exe`` ohne Admin MUSS mit Exit-Code 2 (Admin-Gate) beenden.
    Faellt dieser Vertrag (z. B. weil ein Qt-Import-Bruch den Collector schon vor
    dem is_admin-Check crashen liesse), ist auch der gebaute Collector kaputt.
    """

    def test_run_collector_ohne_admin_gibt_2(self, monkeypatch) -> None:
        # is_admin wird in run_collector lazy aus dem Subscriber-Modul importiert;
        # am Quellmodul patchen, damit der spaete Import den Fake sieht.
        monkeypatch.setattr(
            "tools.network_monitor.data.etw_network_subscriber.is_admin",
            lambda: False,
        )
        assert collector_main.run_collector(duration_s=0) == 2

    def test_main_ohne_admin_gibt_2(self, monkeypatch) -> None:
        # main haertet zuerst den DLL-Suchpfad — im Test KEINEN realen
        # SetDefaultDllDirectories-Seiteneffekt auf den pytest-Prozess zulassen.
        import core.win_security as win_security

        monkeypatch.setattr(win_security, "harden_dll_search_path", lambda: False)
        monkeypatch.setattr(
            "tools.network_monitor.data.etw_network_subscriber.is_admin",
            lambda: False,
        )
        assert main([]) == 2


class TestFinlaiHomeForwarding:
    """``--finlai-home`` setzt den Override VOR run_collector (sonst binden die
    lazy importierten DB-Modul-Konstanten bereits das falsche Profil)."""

    @pytest.fixture(autouse=True)
    def _no_real_dll_hardening(self, monkeypatch) -> None:
        # main ruft harden_dll_search_path; im realen main-Test darf das KEINEN
        # globalen SetDefaultDllDirectories-Seiteneffekt auf den pytest-Prozess haben.
        import core.win_security as win_security

        monkeypatch.setattr(win_security, "harden_dll_search_path", lambda: False)

    def test_override_vor_run_collector_gesetzt(self, monkeypatch) -> None:
        order: list[str] = []
        captured: dict[str, str] = {}

        def fake_set(path: Any) -> None:
            order.append("set")
            captured["home"] = str(path)

        def fake_run(*, duration_s: Any, flush_interval_s: Any) -> int:  # noqa: ARG001
            order.append("run")
            return 0

        # set_finlai_home wird in main lazy importiert -> am Quellmodul patchen.
        monkeypatch.setattr("core.finlai_paths.set_finlai_home", fake_set)
        monkeypatch.setattr(collector_main, "run_collector", fake_run)

        rc = main(["--finlai-home", r"C:\tmp\iso", "--duration", "0"])

        assert rc == 0
        assert captured["home"] == r"C:\tmp\iso"
        assert order == ["set", "run"]

    def test_ohne_override_kein_set(self, monkeypatch) -> None:
        calls = {"set": 0}
        monkeypatch.setattr(
            "core.finlai_paths.set_finlai_home",
            lambda _p: calls.__setitem__("set", calls["set"] + 1),
        )
        monkeypatch.setattr(
            collector_main, "run_collector", lambda **_kw: 0
        )

        rc = main(["--duration", "0"])

        assert rc == 0
        assert calls["set"] == 0
