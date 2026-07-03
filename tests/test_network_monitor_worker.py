"""Tests für NetworkMonitorWorker.

Prüft Worker-Start (emittiert mindestens einmal stats_updated), sauberen
Stopp via Flag und Fehlerbehandlung (emitiert error_occurred statt
crashen).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.network_monitor.data.monitor_worker import NetworkMonitorWorker


@pytest.fixture
def worker():
    w = NetworkMonitorWorker(include_per_process=False)
    yield w
    if w.isRunning():
        w.stop()
        w.wait(2000)


class TestWorkerLifecycle:
    def test_emittiert_stats_updated(self, qtbot, worker) -> None:
        """Worker emittiert nach Start mindestens einmal stats_updated."""
        with qtbot.waitSignal(worker.stats_updated, timeout=5000) as blocker:
            worker.start()
        assert isinstance(blocker.args[0], dict)

    def test_emittiert_connections_updated(self, qtbot, worker) -> None:
        """Worker emittiert connections_updated als Liste."""
        with qtbot.waitSignal(worker.connections_updated, timeout=5000) as blocker:
            worker.start()
        assert isinstance(blocker.args[0], list)

    def test_persistiert_snapshot_im_worker_thread(self, qtbot) -> None:
        """: Mit ``connection_repo`` ruft der Worker ``save_snapshot``
        SELBST auf (Worker-Thread) — die GUI-Persistenz im UI-Thread entfällt."""
        repo = MagicMock()
        w = NetworkMonitorWorker(include_per_process=False, connection_repo=repo)
        try:
            with qtbot.waitSignal(w.connections_updated, timeout=5000):
                w.start()
            # Persistenz läuft NACH dem emit im Worker-Thread -> kurz nachwarten.
            qtbot.waitUntil(lambda: repo.save_snapshot.called, timeout=3000)
            assert repo.save_snapshot.called
        finally:
            if w.isRunning():
                w.stop()
                w.wait(2000)

    def test_kein_repo_kein_persist_kein_crash(self, qtbot, worker) -> None:
        """Ohne ``connection_repo`` (Default) läuft der Zyklus ohne Persistenz
        und ohne Fehler durch."""
        with qtbot.waitSignal(worker.connections_updated, timeout=5000):
            worker.start()
        assert worker.isRunning()

    def test_stop_beendet_worker_sauber(self, qtbot, worker) -> None:
        """stop setzt das Flag, Worker beendet sich ohne terminate."""
        with qtbot.waitSignal(worker.stats_updated, timeout=5000):
            worker.start()
        worker.stop()
        assert worker.wait(3000) is True, "Worker muss nach stop() beenden"
        assert not worker.isRunning()

    def test_fehler_bei_net_connections_loest_error_signal(
        self, qtbot
    ) -> None:
        """psutil.AccessDenied in net_connections → error_occurred."""
        import psutil

        w = NetworkMonitorWorker()
        try:
            with patch(
                "tools.network_monitor.data.monitor_worker.psutil.net_connections",
                side_effect=psutil.AccessDenied(),
            ), qtbot.waitSignal(w.error_occurred, timeout=5000):
                w.start()
        finally:
            w.stop()
            w.wait(2000)
