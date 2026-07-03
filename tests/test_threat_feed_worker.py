"""Tests für den One-Shot-Threat-Feed-Refresh-Worker F-D-GUI).

Prüft, dass:class:`ThreatFeedRefreshOnceWorker` einen erzwungenen Refresh im
Thread fährt und das Ergebnis (entries, whitelist, Quellen-Zähler) als
``refreshed`` emittiert bzw. bei Service-/Netzfehlern fail-soft ``failed``
(generische Meldung, kein Roh-Exception-Text). Service-Factory wird gefälscht —
keine DB, kein Netz (Regel 9).
"""

from __future__ import annotations

import ipaddress

from tools.network_monitor.domain.models import FeedRefreshSnapshot
from tools.network_monitor.gui.threat_feed_worker import ThreatFeedRefreshOnceWorker


class _FakeService:
    """Minimaler ThreatFeedService-Ersatz für den Worker: refresh_snapshot)."""

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.force_seen: bool | None = None

    def refresh_snapshot(self, *, force: bool = False) -> FeedRefreshSnapshot:
        self.force_seen = force
        if self._fail:
            raise RuntimeError("Quelle nicht erreichbar")
        return FeedRefreshSnapshot(
            entries=[(ipaddress.ip_network("9.9.9.9"), "feed")],
            whitelist=[ipaddress.ip_network("10.0.0.0/8")],
            updated_count=1,
            error_count=0,
        )


def _run(qtbot, worker: ThreatFeedRefreshOnceWorker, signal):
    """Startet den Worker und wartet auf das erwartete Signal."""
    with qtbot.waitSignal(signal, timeout=3000) as blocker:
        worker.start()
    worker.wait(2000)
    return blocker.args


class TestRefreshOnceWorker:
    def test_erfolg_emittiert_refreshed(self, qtbot) -> None:
        service = _FakeService()
        worker = ThreatFeedRefreshOnceWorker(service_factory=lambda: service)
        entries, whitelist, updated, errors = _run(qtbot, worker, worker.refreshed)
        assert service.force_seen is True  # manueller Refresh ignoriert TTL
        assert [str(n) for n, _ in entries] == ["9.9.9.9/32"]
        assert [str(n) for n in whitelist] == ["10.0.0.0/8"]
        assert updated == 1
        assert errors == 0

    def test_factory_fehler_emittiert_failed(self, qtbot) -> None:
        def _boom():
            raise RuntimeError("kein KeyManager")

        worker = ThreatFeedRefreshOnceWorker(service_factory=_boom)
        (message,) = _run(qtbot, worker, worker.failed)
        assert "konnten nicht aktualisiert werden" in message
        assert "kein KeyManager" not in message  # kein Roh-Exception-Leak (R-Log)

    def test_update_fehler_emittiert_failed(self, qtbot) -> None:
        service = _FakeService(fail=True)
        worker = ThreatFeedRefreshOnceWorker(service_factory=lambda: service)
        (message,) = _run(qtbot, worker, worker.failed)
        assert "nicht erreichbar" in message
        assert "RuntimeError" not in message  # kein Roh-Exception-Leak (R-Log)
