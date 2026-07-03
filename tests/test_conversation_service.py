"""Tests für ConversationService Phase 5).

Prüft, dass der Service an das Repository delegiert (Zeitfenster durchreicht,
Ergebnis zurückgibt) — mit einem Fake-Repository, kein DB.
"""

from __future__ import annotations

from tools.network_monitor.application.conversation_service import ConversationService
from tools.network_monitor.domain.interfaces import (
    IConnectionRepository,
    IProcessTrafficRepository,
)
from tools.network_monitor.domain.models import (
    ConnectionInfo,
    Conversation,
    RemoteIpTraffic,
)


class _FakeRepo(IConnectionRepository):
    """Minimales IConnectionRepository für den Service-Test."""

    def __init__(self, conversations: list[Conversation]) -> None:
        self._conversations = conversations
        self.seen_hours: int | None = None

    def save_snapshot(self, connections: list[ConnectionInfo]) -> None:  # noqa: D102
        raise AssertionError("save_snapshot sollte hier nicht aufgerufen werden")

    def load_recent(self, hours: int = 24):  # noqa: D102
        raise AssertionError("load_recent sollte hier nicht aufgerufen werden")

    def purge_older_than(self, hours: int = 24) -> int:  # noqa: D102
        raise AssertionError("purge_older_than sollte hier nicht aufgerufen werden")

    def aggregate_conversations(self, hours: int = 24) -> list[Conversation]:  # noqa: D102
        self.seen_hours = hours
        return self._conversations


class _FakeTrafficRepo(IProcessTrafficRepository):
    """Minimales IProcessTrafficRepository fuer die Byte-Anreicherung."""

    def __init__(self, rows: list[RemoteIpTraffic]) -> None:
        self._rows = rows

    def aggregate_last_24h(self):  # noqa: D102
        return []

    def outbound_per_process_since(self, cutoff_ts: float):  # noqa: D102
        return []

    def offhours_outbound_per_process(self, cutoff_ts: float):  # noqa: D102
        return []

    def traffic_per_remote_ip_since(self, cutoff_ts: float):  # noqa: D102
        return self._rows


def test_aggregate_delegiert_und_reicht_fenster_durch() -> None:
    convs = [
        Conversation(process_name="firefox", remote_ip="1.2.3.4", connection_count=5),
    ]
    repo = _FakeRepo(convs)
    service = ConversationService(repository=repo)

    result = service.aggregate(hours=12)

    assert result == convs
    assert repo.seen_hours == 12


def test_aggregate_default_fenster() -> None:
    repo = _FakeRepo([])
    service = ConversationService(repository=repo)
    assert service.aggregate() == []
    assert repo.seen_hours == 24


def test_aggregate_reichert_bytes_an() -> None:
    convs = [
        Conversation(process_name="chrome", remote_ip="8.8.8.8", connection_count=5),
        Conversation(process_name="other", remote_ip="1.1.1.1", connection_count=1),
    ]
    traffic = _FakeTrafficRepo(
        [
            # zwei PIDs desselben Prozesses zur selben IP -> summiert
            RemoteIpTraffic(
                pid=1, process_name="chrome", remote_ip="8.8.8.8",
                bytes_sent=100, bytes_recv=200,
            ),
            RemoteIpTraffic(
                pid=2, process_name="chrome", remote_ip="8.8.8.8",
                bytes_sent=50, bytes_recv=0,
            ),
        ]
    )
    svc = ConversationService(repository=_FakeRepo(convs), traffic_repository=traffic)
    out = {c.process_name: c for c in svc.aggregate(hours=24)}
    assert out["chrome"].bytes_sent == 150
    assert out["chrome"].bytes_recv == 200
    assert out["other"].bytes_sent == 0  # keine ETW-Daten -> 0


def test_aggregate_ohne_traffic_repo_bytes_null() -> None:
    convs = [Conversation(process_name="x", remote_ip="1.2.3.4", connection_count=1)]
    out = ConversationService(repository=_FakeRepo(convs)).aggregate()
    assert out[0].bytes_sent == 0
    assert out[0].bytes_recv == 0
