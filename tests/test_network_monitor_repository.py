"""Tests für ConnectionHistoryRepository.

Prüft Insert + Query (Round-Trip) und die 24h-Retention.
Nutzt eine test-spezifische EncryptedDatabase unter einem eigenen Namen.
"""

from __future__ import annotations

import time

import pytest

from tools.network_monitor.data.connection_repository import (
    ConnectionHistoryRepository,
)
from tools.network_monitor.domain.models import ConnectionInfo


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """Frische, verschlüsselte Test-DB — pro Test isoliert."""
    # EncryptedDatabase legt die Datei unter ~/.finlai/db/ ab; für Tests
    # erzeugen wir einen zufälligen DB-Namen, um Kollisionen mit Prod
    # zu vermeiden.
    name = f"network_monitor_test_{int(time.time() * 1000)}"
    r = ConnectionHistoryRepository(db_name=name)
    return r


def _sample(
    remote_ip: str = "1.2.3.4",
    remote_port: int = 443,
    pid: int = 100,
    suspicious: bool = False,
) -> ConnectionInfo:
    return ConnectionInfo(
        remote_ip=remote_ip,
        remote_port=remote_port,
        local_port=55555,
        pid=pid,
        process_name="firefox",
        status="ESTABLISHED",
        suspicious=suspicious,
        suspicious_reason="test" if suspicious else "",
    )


class TestRoundTrip:
    def test_save_und_load_recent(self, repo) -> None:
        repo.save_snapshot([_sample()])
        rows = repo.load_recent(hours=1)
        assert len(rows) == 1
        ts, conn = rows[0]
        assert isinstance(ts, float)
        assert conn.remote_ip == "1.2.3.4"

    def test_mehrere_verbindungen_gespeichert(self, repo) -> None:
        conns = [_sample(remote_ip=f"1.2.3.{i}", pid=100 + i) for i in range(5)]
        repo.save_snapshot(conns)
        rows = repo.load_recent(hours=1)
        assert len(rows) == 5

    def test_leerer_snapshot_erzeugt_keine_zeilen(self, repo) -> None:
        repo.save_snapshot([])
        assert repo.load_recent(hours=24) == []


class TestRetention:
    def test_purge_loescht_alte_eintraege(self, repo) -> None:
        # Frischen Eintrag speichern
        repo.save_snapshot([_sample()])
        # Direkt mit manipuliertem Zeitstempel alten Eintrag einfügen
        with repo._db.connection() as conn:
            old_ts = time.time() - (48 * 3600)  # 48h alt
            conn.execute(
                "INSERT INTO connection_history "
                "(timestamp, remote_ip, remote_port, local_port, pid, "
                "process_name, status, suspicious, suspicious_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (old_ts, "9.9.9.9", 1, 2, 3, "alt", "X", 0, ""),
            )

        deleted = repo.purge_older_than(hours=24)
        assert deleted >= 1
        remaining = [r[1].remote_ip for r in repo.load_recent(hours=24)]
        assert "9.9.9.9" not in remaining


class TestAggregateConversations:
    """ Phase 5 — SQL-GROUP-BY zu (Prozess, Ziel-IP)-Konversationen."""

    def _conn(
        self,
        process_name: str,
        remote_ip: str,
        remote_port: int,
        *,
        local_port: int = 55555,
        suspicious: bool = False,
        status: str = "ESTABLISHED",
    ) -> ConnectionInfo:
        return ConnectionInfo(
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            pid=100,
            process_name=process_name,
            status=status,
            suspicious=suspicious,
            suspicious_reason="Feed-Treffer" if suspicious else "",
        )

    def test_gruppiert_nach_prozess_und_ip(self, repo) -> None:
        repo.save_snapshot(
            [
                self._conn("firefox", "1.2.3.4", 443),
                self._conn("firefox", "1.2.3.4", 8443, local_port=60000),
                self._conn("evil.exe", "9.9.9.9", 4444, suspicious=True),
            ]
        )
        convs = {(c.process_name, c.remote_ip): c for c in repo.aggregate_conversations(hours=1)}

        ff = convs[("firefox", "1.2.3.4")]
        assert ff.connection_count == 2
        assert ff.ports == (443, 8443)
        assert ff.statuses == ("ESTABLISHED",)
        assert ff.suspicious is False
        assert ff.last_seen >= ff.first_seen > 0

        evil = convs[("evil.exe", "9.9.9.9")]
        assert evil.connection_count == 1
        assert evil.ports == (4444,)
        assert evil.suspicious is True
        assert evil.suspicious_reason == "Feed-Treffer"

    def test_sortiert_nach_haeufigkeit(self, repo) -> None:
        repo.save_snapshot(
            [
                self._conn("a.exe", "1.1.1.1", 80),
                self._conn("b.exe", "2.2.2.2", 80),
                self._conn("b.exe", "2.2.2.2", 81, local_port=60001),
            ]
        )
        convs = repo.aggregate_conversations(hours=1)
        assert convs[0].process_name == "b.exe"  # 2 Verbindungen zuerst

    def test_leere_db_liefert_leere_liste(self, repo) -> None:
        assert repo.aggregate_conversations(hours=1) == []
