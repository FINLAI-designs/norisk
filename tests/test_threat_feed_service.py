"""Tests für threat_feed_service F-D).

Deckt die F-D-Verifikation ab: Feed-Update→Cache, TTL-Skip/Force, Merge aus
Blocklist+Feeds (Dedup), Whitelist-Override, **kein fail-open** und den opt-in
AbuseIPDB-Pfad (Consent + Key). Echte verschlüsselte Cache-DB, gefälschter
HTTP-/Feed-Client.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tools.network_monitor.application.threat_feed_service import ThreatFeedService
from tools.network_monitor.data.threat_feed_cache import ThreatFeedCacheRepository
from tools.network_monitor.data.threat_feed_client import (
    FeedFetchResult,
    parse_feed_text,
)
from tools.network_monitor.domain.models import FeedFormat, ThreatFeedSource

_SOURCE = ThreatFeedSource(
    key="test_feed",
    name="Test Feed",
    url="https://example.invalid/feed.txt",
    feed_format=FeedFormat.PLAINTEXT_IP,
    license_id="CC0-1.0",
    reason="Test-Feed",
)


class _FakeClient:
    """Liefert ein vorgegebenes Roh-Payload (oder einen Fehler) je fetch."""

    def __init__(self, payload: str | None = "9.9.9.9\n", ok: bool = True) -> None:
        self._payload = payload
        self._ok = ok
        self.fetch_count = 0

    def fetch(self, source: ThreatFeedSource) -> FeedFetchResult:
        self.fetch_count += 1
        if not self._ok:
            return FeedFetchResult(False, "", [], "Quelle nicht erreichbar")
        entries = parse_feed_text(self._payload or "", source.reason)
        return FeedFetchResult(True, self._payload or "", entries)


@pytest.fixture
def cache() -> ThreatFeedCacheRepository:
    name = f"network_monitor_feedsvc_test_{int(time.time() * 1_000_000)}"
    return ThreatFeedCacheRepository(db_name=name)


def _service(cache, client, *, ttl=3600.0, blocklist=None, whitelist=None):
    return ThreatFeedService(
        client=client,
        cache=cache,
        sources=(_SOURCE,),
        ttl_seconds=ttl,
        blocklist_path=blocklist,
        whitelist_path=whitelist,
    )


# ── update ────────────────────────────────────────────────────────────────


class TestUpdate:
    def test_update_fuellt_cache(self, cache) -> None:
        client = _FakeClient(payload="9.9.9.9\n8.8.8.8\n")
        result = _service(cache, client).update()
        assert result.updated_keys == ["test_feed"]
        assert client.fetch_count == 1
        cached = cache.load("test_feed")
        assert cached is not None and cached.entry_count == 2

    def test_ttl_skip_ohne_force(self, cache) -> None:
        client = _FakeClient()
        svc = _service(cache, client, ttl=3600.0)
        svc.update()  # befüllt
        result = svc.update()  # innerhalb TTL → skip
        assert result.skipped_keys == ["test_feed"]
        assert client.fetch_count == 1  # kein zweiter Download

    def test_force_laedt_neu(self, cache) -> None:
        client = _FakeClient()
        svc = _service(cache, client, ttl=3600.0)
        svc.update()
        svc.update(force=True)
        assert client.fetch_count == 2

    def test_fehler_laesst_cache_unveraendert(self, cache) -> None:
        # erst gut befüllen, dann Quelle ausfallen lassen
        good = _service(cache, _FakeClient(payload="9.9.9.9\n"), ttl=0.0)
        good.update()
        failing = _service(cache, _FakeClient(ok=False), ttl=0.0)
        result = failing.update()
        assert result.errors and result.errors[0][0] == "test_feed"
        # alter Stand bleibt erhalten (kein fail-open zu leerem Cache)
        cached = cache.load("test_feed")
        assert cached is not None and "9.9.9.9" in cached.raw_payload


# ── build_entries / build_checker ───────────────────────────────────────────


class TestBuild:
    def test_merge_blocklist_und_feed(self, cache, tmp_path: Path) -> None:
        bl = tmp_path / "blocklist.txt"
        bl.write_text("1.2.3.4\n", encoding="utf-8")
        client = _FakeClient(payload="9.9.9.9\n")
        svc = _service(cache, client, ttl=0.0, blocklist=bl)
        svc.update()
        entries = svc.build_entries()
        nets = {str(n) for n, _ in entries}
        assert "1.2.3.4/32" in nets  # lokal
        assert "9.9.9.9/32" in nets  # Feed

    def test_dedup_blocklist_gewinnt(self, cache, tmp_path: Path) -> None:
        bl = tmp_path / "blocklist.txt"
        bl.write_text("9.9.9.9 # lokaler Grund\n", encoding="utf-8")
        svc = _service(cache, _FakeClient(payload="9.9.9.9\n"), ttl=0.0, blocklist=bl)
        svc.update()
        entries = svc.build_entries()
        matches = [(str(n), r) for n, r in entries if str(n) == "9.9.9.9/32"]
        assert len(matches) == 1  # dedupliziert
        assert matches[0][1] == "lokaler Grund"  # Blocklist-Grund gewinnt

    def test_whitelist_override(self, cache, tmp_path: Path) -> None:
        bl = tmp_path / "blocklist.txt"
        bl.write_text("9.9.9.9\n", encoding="utf-8")
        wl = tmp_path / "whitelist.txt"
        wl.write_text("9.9.9.9\n", encoding="utf-8")
        svc = _service(
            cache, _FakeClient(payload=""), ttl=0.0, blocklist=bl, whitelist=wl
        )
        checker = svc.build_checker()
        # 9.9.9.9 ist geblockt UND gewhitelistet → Override gewinnt
        assert checker.is_suspicious("9.9.9.9") == (False, "")

    def test_refresh_snapshot_aggregiert(self, cache, tmp_path: Path) -> None:
        # geteilte Orchestrierung von periodischem + One-Shot-Worker.
        bl = tmp_path / "blocklist.txt"
        bl.write_text("1.2.3.4\n", encoding="utf-8")
        wl = tmp_path / "whitelist.txt"
        wl.write_text("9.9.9.9\n", encoding="utf-8")
        svc = _service(
            cache, _FakeClient(payload="9.9.9.9\n"), ttl=0.0, blocklist=bl, whitelist=wl
        )
        snap = svc.refresh_snapshot(force=True)
        nets = {str(n) for n, _ in snap.entries}
        assert "1.2.3.4/32" in nets and "9.9.9.9/32" in nets
        assert [str(n) for n in snap.whitelist] == ["9.9.9.9/32"]
        assert snap.updated_count == 1
        assert snap.error_count == 0

    def test_refresh_snapshot_zaehlt_fehler(self, cache) -> None:
        svc = _service(cache, _FakeClient(ok=False), ttl=0.0)
        snap = svc.refresh_snapshot(force=True)
        assert snap.error_count == 1
        assert snap.updated_count == 0

    def test_kein_fail_open_bei_muell_feed(self, cache, tmp_path: Path) -> None:
        # Isolierte (leere) Blocklist, damit die Aussage unabhängig vom
        # ausgelieferten data/blocklist.txt-Default gilt (Review F-D #3).
        empty_bl = tmp_path / "empty.txt"
        empty_bl.write_text("", encoding="utf-8")
        svc = _service(
            cache,
            _FakeClient(payload="voll-muell\nkeine-ip\n"),
            ttl=0.0,
            blocklist=empty_bl,
        )
        svc.update()
        checker = svc.build_checker()
        assert checker.entry_count() == 0
        assert checker.is_suspicious("9.9.9.9") == (False, "")


# ── AbuseIPDB (opt-in) ───────────────────────────────────────────────────────


class TestAbuseIpdb:
    def test_ohne_consent_nichts(self, cache) -> None:
        svc = _service(cache, _FakeClient())
        assert svc.abuseipdb_lookup("1.2.3.4", consent=False) == (False, "")

    def test_ohne_key_nichts(self, cache, monkeypatch) -> None:
        svc = _service(cache, _FakeClient())
        monkeypatch.setattr(svc, "_load_abuseipdb_key", lambda: None)
        assert svc.abuseipdb_lookup("1.2.3.4", consent=True) == (False, "")
        assert svc.abuseipdb_available() is False

    def test_mit_key_und_consent_hoher_score(self, cache, monkeypatch) -> None:
        svc = _service(cache, _FakeClient())
        monkeypatch.setattr(svc, "_load_abuseipdb_key", lambda: "fake-key")

        class _Resp:
            @staticmethod
            def json():
                return {"data": {"abuseConfidenceScore": 90}}

        class _Http:
            @staticmethod
            def get(*a, **k):
                return _Resp()

        monkeypatch.setattr(
            "tools.network_monitor.application.threat_feed_service.get_http_client",
            lambda: _Http(),
        )
        suspicious, reason = svc.abuseipdb_lookup("1.2.3.4", consent=True)
        assert suspicious is True
        assert "90" in reason

    def test_niedriger_score_nicht_verdaechtig(self, cache, monkeypatch) -> None:
        svc = _service(cache, _FakeClient())
        monkeypatch.setattr(svc, "_load_abuseipdb_key", lambda: "fake-key")

        class _Resp:
            @staticmethod
            def json():
                return {"data": {"abuseConfidenceScore": 3}}

        monkeypatch.setattr(
            "tools.network_monitor.application.threat_feed_service.get_http_client",
            lambda: type("H", (), {"get": staticmethod(lambda *a, **k: _Resp())})(),
        )
        assert svc.abuseipdb_lookup("1.2.3.4", consent=True) == (False, "")
