"""Tests für threat_feed_cache F-D).

Prüft Save/Load-Round-Trip, Upsert (Überschreiben), load_all und age_seconds
gegen die echte verschlüsselte Test-DB (globaler KeyManager-Bootstrap).
"""

from __future__ import annotations

import time

import pytest

from tools.network_monitor.data.threat_feed_cache import ThreatFeedCacheRepository


@pytest.fixture
def cache() -> ThreatFeedCacheRepository:
    """Frische, verschlüsselte Test-DB unter eindeutigem Namen (pro Test isoliert)."""
    name = f"network_monitor_feedcache_test_{int(time.time() * 1_000_000)}"
    return ThreatFeedCacheRepository(db_name=name)


class TestThreatFeedCache:
    def test_save_load_roundtrip(self, cache: ThreatFeedCacheRepository) -> None:
        cache.save("feodo", "1.2.3.4\n10.0.0.0/8\n", entry_count=2)
        loaded = cache.load("feodo")
        assert loaded is not None
        assert loaded.key == "feodo"
        assert loaded.raw_payload == "1.2.3.4\n10.0.0.0/8\n"
        assert loaded.entry_count == 2
        assert loaded.fetched_at > 0

    def test_load_unbekannt_ist_none(self, cache: ThreatFeedCacheRepository) -> None:
        assert cache.load("gibt-es-nicht") is None

    def test_upsert_ueberschreibt(self, cache: ThreatFeedCacheRepository) -> None:
        cache.save("feodo", "1.2.3.4\n", entry_count=1)
        cache.save("feodo", "9.9.9.9\n8.8.8.8\n", entry_count=2)
        loaded = cache.load("feodo")
        assert loaded is not None
        assert loaded.entry_count == 2
        assert "9.9.9.9" in loaded.raw_payload
        # kein Duplikat: load_all führt die Quelle nur einmal
        keys = [c.key for c in cache.load_all()]
        assert keys.count("feodo") == 1

    def test_load_all(self, cache: ThreatFeedCacheRepository) -> None:
        cache.save("a", "1.1.1.1\n", 1)
        cache.save("b", "2.2.2.2\n", 1)
        keys = sorted(c.key for c in cache.load_all())
        assert keys == ["a", "b"]

    def test_save_many_bulk(self, cache: ThreatFeedCacheRepository) -> None:
        # Perf P0a: mehrere Quellen in EINER Verbindung.
        cache.save_many(
            [("a", "1.1.1.1\n", 1), ("b", "2.2.2.2\n3.3.3.3\n", 2)]
        )
        loaded = {c.key: c for c in cache.load_all()}
        assert set(loaded) == {"a", "b"}
        assert loaded["b"].entry_count == 2

    def test_save_many_upsert(self, cache: ThreatFeedCacheRepository) -> None:
        cache.save("a", "old\n", 1)
        cache.save_many([("a", "new\n9.9.9.9\n", 2)])
        loaded = cache.load("a")
        assert loaded is not None
        assert loaded.entry_count == 2
        assert "9.9.9.9" in loaded.raw_payload

    def test_save_many_leer_ist_noop(self, cache: ThreatFeedCacheRepository) -> None:
        cache.save_many([])
        assert cache.load_all() == []

    def test_age_seconds(self, cache: ThreatFeedCacheRepository) -> None:
        assert cache.age_seconds("fehlt") is None
        cache.save("frisch", "1.2.3.4\n", 1)
        age = cache.age_seconds("frisch")
        assert age is not None
        assert 0.0 <= age < 5.0
