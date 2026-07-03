"""
test_patch_eol_cache — Tests fuer SQLCipher-Cache.

Deckt:
    * Schema-Initialisierung (PRAGMA user_version).
    * get/set Roundtrip.
    * TTL: frischer Eintrag → is_stale=False; alter Eintrag → True.
    * purge_stale loescht alte Eintraege.
    * Kaputtes JSON in der DB → get returnt None (kein Crash).
    * Empty-Slug-Aufrufe (get/set) — no-op.
"""

from __future__ import annotations

import time  # noqa: F401 # genutzt in direct-DB-injection-Tests

from core.patch_eol_cache import (
    DEFAULT_TTL_SECONDS,
    EolCacheRepository,
)


class TestEolCacheRepository:
    def test_schema_version_initialized(self) -> None:
        repo = EolCacheRepository()
        assert repo.get_schema_version() == 1

    def test_roundtrip_set_and_get(self) -> None:
        repo = EolCacheRepository()
        cycles = [
            {"cycle": "7", "eol": "2020-01-14", "latest": "7.0"},
            {"cycle": "10", "eol": False},
        ]
        repo.set("windows", cycles)
        entry = repo.get("windows")
        assert entry is not None
        assert entry.is_stale is False
        assert entry.cycles == cycles

    def test_get_missing_slug_returns_none(self) -> None:
        repo = EolCacheRepository()
        assert repo.get("nonexistent-product") is None

    def test_get_empty_slug_returns_none(self) -> None:
        repo = EolCacheRepository()
        assert repo.get("") is None

    def test_set_empty_slug_is_noop(self) -> None:
        repo = EolCacheRepository()
        repo.set("", [{"cycle": "1"}])
        assert repo.get("") is None

    def test_stale_after_ttl_expiry(self) -> None:
        # TTL = -1 → jeder Eintrag (age >= 0) ist sofort stale, ohne dass
        # der Test eine ganze Sekunde warten muss.
        repo = EolCacheRepository(ttl_seconds=-1)
        repo.set("windows", [{"cycle": "7"}])
        entry = repo.get("windows")
        assert entry is not None
        assert entry.is_stale is True

    def test_fresh_within_ttl(self) -> None:
        repo = EolCacheRepository(ttl_seconds=3600)
        repo.set("windows", [{"cycle": "7"}])
        entry = repo.get("windows")
        assert entry is not None
        assert entry.is_stale is False

    def test_set_overwrites_existing_entry(self) -> None:
        repo = EolCacheRepository()
        repo.set("windows", [{"cycle": "7", "eol": False}])
        repo.set("windows", [{"cycle": "11", "eol": False}])
        entry = repo.get("windows")
        assert entry is not None
        assert entry.cycles == [{"cycle": "11", "eol": False}]

    def test_purge_stale_removes_old_entries(self) -> None:
        repo = EolCacheRepository()
        repo.set("windows", [{"cycle": "7"}])
        # purge_stale mit max_age=-1 → cutoff = now+1, jeder Eintrag (fetched
        # vor "jetzt") wird geloescht.
        deleted = repo.purge_stale(max_age_seconds=-1)
        assert deleted == 1
        assert repo.get("windows") is None

    def test_purge_stale_keeps_fresh_entries(self) -> None:
        repo = EolCacheRepository()
        repo.set("windows", [{"cycle": "7"}])
        # max_age=3600 → frischer Eintrag bleibt
        deleted = repo.purge_stale(max_age_seconds=3600)
        assert deleted == 0
        assert repo.get("windows") is not None

    def test_default_ttl_is_24h(self) -> None:
        assert DEFAULT_TTL_SECONDS == 24 * 60 * 60

    def test_corrupt_cycles_json_returns_none(self) -> None:
        """Wenn die DB durch externes Tooling kaputt geht, soll get
        None zurueckgeben statt zu crashen."""
        repo = EolCacheRepository()
        # Direkt JSON-Garbage in die DB schreiben (umgeht repo.set).
        with repo._db.connection() as conn:  # noqa: SLF001 — Test-Inspektion
            conn.execute(
                "INSERT INTO eol_cache (product_slug, cycles_json, fetched_at) "
                "VALUES (?, ?, ?)",
                ("broken", "{not json", int(time.time())),
            )
        assert repo.get("broken") is None

    def test_non_list_cycles_json_normalized_to_empty(self) -> None:
        """Falls aus irgendeinem Grund ein Objekt statt einer Liste in der
        DB landet (Schema-Drift), soll get leere cycles liefern."""
        repo = EolCacheRepository()
        with repo._db.connection() as conn:  # noqa: SLF001
            conn.execute(
                "INSERT INTO eol_cache (product_slug, cycles_json, fetched_at) "
                "VALUES (?, ?, ?)",
                ("obj", '{"not": "a list"}', int(time.time())),
            )
        entry = repo.get("obj")
        assert entry is not None
        assert entry.cycles == []
