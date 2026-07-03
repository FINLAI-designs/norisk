"""
test_patch_eol_resolver — Tests fuer Stop-Step A +.

Deckt:
    *:class:`EolStatus` — Dataclass-Frozen-Verhalten + ``not_eol``-
      Sentinel.
    *:class:`CuratedEolResolver` — Match-Pfade fuer alle kuratierten
      Eintraege (Windows 7, Office 2010, Flash, Python 2, IE 11, etc.)
    * Edge-Cases: kein Match, leere Inputs, falscher Vendor.
    * Protocol-Konformitaet::class:`IEolResolver` ist ein
      ``runtime_checkable`` Protocol — Tests verifizieren das.
    *::class:`EndoflifeApiResolver` Full-Pipeline mit Mock-HTTP,
      Cache-Hit/Miss/Stale, Rate-Limit-Blocking, Slug-Lookup-Tiers,
      Cycle-Version-Matching, defensives Verhalten bei API-Fehlern.
    *::class:`_TokenBucket` Burst + Refill.
    *::func:`_load_product_map`,:func:`_match_version_to_eol`.
"""

from __future__ import annotations

import json

import pytest

from core.patch_eol_resolver import (
    CuratedEolResolver,
    EndoflifeApiResolver,
    EolStatus,
    IEolResolver,
    _CuratedEntry,
    _load_product_map,
    _match_version_to_eol,
    _TokenBucket,
)

# ---------------------------------------------------------------------------
# EolStatus
# ---------------------------------------------------------------------------


class TestEolStatus:
    def test_not_eol_returns_default_state(self) -> None:
        s = EolStatus.not_eol()
        assert s.is_eol is False
        assert s.cycle is None
        assert s.eol_date is None
        assert s.replacement is None
        assert s.source == ""

    def test_frozen_dataclass_blocks_mutation(self) -> None:
        s = EolStatus.not_eol()
        from dataclasses import FrozenInstanceError

        with pytest.raises(FrozenInstanceError):
            s.is_eol = True  # type: ignore[misc]

    def test_full_construction(self) -> None:
        s = EolStatus(
            is_eol=True,
            cycle="Test Cycle",
            eol_date="2020-01-01",
            replacement="Test Replacement",
            source="test:foo",
        )
        assert s.is_eol is True
        assert s.cycle == "Test Cycle"
        assert s.eol_date == "2020-01-01"
        assert s.replacement == "Test Replacement"
        assert s.source == "test:foo"


# ---------------------------------------------------------------------------
# CuratedEolResolver — Match-Pfade
# ---------------------------------------------------------------------------


class TestCuratedEolResolverMatches:
    """Pro kuratiertem Eintrag ein positiver Test — verhindert dass die
    Liste durch Refactoring schlechter wird."""

    def test_windows_7_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "windows", "6.1.7601")
        assert status.is_eol is True
        assert "Windows 7" in (status.cycle or "")
        assert status.eol_date == "2020-01-14"
        assert status.source == "curated:windows_7"

    def test_windows_8_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "windows", "6.2.9200")
        assert status.is_eol is True
        assert "Windows 8" in (status.cycle or "")
        assert status.source == "curated:windows_8"

    def test_windows_8_1_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "windows", "6.3.9600")
        assert status.is_eol is True
        assert "Windows 8.1" in (status.cycle or "")

    def test_office_2007_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "office", "12.0.4518")
        assert status.is_eol is True
        assert "Office 2007" in (status.cycle or "")

    def test_office_2010_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "office", "14.0.7184")
        assert status.is_eol is True
        assert "Office 2010" in (status.cycle or "")
        assert "Microsoft 365" in (status.replacement or "")

    def test_office_2013_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "office", "15.0.5371")
        assert status.is_eol is True
        assert "Office 2013" in (status.cycle or "")

    def test_internet_explorer_11_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "internet_explorer", "11.0.19041")
        assert status.is_eol is True
        assert "Internet Explorer" in (status.cycle or "")
        assert "Edge" in (status.replacement or "")

    def test_flash_matches_any_version(self) -> None:
        resolver = CuratedEolResolver()
        # Version-Prefix ist leer → jede Version matcht
        for version in ("10.0", "32.0.0.465", "0.1"):
            status = resolver.resolve("adobe", "flash", version)
            assert status.is_eol is True, f"Flash {version} sollte EOL sein"

    def test_python_2_matches_without_vendor(self) -> None:
        """Python ist Open-Source: Eintrag hat ``vendor=None``, matcht
        unabhaengig vom Input-Vendor."""
        resolver = CuratedEolResolver()
        # Vendor irrelevant
        status = resolver.resolve("python_software_foundation", "python", "2.7.18")
        assert status.is_eol is True
        assert "Python 2" in (status.cycle or "")
        # Auch wenn kein Vendor angegeben:
        status = resolver.resolve(None, "python", "2.6.0")
        assert status.is_eol is True

    def test_vcredist_2008_matches(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "vcredist", "9.0.30729")
        assert status.is_eol is True
        assert "2008" in (status.cycle or "")


# ---------------------------------------------------------------------------
# CuratedEolResolver — Negative / Edge Cases
# ---------------------------------------------------------------------------


class TestCuratedEolResolverNegatives:
    def test_modern_windows_does_not_match(self) -> None:
        resolver = CuratedEolResolver()
        # Windows 10 (10.x), 11 (10.x) sind NICHT EOL
        status = resolver.resolve("microsoft", "windows", "10.0.19045")
        assert status.is_eol is False
        assert status.source == ""

    def test_modern_office_does_not_match(self) -> None:
        resolver = CuratedEolResolver()
        # Office 2016+ (16.x), 365
        status = resolver.resolve("microsoft", "office", "16.0.16130")
        assert status.is_eol is False

    def test_wrong_vendor_no_match(self) -> None:
        """Office-Version 14.x von einem anderen Vendor matcht nicht."""
        resolver = CuratedEolResolver()
        status = resolver.resolve("notmicrosoft", "office", "14.0.0")
        assert status.is_eol is False

    def test_unknown_product_no_match(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "edge", "120.0.0")
        assert status.is_eol is False

    def test_empty_product_returns_not_eol(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "", "1.0")
        assert status.is_eol is False

    def test_python_3_does_not_match_python_2_entry(self) -> None:
        resolver = CuratedEolResolver()
        status = resolver.resolve(None, "python", "3.12.0")
        assert status.is_eol is False

    def test_product_with_spaces_normalized(self) -> None:
        """Input 'Internet Explorer' (mit Space) matcht 'internet_explorer'."""
        resolver = CuratedEolResolver()
        status = resolver.resolve("microsoft", "Internet Explorer", "11.0.0")
        assert status.is_eol is True


class TestCuratedEolResolverInjection:
    """Custom-Entries injection — Tests duerfen die Produktiv-Liste nicht
    mutieren."""

    def test_custom_entries_isolate_test_from_production_list(self) -> None:
        custom = (
            _CuratedEntry(
                vendor="testvendor",
                product_match="testapp",
                version_prefix="1.",
                cycle="TestCycle",
                eol_date="2099-01-01",
                replacement="TestReplacement",
                source_key="test:testapp",
            ),
        )
        resolver = CuratedEolResolver(entries=custom)

        # Match-Pfad: nur Test-Eintraege
        status = resolver.resolve("testvendor", "testapp", "1.0.0")
        assert status.is_eol is True
        assert status.source == "test:testapp"

        # Produktiv-Eintraege NICHT verfuegbar
        status_no = resolver.resolve("microsoft", "windows", "6.1.7601")
        assert status_no.is_eol is False


# ---------------------------------------------------------------------------
# Protocol-Konformitaet
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_curated_resolver_implements_protocol(self) -> None:
        assert isinstance(CuratedEolResolver(), IEolResolver)

    def test_endoflife_resolver_implements_protocol(self) -> None:
        # Construction mit Mock-Map verhindert Disk-Read + Cache-DB-Open.
        resolver = _make_resolver(product_map={"microsoft:windows": "windows"})
        assert isinstance(resolver, IEolResolver)


# ---------------------------------------------------------------------------
# _TokenBucket
# ---------------------------------------------------------------------------


class _ManualClock:
    """Deterministische Test-Uhr."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestTokenBucket:
    def test_initial_burst_capacity(self) -> None:
        clock = _ManualClock()
        bucket = _TokenBucket(burst=3, refill_interval_s=1.0, now_fn=clock)
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        # 4. Versuch ohne Zeit-Fortschritt → False
        assert bucket.try_acquire() is False

    def test_refill_after_interval(self) -> None:
        clock = _ManualClock()
        bucket = _TokenBucket(burst=2, refill_interval_s=1.0, now_fn=clock)
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False
        # Eine Sekunde spaeter → ein Token nachgefuellt
        clock.advance(1.0)
        assert bucket.try_acquire() is True
        # Aber sofort danach wieder leer (Refill war nur 1 Token)
        assert bucket.try_acquire() is False

    def test_refill_capped_at_burst(self) -> None:
        clock = _ManualClock()
        bucket = _TokenBucket(burst=2, refill_interval_s=1.0, now_fn=clock)
        # Bucket ist voll. 100s warten → Refill begrenzt auf Burst=2
        clock.advance(100.0)
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False


# ---------------------------------------------------------------------------
# _match_version_to_eol
# ---------------------------------------------------------------------------


class TestMatchVersionToEol:
    def test_empty_cycles_returns_not_eol(self) -> None:
        assert _match_version_to_eol([], "1.0", "test").is_eol is False

    def test_no_matching_cycle_returns_not_eol(self) -> None:
        cycles = [{"cycle": "16.0", "eol": True}]
        assert _match_version_to_eol(cycles, "14.0", "office").is_eol is False

    def test_cycle_with_bool_eol_true(self) -> None:
        cycles = [{"cycle": "14", "eol": True}]
        status = _match_version_to_eol(cycles, "14.0.7184", "office")
        assert status.is_eol is True
        assert status.source == "endoflife.date:office:14"
        assert "14" in (status.cycle or "")

    def test_cycle_with_bool_eol_false(self) -> None:
        cycles = [{"cycle": "16", "eol": False}]
        status = _match_version_to_eol(cycles, "16.0.1", "office")
        assert status.is_eol is False

    def test_cycle_with_past_eol_date(self) -> None:
        cycles = [{"cycle": "14", "eol": "2020-10-13"}]
        status = _match_version_to_eol(cycles, "14.0.7184", "office")
        assert status.is_eol is True
        assert status.eol_date == "2020-10-13"

    def test_cycle_with_future_eol_date(self) -> None:
        cycles = [{"cycle": "14", "eol": "2099-12-31"}]
        status = _match_version_to_eol(cycles, "14.0.7184", "office")
        assert status.is_eol is False

    def test_longest_prefix_wins(self) -> None:
        """Wenn '16' und '16.0' beide matchen, gewinnt der laengere."""
        cycles = [
            {"cycle": "16", "eol": False},
            {"cycle": "16.0", "eol": True},
        ]
        status = _match_version_to_eol(cycles, "16.0.16130", "office")
        assert status.is_eol is True
        assert status.cycle is not None and "16.0" in status.cycle

    def test_major_boundary_check_blocks_false_match(self) -> None:
        """Regression: Cycle '16' darf NICHT auf Version '160.0' matchen
        (Review-P1-2: Major-Versions-Grenze fehlte)."""
        cycles = [{"cycle": "16", "eol": True}]
        status = _match_version_to_eol(cycles, "160.0.0", "office")
        assert status.is_eol is False

    def test_exact_cycle_version_match(self) -> None:
        """Installed-Version == Cycle-String soll matchen."""
        cycles = [{"cycle": "16.0", "eol": True}]
        status = _match_version_to_eol(cycles, "16.0", "office")
        assert status.is_eol is True

    def test_boundary_allows_dash_separator(self) -> None:
        """Manche Vendor-Versionen nutzen ``-`` als Trenner (z. B.
        ``"22.04-LTS"`` fuer Ubuntu)."""
        cycles = [{"cycle": "22.04", "eol": True}]
        status = _match_version_to_eol(cycles, "22.04-LTS", "ubuntu")
        assert status.is_eol is True

    def test_invalid_eol_date_returns_not_eol(self) -> None:
        cycles = [{"cycle": "14", "eol": "kein-datum"}]
        status = _match_version_to_eol(cycles, "14.0.0", "office")
        assert status.is_eol is False

    def test_missing_cycle_field_is_ignored(self) -> None:
        cycles = [{"eol": True}, {"cycle": "14", "eol": True}]
        status = _match_version_to_eol(cycles, "14.0", "office")
        assert status.is_eol is True


# ---------------------------------------------------------------------------
# _load_product_map
# ---------------------------------------------------------------------------


class TestLoadProductMap:
    def test_missing_file_returns_empty_dict(self) -> None:
        result = _load_product_map("nonexistent_path_xyz.json")
        assert result == {}

    def test_path_traversal_outside_repo_returns_empty(self) -> None:
        """Ein Pfad der nicht relativ zum Repo-Root aufloesen kann
        liefert ein leeres Mapping (kein Crash)."""
        result = _load_product_map("__missing__/__nope__.json")
        assert result == {}

    def test_slug_whitelist_rejects_invalid_values(self, tmp_path, monkeypatch) -> None:
        """Slugs die nicht ``[a-z0-9.\\-]+`` matchen werden gefiltert
        (URL-Injection-Schutz, Security-Review)."""
        import json
        from pathlib import Path

        # Wir simulieren das Bundle-Path-Mapping ueber das frozen-Flag.
        bundle = tmp_path / "bundle"
        bundle.mkdir()
        config_dir = bundle / "configs"
        config_dir.mkdir()
        bad_map = {
            "microsoft:good": "windows",
            "microsoft:bad_slash": "../etc/passwd",
            "microsoft:bad_url": "https://evil.com/x",
            "microsoft:bad_upper": "Windows",
            "_comment": "comments stay",
        }
        config_path = config_dir / "map.json"
        config_path.write_text(json.dumps(bad_map), encoding="utf-8")

        import sys as _sys
        monkeypatch.setattr(_sys, "frozen", True, raising=False)
        monkeypatch.setattr(_sys, "_MEIPASS", str(bundle), raising=False)

        result = _load_product_map("configs/map.json")
        assert result == {
            "microsoft:good": "windows",
            "_comment": "comments stay",
        }
        # Pfad-Annahme: Bundle-Logik wurde aktiviert
        assert Path(_sys._MEIPASS).exists()

    def test_loads_valid_production_map(self) -> None:
        """Produktive endoflife_product_map.json wird geladen."""
        result = _load_product_map("core/data/endoflife_product_map.json")
        assert "microsoft:windows" in result
        assert result["microsoft:windows"] == "windows"
        # Comment-Keys (_comment, _schema, _source) sind als String-Values
        # dabei — werden vom _lookup_slug aber gefiltert.
        assert all(isinstance(v, str) for v in result.values())

    def test_production_map_has_no_substring_conflict(self) -> None:
        """Regression-Test (Review P1-2): die produktive Map darf bei
        keinem realistischen Input einen falschen Slug liefern."""
        from core.patch_eol_resolver import EndoflifeApiResolver

        resolver = EndoflifeApiResolver(
            cache=_FakeCache(),
            rate_limiter=_AlwaysAllowLimiter(),
            http_get=lambda url, t: "[]",
        )
        # windows_server_2019 muss windows-server treffen, nicht windows.
        assert (
            resolver._lookup_slug("microsoft", "windows_server_2019")  # noqa: SLF001
            == "windows-server"
        )


# ---------------------------------------------------------------------------
# EndoflifeApiResolver Pipeline
# ---------------------------------------------------------------------------


class _FakeCacheEntry:
    def __init__(self, cycles, is_stale: bool) -> None:
        self.cycles = cycles
        self.is_stale = is_stale


class _FakeCache:
    """Test-Cache ohne SQLCipher — vermeidet DB-Setup in den Pipeline-Tests."""

    def __init__(self) -> None:
        self._store: dict[str, _FakeCacheEntry] = {}
        self.set_calls: list[tuple[str, list]] = []
        self.set_raises: Exception | None = None

    def get(self, slug: str):
        return self._store.get(slug)

    def set(self, slug: str, cycles) -> None:
        self.set_calls.append((slug, cycles))
        if self.set_raises is not None:
            raise self.set_raises
        self._store[slug] = _FakeCacheEntry(cycles, is_stale=False)

    def preload(self, slug: str, cycles, *, stale: bool = False) -> None:
        self._store[slug] = _FakeCacheEntry(cycles, is_stale=stale)


class _AlwaysAllowLimiter:
    def try_acquire(self) -> bool:
        return True


class _AlwaysBlockLimiter:
    def try_acquire(self) -> bool:
        return False


def _make_resolver(
    *,
    product_map: dict[str, str] | None = None,
    cache: _FakeCache | None = None,
    rate_limiter=None,
    http_get=None,
) -> EndoflifeApiResolver:
    return EndoflifeApiResolver(
        cache=cache or _FakeCache(),
        rate_limiter=rate_limiter or _AlwaysAllowLimiter(),
        url_template="https://test/{slug}.json",
        product_map=product_map or {},
        http_get=http_get or (lambda url, t: "[]"),
    )


class TestEndoflifeResolverLookupSlug:
    def test_exact_vendor_product_match(self) -> None:
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
        )
        # Wenn der HTTP-Call einen leeren Cycle-Array liefert, ist resolve
        # not_eol — aber der Slug-Lookup hat geklappt (kein not_eol-Early-Exit).
        # Wir testen das indirekt durch das Vorhandensein des HTTP-Calls.
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        resolver.resolve("microsoft", "windows", "10.0")
        assert calls == ["https://test/windows.json"]

    def test_vendor_free_lookup(self) -> None:
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={":python": "python"},
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        # Auch mit Vendor-Angabe matcht der:python-Eintrag
        resolver.resolve("python_software_foundation", "python", "3.12")
        assert calls == ["https://test/python.json"]

    def test_substring_match_in_product_name(self) -> None:
        calls: list[str] = []
        resolver = _make_resolver(
            # Map enthaelt nur "microsoft:windows_server" — der Input
            # "windows_server_2019" enthaelt diesen Substring.
            product_map={"microsoft:windows_server": "windows-server"},
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        resolver.resolve("microsoft", "windows_server_2019", "10.0")
        assert calls == ["https://test/windows-server.json"]

    def test_unknown_product_returns_not_eol_without_http(self) -> None:
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        status = resolver.resolve("acme", "frobnicator", "1.0")
        assert status.is_eol is False
        assert calls == []  # kein HTTP-Call wenn slug nicht gemappt

    def test_empty_product_returns_not_eol(self) -> None:
        resolver = _make_resolver(product_map={"microsoft:windows": "windows"})
        assert resolver.resolve("microsoft", "", "1.0").is_eol is False

    def test_comment_keys_ignored_in_substring_match(self) -> None:
        """_comment/_schema/_source-Keys duerfen nicht in Slug-Matching landen."""
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={
                "_comment": "blah",
                "_schema": "blah",
                "microsoft:windows": "windows",
            },
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        resolver.resolve("microsoft", "windows", "10.0")
        assert calls == ["https://test/windows.json"]

    def test_longest_substring_match_wins_over_shorter(self) -> None:
        """Regression: ``windows_server_2019`` darf NICHT als Slug
        ``windows`` aufloesen — der laengere ``windows_server`` muss
        gewinnen (Review-P1-2)."""
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={
                # Reihenfolge bewusst: "windows" zuerst → wuerde mit alter
                # First-Match-Logik gewinnen.
                "microsoft:windows": "windows",
                "microsoft:windows_server": "windows-server",
            },
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        resolver.resolve("microsoft", "windows_server_2019", "10.0")
        assert calls == ["https://test/windows-server.json"]

    def test_longest_match_wins_reversed_dict_order(self) -> None:
        """Auch wenn die Map den Server-Eintrag ZUERST hat, gewinnt der
        Substring-Tier weiter den laengsten Match (Symmetrie-Pruefung)."""
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={
                "microsoft:windows_server": "windows-server",
                "microsoft:windows": "windows",
            },
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        resolver.resolve("microsoft", "windows_server_2019", "10.0")
        assert calls == ["https://test/windows-server.json"]


class TestEndoflifeResolverCachePipeline:
    def test_cache_hit_skips_http(self) -> None:
        cache = _FakeCache()
        cache.preload(
            "windows",
            [{"cycle": "7", "eol": True}],
            stale=False,
        )
        calls: list[str] = []
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            http_get=lambda url, t: (calls.append(url) or "[]"),
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True
        assert calls == []  # kein HTTP-Call bei Cache-Hit

    def test_cache_miss_fetches_and_caches(self) -> None:
        cache = _FakeCache()
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            http_get=lambda url, t: json.dumps(
                [{"cycle": "7", "eol": "2020-01-14"}]
            ),
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True
        assert len(cache.set_calls) == 1
        assert cache.set_calls[0][0] == "windows"

    def test_stale_cache_refreshes(self) -> None:
        cache = _FakeCache()
        cache.preload(
            "windows",
            [{"cycle": "7", "eol": False}],
            stale=True,
        )
        # Stale → HTTP-Fetch laeuft, neue Daten ueberschreiben Cache
        fresh = [{"cycle": "7", "eol": "2020-01-14"}]
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            http_get=lambda url, t: json.dumps(fresh),
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True  # frische Daten haben EOL=True
        assert len(cache.set_calls) == 1

    def test_rate_limit_blocked_falls_back_to_stale(self) -> None:
        cache = _FakeCache()
        cache.preload(
            "windows",
            [{"cycle": "7", "eol": True}],
            stale=True,
        )
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            rate_limiter=_AlwaysBlockLimiter(),
            http_get=lambda url, t: (_ for _ in ()).throw(
                AssertionError("Rate-Limit-blocked sollte HTTP nicht aufrufen")
            ),
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True  # Stale-Cache wurde genutzt

    def test_rate_limit_blocked_without_cache_returns_not_eol(self) -> None:
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=_FakeCache(),
            rate_limiter=_AlwaysBlockLimiter(),
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is False


class TestEndoflifeResolverDefensive:
    def test_http_exception_returns_not_eol(self) -> None:
        def raise_http(_url: str, _t: float) -> str:
            raise OSError("Netzwerk weg")

        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            http_get=raise_http,
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is False

    def test_http_exception_with_stale_cache_uses_stale(self) -> None:
        cache = _FakeCache()
        cache.preload(
            "windows",
            [{"cycle": "7", "eol": True}],
            stale=True,
        )

        def raise_http(_url: str, _t: float) -> str:
            raise OSError("Netzwerk weg")

        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            http_get=raise_http,
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True  # Stale-Fallback

    def test_invalid_json_returns_not_eol(self) -> None:
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            http_get=lambda url, t: "not-valid-json{",
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is False

    def test_non_list_json_returns_not_eol(self) -> None:
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            http_get=lambda url, t: '{"unexpected": "object"}',
        )
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is False

    def test_cache_write_failure_does_not_crash(self) -> None:
        cache = _FakeCache()
        cache.set_raises = RuntimeError("Disk voll")
        resolver = _make_resolver(
            product_map={"microsoft:windows": "windows"},
            cache=cache,
            http_get=lambda url, t: json.dumps(
                [{"cycle": "7", "eol": True}]
            ),
        )
        # Trotz Cache-Schreib-Fehler liefert resolve ein korrektes Result
        status = resolver.resolve("microsoft", "windows", "7.0.0")
        assert status.is_eol is True
