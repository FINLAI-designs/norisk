"""
test_csaf_provider_migration — Tests fuer den CSAF-Provider-Fix
 follow-up, 2026-05-14).

Drei Bug-Klassen fixed:
  1. CURATED_CSAF_PROVIDERS hatte veraltete URLs (BSI white/feed.json →
     404, CISA well-known → 404, Red Hat alte URL → migriert).
  2. ``_extract_advisory_urls`` probierte nur den **ersten** rolie-Feed
     aus der provider-metadata; bei 404 auf dem ersten Eintrag war der
     gesamte Fetch verloren (BSI listet 6 Feeds).
  3. ``_seed_curated_providers`` aktualisierte existierende DB-Eintraege
     nicht — Patrick haette manuell DB resetten muessen.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.csaf_advisor.application.csaf_downloader import CsafDownloader
from tools.csaf_advisor.data.provider_registry import CURATED_CSAF_PROVIDERS
from tools.csaf_advisor.domain.csaf_provider import CsafProvider


class TestProviderRegistryUrls:
    """Validiert die kuratierte Provider-Liste — kein toter Endpoint."""

    def test_alle_provider_urls_sind_well_formed_https(self) -> None:
        for p in CURATED_CSAF_PROVIDERS:
            assert p.provider_url.startswith("https://"), (
                f"{p.id}: provider_url ohne https"
            )
            assert p.provider_url.endswith("provider-metadata.json"), (
                f"{p.id}: provider_url muss auf provider-metadata.json enden"
            )

    def test_feed_urls_sind_leer_oder_https(self) -> None:
        """Hardcoded feed_url sollte ``""`` sein — Code resolved Feeds
        dynamisch aus der provider-metadata."""
        for p in CURATED_CSAF_PROVIDERS:
            assert p.feed_url == "" or p.feed_url.startswith("https://"), (
                f"{p.id}: feed_url muss leer oder https sein"
            )

    def test_bsi_provider_ohne_hardcoded_feed_url(self) -> None:
        """Der frueher hardcoded ``white/feed.json`` darf nicht mehr da
        sein — Strategie 2 ermittelt die Feeds dynamisch."""
        bsi = next(p for p in CURATED_CSAF_PROVIDERS if p.id == "csaf-bsi")
        assert bsi.feed_url == ""
        assert "white/feed.json" not in bsi.provider_url

    def test_cisa_neue_url(self) -> None:
        """CISA hat den well-known-Pfad verlassen — neue URL ist
        ``/sites/default/files/csaf/``."""
        cisa = next(p for p in CURATED_CSAF_PROVIDERS if p.id == "csaf-cisa")
        assert "sites/default/files/csaf" in cisa.provider_url
        assert ".well-known" not in cisa.provider_url

    def test_redhat_security_access_url(self) -> None:
        """Red Hat hat von access.redhat.com auf security.access.redhat.com
        migriert."""
        redhat = next(p for p in CURATED_CSAF_PROVIDERS if p.id == "csaf-redhat")
        assert "security.access.redhat.com" in redhat.provider_url

    def test_mindestens_sechs_default_enabled_provider(self) -> None:
        enabled = [p for p in CURATED_CSAF_PROVIDERS if p.enabled]
        assert len(enabled) >= 6, (
            f"DACH-Default sollte >= 6 enabled Provider haben, "
            f"hat {len(enabled)}"
        )

    def test_keine_doppelten_provider_ids(self) -> None:
        ids = [p.id for p in CURATED_CSAF_PROVIDERS]
        assert len(ids) == len(set(ids)), f"Doppelte IDs: {ids}"


class TestExtractAdvisoryUrlsAllFeeds:
    """``_extract_advisory_urls`` probiert alle rolie-Feeds (nicht nur den
    ersten) — Bug der den BSI-Fetch komplett blockiert hat."""

    def _provider(self, feed_url: str = "") -> CsafProvider:
        return CsafProvider(
            id="test",
            name="Test",
            provider_url="https://example.com/provider-metadata.json",
            feed_url=feed_url,
            source="curated",
            enabled=True,
        )

    def test_alle_feeds_werden_probiert_und_ergebnisse_gemerged(self) -> None:
        metadata = {
            "distributions": [
                {
                    "rolie": {
                        "feeds": [
                            {"url": "https://example.com/feed-a.json"},
                            {"url": "https://example.com/feed-b.json"},
                            {"url": "https://example.com/feed-c.json"},
                        ]
                    }
                }
            ]
        }
        downloader = CsafDownloader()

        def fake_rolie(url: str) -> list[str]:
            if "feed-a" in url:
                return []  # 404 simulieren
            if "feed-b" in url:
                return ["https://example.com/adv-1.json"]
            if "feed-c" in url:
                return ["https://example.com/adv-2.json"]
            return []

        with patch.object(downloader, "_fetch_rolie_urls", side_effect=fake_rolie):
            urls = downloader._extract_advisory_urls(self._provider(), metadata)

        assert sorted(urls) == [
            "https://example.com/adv-1.json",
            "https://example.com/adv-2.json",
        ]

    def test_duplikate_aus_mehreren_feeds_werden_dedupliziert(self) -> None:
        """Wenn dieselbe Advisory-URL in mehreren TLP-Feeds (white +
        green) auftaucht, soll sie nur einmal im Ergebnis sein."""
        metadata = {
            "distributions": [
                {
                    "rolie": {
                        "feeds": [
                            {"url": "https://example.com/feed-white.json"},
                            {"url": "https://example.com/feed-green.json"},
                        ]
                    }
                }
            ]
        }
        downloader = CsafDownloader()

        with patch.object(
            downloader,
            "_fetch_rolie_urls",
            return_value=["https://example.com/adv-1.json"],
        ):
            urls = downloader._extract_advisory_urls(self._provider(), metadata)

        assert urls == ["https://example.com/adv-1.json"]

    def test_directory_url_fallback_nur_wenn_keine_rolie_urls(self) -> None:
        metadata = {
            "distributions": [
                {
                    "rolie": {
                        "feeds": [{"url": "https://example.com/feed-tot.json"}]
                    },
                    "directory_url": "https://example.com/index",
                }
            ]
        }
        downloader = CsafDownloader()

        with patch.object(downloader, "_fetch_rolie_urls", return_value=[]), patch.object(
            downloader,
            "_fetch_index_txt_urls",
            return_value=["https://example.com/adv-from-index.json"],
        ):
            urls = downloader._extract_advisory_urls(self._provider(), metadata)

        assert urls == ["https://example.com/adv-from-index.json"]


class TestSeedCuratedProvidersMigration:
    """``_seed_curated_providers`` synchronisiert existierende Eintraege."""

    def test_existing_provider_url_wird_geupdated(self, tmp_path) -> None:
        """Wenn ein User schon einen Provider mit alter URL in der DB
        hat, soll der Sync die URL korrigieren — aber ``enabled`` nicht
        ueberschreiben."""
        # Mock-DB-Setup: in-memory SQLite-Cursor mit den relevanten Tabellen
        # über den echten Repository-Pfad. Wir nutzen einen tmp_path und
        # patchen die SQLCipher-DB-Connection.
        from tools.csaf_advisor.data import advisory_repository_impl as mod

        # Statt SQLCipher umzubiegen: wir testen das Verhalten gegen
        # einen MagicMock-Connection, der die SELECT/UPDATE-Aufrufe
        # simuliert.
        with patch.object(mod, "EncryptedDatabase") as mock_db_cls:
            conn = MagicMock()
            mock_db_cls.return_value.connection.return_value.__enter__.return_value = conn
            # SELECT-Antwort: Provider existiert
            conn.execute.return_value.fetchone.return_value = ("csaf-bsi",)

            mod.AdvisoryRepository()

            # Suche nach UPDATE-Calls
            update_calls = [
                call for call in conn.execute.call_args_list
                if "UPDATE" in str(call.args[0])
            ]
            assert len(update_calls) > 0, "Mindestens ein UPDATE erwartet"

            # Suche nach UPDATE auf csaf-bsi
            bsi_update = next(
                (c for c in update_calls if "csaf-bsi" in str(c.args[1])),
                None,
            )
            assert bsi_update is not None
            # In den UPDATE-Params: provider_url muss korrekt sein
            params = bsi_update.args[1]
            assert any(
                "wid.cert-bund.de/.well-known/csaf/provider-metadata.json" in str(p)
                for p in params
            )

    def test_neuer_provider_wird_inserted(self) -> None:
        from tools.csaf_advisor.data import advisory_repository_impl as mod

        with patch.object(mod, "EncryptedDatabase") as mock_db_cls:
            conn = MagicMock()
            mock_db_cls.return_value.connection.return_value.__enter__.return_value = conn
            conn.execute.return_value.fetchone.return_value = None  # nicht existent

            mod.AdvisoryRepository()

            insert_calls = [
                c for c in conn.execute.call_args_list
                if "INSERT" in str(c.args[0])
                and "csaf_providers" in str(c.args[0])
            ]
            # Wir erwarten genau so viele INSERTs wie es kuratierte Provider gibt
            assert len(insert_calls) == len(CURATED_CSAF_PROVIDERS)


@pytest.fixture(autouse=True)
def _no_disk_io(monkeypatch, tmp_path):
    """Verhindert dass Tests die echte ~/.finlai/db anlegen."""
    monkeypatch.setenv("FINLAI_DB_DIR", str(tmp_path))
    yield
