"""
test_watchlist_internet_rss — Tests fuer die Watchlist-Internet-RSS-
Integration und die Linkliste-Neugliederung.

Patrick-Wunsch 2026-05-14: aktuelle Phishing-/Betrugs-Warnungen auf
der Welcome-Page. Watchlist Internet (OIAT) hat einen funktionierenden
RSS-Feed unter ``/rss/`` — wird in den bestehenden ``rss_service``
eingebunden. Zusaetzlich Linkliste neu gegliedert (Submenues nach
Anbieter/Land/Thema).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from core.curated_links import NORISK_CURATED_LINKS
from tools.cyber_dashboard.application.rss_service import RSS_FEEDS, RssService
from tools.cyber_dashboard.domain.models import QuelleTyp, Schweregrad


class TestWatchlistInternetFeed:
    """Watchlist Internet ist als RSS-Quelle eingebunden."""

    def test_quelle_typ_watchlist_at_existiert(self) -> None:
        assert QuelleTyp.WATCHLIST_AT.value == "Watchlist Internet"

    def test_rss_feeds_enthaelt_watchlist_internet(self) -> None:
        assert QuelleTyp.WATCHLIST_AT in RSS_FEEDS
        assert RSS_FEEDS[QuelleTyp.WATCHLIST_AT] == (
            "https://www.watchlist-internet.at/rss/"
        )

    def test_watchlist_entries_werden_auf_hoch_gemappt(self) -> None:
        """Watchlist-Items haben keine ``[kritisch]``-/``[high]``-Marker,
        der Regex-Parser wuerde sonst ``INFO`` zurueckgeben — und INFO-
        Meldungen werden in ``lade_meldungen`` ausgefiltert. Daher
        Override im ``_parse_feed``-Pfad."""
        # feedparser-Mock: ein "harmloser" Watchlist-Titel ohne Schwere-Markers
        fake_feed = MagicMock()
        fake_entry = MagicMock()
        fake_entry.get = lambda key, default="": {
            "title": "Use.ai: Ein Abo der besonders schwer zu kündigenden Art",
            "summary": "Die Plattform Use.ai verspricht KI-Zugang, die "
            "Kündigung ist aber unmoeglich.",
            "link": "https://www.watchlist-internet.at/news/abo-useai-kuendigen/",
            "id": "news-30999014",
            "published": "Wed, 13 May 2026 11:49:00 +0200",
        }.get(key, default)
        fake_feed.entries = [fake_entry]

        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=fake_feed,
        ):
            meldungen = svc._parse_feed(
                QuelleTyp.WATCHLIST_AT,
                "https://www.watchlist-internet.at/rss/",
            )

        assert len(meldungen) == 1
        assert meldungen[0].schweregrad == Schweregrad.HOCH
        assert meldungen[0].quelle == QuelleTyp.WATCHLIST_AT
        assert "Use.ai" in meldungen[0].titel

    def test_andere_feeds_bleiben_regex_basiert(self) -> None:
        """CERT-AT/BSI behalten das alte ``parse_schweregrad``-Verhalten —
        nur Watchlist bekommt den HOCH-Override."""
        fake_feed = MagicMock()
        fake_entry = MagicMock()
        fake_entry.get = lambda key, default="": {
            "title": "Banalmeldung ohne Severity-Marker",
            "summary": "blabla",
            "link": "https://example.com",
            "id": "abc",
            "published": "Wed, 13 May 2026 11:49:00 +0200",
        }.get(key, default)
        fake_feed.entries = [fake_entry]

        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=fake_feed,
        ):
            meldungen = svc._parse_feed(QuelleTyp.CERT_AT, "https://example.com/feed")

        # Ohne Marker → parse_schweregrad liefert INFO
        assert meldungen[0].schweregrad == Schweregrad.INFO


class TestCuratedLinksReorg:
    """NoRisk-Linkliste hat eine Submenue-Struktur nach Herausgeber/Land/Thema."""

    def test_alle_links_haben_eine_der_neuen_kategorien(self) -> None:
        # 2026-06-25 (Patrick-Live-Test): Liste auf 3 Leitquellen verschlankt —
        # Rubrik "Tools & Standards" entfernt.
        erwartete_kategorien = {
            "BSI & Deutschland",
            "Österreich",
            "Schwachstellen-Datenbanken",
        }
        kategorien = {link.category for link in NORISK_CURATED_LINKS}
        assert kategorien == erwartete_kategorien

    def test_alte_thematische_kategorien_sind_weg(self) -> None:
        """Vorher gab es ``Offizielle Ressourcen`` / ``Netzwerke & Communities``
        — Submenues laut Variante A nicht mehr noetig."""
        veraltet = {
            "Offizielle Ressourcen",
            "Netzwerke & Communities",
            "Datenbanken",
        }
        kategorien = {link.category for link in NORISK_CURATED_LINKS}
        assert kategorien.isdisjoint(veraltet)

    def test_oesterreich_eintrag_ist_ncsc_austria(self) -> None:
        # 2026-06-25: Österreich auf EINE Leitquelle (NCSC Austria) reduziert.
        # Die Watchlist-Internet-Phishing-RSS bleibt davon unberührt (separat
        # in rss_service / feed_settings — kein Curated-Link mehr).
        at = next(
            (
                link
                for link in NORISK_CURATED_LINKS
                if link.category == "Österreich"
            ),
            None,
        )
        assert at is not None
        assert "NCSC Austria" in at.title
        # 2026-06-26: offizielle Domain ist ncc.GV.at (NCC-AT); ncc.at ohne.gv
        # war eine 564ee75-Regression auf einen geparkten Server (D7-Batch).
        assert "ncc.gv.at" in at.url

    def test_bsi_links_in_einer_kategorie_gebuendelt(self) -> None:
        """Frueher waren BSI-Links auf 3 Kategorien verstreut. Jetzt
        leben alle BSI-Links in ``BSI & Deutschland``."""
        bsi_kategorien = {
            link.category
            for link in NORISK_CURATED_LINKS
            if "BSI" in link.title or "CSAF Open-Source" in link.title or "ISDuBA" in link.title
        }
        assert bsi_kategorien == {"BSI & Deutschland"}

    def test_genau_eine_leitquelle_pro_kategorie(self) -> None:
        # 2026-06-25: je Kategorie EINE Leitquelle (10 -> 3 Links).
        assert len(NORISK_CURATED_LINKS) == 3
        kategorien = [link.category for link in NORISK_CURATED_LINKS]
        assert len(set(kategorien)) == 3  # alle verschieden -> 1 pro Kategorie
