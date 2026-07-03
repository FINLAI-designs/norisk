"""
test_phishing_radar_rss_quellen — Tests fuer die 11 neuen RSS-Quellen,
Severity-Override-Map und Phishing-Heuristik-Filter (Phishing-Radar-
Refactor 2026-05-28).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.cyber_dashboard.application.rss_service import (
    _PHISHING_FILTER_QUELLEN,
    _PHISHING_PATTERN,
    _SOURCE_DEFAULT_SEVERITY,
    RSS_FEEDS,
    RssService,
)
from tools.cyber_dashboard.domain.models import (
    QUELLE_KATEGORIE,
    Kategorie,
    QuelleTyp,
    Schweregrad,
)

# VZ_DIGITAL 2026-06-20 aus RSS_FEEDS entfernt (Endpunkt dauerhaft HTTP 404);
# Enum + Kategorie-Mapping bleiben fuer Cache-Kompat. Siehe test_toter_vz_feed_entfernt.
_NEUE_QUELLEN_TIER1 = [
    QuelleTyp.MIMIKAMA,
    QuelleTyp.NCSC_CH,
    QuelleTyp.POLIZEI_NDS,
    QuelleTyp.HEISE_SECURITY,
]

_NEUE_QUELLEN_TIER2 = [
    QuelleTyp.ESET_WLS_DE,
    QuelleTyp.MALWAREBYTES_LABS,
    QuelleTyp.KREBS,
    QuelleTyp.BLEEPING,
    QuelleTyp.NCSC_UK,
    QuelleTyp.SANS_ISC,
]


class TestRssFeedMapping:
    def test_alle_neuen_quellen_haben_url(self) -> None:
        for q in _NEUE_QUELLEN_TIER1 + _NEUE_QUELLEN_TIER2:
            assert q in RSS_FEEDS, f"{q.value} fehlt in RSS_FEEDS"
            assert RSS_FEEDS[q].startswith("https://"), q.value

    def test_keine_alten_quellen_entfernt(self) -> None:
        bestand = {
            QuelleTyp.CERT_AT,
            QuelleTyp.BSI,
            QuelleTyp.THE_HACKER_NEWS,
            QuelleTyp.WATCHLIST_AT,
        }
        for q in bestand:
            assert q in RSS_FEEDS

    def test_toter_vz_feed_entfernt(self) -> None:
        # VZ_DIGITAL lieferte dauerhaft HTTP 404 -> bewusst aus dem aktiven
        # Abruf entfernt (Enum + Kategorie-Mapping bleiben fuer Cache-Kompat).
        assert QuelleTyp.VZ_DIGITAL not in RSS_FEEDS
        assert QuelleTyp.VZ_DIGITAL not in _SOURCE_DEFAULT_SEVERITY


class TestKategorieMapping:
    def test_konsumenten_quellen(self) -> None:
        konsumenten = {
            QuelleTyp.WATCHLIST_AT,
            QuelleTyp.MIMIKAMA,
            QuelleTyp.VZ_DIGITAL,
            QuelleTyp.NCSC_CH,
            QuelleTyp.POLIZEI_NDS,
        }
        for q in konsumenten:
            assert QUELLE_KATEGORIE[q] == Kategorie.PHISHING_CONSUMER

    def test_awareness_quellen(self) -> None:
        awareness = {
            QuelleTyp.ESET_WLS_DE,
            QuelleTyp.MALWAREBYTES_LABS,
            QuelleTyp.KREBS,
            QuelleTyp.BLEEPING,
        }
        for q in awareness:
            assert QUELLE_KATEGORIE[q] == Kategorie.PHISHING_AWARENESS

    def test_tech_cve_quellen_bleiben(self) -> None:
        for q in (QuelleTyp.CERT_AT, QuelleTyp.BSI, QuelleTyp.THE_HACKER_NEWS):
            assert QUELLE_KATEGORIE[q] == Kategorie.TECH_CVE


class TestSeverityOverride:
    @pytest.mark.parametrize(
        "quelle",
        [
            QuelleTyp.WATCHLIST_AT,
            QuelleTyp.MIMIKAMA,
            QuelleTyp.POLIZEI_NDS,
            QuelleTyp.NCSC_CH,
            QuelleTyp.HEISE_SECURITY,
        ],
    )
    def test_override_quellen_mappen_auf_hoch(self, quelle: QuelleTyp) -> None:
        assert _SOURCE_DEFAULT_SEVERITY[quelle] == Schweregrad.HOCH

    def test_kein_override_fuer_awareness_und_tech(self) -> None:
        for q in (
            QuelleTyp.KREBS,
            QuelleTyp.BLEEPING,
            QuelleTyp.CERT_AT,
            QuelleTyp.BSI,
        ):
            assert q not in _SOURCE_DEFAULT_SEVERITY


class TestPhishingFilter:
    def test_pattern_findet_typische_keywords(self) -> None:
        positive = [
            "Phishing wave against Sparkasse customers",
            "PayPal smishing campaign hits EU",
            "Massive scam targeting elderly",
            "Vorsicht vor neuem Betrug",
            "Krebs uncovers fake-shop network",
            "Fraud alert: spoof emails",
        ]
        for text in positive:
            assert _PHISHING_PATTERN.search(text), text

    def test_pattern_lehnt_andere_themen_ab(self) -> None:
        negative = [
            "Microsoft patches kernel vulnerability",
            "New Linux LTS released",
            "DSGVO Update: Fristen geaendert",
        ]
        for text in negative:
            assert _PHISHING_PATTERN.search(text) is None, text

    def test_filter_quellen_sind_awareness_und_alert(self) -> None:
        assert QuelleTyp.KREBS in _PHISHING_FILTER_QUELLEN
        assert QuelleTyp.BLEEPING in _PHISHING_FILTER_QUELLEN
        assert QuelleTyp.NCSC_UK in _PHISHING_FILTER_QUELLEN
        assert QuelleTyp.SANS_ISC in _PHISHING_FILTER_QUELLEN
        # Konsumenten-Quellen werden NICHT gefiltert (alles ist Phishing).
        assert QuelleTyp.WATCHLIST_AT not in _PHISHING_FILTER_QUELLEN
        assert QuelleTyp.MIMIKAMA not in _PHISHING_FILTER_QUELLEN


class TestParseFeedMitNeuenQuellen:
    def _fake_feed(self, titel: str, summary: str = "") -> MagicMock:
        feed = MagicMock()
        entry = MagicMock()
        entry.get = lambda key, default="": {
            "title": titel,
            "summary": summary,
            "link": "https://example.com/x",
            "id": "x1",
            "published": "Wed, 13 May 2026 11:49:00 +0200",
        }.get(key, default)
        feed.entries = [entry]
        return feed

    def test_mimikama_eintrag_wird_auf_hoch_gemappt(self) -> None:
        feed = self._fake_feed("Aktueller Hinweis ohne Marker")
        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=feed,
        ):
            ergebnis = svc._parse_feed(
                QuelleTyp.MIMIKAMA, "https://www.mimikama.org/feed/"
            )
        assert len(ergebnis) == 1
        assert ergebnis[0].schweregrad == Schweregrad.HOCH

    def test_krebs_eintrag_ohne_phishing_keyword_wird_verworfen(self) -> None:
        feed = self._fake_feed("Cloud-Migration in Banking")
        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=feed,
        ):
            ergebnis = svc._parse_feed(
                QuelleTyp.KREBS,
                "https://krebsonsecurity.com/category/latest-warnings/feed/",
            )
        assert ergebnis == []

    def test_krebs_eintrag_mit_phishing_keyword_durchgelassen(self) -> None:
        feed = self._fake_feed(
            "New phishing campaign hits remote workers",
            summary="Targets payroll departments.",
        )
        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=feed,
        ):
            ergebnis = svc._parse_feed(
                QuelleTyp.KREBS,
                "https://krebsonsecurity.com/category/latest-warnings/feed/",
            )
        assert len(ergebnis) == 1
        # Krebs hat keinen Source-Default → parse_schweregrad-Regex greift.
        # Ohne Severity-Marker im Titel → INFO (Filter im Aufruf-Pfad
        # wuerde INFO rauswerfen, hier testen wir nur den Parse).
        assert ergebnis[0].schweregrad == Schweregrad.INFO

    def test_watchlist_at_bleibt_hoch(self) -> None:
        """Regressionstest: alter Test bleibt grun, weil
        Watchlist-AT jetzt im generischen `_SOURCE_DEFAULT_SEVERITY`-
        Dict statt im hartcodierten `if`-Branch lebt."""

        feed = self._fake_feed("Banal-Titel ohne Marker")
        svc = RssService()
        with patch(
            "tools.cyber_dashboard.application.rss_service.fetch_and_parse",
            return_value=feed,
        ):
            ergebnis = svc._parse_feed(
                QuelleTyp.WATCHLIST_AT, "https://www.watchlist-internet.at/rss/"
            )
        assert ergebnis[0].schweregrad == Schweregrad.HOCH
