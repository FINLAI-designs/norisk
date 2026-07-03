"""
test_feed_fetch — Tests fuer ``feed_fetch.fetch_and_parse``.

Stellt sicher, dass der RSS-Abruf ueber den gehaerteten core.http_client
laeuft und Netzwerk-/Rate-Limit-Fehler defensiv zu einem leeren Feed
degradieren.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from core.http_client import RateLimitExceeded
from tools.cyber_dashboard.application.feed_fetch import fetch_and_parse

_RSS = (
    b'<?xml version="1.0"?><rss version="2.0"><channel>'
    b"<item><title>Testmeldung</title>"
    b"<link>https://example.com/x</link></item>"
    b"</channel></rss>"
)


class TestFetchAndParse:
    def test_erfolg_parst_body_aus_http_client(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.content = _RSS
        client.get.return_value = resp
        with patch(
            "tools.cyber_dashboard.application.feed_fetch.get_http_client",
            return_value=client,
        ):
            feed = fetch_and_parse("https://example.com/feed", "NoRisk-by-FINLAI/1.0")
        # Body wurde an feedparser gegeben, nicht die URL selbst.
        assert len(feed.entries) == 1
        assert feed.entries[0].title == "Testmeldung"
        # User-Agent wurde als Header gesetzt.
        _args, kwargs = client.get.call_args
        assert kwargs["headers"]["User-Agent"] == "NoRisk-by-FINLAI/1.0"

    def test_netzwerkfehler_liefert_leeren_feed(self) -> None:
        client = MagicMock()
        client.get.side_effect = requests.ConnectionError("down")
        with patch(
            "tools.cyber_dashboard.application.feed_fetch.get_http_client",
            return_value=client,
        ):
            feed = fetch_and_parse("https://example.com/feed", "NoRisk-by-FINLAI/1.0")
        assert feed.entries == []

    def test_rate_limit_liefert_leeren_feed(self) -> None:
        client = MagicMock()
        client.get.side_effect = RateLimitExceeded("zu viele Anfragen")
        with patch(
            "tools.cyber_dashboard.application.feed_fetch.get_http_client",
            return_value=client,
        ):
            feed = fetch_and_parse("https://example.com/feed", "NoRisk-by-FINLAI/1.0")
        assert feed.entries == []
