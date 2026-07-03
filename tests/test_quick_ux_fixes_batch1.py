"""
test_quick_ux_fixes_batch1.

Quick-Win aus Patrick's Smoke nach:

- **Consumer-Feeds um Watchlist Internet erweitert** — neuer Eintrag
  ``watchlist_at`` in ``_DEFAULT_CONSUMER_FEEDS`` und in der GUI-
  Tabelle.

(Der frühere Chat-Footer-Testblock entfiel mit — der Security-Chat
``tools/ki_integration`` wurde entfernt.)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.gui


class TestConsumerFeedsWatchlist:
    def test_default_consumer_feeds_enthaelt_watchlist(self) -> None:
        from core.feed_settings import _DEFAULT_CONSUMER_FEEDS

        assert "watchlist_at" in _DEFAULT_CONSUMER_FEEDS

    def test_feed_settings_default_watchlist_aktiv(self) -> None:
        from core.feed_settings import FeedSettings

        settings = FeedSettings()
        assert settings.consumer_feeds.get("watchlist_at") is True

    def test_from_dict_ergaenzt_watchlist_bei_alten_files(self) -> None:
        """Alte JSON-Datei ohne ``watchlist_at``-Key bekommt den Default
        True nachgereicht — keine Migration noetig."""
        from core.feed_settings import FeedSettings

        old_data = {
            "consumer_feeds": {
                "bsi": True,
                "msrc": False,
                "chrome": True,
                "mozilla": True,
            }
        }
        s = FeedSettings.from_dict(old_data)
        assert s.consumer_feeds["watchlist_at"] is True
        assert s.consumer_feeds["msrc"] is False  # alter Wert erhalten

    def test_feed_settings_tab_zeigt_watchlist(self, qapp, qtbot) -> None:  # noqa: ARG002
        """Die GUI-Tabelle hat einen Watchlist-Eintrag."""
        from tools.einstellungen.gui.feed_settings_tab import (
            _FEED_BESCHREIBUNGEN,
        )

        keys = [k for k, _, _ in _FEED_BESCHREIBUNGEN]
        assert "watchlist_at" in keys
