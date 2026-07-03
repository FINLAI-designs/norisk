"""
test_feed_settings — Tests für core.feed_settings.

Abdeckung:
- Default-Instanz hat alle vier Consumer-Feeds aktiv.
- load/save/load Roundtrip bewahrt Ein/Aus-Zustaende.
- load faellt bei kaputtem JSON auf Default zurueck.
- from_dict ignoriert unbekannte Keys.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from pathlib import Path

from core.feed_settings import (
    FeedSettings,
    external_fetches_allowed,
    load_feed_settings,
    save_feed_settings,
)


def test_default_aktiviert_alle_feeds() -> None:
    settings = FeedSettings()
    assert settings.consumer_feeds == {
        "bsi": True,
        "msrc": True,
        "chrome": True,
        "mozilla": True,
        "watchlist_at": True,
    }


def test_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "feed_settings.json"
    original = FeedSettings(
        consumer_feeds={
            "bsi": True,
            "msrc": False,
            "chrome": True,
            "mozilla": False,
            "watchlist_at": True,
        }
    )
    save_feed_settings(original, path=target)
    geladen = load_feed_settings(path=target)
    assert geladen.consumer_feeds == original.consumer_feeds


def test_load_nicht_vorhanden_liefert_default(tmp_path: Path) -> None:
    target = tmp_path / "fehlt.json"
    settings = load_feed_settings(path=target)
    assert all(settings.consumer_feeds.values())


def test_load_mit_kaputtem_json_liefert_default(tmp_path: Path) -> None:
    target = tmp_path / "kaputt.json"
    target.write_text("nicht json {{{", encoding="utf-8")
    settings = load_feed_settings(path=target)
    assert all(settings.consumer_feeds.values())


def test_from_dict_ignoriert_unbekannte_keys() -> None:
    settings = FeedSettings.from_dict(
        {"consumer_feeds": {"bsi": False, "unbekannt": True, "msrc": True}}
    )
    assert settings.consumer_feeds["bsi"] is False
    assert settings.consumer_feeds["msrc"] is True
    assert "unbekannt" not in settings.consumer_feeds


def test_from_dict_merge_mit_defaults() -> None:
    """Wenn nur ein Key gesetzt ist, werden die anderen mit True ergaenzt."""
    settings = FeedSettings.from_dict({"consumer_feeds": {"chrome": False}})
    assert settings.consumer_feeds["chrome"] is False
    assert settings.consumer_feeds["bsi"] is True
    assert settings.consumer_feeds["msrc"] is True
    assert settings.consumer_feeds["mozilla"] is True
    assert settings.consumer_feeds["watchlist_at"] is True


def test_from_dict_ignoriert_nicht_bool_werte() -> None:
    """String-Wert statt bool -> Default True bleibt."""
    settings = FeedSettings.from_dict({"consumer_feeds": {"bsi": "ja"}})
    assert settings.consumer_feeds["bsi"] is True


def test_external_fetches_default_an() -> None:
    """: Master-Schalter ist standardmaessig an (Online-Modus)."""
    assert FeedSettings().external_fetches_enabled is True


def test_external_fetches_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "feed_settings.json"
    save_feed_settings(FeedSettings(external_fetches_enabled=False), path=target)
    assert load_feed_settings(path=target).external_fetches_enabled is False


def test_external_fetches_migration_alt_json_default_an() -> None:
    """Alte feed_settings.json ohne den neuen Key -> Default True (kein Bruch)."""
    settings = FeedSettings.from_dict({"consumer_feeds": {"chrome": False}})
    assert settings.external_fetches_enabled is True


def test_external_fetches_allowed_helper(tmp_path: Path) -> None:
    target = tmp_path / "feed_settings.json"
    assert external_fetches_allowed(path=target) is True  # fehlt -> Default an
    save_feed_settings(FeedSettings(external_fetches_enabled=False), path=target)
    assert external_fetches_allowed(path=target) is False


def test_phishing_ebene_default_beide() -> None:
    assert FeedSettings().phishing_ebene == "beide"


def test_phishing_ebene_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "feed_settings.json"
    save_feed_settings(FeedSettings(phishing_ebene="kmu"), path=target)
    assert load_feed_settings(path=target).phishing_ebene == "kmu"


def test_phishing_ebene_ungueltig_faellt_auf_default() -> None:
    # Tippfehler / alter Wert -> Default "beide" statt kaputtem State.
    assert FeedSettings.from_dict({"phishing_ebene": "quatsch"}).phishing_ebene == "beide"


def test_phishing_ebene_migration_alt_json_default() -> None:
    # Alte feed_settings.json ohne den Key -> Default "beide".
    assert FeedSettings.from_dict({"consumer_feeds": {}}).phishing_ebene == "beide"
