"""Tests fuer den Game-CDN-Domain-Matcher Regel 3)."""

from __future__ import annotations

from tools.network_monitor.application.game_cdn import match_game_cdn


class TestMatchGameCdn:
    def test_exakte_domain(self) -> None:
        assert match_game_cdn("steampowered.com") == "Steam"

    def test_subdomain(self) -> None:
        assert match_game_cdn("cdn.steamcontent.com") == "Steam"

    def test_case_insensitiv(self) -> None:
        assert match_game_cdn("CDN.EpicGames.com") == "Epic Games"

    def test_fqdn_endpunkt(self) -> None:
        assert match_game_cdn("battle.net.") == "Battle.net"

    def test_kein_match(self) -> None:
        assert match_game_cdn("example.com") == ""

    def test_leer(self) -> None:
        assert match_game_cdn("") == ""

    def test_kein_suffix_falschpositiv(self) -> None:
        # Kein Match ohne Punkt-Grenze (klassische Suffix-Falle).
        assert match_game_cdn("notsteampowered.com") == ""
        assert match_game_cdn("steampowered.com.evil.com") == ""
