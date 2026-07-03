"""Tests für threat_feed_client F-D).

Deckt den toleranten Zeilen-Parser (Feodo-Plaintext + ThreatFox-CSV + Müll),
die Mindest-Prefix-Klemme (kein ``0.0.0.0/0``-Blanket), und das Fail-soft-
Verhalten bei Netzwerk-/Größen-Fehlern ab. Kein echter Netzzugriff — der
gehärtete ``get_capped``-Pfad wird durch einen Fake ersetzt.
"""

from __future__ import annotations

import requests

from core.http_client import ResponseTooLargeError
from tools.network_monitor.data.blocklist_loader import parse_network_token
from tools.network_monitor.data.threat_feed_client import (
    ThreatFeedClient,
    parse_feed_text,
)
from tools.network_monitor.domain.models import FeedFormat, ThreatFeedSource

_SOURCE = ThreatFeedSource(
    key="test_feed",
    name="Test Feed",
    url="https://example.invalid/feed.txt",
    feed_format=FeedFormat.PLAINTEXT_IP,
    license_id="CC0-1.0",
    reason="Test-Grund",
)


class _FakeHttpClient:
    """Ersetzt den core-HTTP-Client: get_capped liefert/raised, was der Test vorgibt."""

    def __init__(self, body: bytes | None = None, exc: Exception | None = None) -> None:
        self._body = body
        self._exc = exc
        self.calls: list[str] = []

    def get_capped(self, url: str, *, max_bytes: int, timeout=None) -> bytes:
        self.calls.append(url)
        if self._exc is not None:
            raise self._exc
        body = self._body or b""
        if len(body) > max_bytes:
            raise ResponseTooLargeError("zu groß")
        return body


def _client_with(body=None, exc=None) -> ThreatFeedClient:
    client = ThreatFeedClient()
    client._client = _FakeHttpClient(body=body, exc=exc)  # type: ignore[assignment]
    return client


# ── parse_network_token (geteilter Low-Level-Parser) ─────────────────────────


class TestParseNetworkToken:
    def test_plain_ipv4(self) -> None:
        assert str(parse_network_token("1.2.3.4")) == "1.2.3.4/32"

    def test_ipv4_cidr(self) -> None:
        assert str(parse_network_token("10.0.0.0/8")) == "10.0.0.0/8"

    def test_ipv4_mit_port(self) -> None:
        assert str(parse_network_token("5.6.7.8:443")) == "5.6.7.8/32"

    def test_ipv6_plain_nicht_als_port_zerschnitten(self) -> None:
        assert str(parse_network_token("2001:db8::1")) == "2001:db8::1/128"

    def test_ipv6_cidr(self) -> None:
        assert str(parse_network_token("2001:db8::/32")) == "2001:db8::/32"

    def test_bracket_ipv6_mit_port(self) -> None:
        assert str(parse_network_token("[2001:db8::5]:8443")) == "2001:db8::5/128"

    def test_muell_ist_none(self) -> None:
        assert parse_network_token("not-an-ip") is None
        assert parse_network_token("") is None
        assert parse_network_token("999.999.999.999") is None

    def test_strict_lehnt_host_bits_ab(self) -> None:
        # Default (strict=False) toleriert + verbreitert; strict=True lehnt ab.
        assert str(parse_network_token("203.0.113.10/24")) == "203.0.113.0/24"
        assert parse_network_token("203.0.113.10/24", strict=True) is None
        # saubere Netz-Adresse + Einzel-Host bleiben unter strict gueltig
        assert str(parse_network_token("203.0.113.0/24", strict=True)) == "203.0.113.0/24"
        assert str(parse_network_token("1.2.3.4", strict=True)) == "1.2.3.4/32"


# ── parse_feed_text ──────────────────────────────────────────────────────────


class TestParseFeedText:
    def test_feodo_plaintext(self) -> None:
        text = "# Header\n1.2.3.4\n10.0.0.0/8\n2001:db8::/32\nmuell\n\n"
        entries = parse_feed_text(text, "feodo")
        assert [str(n) for n, _ in entries] == [
            "1.2.3.4/32",
            "10.0.0.0/8",
            "2001:db8::/32",
        ]
        assert all(reason == "feodo" for _, reason in entries)

    def test_threatfox_csv(self) -> None:
        text = (
            "# ThreatFox export\n"
            '"first_seen","ioc_id","ioc_value","ioc_type"\n'
            '"2026-06-14","1","5.6.7.8:443","ip:port"\n'
            '"2026-06-14","2","[2001:db8::5]:8443","ip:port"\n'
            '"2026-06-14","3","keine-ip","ip:port"\n'
        )
        entries = parse_feed_text(text, "threatfox")
        assert [str(n) for n, _ in entries] == ["5.6.7.8/32", "2001:db8::5/128"]

    def test_leere_und_kommentarzeilen_ignoriert(self) -> None:
        assert parse_feed_text("\n# nur kommentar\n   \n", "x") == []

    def test_keine_block_regel_aus_muell(self) -> None:
        # Kein fail-open: rein ungültiger Inhalt → 0 Einträge.
        assert parse_feed_text("foo\nbar\n12345\n", "x") == []

    def test_zu_breite_netze_werden_verworfen(self) -> None:
        # Min-Prefix-Klemme: ein bösartiger Feed darf nicht alles blocken.
        text = "0.0.0.0/0\n10.0.0.0/4\n::/0\n1.2.3.4\n10.0.0.0/8\n2001:db8::/32\n"
        entries = parse_feed_text(text, "x")
        nets = {str(n) for n, _ in entries}
        assert nets == {"1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32"}
        assert "0.0.0.0/0" not in nets
        assert "10.0.0.0/4" not in nets  # prefix 4 < 8
        assert "::/0" not in nets


# ── ThreatFeedClient.fetch ──────────────────────────────────────────────────


class TestFetch:
    def test_erfolg(self) -> None:
        client = _client_with(b"1.2.3.4\n10.0.0.0/8\n")
        result = client.fetch(_SOURCE)
        assert result.ok is True
        assert result.error == ""
        assert [str(n) for n, _ in result.entries] == ["1.2.3.4/32", "10.0.0.0/8"]
        assert result.raw_payload == "1.2.3.4\n10.0.0.0/8\n"

    def test_netzwerkfehler_fail_soft(self) -> None:
        client = _client_with(exc=requests.ConnectionError("boom"))
        result = client.fetch(_SOURCE)
        assert result.ok is False
        assert result.entries == []
        assert result.raw_payload == ""
        assert result.error  # generischer Grund gesetzt

    def test_groesse_ueberschritten_fail_soft(self) -> None:
        # get_capped bricht beim Streaming ab → ResponseTooLargeError → ok=False.
        client = _client_with(exc=ResponseTooLargeError("zu groß"))
        result = client.fetch(_SOURCE)
        assert result.ok is False
        assert result.entries == []
        assert "groß" in result.error or "gross" in result.error.lower()

    def test_grosser_body_oberhalb_cap_wird_abgelehnt(self) -> None:
        from tools.network_monitor.data.threat_feed_client import MAX_FEED_BYTES

        big = b"1.2.3.4\n" * (MAX_FEED_BYTES // 4)  # > MAX_FEED_BYTES
        client = _client_with(big)
        result = client.fetch(_SOURCE)
        assert result.ok is False
