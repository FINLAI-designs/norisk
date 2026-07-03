"""
test_consumer_feeds — Tests für den ConsumerFeedsService.

Abdeckung:
- ``_extrahiere_produkt`` erkennt Produkte je Quelle (MSRC/Chrome/Mozilla/BSI).
- ``_parse_datum`` verarbeitet RFC-2822 und ISO-8601.
- ``_parse_schweregrad`` erkennt [kritisch]/[hoch]/…-Tags.
- ``lade_meldungen`` respektiert das ``aktiv``-Dict und uebergeht deaktivierte
  Feeds.
- Ein Feed-Ausfall blockiert die übrigen nicht (``feedparser``-Mock).
- Per-Feed-Timeout wird nicht ueberschritten (socket.setdefaulttimeout-Test).

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import socket
import types
from datetime import datetime
from unittest.mock import MagicMock, patch

from tools.cyber_dashboard.application.consumer_feeds_service import (
    CONSUMER_FEEDS,
    ConsumerFeedsService,
    _extrahiere_produkt,
    _parse_datum,
    _parse_schweregrad,
)
from tools.cyber_dashboard.domain.models import ConsumerQuelle, Schweregrad


class TestExtrahiereProdukt:
    def test_chrome_desktop_wird_erkannt(self) -> None:
        result = _extrahiere_produkt(
            ConsumerQuelle.CHROME, "Stable Channel Update for Desktop 123.0"
        )
        assert "Desktop" in result

    def test_chrome_ohne_kanal_fallback(self) -> None:
        result = _extrahiere_produkt(ConsumerQuelle.CHROME, "Chrome Beta")
        assert result == "Chrome"

    def test_msrc_windows_11(self) -> None:
        result = _extrahiere_produkt(
            ConsumerQuelle.MSRC, "Security update for Windows 11 KB1234"
        )
        assert result == "Windows 11"

    def test_msrc_office(self) -> None:
        result = _extrahiere_produkt(
            ConsumerQuelle.MSRC, "Microsoft Office patch rollup"
        )
        assert result in ("Microsoft Office", "Office")

    def test_msrc_fallback(self) -> None:
        assert (
            _extrahiere_produkt(ConsumerQuelle.MSRC, "General advisory")
            == "Microsoft"
        )

    def test_mozilla_firefox(self) -> None:
        result = _extrahiere_produkt(
            ConsumerQuelle.MOZILLA, "Firefox Security Response to pwn2own 2025"
        )
        assert result == "Firefox"

    def test_mozilla_fallback(self) -> None:
        assert (
            _extrahiere_produkt(ConsumerQuelle.MOZILLA, "CA Practices policy update")
            == "Mozilla"
        )

    def test_bsi_klassisches_format(self) -> None:
        result = _extrahiere_produkt(
            ConsumerQuelle.BSI,
            "[hoch] OpenSSL: Mehrere Schwachstellen ermöglichen",
        )
        assert result == "OpenSSL"

    def test_bsi_fallback(self) -> None:
        assert (
            _extrahiere_produkt(ConsumerQuelle.BSI, "kein erkennbares Produkt")
            == "BSI-WID"
        )


class TestParseDatum:
    def test_rfc2822(self) -> None:
        entry = types.SimpleNamespace(
            published="Thu, 19 Mar 2026 18:00:00 -0700"
        )
        dt = _parse_datum(entry)
        assert dt.year == 2026
        assert dt.month == 3
        assert dt.tzinfo is not None

    def test_iso8601_z_suffix(self) -> None:
        entry = types.SimpleNamespace(updated="2026-04-21T12:34:56Z")
        dt = _parse_datum(entry)
        assert dt.year == 2026
        assert dt.tzinfo is not None

    def test_fallback_ohne_datum(self) -> None:
        entry = types.SimpleNamespace()
        dt = _parse_datum(entry)
        assert isinstance(dt, datetime)


class TestParseSchweregrad:
    def test_erkennt_kritisch_tag(self) -> None:
        assert _parse_schweregrad("[kritisch] Foo") is Schweregrad.KRITISCH

    def test_erkennt_hoch_tag(self) -> None:
        assert _parse_schweregrad("[hoch] Bar") is Schweregrad.HOCH

    def test_erkennt_medium(self) -> None:
        assert _parse_schweregrad("medium severity advisory") is Schweregrad.MITTEL

    def test_kein_match(self) -> None:
        assert _parse_schweregrad("generischer Text") is None


class _Entry(dict):
    """Dict mit Attribut-Zugriff — emuliert ``feedparser.FeedParserDict``."""

    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class TestConsumerFeedsService:
    """Integrations-Tests mit gepatchtem feedparser."""

    def _mock_feed(self, entries: list[dict], status: int = 200) -> MagicMock:
        feed = MagicMock()
        feed.entries = [_Entry(e) for e in entries]
        feed.get.side_effect = (
            lambda key, default=None: status if key == "status" else default
        )
        return feed

    def test_respektiert_aktiv_dict(self) -> None:
        service = ConsumerFeedsService()
        with patch(
            "tools.cyber_dashboard.application.consumer_feeds_service.fetch_and_parse"
        ) as parse:
            parse.return_value = self._mock_feed([])
            service.lade_meldungen(
                aktiv={
                    ConsumerQuelle.BSI: False,
                    ConsumerQuelle.MSRC: True,
                    ConsumerQuelle.CHROME: False,
                    ConsumerQuelle.MOZILLA: False,
                }
            )
            called_urls = [c.args[0] for c in parse.call_args_list]
            assert len(called_urls) == 1
            assert called_urls[0] == CONSUMER_FEEDS[ConsumerQuelle.MSRC]

    def test_ein_feed_ausfall_blockiert_andere_nicht(self) -> None:
        service = ConsumerFeedsService()

        def _seitenweise(url: str, user_agent: str):  # noqa: ARG001
            if "msrc" in url:
                raise RuntimeError("MSRC tot")
            return self._mock_feed(
                [
                    {
                        "title": "[hoch] OpenSSL: Update",
                        "summary": "kurze Beschreibung",
                        "link": f"https://example.com/{url[-20:]}",
                        "published": "Mon, 21 Apr 2026 10:00:00 +0000",
                    }
                ]
            )

        with patch(
            "tools.cyber_dashboard.application.consumer_feeds_service.fetch_and_parse",
            side_effect=_seitenweise,
        ):
            meldungen = service.lade_meldungen()
        # 3 Feeds liefern je 1 Meldung, MSRC faellt aus — erwartet: >= 3.
        assert len(meldungen) >= 3
        quellen = {m.quelle for m in meldungen}
        assert ConsumerQuelle.MSRC not in quellen

    def test_http_error_wird_behandelt(self) -> None:
        # HTTP-Fehler (4xx/5xx) faengt fetch_and_parse intern ab und degradiert
        # zu einem leeren Feed (siehe test_feed_fetch.py). Der Service ueberspringt
        # die Quelle dann ohne Crash und liefert eine leere Liste.
        service = ConsumerFeedsService()
        with patch(
            "tools.cyber_dashboard.application.consumer_feeds_service.fetch_and_parse"
        ) as parse:
            parse.return_value = self._mock_feed([])
            result = service.lade_meldungen(
                aktiv={q: q is ConsumerQuelle.BSI for q in CONSUMER_FEEDS}
            )
        assert result == []

    def test_socket_timeout_wird_wiederhergestellt(self) -> None:
        """Nach dem Aufruf muss der globale Timeout wieder so sein wie vorher."""
        service = ConsumerFeedsService()
        vorher = socket.getdefaulttimeout()
        with patch(
            "tools.cyber_dashboard.application.consumer_feeds_service.fetch_and_parse"
        ) as parse:
            parse.return_value = self._mock_feed([])
            service.lade_meldungen()
        assert socket.getdefaulttimeout() == vorher

    def test_sortiert_nach_datum_absteigend(self) -> None:
        service = ConsumerFeedsService()

        def _mk(url: str, user_agent: str):  # noqa: ARG001
            quelle_id = url.split("/")[2][:6]
            return self._mock_feed(
                [
                    {
                        "title": f"[hoch] {quelle_id}: Meldung",
                        "summary": "x",
                        "link": f"https://{quelle_id}.test/a",
                        "published": "Mon, 01 Apr 2026 10:00:00 +0000",
                    },
                    {
                        "title": f"[hoch] {quelle_id}: neuer",
                        "summary": "y",
                        "link": f"https://{quelle_id}.test/b",
                        "published": "Mon, 20 Apr 2026 10:00:00 +0000",
                    },
                ]
            )

        with patch(
            "tools.cyber_dashboard.application.consumer_feeds_service.fetch_and_parse",
            side_effect=_mk,
        ):
            meldungen = service.lade_meldungen()
        assert meldungen  # nicht leer
        for a, b in zip(meldungen, meldungen[1:], strict=False):
            assert a.veroeffentlicht >= b.veroeffentlicht
