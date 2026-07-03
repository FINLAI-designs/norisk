"""network_monitor.data.threat_feed_client — Lädt Threat-Intel-Feeds F-D).

Lädt offline CIDR-/IP-Blocklisten von **abuse.ch** (Default: Feodo Tracker +
ThreatFox, beide CC0) über den gehärteten:mod:`core.http_client`
(``verify=True``, Timeout, Rate-Limit) und parst sie streng über
:mod:`ipaddress`. Es werden **keine lokalen IPs** an Dritte gesendet — der
Default-Pfad ist ein reiner Bulk-Download öffentlicher Listen.

Sicherheitsdesign (STRIDE):
  - Tampering: TLS-``verify=True`` fest im core-Client.
  - Info Discl.: Es wird nur die Domain geloggt (core-Client), nie die IPs.
  - DoS: Der Download ist **gestreamt hart begrenzt** (``get_capped`` bricht
                 bei ``MAX_FEED_BYTES`` ab — auch ohne/mit gelogenem Content-Length,
                 kein Voll-Buffering). Zusätzlich Eintrags-Limit und eine
                 **Mindest-Prefix-Länge** (ein bösartiger Feed kann via ``0.0.0.0/0``
                 nicht pauschal alles als verdächtig markieren). Ungültige Zeilen
                 werden still verworfen (kein fail-open).

Schichtzugehörigkeit: ``data/`` — darf ``core`` + Domain importieren.

Author: Patrick Riederich
Version: 1.1 F-D — Streaming-Cap, Min-Prefix, geteilter Token-Parser)
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.http_client import (
    RateLimitExceeded,
    ResponseTooLargeError,
    get_http_client,
)
from core.logger import get_logger
from tools.network_monitor.data.blocklist_loader import Network, parse_network_token
from tools.network_monitor.domain.models import FeedFormat, ThreatFeedSource

_log = get_logger(__name__)

#: Harte Obergrenze für einen einzelnen Feed-Download (16 MiB). abuse.ch-Feeds
#: liegen weit darunter (Feodo ~KB, ThreatFox ~wenige MB) — die Grenze ist eine
#: fail-closed-Klemme gegen einen kompromittierten/fehlerhaften Endpoint und
#: greift gestreamt während des Downloads (siehe ``get_capped``).
MAX_FEED_BYTES: int = 16 * 1024 * 1024

#: Obergrenze geparster Einträge pro Quelle — begrenzt Speicher und die lineare
#: Checker-Suche. Überzählige Einträge werden verworfen (mit Log-Hinweis).
MAX_ENTRIES_PER_SOURCE: int = 100_000

#: Mindest-Prefix-Länge für Feed-Netze (Default-Quellen). Ein bösartiger/kaputter
#: Feed mit ``0.0.0.0/0`` oder ``::/0`` würde sonst JEDE Verbindung als verdächtig
#: markieren (DoS auf die Bedrohungssicht). Die lokale ``blocklist.txt`` darf
#: bewusst breiter sein — sie stammt nicht aus dem Netz.
MIN_FEED_PREFIX_V4: int = 8
MIN_FEED_PREFIX_V6: int = 32

#: Download-Timeout in Sekunden (verbindungs- + lese-seitig via core-Client).
_FEED_TIMEOUT: int = 20

# ── Default-Quellen (abuse.ch, CC0) ────────────────────────────────────────
# URLs zentral hier (Tool-Data-Schicht, analog cyber_dashboard CISA-KEV). Beide
# CC0 — bulk-Download öffentlicher Listen, keine lokalen Daten verlassen das Gerät.
DEFAULT_SOURCES: tuple[ThreatFeedSource, ...] = (
    ThreatFeedSource(
        key="abuse_ch_feodo",
        name="abuse.ch Feodo Tracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        feed_format=FeedFormat.PLAINTEXT_IP,
        license_id="CC0-1.0",
        reason="abuse.ch Feodo Tracker (C2-Botnetz)",
        enabled=True,
    ),
    ThreatFeedSource(
        key="abuse_ch_threatfox",
        name="abuse.ch ThreatFox",
        url="https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        feed_format=FeedFormat.THREATFOX_CSV,
        license_id="CC0-1.0",
        reason="abuse.ch ThreatFox (IOC)",
        enabled=True,
    ),
)


@dataclass(frozen=True)
class FeedFetchResult:
    """Ergebnis eines einzelnen Feed-Downloads.

    Attributes:
        ok: ``True`` bei erfolgreichem Download (auch wenn 0 Einträge geparst).
        raw_payload: Roher (größen-geprüfter) Feed-Text; ``""`` bei Fehler.
        entries: Geparste (Netz, Grund)-Tupel.
        error: Generischer Kurzgrund bei Fehler (kein Roh-Exception-Text), sonst "".
    """

    ok: bool
    raw_payload: str
    entries: list[tuple[Network, str]]
    error: str = ""


def _is_acceptable_feed_network(network: Network) -> bool:
    """``True`` wenn das Netz für eine **Feed**-Quelle eng genug ist (Min-Prefix)."""
    if network.version == 4:
        return network.prefixlen >= MIN_FEED_PREFIX_V4
    return network.prefixlen >= MIN_FEED_PREFIX_V6


def parse_feed_text(text: str, reason: str) -> list[tuple[Network, str]]:
    """Parst einen rohen Feed-Text tolerant in (Netz, Grund)-Tupel.

    Ein toleranter Zeilen-Parser für beide abuse.ch-Formate: ``#``-Kommentare
    werden ignoriert, jede Zeile wird an üblichen Trennern (Komma/Whitespace)
    zerlegt und das **erste** Token genommen, das streng als IP/CIDR parst
    (geteilter:func:`parse_network_token`). Zu breite Netze (unter der
    Mindest-Prefix-Länge) und nicht-parsebare Zeilen werden verworfen — kein
    fail-open: aus Müll oder einem ``0.0.0.0/0`` entsteht KEINE Block-Regel.

    Args:
        text: Roher Feed-Inhalt.
        reason: Match-Begründung, die jedes Netz dieser Quelle trägt.

    Returns:
        Liste der (Netz, Grund)-Tupel, begrenzt auf:data:`MAX_ENTRIES_PER_SOURCE`.
    """
    entries: list[tuple[Network, str]] = []
    truncated = False
    too_broad = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for token in stripped.replace(",", " ").split():
            cleaned = token.strip().strip('"').strip("'")
            network = parse_network_token(cleaned)
            if network is None:
                continue
            if not _is_acceptable_feed_network(network):
                too_broad += 1
                break
            entries.append((network, reason))
            break
        if len(entries) >= MAX_ENTRIES_PER_SOURCE:
            truncated = True
            break
    if too_broad:
        _log.warning(
            "Feed: %d zu breite Netze (unter Min-Prefix) verworfen.", too_broad
        )
    if truncated:
        _log.warning(
            "Feed-Quelle übersteigt %d Einträge — Rest verworfen.",
            MAX_ENTRIES_PER_SOURCE,
        )
    return entries


class ThreatFeedClient:
    """Lädt einen:class:`ThreatFeedSource` über den gehärteten core-HTTP-Client."""

    def __init__(self) -> None:
        """Initialisiert den Client mit dem zentralen HTTP-Client-Singleton."""
        self._client = get_http_client()

    def fetch(self, source: ThreatFeedSource) -> FeedFetchResult:
        """Lädt und parst einen Feed fail-soft.

        Netzwerk-/HTTP-/Rate-Limit-Fehler und Größenüberschreitungen führen NIE
        zu einer Exception nach außen, sondern zu ``ok=False`` mit generischem
        Grund — der Aufrufer behält dann den bestehenden Cache (kein fail-open,
        keine leere Blocklist durch einen Ausfall).

        Args:
            source: Die abzurufende Quelle.

        Returns:
:class:`FeedFetchResult`.
        """
        if not external_fetches_allowed():
            return FeedFetchResult(False, "", [], OFFLINE_HINT)
        try:
            body = self._client.get_capped(
                source.url, max_bytes=MAX_FEED_BYTES, timeout=_FEED_TIMEOUT
            )
        except ResponseTooLargeError:
            _log.warning(
                "Feed '%s' überschreitet das Größenlimit — verworfen.", source.key
            )
            return FeedFetchResult(False, "", [], "Antwort zu groß")
        except (requests.RequestException, RateLimitExceeded) as exc:
            _log.warning(
                "Feed '%s' nicht abrufbar: %s", source.key, type(exc).__name__
            )
            return FeedFetchResult(False, "", [], "Quelle nicht erreichbar")

        payload = body.decode("utf-8", errors="replace")
        entries = parse_feed_text(payload, source.reason)
        _log.info(
            "Feed '%s' geladen: %d gültige Einträge (%d Bytes).",
            source.key,
            len(entries),
            len(body),
        )
        return FeedFetchResult(True, payload, entries)
