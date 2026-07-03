"""feed_fetch — Zentraler RSS-Abruf ueber den gehaerteten ``core.http_client``.

``feedparser.parse(url)`` nutzt System-urllib direkt: kein erzwungenes
TLS-``verify``, kein Timeout, kein Retry/Backoff, kein ``raise_for_status``.
Dieser Helfer holt den Feed-Body stattdessen ueber
:func:`core.http_client.get_http_client` (Token-Bucket-Rate-Limiting,
``verify=True``, Timeout, Retry) und reicht die Roh-Bytes an ``feedparser``
weiter — so teilen sich alle cyber_dashboard-Feeds dieselbe gehaertete
Netzwerk-Schicht wie CISA-KEV/NVD.

Schicht: application/ (orchestriert core-HTTP + feedparser-Parsing).
Hintergrund: (ausgegliedert aus dem-Sicherheits-Review).
"""

from __future__ import annotations

from urllib.parse import urlparse

import feedparser
import requests

from core.http_client import RateLimitExceeded, get_http_client
from core.logger import get_logger

log = get_logger(__name__)


def fetch_and_parse(url: str, user_agent: str) -> feedparser.FeedParserDict:
    """Holt ``url`` ueber den gehaerteten HTTP-Client und parst den Feed.

    Args:
        url: Feed-URL (https).
        user_agent: Wert fuer den ``User-Agent``-Header.

    Returns:
        Die geparste ``feedparser``-Struktur. Bei Netzwerk-, HTTP- oder
        Rate-Limit-Fehler eine **leere** Struktur (``entries == []``), damit
        Aufrufer defensiv bleiben und ein Feed-Ausfall die uebrigen nicht
        blockiert.
    """

    try:
        resp = get_http_client().get(
            url,
            headers={"User-Agent": user_agent},
            retry_on_timeout=True,
        )
    except (requests.RequestException, RateLimitExceeded) as exc:
        host = urlparse(url).hostname or "_unbekannt"
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status in (404, 410):
            # Dauerhaft tot (Feed entfernt/umgezogen) -> nur debug statt WARNING,
            # damit ein bekannter toter Feed nicht bei jedem Refresh Alarm-
            # Rauschen erzeugt. Transiente Fehler (Timeout/5xx) bleiben WARNING.
            log.debug("Feed dauerhaft nicht verfuegbar (%s): HTTP %s", host, status)
        else:
            log.warning("Feed-Abruf fehlgeschlagen (%s): %s", host, type(exc).__name__)
        return feedparser.parse(b"")
    return feedparser.parse(resp.content)
