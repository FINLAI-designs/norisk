"""
rss_service — Lädt und parst RSS-Feeds für Cybersicherheits-Meldungen.

Enthält keine GUI-Logik und keine Datenbankaufrufe. Gibt reine
Domain-Objekte zurück.

Sicherheitsdesign:
  - Keine Benutzerinhalte werden geloggt
  - User-Agent identifiziert FINLAI korrekt
  - Timeouts verhindern Hänger beim Feed-Abruf

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from core.logger import get_logger
from tools.cyber_dashboard.application.feed_fetch import fetch_and_parse
from tools.cyber_dashboard.domain.models import (
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
    YouTubeVideo,
)

log = get_logger(__name__)

# RSS Feed URLs — 3 zuverlaessige, aktuelle Quellen.
# ENISA, CERT-EU und CVEfeed entfernt (langsam, veraltet oder unverlässlich).
# BSI WID: alte bsi.bund.de-URL (RSSNewsfeed_WID.xml) seit Dez 2024 tot.
# 2026-04: Pfad ``.../securityAdvisory.rss`` liefert 404 — richtiger Endpunkt
# ist ``.../securityAdvisory/rss`` (CERT-Bund WID-Portal, 250 Eintraege).
RSS_FEEDS: dict[QuelleTyp, str] = {
    QuelleTyp.CERT_AT: "https://www.cert.at/cert-at.de.warnings.rss_2.0.xml",
    QuelleTyp.BSI: "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
    QuelleTyp.THE_HACKER_NEWS: "https://feeds.feedburner.com/TheHackersNews",
    # Watchlist Internet (OIAT) — oesterreichischer Phishing-/Betrugs-
    # Newsfeed. Quelle: 2026-05-14 mit HTTP 200 verifiziert, RSS 2.0
    # mit category-Tags. Alle Eintraege werden auf HOCH-Schweregrad
    # gemappt — es handelt sich durchgehend um aktive Warnungen, nicht
    # um informative Berichte.
    QuelleTyp.WATCHLIST_AT: "https://www.watchlist-internet.at/rss/",
    # 2026-05-28 — Phishing-Radar-Refactor (Plan: sehr-gute-recherche-bevor-
    # cozy-fiddle.md). Alle URLs am 2026-05-28 mit HTTP 200 + valides XML
    # verifiziert. Tier 1 DACH (Phishing-Konsumenten):
    QuelleTyp.MIMIKAMA: "https://www.mimikama.org/feed/",
    # VZ_DIGITAL (verbraucherzentrale.de/wissen/digitale-welt/feed) 2026-06-20
    # entfernt — Endpunkt liefert dauerhaft HTTP 404 (Feed eingestellt/umgezogen,
    # kein verifizierter Nachfolger-URL). Enum-Wert bleibt fuer Cache-Kompat.
    QuelleTyp.NCSC_CH: "https://www.newsd.admin.ch/newsd/feeds/rss?lang=de&org-nr=1101",
    QuelleTyp.POLIZEI_NDS: "https://www.polizei-praevention.de/feed",
    QuelleTyp.HEISE_SECURITY: "https://www.heise.de/security/rss/alert-news-atom.xml",
    # Tier 2 international (Awareness/Alerts):
    QuelleTyp.ESET_WLS_DE: "https://www.welivesecurity.com/deutsch/feed/",
    QuelleTyp.MALWAREBYTES_LABS: "https://www.malwarebytes.com/blog/feed",
    QuelleTyp.KREBS: "https://krebsonsecurity.com/category/latest-warnings/feed/",
    QuelleTyp.BLEEPING: "https://www.bleepingcomputer.com/feed/",
    QuelleTyp.NCSC_UK: "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
    QuelleTyp.SANS_ISC: "https://isc.sans.edu/rssfeed_full.xml",
}

# Minimaler Schweregrad fuer RSS-Meldungen — INFO wird herausgefiltert.
_MIN_SCHWEREGRAD: frozenset[Schweregrad] = frozenset(
    {Schweregrad.KRITISCH, Schweregrad.HOCH, Schweregrad.MITTEL, Schweregrad.NIEDRIG}
)

# Source-Default-Severity-Override — wenn ein Feed aktive Warnungen ohne
# ``[kritisch]``-/``[high]``-Marker liefert, mappen wir auf HOCH, damit
# die Eintraege nicht durch den ``INFO``-Filter rausfallen. Die heuristische
# ``parse_schweregrad``-Regex wird fuer diese Quellen uebersprungen.
_SOURCE_DEFAULT_SEVERITY: dict[QuelleTyp, Schweregrad] = {
    QuelleTyp.WATCHLIST_AT: Schweregrad.HOCH,
    QuelleTyp.MIMIKAMA: Schweregrad.HOCH,
    QuelleTyp.POLIZEI_NDS: Schweregrad.HOCH,
    QuelleTyp.NCSC_CH: Schweregrad.HOCH,
    QuelleTyp.HEISE_SECURITY: Schweregrad.HOCH,
}

# Quellen, bei denen wir Items auf Phishing-Bezug filtern, weil sie
# zwar Phishing-Stories liefern, aber auch viele andere Tech-News.
# Items ohne Match auf das Phishing-Regex werden verworfen.
_PHISHING_FILTER_QUELLEN: frozenset[QuelleTyp] = frozenset(
    {
        QuelleTyp.ESET_WLS_DE,
        QuelleTyp.MALWAREBYTES_LABS,
        QuelleTyp.KREBS,
        QuelleTyp.BLEEPING,
        QuelleTyp.NCSC_UK,
        QuelleTyp.SANS_ISC,
    }
)

# Erkennt Phishing-/Scam-/Betrug-Bezug in Titel oder Beschreibung.
_PHISHING_PATTERN: re.Pattern = re.compile(
    r"phish|smish|vish|scam|betrug|abzocke|fake[\s\-]?(mail|sms|shop|store)"
    r"|fraud|trickbetrug|fake[\s\-]?invoice|spoof",
    re.IGNORECASE,
)

# SimplyCyber YouTube-Kanal RSS
# Channel ID: UCG-48Ki-b6W_siaUkukJOSw
YOUTUBE_RSS: str = (
    "https://www.youtube.com/feeds/videos.xml?channel_id=UCG-48Ki-b6W_siaUkukJOSw"
)

_USER_AGENT = "NoRisk-by-FINLAI/1.0"
_MAX_ENTRIES_PER_FEED = 50
_MAX_VIDEOS = 10

# Schweregrad-Erkennung aus Titel/Beschreibung
_SEVERITY_PATTERNS: dict[Schweregrad, re.Pattern] = {
    Schweregrad.KRITISCH: re.compile(
        r"\[kritisch\]|\[critical\]|CVSS\s*1[0-9]\."
        r"|\bkritisch\b|\bcritical\b",
        re.IGNORECASE,
    ),
    Schweregrad.HOCH: re.compile(
        r"\[hoch\]|\[high\]|\bhoch\b|\bhigh\b",
        re.IGNORECASE,
    ),
    Schweregrad.MITTEL: re.compile(
        r"\[mittel\]|\[medium\]|\bmittel\b|\bmedium\b",
        re.IGNORECASE,
    ),
    Schweregrad.NIEDRIG: re.compile(
        r"\[niedrig\]|\[low\]|\bniedrig\b|\blow\b",
        re.IGNORECASE,
    ),
}

# YouTube Video-ID aus diversen URL-Formen extrahieren
_YT_ID_PATTERN: re.Pattern = re.compile(
    r"(?:v=|/embed/|/v/|youtu\.be/)([a-zA-Z0-9_-]{11})"
)


def parse_schweregrad(titel: str, beschreibung: str = "") -> Schweregrad:
    """Erkennt Schweregrad aus Titel und Beschreibung.

    Args:
        titel: Meldungstitel.
        beschreibung: Optionale Beschreibung.

    Returns:
        Erkannter Schweregrad, Standard: INFO.
    """
    text = f"{titel} {beschreibung}"
    for grad, pattern in _SEVERITY_PATTERNS.items():
        if pattern.search(text):
            return grad
    return Schweregrad.INFO


def parse_datum(entry: object) -> datetime:
    """Parst das Datum aus einem Feed-Entry.

    Probiert nacheinander published, updated und created.
    Fallback: aktueller Zeitstempel.

    Args:
        entry: feedparser Entry-Objekt.

    Returns:
        Geparster datetime oder datetime.now.
    """
    for field_name in ("published", "updated", "created"):
        val = getattr(entry, field_name, None)
        if not val:
            continue
        # Versuch 1: RFC 2822 (Standard RSS 2.0)
        try:
            dt = parsedate_to_datetime(val)
            # RFC 2822 -0000 bedeutet "unbekannte Timezone" → gibt naive datetime zurück
            # Behandlung: als UTC interpretieren (konservativ, korrekt für die meisten Feeds)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError, AttributeError):
            pass
        # Versuch 2: ISO 8601 (Atom-Feeds, z.B. YouTube, WID)
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError, AttributeError):
            pass
    return datetime.now(UTC)


def extract_video_id(url: str) -> str:
    """Extrahiert die YouTube Video-ID aus einer URL.

    Args:
        url: YouTube-URL in beliebigem Format.

    Returns:
        11-stellige Video-ID oder leerer String.
    """
    m = _YT_ID_PATTERN.search(url)
    return m.group(1) if m else ""


class RssService:
    """Lädt und parst RSS-Feeds für Cybersicherheits-Meldungen.

    Keine Datenbankzugriffe — gibt reine Domain-Objekte zurück.
    Der Cache wird vom DashboardService verwaltet.
    """

    def lade_meldungen(
        self,
        quelle: QuelleTyp | None = None,
    ) -> list[CyberMeldung]:
        """Lädt Meldungen aus RSS-Feeds.

        Args:
            quelle: Nur diese Quelle laden. None = alle Quellen.

        Returns:
            Liste der Meldungen, neueste zuerst.
        """
        feeds = {quelle: RSS_FEEDS[quelle]} if quelle else RSS_FEEDS
        meldungen: list[CyberMeldung] = []
        t_gesamt = time.monotonic()

        for qt, url in feeds.items():
            t0 = time.monotonic()
            try:
                neu = self._parse_feed(qt, url)
                meldungen.extend(neu)
                log.debug(
                    "Feed %s geladen in %.1fs: %d Eintraege",
                    qt.value,
                    time.monotonic() - t0,
                    len(neu),
                )
            except (OSError, RuntimeError, ValueError, AttributeError) as exc:
                log.warning(
                    "Feed %s fehlgeschlagen nach %.1fs: %s",
                    qt.value,
                    time.monotonic() - t0,
                    type(exc).__name__,
                )

        # Severity-Filter: nur NIEDRIG und hoeher — INFO ausblenden
        meldungen = [m for m in meldungen if m.schweregrad in _MIN_SCHWEREGRAD]
        meldungen.sort(key=lambda m: m.veroeffentlicht, reverse=True)
        log.info(
            "RSS gesamt: %d Meldungen aus %d Feeds in %.1fs",
            len(meldungen),
            len(feeds),
            time.monotonic() - t_gesamt,
        )
        return meldungen

    def lade_youtube_videos(
        self,
        max_videos: int = _MAX_VIDEOS,
    ) -> list[YouTubeVideo]:
        """Lädt neueste SimplyCyber Videos aus dem YouTube RSS-Feed.

        Args:
            max_videos: Maximale Anzahl der Videos.

        Returns:
            Liste der Videos, neueste zuerst.
        """
        try:
            feed = fetch_and_parse(YOUTUBE_RSS, _USER_AGENT)
            videos: list[YouTubeVideo] = []
            for entry in feed.entries[:max_videos]:
                video_id = extract_video_id(entry.get("link", ""))
                if not video_id:
                    # Versuche aus yt:videoId direkt
                    video_id = getattr(entry, "yt_videoid", "")
                if not video_id:
                    continue
                videos.append(
                    YouTubeVideo(
                        video_id=video_id,
                        titel=entry.get("title", ""),
                        beschreibung=entry.get("summary", "")[:200],
                        url=entry.get("link", ""),
                        veroeffentlicht=parse_datum(entry),
                    )
                )
            log.debug("YouTube: %d Videos geladen", len(videos))
            return videos
        except (OSError, RuntimeError, ValueError, AttributeError) as exc:
            log.warning("YouTube Feed fehlgeschlagen: %s", type(exc).__name__)
            return []

    def _parse_feed(
        self,
        quelle: QuelleTyp,
        url: str,
    ) -> list[CyberMeldung]:
        """Parst einen einzelnen RSS-Feed.

        Args:
            quelle: Quellen-Typ für die Meldungen.
            url: Feed-URL.

        Returns:
            Liste geparster CyberMeldung-Objekte.
        """
        feed = fetch_and_parse(url, _USER_AGENT)
        meldungen: list[CyberMeldung] = []
        verworfen = 0
        default_severity = _SOURCE_DEFAULT_SEVERITY.get(quelle)
        phishing_filter = quelle in _PHISHING_FILTER_QUELLEN
        for entry in feed.entries[:_MAX_ENTRIES_PER_FEED]:
            titel = entry.get("title", "")
            beschreibung = entry.get("summary", "")[:300]
            # Phishing-Awareness-Quellen liefern breite Tech-News; nur
            # Items mit explizitem Phishing/Scam-Bezug durchlassen.
            if phishing_filter and not _PHISHING_PATTERN.search(
                f"{titel} {beschreibung}"
            ):
                verworfen += 1
                continue
            if default_severity is not None:
                schweregrad = default_severity
            else:
                schweregrad = parse_schweregrad(titel, beschreibung)
            meldungen.append(
                CyberMeldung(
                    titel=titel,
                    beschreibung=beschreibung,
                    url=entry.get("link", ""),
                    quelle=quelle,
                    schweregrad=schweregrad,
                    veroeffentlicht=parse_datum(entry),
                    guid=entry.get("id", entry.get("link", "")),
                )
            )
        log.debug(
            "%s: %d Meldungen geladen, %d gefiltert",
            quelle.value,
            len(meldungen),
            verworfen,
        )
        return meldungen
