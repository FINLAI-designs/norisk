"""
consumer_feeds_service — Lädt Consumer-Software-Security-Feeds.

Vier Quellen, jeweils mit Per-Feed-Timeout und unabhängigem Fehlerbranch:
- **BSI**: WID (CERT-Bund) — liefert auch Windows/Office/Browser-Warnungen.
- **MSRC**: Microsoft Security Update Guide (Patch-Tuesday-Stream).
- **Chrome Releases**: Stable/Beta/Extended/Desktop-Channel-Posts.
- **Mozilla Security Blog**: Firefox + Thunderbird + Security-Policy-Posts.

Ein Feed-Ausfall blockiert die übrigen nie. Jede Quelle hat einen
Zeitbudget von:data:`_FEED_TIMEOUT_S` Sekunden.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.logger import get_logger
from tools.cyber_dashboard.application.feed_fetch import fetch_and_parse
from tools.cyber_dashboard.domain.models import (
    ConsumerMeldung,
    ConsumerQuelle,
    Schweregrad,
)

log = get_logger(__name__)

CONSUMER_FEEDS: dict[ConsumerQuelle, str] = {
    ConsumerQuelle.BSI: (
        "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
    ),
    ConsumerQuelle.MSRC: "https://api.msrc.microsoft.com/update-guide/rss",
    ConsumerQuelle.CHROME: (
        "https://chromereleases.googleblog.com/feeds/posts/default"
    ),
    ConsumerQuelle.MOZILLA: "https://blog.mozilla.org/security/feed/",
}

_USER_AGENT = "NoRisk-by-FINLAI/1.0"
_FEED_TIMEOUT_S = 10
_MAX_ENTRIES_PER_FEED = 50


def _parse_datum(entry: object) -> datetime:
    """Parst das Veroeffentlichungsdatum eines Feed-Eintrags.

    Args:
        entry: feedparser-Entry.

    Returns:
        UTC-datetime, Fallback ``datetime.now(UTC)``.
    """
    for field_name in ("published", "updated", "created"):
        val = getattr(entry, field_name, None)
        if not val:
            continue
        try:
            dt = parsedate_to_datetime(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError, AttributeError):
            pass
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError, AttributeError):
            pass
    return datetime.now(UTC)


def _parse_schweregrad(text: str) -> Schweregrad | None:
    """Sucht Schweregrad-Indikatoren in Titel/Beschreibung (heuristisch).

    Args:
        text: Kombinierter Titel + Beschreibung.

    Returns:
        Schweregrad oder ``None`` falls nichts erkannt.
    """
    t = text.lower()
    if "[kritisch]" in t or "critical" in t:
        return Schweregrad.KRITISCH
    if "[hoch]" in t or " high " in f" {t} ":
        return Schweregrad.HOCH
    if "[mittel]" in t or "medium" in t:
        return Schweregrad.MITTEL
    if "[niedrig]" in t or " low " in f" {t} ":
        return Schweregrad.NIEDRIG
    return None


def _extrahiere_produkt(quelle: ConsumerQuelle, titel: str) -> str:
    """Extrahiert den Produktnamen aus dem Eintragstitel.

    Quellen-spezifische Heuristik — nicht perfekt, aber fuer Badge/Spalte
    ausreichend. Bei unklarem Titel wird der Quell-Name zurueckgegeben.

    Args:
        quelle: Feed-Quelle.
        titel: Titel des Eintrags.

    Returns:
        Produktname oder Quell-Name als Fallback.
    """
    if quelle is ConsumerQuelle.CHROME:
        # "Stable Channel Update for Desktop" / "Chrome Stable update..."
        for token in ("Desktop", "Android", "iOS", "ChromeOS", "Extended"):
            if token.lower() in titel.lower():
                return f"Chrome ({token})"
        return "Chrome"
    if quelle is ConsumerQuelle.MSRC:
        # MSRC-Titel enthalten oft "Windows", "Office", "Edge" etc.
        for token in (
            "Windows 11",
            "Windows 10",
            "Windows Server",
            "Microsoft Office",
            "Office",
            "Microsoft Edge",
            "Edge",
            "Teams",
            "Outlook",
            "SharePoint",
            "Exchange",
            ".NET",
            "Visual Studio",
        ):
            if token.lower() in titel.lower():
                return token
        return "Microsoft"
    if quelle is ConsumerQuelle.MOZILLA:
        for token in ("Firefox", "Thunderbird", "Focus"):
            if token.lower() in titel.lower():
                return token
        return "Mozilla"
    if quelle is ConsumerQuelle.BSI:
        # BSI-Titel: "[hoch] Produkt XY: Beschreibung"
        import re

        m = re.match(r"^\s*\[[^\]]+\]\s*([^:]+?)[:\s]", titel)
        if m:
            return m.group(1).strip()[:40]
        return "BSI-WID"
    return quelle.value


class ConsumerFeedsService:
    """Lädt und parst die vier Consumer-Security-Feeds.

    Gibt reine Domain-Objekte zurueck. Kein Cache auf Service-Ebene —
    der Cache liegt im:class:`BriefingService` (1h-TTL dort).
    """

    def lade_meldungen(
        self,
        aktiv: dict[ConsumerQuelle, bool] | None = None,
    ) -> list[ConsumerMeldung]:
        """Lädt alle konfigurierten Consumer-Feeds.

        Args:
            aktiv: Dict ``{ConsumerQuelle: bool}``. Feeds mit ``False``
                werden uebersprungen. Default: alle aktiv.

        Returns:
            Liste aller ConsumerMeldung-Eintraege, neueste zuerst.
        """
        if not external_fetches_allowed():
            log.debug("Consumer-Feeds uebersprungen: %s", OFFLINE_HINT)
            return []
        aktiv = aktiv or {q: True for q in CONSUMER_FEEDS}
        meldungen: list[ConsumerMeldung] = []
        t_gesamt = time.monotonic()

        for quelle, url in CONSUMER_FEEDS.items():
            if not aktiv.get(quelle, True):
                continue
            t0 = time.monotonic()
            try:
                neu = self._lade_einen(quelle, url)
                meldungen.extend(neu)
                log.debug(
                    "Consumer-Feed %s: %d Eintraege in %.1fs",
                    quelle.value,
                    len(neu),
                    time.monotonic() - t0,
                )
            except (OSError, RuntimeError, ValueError, AttributeError) as exc:
                log.warning(
                    "Consumer-Feed %s fehlgeschlagen nach %.1fs: %s",
                    quelle.value,
                    time.monotonic() - t0,
                    type(exc).__name__,
                )

        meldungen.sort(key=lambda m: m.veroeffentlicht, reverse=True)
        log.info(
            "Consumer-Feeds: %d Eintraege aus %d Quellen in %.1fs",
            len(meldungen),
            sum(1 for v in aktiv.values() if v),
            time.monotonic() - t_gesamt,
        )
        return meldungen

    def _lade_einen(
        self,
        quelle: ConsumerQuelle,
        url: str,
    ) -> list[ConsumerMeldung]:
        """Laedt einen einzelnen Feed mit Per-Call-Timeout.

        ``feedparser`` bietet kein Timeout-Argument — der globale
        Socket-Timeout wird fuer die Dauer des Aufrufs gesetzt und danach
        wiederhergestellt.

        Args:
            quelle: Zu ladende Feed-Quelle.
            url: URL des Feeds.

        Returns:
            Liste geparster ConsumerMeldungen (max ``_MAX_ENTRIES_PER_FEED``).
        """
        # Timeout/Retry/TLS kommen jetzt aus core.http_client (via
        # fetch_and_parse). Der socket-Default-Timeout bleibt als
        # Belt-and-Suspenders fuer eventuelle Alt-Pfade erhalten.
        alter_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(_FEED_TIMEOUT_S)
        try:
            parsed = fetch_and_parse(url, _USER_AGENT)
        finally:
            socket.setdefaulttimeout(alter_timeout)

        # HTTP-/Netzwerkfehler werden in fetch_and_parse abgefangen und zu einem
        # leeren Feed degradiert (mit Host-Logging dort) — ein status>=400-Branch
        # waere hier toter Code, da der Fehler den Service nie als Status erreicht.
        meldungen: list[ConsumerMeldung] = []
        for entry in parsed.entries[:_MAX_ENTRIES_PER_FEED]:
            titel = entry.get("title", "")
            beschreibung = entry.get("summary", "")[:300]
            link = entry.get("link", "")
            if not titel or not link:
                continue
            meldungen.append(
                ConsumerMeldung(
                    titel=titel,
                    beschreibung=beschreibung,
                    url=link,
                    quelle=quelle,
                    veroeffentlicht=_parse_datum(entry),
                    produkt=_extrahiere_produkt(quelle, titel),
                    schweregrad=_parse_schweregrad(f"{titel} {beschreibung}"),
                    guid=entry.get("id", link),
                )
            )
        return meldungen
