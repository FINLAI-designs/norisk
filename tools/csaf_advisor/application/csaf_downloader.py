"""
csaf_downloader — Lädt CSAF 2.0 Advisories von Trusted Providers herunter.

Ablauf pro Provider:
  1. provider-metadata.json abrufen → Validierung + Feed-URL-Extraktion
  2. ROLIE-Feed oder index.txt abrufen → Liste der Advisory-URLs
  3. Jede Advisory-URL abrufen + parsen → CsafAdvisory-Objekte

Netzwerk-Policy:
  - User-Agent: "NoRisk-by-FINLAI/1.0 CSAF-Client"
  - Timeout: 30s pro Request
  - Max. 3 Versuche mit exponentiellem Backoff
  - TLS-Zertifikats-Validierung: aktiv (kein verify=False)

Schichtzugehörigkeit: application/ — kein GUI-Import, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from core.logger import get_logger
from tools.csaf_advisor.application.csaf_parser import CsafParser
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.csaf_provider import CsafProvider

log = get_logger(__name__)

# Netzwerk-Konstanten
_USER_AGENT = "NoRisk-by-FINLAI/1.0 CSAF-Client"
_TIMEOUT_SECONDS = 30
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # Sekunden, wird mit 2^attempt multipliziert
_MAX_ADVISORIES_PER_FETCH = 100
_MAX_RESPONSE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB Safety-Limit
_MAX_ADVISORY_URL_LEN = 2048


def _validate_advisory_url(raw: str, base_url: str) -> str | None:
    """Validiert und normalisiert eine Advisory-URL gegen eine Basis-URL.

    Schutz gegen drei Angriffe aus präparierten Provider-Inhalten:

    1. **Schema-Downgrade:** Nur ``https://`` ist erlaubt — ``http://`` und
       beliebige Schemes (``file://``, ``ftp://``, ``javascript:``) werden
       abgelehnt.
    2. **Host-Jumping:** Die resolved Host muss exakt mit dem Host der
       ``base_url`` übereinstimmen. Sonst könnte ein kompromittierter
       Trusted-Provider beliebige Drittsysteme als "Advisory-Quelle"
       angeben (SSRF, Drive-by-Trust-Übertragung).
    3. **Path-Escape:** Auch wenn ``urljoin`` ``..``-Sequenzen RFC-3986-
       konform auflöst, darf der resultierende Pfad nicht aus dem
       Verzeichnis-Prefix der ``base_url`` ausbrechen. Verhindert, dass
       eine Zeile ``../../private/secrets.json`` in einem index.txt
       Provider-interne Dateien außerhalb des Advisory-Verzeichnisses
       fetched.

    Effekt: wird in:meth:`_fetch_index_txt_urls` und
:meth:`_fetch_rolie_urls` für jede extrahierte URL aufgerufen — eine
    abgelehnte URL wird mit DEBUG-Log überschrieben und ausgefiltert.

    Args:
        raw: Rohe URL aus einem Provider-Feed (index.txt-Zeile,
                  ROLIE ``content.src`` oder ``link.href``).
        base_url: URL des Feeds selbst — relativ zu dieser Verzeichnis-URL
                  werden relative ``raw``-Werte aufgelöst, gegen den
                  authoritative Host wird verglichen.

    Returns:
        Validierte absolute HTTPS-URL oder ``None`` wenn die URL unsicher,
        zu lang, leer oder feindlich ist.
    """
    if not raw or len(raw) > _MAX_ADVISORY_URL_LEN:
        return None

    resolved = urljoin(base_url, raw)
    parsed = urlparse(resolved)
    base_parsed = urlparse(base_url)

    if parsed.scheme != "https":
        return None
    if not parsed.netloc or parsed.netloc != base_parsed.netloc:
        return None

    # Verzeichnis-Prefix: alles bis zum letzten "/" der base_url. Bei
    # base_url="https://p/x/feed.json" ist das "/x/", bei
    # base_url="https://p/dir/" bleibt "/dir/". resolved.path muss damit
    # beginnen, sonst hat ein "../" sich aus dem Verzeichnis befreit.
    if base_parsed.path.endswith("/"):
        base_dir = base_parsed.path
    else:
        base_dir = base_parsed.path.rsplit("/", 1)[0] + "/"
    if not parsed.path.startswith(base_dir):
        return None

    return resolved


class CsafDownloadError(Exception):
    """Wird ausgelöst wenn ein CSAF-Download endgültig fehlschlägt."""


class CsafDownloader:
    """Lädt CSAF-Advisories von einem Trusted Provider herunter.

    Attributes:
        _parser: CsafParser-Instanz für das Parsen der JSON-Dokumente.
        _session: requests.Session für Connection-Reuse.
    """

    def __init__(self) -> None:
        """Initialisiert den Downloader mit einer konfigurierten HTTP-Session."""
        self._parser = CsafParser()
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": _USER_AGENT})

    def fetch_advisories(
        self,
        provider: CsafProvider,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[CsafAdvisory]:
        """Lädt alle neuen Advisories von einem Provider herunter.

        Args:
            provider: Der CSAF Provider mit Verbindungsdaten.
            progress_callback: Optional — wird mit (current, total, info) aufgerufen.

        Returns:
            Liste der geparsten CsafAdvisory-Objekte.

        Raises:
            CsafDownloadError: Wenn der Provider nicht erreichbar ist oder
                               kein gültiges CSAF-Metadaten-Dokument liefert.
        """
        log.info("CSAF Fetch gestartet: %s (%s)", provider.name, provider.provider_url)

        # 1. Provider-Metadata laden
        metadata = self._fetch_json(provider.provider_url)
        if metadata is None:
            raise CsafDownloadError(
                f"Provider-Metadata nicht abrufbar: {provider.provider_url}"
            )

        # 2. Advisory-URLs aus Feed ermitteln
        advisory_urls = self._extract_advisory_urls(provider, metadata)
        if not advisory_urls:
            log.info("Keine Advisory-URLs bei Provider %s gefunden.", provider.name)
            return []

        # Auf Limit begrenzen (neuste zuerst)
        advisory_urls = advisory_urls[:_MAX_ADVISORIES_PER_FETCH]
        total = len(advisory_urls)
        log.info("%d Advisories werden geladen von %s", total, provider.name)

        # 3. Jede Advisory-URL herunterladen und parsen
        advisories: list[CsafAdvisory] = []
        for idx, url in enumerate(advisory_urls):
            if progress_callback:
                progress_callback(idx + 1, total, url.split("/")[-1])

            csaf_data = self._fetch_json(url)
            if csaf_data is None:
                log.warning("Advisory nicht abrufbar: %s", url)
                continue

            try:
                advisory = self._parser.parse(csaf_data, source_url=url)
                advisories.append(advisory)
            except Exception as exc:
                log.warning("Advisory-Parsing fehlgeschlagen (%s): %s", url, exc)

        log.info(
            "%d Advisories erfolgreich geladen von %s", len(advisories), provider.name
        )
        return advisories

    # ------------------------------------------------------------------
    # Feed-Extraktion
    # ------------------------------------------------------------------

    def _extract_advisory_urls(
        self,
        provider: CsafProvider,
        metadata: dict[str, Any],
    ) -> list[str]:
        """Extrahiert Advisory-URLs aus Provider-Metadata.

        Unterstützte Strategien (in Prioritätsreihenfolge):
        1. feed_url direkt am Provider → ROLIE-Feed oder index.txt
        2. distribution → **alle** rolie-Feeds aus provider-metadata.json
           durchprobieren (BSI listet z.B. 6 Feeds, von denen einzelne
           404 sind; der erste-Treffer-gewinnt war ein Bug, der den
           gesamten Feed-Run auf 0 Advisories abgewuergt hat).
        3. distribution → directory_url + index.txt

        Args:
            provider: Provider mit optionaler feed_url.
            metadata: Geparstes provider-metadata.json.

        Returns:
            Liste der Advisory-URLs (leer wenn keine gefunden).
        """
        # Strategie 1: Direkte feed_url am Provider
        if provider.feed_url:
            urls = self._fetch_feed_urls(provider.feed_url)
            if urls:
                return urls

        # Strategie 2: ROLIE-Feeds aus provider-metadata.json — alle
        # Feeds durchprobieren und Ergebnisse zusammenfuehren. Provider
        # wie das BSI WID listen mehrere Feeds (white/green TLP-
        # Varianten), von denen einzelne 404 sein koennen.
        all_urls: list[str] = []
        distributions = metadata.get("distributions", [])
        for dist in distributions:
            for feed_entry in dist.get("rolie", {}).get("feeds", []):
                rolie_url = feed_entry.get("url", "")
                if not rolie_url:
                    continue
                urls = self._fetch_rolie_urls(rolie_url)
                if urls:
                    all_urls.extend(urls)

            # Strategie 3: directory_url + index.txt (nur wenn keine
            # rolie-Feeds Treffer hatten)
            if not all_urls:
                dir_url = dist.get("directory_url", "").rstrip("/")
                if dir_url:
                    index_url = f"{dir_url}/index.txt"
                    urls = self._fetch_index_txt_urls(index_url, dir_url)
                    if urls:
                        all_urls.extend(urls)

        # Duplikat-Schutz: Advisory-URLs koennen in mehreren TLP-Feeds
        # (white + green) gleichzeitig auftauchen.
        return list(dict.fromkeys(all_urls))

    def _fetch_feed_urls(self, feed_url: str) -> list[str]:
        """Versucht, URLs aus einem Feed (ROLIE oder index.txt) zu laden.

        Args:
            feed_url: URL des Feeds.

        Returns:
            Liste der Advisory-URLs oder leere Liste bei Fehler.
        """
        if feed_url.endswith(".json"):
            return self._fetch_rolie_urls(feed_url)
        if feed_url.endswith(".txt"):
            base = feed_url.rsplit("/", 1)[0]
            return self._fetch_index_txt_urls(feed_url, base)
        # Versuche ROLIE zuerst
        urls = self._fetch_rolie_urls(feed_url)
        return urls if urls else self._fetch_index_txt_urls(feed_url, "")

    def _fetch_rolie_urls(self, rolie_url: str) -> list[str]:
        """Extrahiert Advisory-URLs aus einem ROLIE JSON-Feed.

        Args:
            rolie_url: URL des ROLIE-Feeds.

        Returns:
            Liste der Advisory-URLs oder leere Liste bei Fehler.
        """
        data = self._fetch_json(rolie_url)
        if data is None:
            return []

        urls: list[str] = []
        rejected = 0
        # ROLIE-Format: feed.entry[].content.src oder feed.entry[].link[].href
        feed = data.get("feed", data)
        for entry in feed.get("entry", []):
            # content.src
            src = entry.get("content", {}).get("src", "")
            if src:
                validated = _validate_advisory_url(src, rolie_url)
                if validated:
                    urls.append(validated)
                else:
                    rejected += 1
                continue
            # links mit rel="self"
            for link in entry.get("link", []):
                if link.get("rel", "") in ("self", "alternate"):
                    href = link.get("href", "")
                    if href and href.endswith(".json"):
                        validated = _validate_advisory_url(href, rolie_url)
                        if validated:
                            urls.append(validated)
                        else:
                            rejected += 1
                        break

        if rejected:
            log.warning(
                "ROLIE Feed %s: %d URLs verworfen (Schema/Host/Path-Escape)",
                rolie_url,
                rejected,
            )
        log.debug("ROLIE Feed %s: %d URLs", rolie_url, len(urls))
        return urls

    def _fetch_index_txt_urls(self, index_url: str, base_url: str) -> list[str]:
        """Extrahiert Advisory-URLs aus einer index.txt Datei.

        Args:
            index_url: URL der index.txt.
            base_url: Basis-URL für relative Pfade.

        Returns:
            Liste der Advisory-URLs oder leere Liste bei Fehler.
        """
        try:
            resp = self._get_with_retry(index_url)
            if resp is None or resp.status_code != 200:
                return []
            lines = resp.text.strip().splitlines()
        except Exception as exc:
            log.warning("index.txt laden fehlgeschlagen (%s): %s", index_url, exc)
            return []

        # base_url muss mit "/" enden, damit urljoin relative Pfade als
        # "im Verzeichnis" und nicht als "neben der Datei" auflöst.
        base_for_join = base_url if base_url.endswith("/") else f"{base_url}/"

        urls: list[str] = []
        rejected = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            validated = _validate_advisory_url(stripped, base_for_join)
            if validated:
                urls.append(validated)
            else:
                rejected += 1

        if rejected:
            log.warning(
                "index.txt %s: %d URLs verworfen (Schema/Host/Path-Escape)",
                index_url,
                rejected,
            )
        log.debug("index.txt %s: %d URLs", index_url, len(urls))
        return urls

    # ------------------------------------------------------------------
    # HTTP-Hilfsmethoden
    # ------------------------------------------------------------------

    def _fetch_json(self, url: str) -> dict[str, Any] | None:
        """Lädt und parst eine JSON-Ressource.

        Args:
            url: Vollständige HTTPS-URL.

        Returns:
            Geparstes dict oder None bei Fehler.
        """
        resp = self._get_with_retry(url)
        if resp is None:
            return None
        if resp.status_code != 200:
            log.warning("HTTP %d beim Abruf: %s", resp.status_code, url)
            return None

        # Safety-Limit prüfen
        content_length = int(resp.headers.get("Content-Length", 0))
        if content_length > _MAX_RESPONSE_SIZE_BYTES:
            log.warning(
                "Antwort zu groß (%d Bytes), übersprungen: %s", content_length, url
            )
            return None

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            log.warning("JSON-Parsing fehlgeschlagen (%s): %s", url, exc)
            return None

    def _get_with_retry(self, url: str) -> requests.Response | None:
        """Führt einen GET-Request mit exponentiellem Backoff durch.

        Args:
            url: Vollständige URL.

        Returns:
            requests.Response oder None wenn alle Versuche fehlgeschlagen.
        """
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._session.get(url, timeout=_TIMEOUT_SECONDS, stream=False)
                return resp
            except requests.exceptions.SSLError as exc:
                log.error("SSL-Fehler bei %s: %s", url, exc)
                return None  # SSL-Fehler nicht wiederholen
            except requests.exceptions.ConnectionError as exc:
                log.warning(
                    "Verbindungsfehler bei %s (Versuch %d/%d): %s",
                    url,
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                )
            except requests.exceptions.Timeout:
                log.warning(
                    "Timeout bei %s (Versuch %d/%d)",
                    url,
                    attempt + 1,
                    _MAX_RETRIES,
                )
            except requests.exceptions.RequestException as exc:
                log.warning("Request-Fehler bei %s: %s", url, exc)
                return None

            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2**attempt)
                time.sleep(delay)

        log.error("Alle %d Versuche fehlgeschlagen für: %s", _MAX_RETRIES, url)
        return None
