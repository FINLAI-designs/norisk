"""
nvd_service — NVD CVE API 2.0 Integration mit SQLCipher-Cache.

Lädt CVE-Einträge mit CVSS-Scores und CISA-KEV-Markierungen.
Der API-Key wird aus SecureStorage geladen — niemals im Klartext.

Resilienz-Strategie:
  - Timeout: ``(CONNECT_TIMEOUT, READ_TIMEOUT)`` = ``(3, 8)``
  - Retry-Differenzierung:
    * Background-Bulk-Lade (``lade_neueste_cves``, ``lade_kev_cves``)
      laufen mit ``retry_on_timeout=False`` — bei einem Timeout sofort
      Cache-Fallback statt 36 s zu warten. Der Lade-Thread sperrt
      sonst das UI > 30 s und ``_lade_timeout`` blendet den Ladescreen
      vor Datenankunft aus.
    * User-getriggerte Produktsuche (``suche_produkt``) behält
      ``retry_on_timeout=True`` — kurze Mehrfach-Wartezeit ist hier
      akzeptabel, weil der User aktiv auf das Ergebnis wartet.
    * ``requests.ConnectionError`` wird unabhängig vom Flag immer
      retried (HTTP-Client-Default).
  - Cache: SQLCipher via:class:`NvdCacheRepository`, TTL 6 Stunden
  - Offline-Fallback: bei Timeout/Connection-Error wird stale Cache
    verwendet statt leerer Liste.:attr:`last_status` signalisiert der
    UI ob Daten frisch, aus Cache oder gar nicht verfügbar sind.

Sicherheitsdesign:
  - API-Key wird über SecureStorage (Fernet-verschlüsselt) gespeichert
  - CVE-Inhalte werden nicht geloggt
  - User-Agent identifiziert FINLAI korrekt

Author: Patrick Riederich
Version: 1.2
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import requests

from core.http_client import RateLimitExceeded, get_http_client
from core.logger import get_logger
from core.security.encryption import SecureStorage
from tools.cyber_dashboard.data.nvd_cache_repository import (
    NvdCacheRepository,
    compute_cache_key,
)
from tools.cyber_dashboard.domain.models import CveEintrag

log = get_logger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_USER_AGENT = "NoRisk-by-FINLAI/1.0"

CONNECT_TIMEOUT = 3
READ_TIMEOUT = 8

# NVD REST API 2.0 begrenzt jede pubStartDate/pubEndDate-Spanne auf maximal
# 120 aufeinanderfolgende Tage; ein größeres Fenster quittiert die API mit 404
# (statt einer leeren 200-Liste) — die Abfrage schlägt dann still fehl.
# 119 statt exakt 120 als Sicherheitsmarge gegen Off-by-one/Clock-Skew am
# oberen Rand. Siehe T-... (Live-Test-Batch 2026-07-01).
NVD_MAX_DATE_RANGE_DAYS = 119

# Circuit-Breaker. Nach so vielen AUFEINANDERFOLGENDEN Fehlversuchen
# (Timeout/Server/Auth/Netz) stellt der Service die automatischen HINTERGRUND-
# Abrufe ein, statt bei jedem Refresh erneut in denselben Timeout zu laufen
# (Patrick: "geht nach 3 Retries offline, versucht es danach aber WIEDER").
# Effekt: ``NvdService.circuit_open`` -> True; Hintergrund-``_request`` liefert
# dann direkt aus dem Cache, ohne NVD anzufragen. Reset bei: erfolgreichem
# Abruf, ``setze_api_key`` (neuer Key) oder ``reset_circuit`` (User-Aktion).
# User-initiierte Suchen (``retry_on_timeout=True``) duerfen die Leitung trotz
# offenem Circuit erneut testen (Half-Open).
_CIRCUIT_THRESHOLD = 3

# NVD-503: HTTP-Status-Codes, die einen transienten Server-Ausfall anzeigen.
# Bei diesen Codes ist ein vorhandener Cache eine valide Notlösung — es liegt
# kein dauerhafter Offline-Zustand und kein veralteter Cache vor, sondern ein
# kurzzeitiger Server-Ausfall auf NVD-Seite. Wird auf WARNING geloggt
# (kein log.ERROR), weil bei Cache-Fallback kein echter Nutzerfehler vorliegt.
_TRANSIENT_SERVER_ERRORS: frozenset[int] = frozenset({500, 502, 503, 504})


class NvdStatus(StrEnum):
    """Status des letzten NVD-Abrufs. Für UI-Offline-Banner."""

    UNKNOWN = "unknown"
    ONLINE = "online"
    CACHE_FRESH = "cache_fresh"
    CACHE_STALE_OFFLINE = "cache_stale_offline"
    OFFLINE_NO_CACHE = "offline_no_cache"
    # explizit unterscheidbarer Zustand fuer User-facing Hinweis.
    # Wenn die API HTTP 429 wirft, koennen Konsumenten den Tooltip /
    # Status-Text gezielt anpassen ("Rate-Limit — bitte API-Key
    # hinterlegen oder spaeter erneut versuchen") statt nur ``offline``.
    RATE_LIMIT = "rate_limit"
    # NVD-503: transienter 5xx-Server-Fehler (500/502/503/504). Anders als
    # CACHE_STALE_OFFLINE bedeutet dieser Zustand NICHT, dass der Cache
    # veraltet ist — er signalisiert "NVD gerade nicht erreichbar, Anzeige
    # aus Cache" und wird auch dann gesetzt, wenn der Cache noch frisch ist.
    # So vermeidet die UI den falschen Hinweis "Cache veraltet".
    SERVER_ERROR = "server_error"
    # Circuit-Breaker offen — nach >=_CIRCUIT_THRESHOLD Fehlversuchen
    # pausieren die automatischen Hintergrund-Abrufe. Die UI zeigt einen
    # praezisen Hinweis ("Abfragen pausiert, gueltigen API-Key hinterlegen oder
    # spaeter erneut versuchen") statt eines weiteren stummen Timeout-Laufs.
    CIRCUIT_OPEN = "circuit_open"


@dataclass(frozen=True)
class NvdFetchResult:
    """Ergebnis eines NVD-Abrufs inkl. Metadaten für die UI.

    Attributes:
        cves: Geparste CVE-Einträge.
        status::class:`NvdStatus` des Abrufs.
        fetched_at: Zeitpunkt des zugrunde liegenden Fetch (UTC).
            Bei Cache-Hits das Cache-Datum; bei Online-Fetch die aktuelle
            Zeit; bei ``OFFLINE_NO_CACHE`` ``None``.
    """

    cves: list[CveEintrag]
    status: NvdStatus
    fetched_at: datetime | None


class NvdService:
    """NVD CVE API 2.0 Integration mit Cache und Retry-Logik.

    Der API-Key wird aus SecureStorage geladen — niemals im Klartext.
    Alle öffentlichen ``lade_*``/``suche_*``-Methoden geben ``list[CveEintrag]``
    zurück (rückwärtskompatibel); für Offline-Banner-Logik kann nach dem
    Aufruf:attr:`last_status` und:attr:`last_fetched_at` gelesen werden.
    """

    def __init__(self, cache: NvdCacheRepository | None = None) -> None:
        """Initialisiert NvdService und lädt API-Key aus SecureStorage.

        Args:
            cache: Optionaler injizierter Cache (für Tests). Standard:
                neue:class:`NvdCacheRepository`-Instanz.
        """
        self._storage = SecureStorage()
        self._api_key = self._lade_api_key()
        self._cache = cache or NvdCacheRepository()
        self._last_status: NvdStatus = NvdStatus.UNKNOWN
        self._last_fetched_at: datetime | None = None
        # NVD-503: Signal des letzten Fetch an _request — True, wenn der
        # Fetch an einem transienten 5xx-Server-Fehler scheiterte. Erlaubt
        # _request, einen präzisen SERVER_ERROR-Status zu setzen, statt den
        # Cache-Fallback pauschal als "veraltet/offline" zu deklarieren.
        self._last_fetch_transient: bool = False
        # Zaehler aufeinanderfolgender Fehlversuche fuer den
        # Circuit-Breaker (in-memory, lebt mit der NvdService-Instanz; ein
        # App-Neustart ist ein natuerlicher Retry-Punkt).
        self._consecutive_failures: int = 0

    # ------------------------------------------------------------------
    # API-Key Management
    # ------------------------------------------------------------------

    def _lade_api_key(self) -> str | None:
        """Lädt NVD API-Key aus SecureStorage.

        Whitespace wird beim Laden defensiv entfernt — ein historisch
        mit Leerzeichen/Zeilenumbruch (aus Copy-Paste) gespeicherter Key heilt
        so beim naechsten Start, ohne dass der User ihn neu eingeben muss.

        Returns:
            Getrimmter API-Key oder None wenn nicht gesetzt/leer.
        """
        try:
            raw = self._storage.get("nvd_api_key")
        except (OSError, RuntimeError, KeyError, ValueError):
            return None
        if raw is None:
            return None
        trimmed = raw.strip()
        return trimmed or None

    def api_key_gesetzt(self) -> bool:
        """Prüft ob ein NVD API-Key vorhanden ist."""
        return bool(self._api_key)

    def setze_api_key(self, key: str) -> None:
        """Speichert NVD API-Key sicher in SecureStorage.

        Der Key wird getrimmt — beim Einfuegen schleicht sich oft ein
        fuehrendes/abschliessendes Leerzeichen oder ein Zeilenumbruch ein, der
        sonst im ``apiKey``-Header landet und von NVD mit 403 abgelehnt wird
        ("alter Key neu eingegeben, funktioniert scheinbar nicht").

        Ein neuer Key schliesst den Circuit-Breaker — der frische Key
        bekommt sofort wieder eine Chance auf Hintergrund-Abrufe.

        Args:
            key: NVD API-Key (UUID-Format), darf umgebenden Whitespace haben.
        """
        cleaned = key.strip()
        self._storage.set("nvd_api_key", cleaned)
        self._api_key = cleaned or None
        self.reset_circuit()
        log.info("NVD API Key gespeichert")

    # ------------------------------------------------------------------
    # Status (für UI-Offline-Banner)
    # ------------------------------------------------------------------

    @property
    def last_status(self) -> NvdStatus:
        """Status des letzten Abrufs. Wird von UI für Offline-Banner gelesen."""
        return self._last_status

    @property
    def last_fetched_at(self) -> datetime | None:
        """Zeitpunkt des letzten erfolgreich geladenen (oder gecachten) Fetch."""
        return self._last_fetched_at

    def is_offline(self) -> bool:
        """True wenn der letzte Abruf nicht live war (Cache/Server-Fehler/No-Cache).

        Schließt den transienten ``SERVER_ERROR`` und den ``CIRCUIT_OPEN``-Zustand ein: In beiden Faellen werden Daten aus dem Cache statt live
        angezeigt, sodass die UI den "nicht live"-Hinweis zeigen soll.
        """
        return self._last_status in (
            NvdStatus.CACHE_STALE_OFFLINE,
            NvdStatus.OFFLINE_NO_CACHE,
            NvdStatus.SERVER_ERROR,
            NvdStatus.CIRCUIT_OPEN,
        )

    @property
    def circuit_open(self) -> bool:
        """: True, wenn nach >=:data:`_CIRCUIT_THRESHOLD` aufeinanderfolgenden
        Fehlversuchen die automatischen Hintergrund-Abrufe pausiert sind.

        Schliesst wieder bei erfolgreichem Abruf,:meth:`setze_api_key` (neuer
        Key) oder:meth:`reset_circuit` (User-Aktion).
        """
        return self._consecutive_failures >= _CIRCUIT_THRESHOLD

    def reset_circuit(self) -> None:
        """Setzt den Fehlversuch-Zaehler zurueck und schliesst den Circuit.

        Aufrufer: ``setze_api_key`` (neuer Key) und eine manuelle "erneut
        versuchen"-Aktion in der GUI.
        """
        if self._consecutive_failures:
            log.info("NVD Circuit zurueckgesetzt (war %s Fehlversuche)",
                     self._consecutive_failures)
        self._consecutive_failures = 0

    # ------------------------------------------------------------------
    # Public API (unverändert)
    # ------------------------------------------------------------------

    def lade_neueste_cves(
        self,
        tage: int = 7,
        schweregrad: str | None = None,
        max_results: int = 50,
    ) -> list[CveEintrag]:
        """Lädt neueste CVEs der letzten N Tage.

        Background-Bulk-Lade: ``retry_on_timeout=False`` (siehe Modul-
        Docstring) — bei NVD-Timeout sofort Cache-Fallback.
        """
        bis = datetime.now(UTC)
        von = bis - timedelta(days=tage)

        params: dict = {
            "pubStartDate": von.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": bis.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max_results, 2000),
        }
        if schweregrad:
            params["cvssV3Severity"] = schweregrad.upper()

        return self._request(params, retry_on_timeout=False)

    def lade_kev_cves(self, max_results: int = 20) -> list[CveEintrag]:
        """Lädt CVEs aus der CISA KEV-Liste im maximal zulässigen Datumsfenster.

        Fenster = ``NVD_MAX_DATE_RANGE_DAYS`` (119 Tage): NVD 2.0 erlaubt
        pro Datumsspanne höchstens 120 Tage, ein größeres Fenster (früher
        180 Tage) führte zu einem 404 und damit still zu leeren Ergebnissen.

        Background-Bulk-Lade: ``retry_on_timeout=False``.
        """
        bis = datetime.now(UTC)
        von = bis - timedelta(days=NVD_MAX_DATE_RANGE_DAYS)
        params: dict = {
            "hasCertAlerts": "true",
            "pubStartDate": von.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": bis.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max_results, 2000),
        }
        return self._request(params, retry_on_timeout=False)

    def suche_produkt(self, produkt: str, tage: int = 30) -> list[CveEintrag]:
        """Sucht CVEs für ein bestimmtes Produkt.

        User-Action: ``retry_on_timeout=True`` — der Suchende wartet
        aktiv auf das Ergebnis, kurze Retry-Sequenz akzeptabel.
        """
        bis = datetime.now(UTC)
        von = bis - timedelta(days=tage)

        params: dict = {
            "keywordSearch": produkt,
            "pubStartDate": von.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": bis.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 50,
        }
        return self._request(params, retry_on_timeout=True)

    # ------------------------------------------------------------------
    # Request-Pipeline: Cache → Fetch → Cache-Update / Offline-Fallback
    # ------------------------------------------------------------------

    def _request(
        self, params: dict, *, retry_on_timeout: bool = False
    ) -> list[CveEintrag]:
        """Führt einen NVD-Abruf mit Cache & Retry-Logik aus.

        Pipeline:
          1. Cache-Check — wenn frisch (< 6h), direkt zurück (``CACHE_FRESH``)
          2. Online-Fetch (Retry-Verhalten siehe ``retry_on_timeout``)
          3. Bei Erfolg: Cache aktualisieren (``ONLINE``)
          4. Bei Netzwerk-Fehler: Stale-Cache zurück (``CACHE_STALE_OFFLINE``)
             oder leere Liste (``OFFLINE_NO_CACHE``)

        Args:
            params: NVD API Query-Parameter.
            retry_on_timeout: Bei ``True`` wird ``requests.Timeout`` bis zu
                ``_MAX_RETRIES`` wiederholt (User-Action). Bei ``False`` —
                sofort Cache-Fallback (Background-Bulk-Lade).
                ``requests.ConnectionError`` wird unabhängig immer retried.

        Returns:
            Liste geparster CVE-Einträge (kann leer sein).
        """
        cache_key = compute_cache_key(params)
        cached = self._cache.get(cache_key)

        if cached is not None and not cached.is_stale:
            self._last_status = NvdStatus.CACHE_FRESH
            self._last_fetched_at = cached.fetched_at
            log.debug("NVD Cache-Hit (frisch): %s", cache_key[:12])
            return self._parse_vulnerabilities(cached.data)

        # Circuit-Breaker. Ist die Leitung nach wiederholten Fehlversuchen
        # offen, fragen HINTERGRUND-Abrufe NVD nicht erneut an (kein weiterer
        # Timeout-Lauf) — sie liefern direkt aus dem Cache. User-Aktionen
        # (retry_on_timeout=True) testen die Leitung trotzdem (Half-Open).
        if self.circuit_open and not retry_on_timeout:
            return self._serve_while_circuit_open(cached)

        # NVD-503: Vor jedem Fetch das Transient-Signal zurücksetzen, damit ein
        # alter 5xx-Marker nicht in einen späteren Cache-Fallback durchschlägt.
        self._last_fetch_transient = False
        raw = self._fetch_online_with_retry(params, retry_on_timeout=retry_on_timeout)

        if raw is not None:
            # Erfolg (auch leeres 404-Ergebnis) schliesst den Circuit.
            self._consecutive_failures = 0
            self._cache.set(cache_key, raw)
            self._last_status = NvdStatus.ONLINE
            self._last_fetched_at = datetime.now(UTC)
            eintraege = self._parse_vulnerabilities(raw)
            self._store_products(eintraege)
            return eintraege

        # endgueltiger Fehlschlag (Timeout/Server/Auth/Netz) — zaehlen,
        # bis der Circuit nach _CIRCUIT_THRESHOLD aufeinanderfolgenden oeffnet.
        self._consecutive_failures += 1
        if self.circuit_open:
            log.warning(
                "NVD Circuit offen nach %s Fehlversuchen — automatische Abrufe "
                "pausiert bis neuer API-Key / manueller Retry.",
                self._consecutive_failures,
            )

        if cached is not None:
            self._last_fetched_at = cached.fetched_at
            if self._last_fetch_transient:
                # Transienter 5xx-Server-Fehler: Der Cache ist nicht "veraltet",
                # NVD ist nur kurz nicht erreichbar. Präziser SERVER_ERROR-Status,
                # WARNING statt ERROR (kein echter Nutzerfehler bei Cache-Hit).
                self._last_status = NvdStatus.SERVER_ERROR
                log.warning(
                    "NVD-Server transient nicht erreichbar — verwende Cache vom %s",
                    cached.fetched_at.isoformat(),
                )
            else:
                self._last_status = NvdStatus.CACHE_STALE_OFFLINE
                log.warning(
                    "NVD offline — verwende Stale-Cache vom %s",
                    cached.fetched_at.isoformat(),
                )
            return self._parse_vulnerabilities(cached.data)

        self._last_status = NvdStatus.OFFLINE_NO_CACHE
        self._last_fetched_at = None
        return []

    def _serve_while_circuit_open(self, cached) -> list[CveEintrag]:  # noqa: ANN001
        """Hintergrund-Antwort bei offenem Circuit OHNE Netzabruf.

        Liefert den (ggf. veralteten) Cache und setzt Status ``CIRCUIT_OPEN``,
        damit die UI den praezisen Hinweis zeigen kann. Kein NVD-Request -> der
        Endlos-Retry im Hintergrund ist gestoppt.
        """
        self._last_status = NvdStatus.CIRCUIT_OPEN
        if cached is not None:
            self._last_fetched_at = cached.fetched_at
            log.info(
                "NVD Circuit offen — Cache vom %s ohne neuen Abruf.",
                cached.fetched_at.isoformat(),
            )
            return self._parse_vulnerabilities(cached.data)
        self._last_fetched_at = None
        log.info("NVD Circuit offen — kein Cache, kein neuer Abruf.")
        return []

    def _fetch_online_with_retry(
        self, params: dict, *, retry_on_timeout: bool = False
    ) -> list[dict] | None:
        """Holt die NVD-Response; delegiert Retry-Backoff an http_client.

        ``requests.ConnectionError`` wird vom HTTP-Client immer mit
        Backoff retried. ``requests.Timeout`` wird nur retried wenn
        ``retry_on_timeout=True``. Rate-Limiting ebenfalls. Dieser
        Service bleibt frei von ``time.sleep`` — Scheduling liegt im
        Token-Bucket der Infrastrukturschicht.

        Args:
            params: NVD API Query-Parameter.
            retry_on_timeout: An den HTTP-Client weitergereicht.

        Returns:
            Liste von ``vulnerabilities``-Items oder ``None`` bei endgültigem
            Netz-/Timeout-Fehler.
        """
        headers = {"User-Agent": _USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            resp = get_http_client().get(
                NVD_BASE,
                params=params,
                headers=headers,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                api_key_header=self._api_key if self._api_key else None,
                retry_on_timeout=retry_on_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return [item for item in data.get("vulnerabilities", []) if item.get("cve")]
        except requests.Timeout:
            log.error("NVD Timeout nach allen Retries — gehe offline")
            return None
        except RateLimitExceeded:
            log.error("NVD: Rate-Limit-Timeout")
            self._last_status = NvdStatus.RATE_LIMIT
            return None
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 404:
                log.debug("NVD: Keine Ergebnisse (404)")
                return []  # leere Response ist gültig, nicht offline
            if status == 403:
                log.error("NVD: Ungültiger API Key")
            elif status == 429:
                log.warning("NVD: Rate Limit überschritten")
                self._last_status = NvdStatus.RATE_LIMIT
            elif status in _TRANSIENT_SERVER_ERRORS:
                # NVD-503: transienter Server-Fehler. WARNING statt ERROR —
                # bei vorhandenem Cache liegt kein echter Nutzerfehler vor.
                # _request wertet das Flag aus und setzt SERVER_ERROR.
                log.warning("NVD: transienter Server-Fehler (%s)", status)
                self._last_fetch_transient = True
            else:
                log.error("NVD HTTP-Fehler: %s", status)
            return None
        except (requests.RequestException, ValueError) as exc:
            log.error("NVD Verbindungsfehler: %s", type(exc).__name__)
            return None

    # ------------------------------------------------------------------
    # Parsing (aus Cache oder Live-Response)
    # ------------------------------------------------------------------

    def _parse_vulnerabilities(self, items: list[dict]) -> list[CveEintrag]:
        """Parst eine Liste roher NVD-``vulnerabilities``-Items."""
        return [self._parse_cve(item) for item in items if item.get("cve")]

    # ------------------------------------------------------------------
    # cve_products — Persistierung der (cve_id, product_name)-Paare
    # ------------------------------------------------------------------

    def _store_products(self, eintraege: list[CveEintrag]) -> int:
        """Schreibt die ``betroffene_produkte``-Listen in ``cve_products``.

        Wird nach jedem Online-Fetch in:meth:`_request` aufgerufen, damit
        die normalisierte Lookup-Tabelle ``cve_products`` mit jedem
        NVD-Sync aktualisiert wird (vgl. Sprint S0b).

        Args:
            eintraege: Geparste CVE-Einträge.

        Returns:
            Anzahl tatsächlich neu eingefügter (cve_id, product)-Paare.
        """
        inserted = 0
        for eintrag in eintraege:
            if eintrag.betroffene_produkte:
                try:
                    inserted += self._cache.upsert_products(
                        eintrag.cve_id, eintrag.betroffene_produkte
                    )
                except (OSError, RuntimeError) as exc:
                    log.warning(
                        "cve_products-Upsert fehlgeschlagen (%s): %s",
                        eintrag.cve_id,
                        type(exc).__name__,
                    )
        return inserted

    def backfill_products(self) -> int:
        """Befüllt ``cve_products`` aus den vorhandenen NVD-Cache-Rohdaten.

        Iteriert über alle in ``nvd_cache`` persistierten Antworten,
        re-parsed sie und schreibt die abgeleiteten Produkt-Zuordnungen
        in ``cve_products``. Idempotent — wiederholte Aufrufe haben durch
        ``INSERT OR IGNORE`` keinen Effekt auf bereits eingefügte Zeilen.

        Returns:
            Summe der neu eingefügten (cve_id, product)-Paare.
        """
        inserted = 0
        for items in self._cache.iter_cache_payloads():
            eintraege = self._parse_vulnerabilities(items)
            inserted += self._store_products(eintraege)
        log.info("Backfill cve_products abgeschlossen: %d Zeilen", inserted)
        return inserted

    def _parse_cve(self, item: dict) -> CveEintrag:
        """Parst einen NVD API CVE-Eintrag in ein CveEintrag-Objekt."""
        cve = item["cve"]
        cve_id = cve.get("id", "")

        # Englische Beschreibung bevorzugt
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS Score + Schweregrad (v3.1 → v3.0 → v2)
        score = 0.0
        schweregrad = "INFO"
        metrics = cve.get("metrics", {})
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version in metrics:
                m = metrics[version][0]
                cvss = m.get("cvssData", {})
                score = float(cvss.get("baseScore", 0.0))
                schweregrad = cvss.get(
                    "baseSeverity",
                    m.get("baseSeverity", "INFO"),
                ).upper()
                break

        # CISA KEV
        kev = cve.get("cisaExploitAdd", "")
        frist = cve.get("cisaActionDue", "")

        # Datum
        pub = cve.get("published", "")
        mod = cve.get("lastModified", "")
        try:
            pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            pub_dt = datetime.now(UTC)
        try:
            mod_dt = datetime.fromisoformat(mod.replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            mod_dt = datetime.now(UTC)

        # Betroffene Produkte (max. 3)
        produkte: list[str] = []
        for cfg in cve.get("configurations", [])[:3]:
            for node in cfg.get("nodes", [])[:1]:
                for cpe in node.get("cpeMatch", [])[:1]:
                    uri = cpe.get("criteria", "")
                    parts = uri.split(":")
                    if len(parts) > 4:
                        produkte.append(f"{parts[3]} {parts[4]}")

        return CveEintrag(
            cve_id=cve_id,
            beschreibung=desc[:300],
            schweregrad=schweregrad,
            cvss_score=score,
            veroeffentlicht=pub_dt,
            geaendert=mod_dt,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cisa_kev=bool(kev),
            cisa_frist=frist,
            betroffene_produkte=produkte,
        )
