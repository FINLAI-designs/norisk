"""
Zentraler HTTP-Client fuer FINLAI.

Verwendet fuer alle ausgehenden HTTP-Requests an externe APIs.
NICHT verwenden fuer lokale Services (Ollama auf localhost) —
die brauchen kein Throttling.

Features:
  - Token-Bucket Rate-Limiting pro Domain (thread-safe)
  - Retry mit Retry-After-Header-Support bei HTTP 429
  - Exponentieller Backoff bei Verbindungsfehlern
  - Zentrale Timeout-Defaults
  - Connection-Pooling via requests.Session

Sicherheitsdesign (STRIDE):
  - Tampering: verify=True ist fest kodiert — SSL nie abschalten
  - Info Discl.: Nur die Domain wird geloggt, NICHT die vollstaendige URL
                   (Query-Strings koennen API-Keys enthalten);
                   api_key_header-Wert wird NIEMALS geloggt
  - DoS: Token-Bucket verhindert Burst-Requests;
                   Retry-After-Header wird respektiert, aber auf
                   ``HTTP_MAX_RETRY_AFTER`` gekappt — ein einzelner Retry-Sleep
                   kann einen Worker-Thread nie laenger als diese Schranke
                   blockieren (Schutz gegen einen Server/Cooldown-Endpoint, der
                   eine sehr lange Wartezeit vorgibt). Caller, die einen 429
                   selbst semantisch behandeln (Lizenz-Cooldown), setzen
                   ``retry_on_429=False`` und bekommen den 429 (mit
                   ``raise_for_status=False``) sofort als Response zurueck.
  - Spoofing: User-Agent identifiziert FINLAI korrekt

Schichtzugehoerigkeit: core/ (framework-agnostisch).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

import requests

from core.config import (
    HTTP_DEFAULT_RATE,
    HTTP_DEFAULT_TIMEOUT,
    HTTP_MAX_RETRIES,
    HTTP_MAX_RETRY_AFTER,
    HTTP_RETRY_BACKOFF_BASE,
    NVD_RATE_WITH_KEY,
    NVD_RATE_WITHOUT_KEY,
)
from core.logger import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Rate-Limit-Konfiguration pro Domain
# ---------------------------------------------------------------------------

# Token-Bucket-Parameter je Domain und Auth-Status.
# Werte kommen aus core/config.py — dort zentral anpassen.
RATE_LIMITS: dict[str, dict] = {
    "services.nvd.nist.gov": {
        # 50 req/30s mit Key → 1,67 req/s; konservativ: NVD_RATE_WITH_KEY
        "with_key": {"tokens_per_second": NVD_RATE_WITH_KEY, "max_tokens": 50},
        # 5 req/30s ohne Key → 0,17 req/s; konservativ: NVD_RATE_WITHOUT_KEY
        "without_key": {"tokens_per_second": NVD_RATE_WITHOUT_KEY, "max_tokens": 5},
    },
    # Konservativer Default fuer unbekannte externe Domains
    "_default": {
        "tokens_per_second": HTTP_DEFAULT_RATE,
        "max_tokens": 10,
    },
}


# ---------------------------------------------------------------------------
# Token-Bucket
# ---------------------------------------------------------------------------


class TokenBucket:
    """Thread-sicherer Token-Bucket fuer Rate-Limiting pro Domain.

    Implementiert den klassischen Token-Bucket-Algorithmus:
    Tokens werden mit fester Rate aufgefuellt; ein Request verbraucht
    einen Token. Sind keine Tokens vorhanden, wartet acquire bis
    einer verfuegbar ist (oder der Timeout ablaeuft).
    """

    def __init__(self, tokens_per_second: float, max_tokens: int) -> None:
        """Initialisiert den Token-Bucket.

        Args:
            tokens_per_second: Auffuellrate in Tokens pro Sekunde.
            max_tokens: Maximale Kapazitaet (Burst-Groesse).
        """
        self._rate = tokens_per_second
        self._max_tokens = max_tokens
        self._tokens = float(max_tokens)  # Bucket startet voll
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Wartet bis ein Token verfuegbar ist.

        Args:
            timeout: Maximale Wartezeit in Sekunden.

        Returns:
            True wenn Token erworben, False bei Timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def _refill(self) -> None:
        """Fuellt Tokens entsprechend der verstrichenen Zeit auf.

        Muss unter self._lock aufgerufen werden.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._max_tokens),
            self._tokens + elapsed * self._rate,
        )
        self._last_refill = now


# ---------------------------------------------------------------------------
# Ausnahmetypen
# ---------------------------------------------------------------------------


class RateLimitExceeded(Exception):
    """Rate-Limit-Timeout — Token-Bucket-Wartezeit ueberschritten.

    Wird geworfen wenn acquire innerhalb von 30 Sekunden keinen
    Token erwerben konnte. Deutet auf anhaltende Ueberlastung hin.
    """


class ResponseTooLargeError(Exception):
    """Der Response-Body ueberschreitet das vom Aufrufer gesetzte ``max_bytes``.

    Wird von:meth:`FinLaiHttpClient.get_capped` waehrend des **gestreamten**
    Downloads geworfen, sobald die Summe der gelesenen Chunks ``max_bytes``
    ueberschreitet — fail-closed gegen einen Endpoint, der eine unbegrenzte (oder
    Content-Length-lose/luegende) Antwort liefert. Der Body wird NICHT vollstaendig
    in den Speicher materialisiert.
    """


# ---------------------------------------------------------------------------
# HTTP-Client
# ---------------------------------------------------------------------------


class FinLaiHttpClient:
    """Zentraler HTTP-Client mit Rate-Limiting, Retry und Connection-Pooling.

    Alle ausgehenden HTTP-Requests an externe APIs sollten ueber diesen
    Client gehen. Lokale Services (Ollama auf localhost) sind ausgenommen.

    Beispiel::

        client = get_http_client
        resp = client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cvssV3Severity": "CRITICAL"},
            headers={"apiKey": api_key},
            api_key_header=api_key, # signalisiert hoehere Rate-Limit-Config
)
        data = resp.json
    """

    _DEFAULT_TIMEOUT = HTTP_DEFAULT_TIMEOUT
    _MAX_RETRIES = HTTP_MAX_RETRIES
    _RETRY_BACKOFF_BASE = HTTP_RETRY_BACKOFF_BASE
    _MAX_RETRY_AFTER = HTTP_MAX_RETRY_AFTER

    def __init__(self) -> None:
        """Initialisiert Client mit Session und leerem Bucket-Cache."""
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "NoRisk-by-FINLAI/1.0 (Desktop Security Tool)",
            }
        )
        self._buckets: dict[str, TokenBucket] = {}
        self._bucket_lock = threading.Lock()

    def get(
        self,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        timeout: int | tuple[int, int] | None = None,
        api_key_header: str | None = None,
        retry_on_timeout: bool = False,
        raise_for_status: bool = True,
        retry_on_429: bool = True,
    ) -> requests.Response:
        """HTTP GET mit Rate-Limiting und Retry.

        Args:
            url: Ziel-URL (nur HTTPS fuer externe APIs).
            params: Query-Parameter.
            headers: Zusaetzliche HTTP-Header (ueberschreiben Session-Header).
            timeout: Timeout in Sekunden — entweder int (gesamt) oder
                            Tupel ``(connect, read)``. Standard: 15.
            api_key_header: Signalisiert ob ein API-Key vorhanden ist —
                            bestimmt die Token-Bucket-Konfiguration (hoehere
                            Rate bei vorhandenem Key). Der Wert wird
                            NIEMALS geloggt.
            retry_on_timeout: Opt-in: ``requests.Timeout`` wird bis zu
                            ``_MAX_RETRIES`` wiederholt (Backoff wie bei
                            ConnectionError). Default ``False`` — langsame
                            Netze werden normal nach oben durchgereicht.
            raise_for_status: Default ``True`` — HTTP 4xx/5xx werfen
                            ``requests.HTTPError``. Auf ``False`` setzen, wenn
                            der Caller Fehler-Status selbst auswertet (z.B.
                            Lizenz-Services, die 403/409/410 semantisch
                            behandeln). 429-Retry bleibt davon unberuehrt.
            retry_on_429: Default ``True`` — HTTP 429 wird mit gekapptem
                            ``Retry-After`` bis zu ``_MAX_RETRIES`` mal
                            wiederholt (passend fuer fail-soft Rate-Limit-Caller
                            wie NVD/Feeds). Auf ``False`` setzen, wenn der Caller
                            den 429 selbst semantisch behandelt (Lizenz-
                            Cooldown) — dann wird NICHT geschlafen/wiederholt,
                            sondern der 429 sofort durchgereicht (mit
                            ``raise_for_status=False`` als Response).

        Returns:
            requests.Response

        Raises:
            RateLimitExceeded: Token-Bucket-Timeout nach 30s.
            requests.HTTPError: HTTP 4xx/5xx nach allen Retries (nur bei
                                    ``raise_for_status=True``).
            requests.ConnectionError: Netzwerkfehler nach allen Retries.
            requests.Timeout: Request-Timeout (nur wiederholt bei
                                    ``retry_on_timeout=True``).
        """
        return self._request(
            "GET",
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            api_key_header=api_key_header,
            retry_on_timeout=retry_on_timeout,
            raise_for_status=raise_for_status,
            retry_on_429=retry_on_429,
        )

    def get_capped(
        self,
        url: str,
        *,
        max_bytes: int,
        headers: dict | None = None,
        timeout: int | tuple[int, int] | None = None,
    ) -> bytes:
        """GET mit **gestreamtem**, hart begrenztem Body (fail-closed gegen Body-DoS).

        Im Gegensatz zu:meth:`get` wird der Body NICHT vollstaendig in den
        Speicher materialisiert: er wird via ``stream=True`` chunk-weise gelesen
        und der Download bei Ueberschreiten von ``max_bytes`` sofort abgebrochen
        (``ResponseTooLargeError``). So kann ein Endpoint mit fehlendem/luegendem
        ``Content-Length`` (chunked transfer) keinen unbegrenzten Body in den RAM
        zwingen. Rate-Limiting (Token-Bucket) und ``verify=True`` gelten wie bei
:meth:`get`; bewusst OHNE Retry-Maschinerie (One-Shot — der Aufrufer ist
        fail-soft).

        Args:
            url: Ziel-URL (HTTPS).
            max_bytes: Harte Obergrenze fuer den Body (Bytes).
            headers: Zusaetzliche HTTP-Header.
            timeout: Timeout in Sekunden (Default: ``_DEFAULT_TIMEOUT``).

        Returns:
            Der vollstaendige Body als ``bytes`` (garantiert ``<= max_bytes``).

        Raises:
            RateLimitExceeded: Token-Bucket-Timeout nach 30s.
            ResponseTooLargeError: Body ueberschreitet ``max_bytes``.
            requests.HTTPError: HTTP 4xx/5xx.
            requests.ConnectionError: Netzwerkfehler.
            requests.Timeout: Request-Timeout.
        """
        effective_timeout = timeout or self._DEFAULT_TIMEOUT
        domain = urlparse(url).hostname or "_unknown"

        bucket = self._get_bucket(domain, has_key=False)
        if not bucket.acquire(timeout=30.0):
            raise RateLimitExceeded(
                f"Rate-Limit-Timeout fuer Domain '{domain}' nach 30s"
            )

        response = self._session.get(
            url,
            headers=headers,
            timeout=effective_timeout,
            verify=True,  # SSL nie abschalten!
            stream=True,
        )
        try:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLargeError(
                        f"Body von '{domain}' ueberschreitet {max_bytes} Bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            response.close()

    def post(
        self,
        url: str,
        *,
        json: dict | None = None,
        data: bytes | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        raise_for_status: bool = True,
        retry_on_429: bool = True,
    ) -> requests.Response:
        """HTTP POST mit Rate-Limiting und Retry.

        Args:
            url: Ziel-URL.
            json: JSON-Body (wird automatisch serialisiert).
            data: Roher Request-Body.
            headers: Zusaetzliche HTTP-Header.
            timeout: Timeout in Sekunden (Standard: 15).
            raise_for_status: Default ``True`` — HTTP 4xx/5xx werfen
                     ``requests.HTTPError``. Auf ``False`` setzen, wenn der
                     Caller Fehler-Status selbst auswertet (Lizenz-Services
                     mappen 403/409/410 auf semantische Outcomes). 429-Retry
                     bleibt davon unberuehrt.
            retry_on_429: Default ``True`` — HTTP 429 wird mit gekapptem
                     ``Retry-After`` wiederholt. Auf ``False`` setzen, wenn der
                     Caller den 429 selbst behandelt (Lizenz-Cooldown): dann
                     KEIN Sleep/Retry, der 429 wird sofort durchgereicht (mit
                     ``raise_for_status=False`` als Response). Hebt den ~2h-Hang
                     auf, den ``_MAX_RETRIES`` Sleeps a ``Retry-After`` sonst
                     verursachen.

        Returns:
            requests.Response
        """
        return self._request(
            "POST",
            url,
            json=json,
            data=data,
            headers=headers,
            timeout=timeout,
            raise_for_status=raise_for_status,
            retry_on_429=retry_on_429,
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        timeout: int | tuple[int, int] | None = None,
        api_key_header: str | None = None,
        retry_on_timeout: bool = False,
        raise_for_status: bool = True,
        retry_on_429: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Interne Request-Methode mit Rate-Limiting, Retry und Retry-After.

        Security:
            - Nur die Domain wird geloggt, NICHT die vollstaendige URL.
            - api_key_header wird NIEMALS geloggt.
            - verify=True ist fest kodiert — kann nicht ueberschrieben werden.

        Hinweis: ``raise_for_status`` und ``retry_on_429`` sind benannte
        Parameter (nicht in ``**kwargs``), damit sie NICHT an ``requests``
        durchgereicht werden.
        """
        effective_timeout = timeout or self._DEFAULT_TIMEOUT
        domain = urlparse(url).hostname or "_unknown"

        # Token fuer diese Domain anfordern — blockiert bis Slot frei
        bucket = self._get_bucket(domain, has_key=bool(api_key_header))
        if not bucket.acquire(timeout=30.0):
            raise RateLimitExceeded(
                f"Rate-Limit-Timeout fuer Domain '{domain}' nach 30s"
            )

        # None-Werte herausfiltern damit requests sie nicht erhaelt
        request_kwargs = {k: v for k, v in kwargs.items() if v is not None}

        last_exc: Exception | None = None
        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=effective_timeout,
                    verify=True,  # SSL nie abschalten!
                    **request_kwargs,
                )

                # Retry-After bei HTTP 429 auswerten — nur wenn der Caller den
                # 429 NICHT selbst semantisch behandelt (``retry_on_429``).
                # Bei ``retry_on_429=False`` (Lizenz-Cooldown) wird der 429-Block
                # uebersprungen und die Response sofort durchgereicht — kein
                # Sleep, kein Retry (verhindert den ~2h-Hang aus 2x gekapptem
                # Retry-After).
                if response.status_code == 429 and retry_on_429:
                    if attempt < self._MAX_RETRIES:
                        retry_after = self._parse_retry_after(response)
                        _log.warning(
                            "HTTP 429 von '%s' — warte %ds (Versuch %d/%d)",
                            domain,
                            retry_after,
                            attempt,
                            self._MAX_RETRIES,
                        )
                        time.sleep(retry_after)
                        continue
                    _log.error(
                        "HTTP 429 von '%s' — alle %d Versuche erschoepft",
                        domain,
                        self._MAX_RETRIES,
                    )

                if raise_for_status:
                    response.raise_for_status()
                return response

            except requests.ConnectionError as exc:
                last_exc = exc
                if attempt < self._MAX_RETRIES:
                    delay = self._RETRY_BACKOFF_BASE * attempt
                    _log.warning(
                        "Verbindungsfehler '%s' — Retry in %.1fs (%d/%d)",
                        domain,
                        delay,
                        attempt,
                        self._MAX_RETRIES,
                    )
                    time.sleep(delay)
                    continue
                raise

            except requests.Timeout as exc:
                # Timeouts werden standardmaessig NICHT wiederholt — Netz ist
                # dauerhaft langsam. Services mit Cache-Fallback (z.B. NVD)
                # koennen ``retry_on_timeout=True`` setzen, dann wird wie bei
                # ConnectionError mit exponentiellem Backoff wiederholt.
                if retry_on_timeout:
                    last_exc = exc
                    if attempt < self._MAX_RETRIES:
                        delay = self._RETRY_BACKOFF_BASE * attempt
                        _log.warning(
                            "Timeout '%s' — Retry in %.1fs (%d/%d)",
                            domain,
                            delay,
                            attempt,
                            self._MAX_RETRIES,
                        )
                        time.sleep(delay)
                        continue
                raise

            except requests.HTTPError:
                # 4xx/5xx (ausser 429 s.o.) werden nicht wiederholt
                raise

        # Erreichbar nur wenn alle ConnectionError-Retries erschoepft sind
        if last_exc is not None:
            raise last_exc
        raise requests.ConnectionError(  # pragma: no cover
            f"Alle {self._MAX_RETRIES} Verbindungsversuche zu '{domain}' fehlgeschlagen"
        )

    def _get_bucket(self, domain: str, has_key: bool = False) -> TokenBucket:
        """Gibt den Token-Bucket fuer eine Domain zurueck (thread-safe, lazy).

        Args:
            domain: Hostname der Ziel-Domain.
            has_key: True wenn ein API-Key vorhanden ist.

        Returns:
            Vorhandener oder neu erstellter TokenBucket.
        """
        bucket_key = f"{domain}:{'key' if has_key else 'nokey'}"
        with self._bucket_lock:
            if bucket_key not in self._buckets:
                domain_cfg = RATE_LIMITS.get(domain, RATE_LIMITS["_default"])
                # NVD hat zwei Konfigurationen (with_key / without_key)
                if "with_key" in domain_cfg:
                    cfg = (
                        domain_cfg["with_key"] if has_key else domain_cfg["without_key"]
                    )
                else:
                    cfg = domain_cfg
                self._buckets[bucket_key] = TokenBucket(**cfg)
                _log.debug(
                    "Token-Bucket erstellt: %s (%.2f req/s, max %d)",
                    bucket_key,
                    cfg["tokens_per_second"],
                    cfg["max_tokens"],
                )
            return self._buckets[bucket_key]

    @classmethod
    def _parse_retry_after(cls, response: requests.Response) -> int:
        """Parst den Retry-After-Header — gekappt auf ``_MAX_RETRY_AFTER``.

        Der vom Server vorgegebene Wert wird hart auf ``_MAX_RETRY_AFTER``
        begrenzt, damit ein einzelner Retry-Sleep einen Worker-Thread nie
        laenger als diese Schranke blockiert (Schutz gegen einen Server/
        Cooldown-Endpoint, der eine sehr lange Wartezeit vorgibt). Fallback bei
        fehlendem/ungueltigem Header: 30 Sekunden (ebenfalls gekappt).

        Args:
            response: HTTP-Response mit moeglichem Retry-After-Header.

        Returns:
            Wartezeit in Sekunden, ``1 <= wert <= _MAX_RETRY_AFTER``.
        """
        header = response.headers.get("Retry-After", "")
        try:
            seconds = max(1, int(header))
        except (ValueError, TypeError):
            seconds = 30
        return min(seconds, cls._MAX_RETRY_AFTER)

    def close(self) -> None:
        """Schliesst die Session und gibt Ressourcen frei."""
        self._session.close()


# ---------------------------------------------------------------------------
# Thread-sicherer Singleton
# ---------------------------------------------------------------------------

_client: FinLaiHttpClient | None = None
_client_lock = threading.Lock()


def get_http_client() -> FinLaiHttpClient:
    """Gibt die globale FinLaiHttpClient-Instanz zurueck (thread-safe Singleton).

    Returns:
        Globale FinLaiHttpClient-Instanz.
    """
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = FinLaiHttpClient()
                _log.debug("FinLaiHttpClient Singleton erstellt")
    return _client
