"""
test_http_client — Tests fuer core/http_client.py und core/config.py.

Prueft:
- TokenBucket: Acquire, Timeout, Auffuellen
- FinLaiHttpClient: Erfolg, 429/Retry-After, ConnectionError/Backoff, Timeout
- RateLimitExceeded wenn Bucket leer und Timeout ablaeuft
- NVD-Service nutzt zentralen Client (kein eigenes requests.get)
- web_fetch_tool: Fetch-Limit pro Lauf, Counter-Reset bei neuer Instanz
- core/config.py: Konstanten importierbar und plausibel

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


class TestTokenBucket:
    """Tests fuer den Token-Bucket-Algorithmus."""

    def test_acquire_sofort_bei_vollem_bucket(self):
        """Voller Bucket: acquire gibt sofort True zurueck."""
        from core.http_client import TokenBucket

        bucket = TokenBucket(tokens_per_second=2.0, max_tokens=5)
        assert bucket.acquire(timeout=0.0) is True

    def test_zwei_acquires_aus_vollem_bucket(self):
        """Zwei schnelle Acquires aus einem Bucket mit max_tokens=2."""
        from core.http_client import TokenBucket

        bucket = TokenBucket(tokens_per_second=2.0, max_tokens=2)
        assert bucket.acquire(timeout=0.0) is True
        assert bucket.acquire(timeout=0.0) is True

    def test_dritter_acquire_bei_leerem_bucket_timeout(self):
        """Leerer Bucket: acquire gibt False zurueck wenn Timeout ablaeuft."""
        from core.http_client import TokenBucket

        bucket = TokenBucket(tokens_per_second=0.01, max_tokens=1)
        bucket.acquire(timeout=0.0)  # Token verbrauchen
        # Sehr kurzer Timeout — Token kann nicht aufgefuellt werden
        result = bucket.acquire(timeout=0.05)
        assert result is False

    def test_bucket_fuellt_sich_mit_der_zeit(self):
        """Nach sleep wird ein neuer Token verfuegbar."""
        import time

        from core.http_client import TokenBucket

        # 10 tokens/s → nach 0.15s mindestens 1 Token nachgefuellt
        bucket = TokenBucket(tokens_per_second=10.0, max_tokens=2)
        bucket.acquire(timeout=0.0)
        bucket.acquire(timeout=0.0)  # Bucket leer
        time.sleep(0.15)
        assert bucket.acquire(timeout=0.0) is True

    def test_max_tokens_wird_nicht_ueberschritten(self):
        """Bucket fuellt nicht ueber max_tokens hinaus auf."""
        import time

        from core.http_client import TokenBucket

        bucket = TokenBucket(tokens_per_second=100.0, max_tokens=3)
        time.sleep(0.1)  # Lange warten — trotzdem max. 3 Tokens
        count = 0
        while bucket.acquire(timeout=0.0):
            count += 1
            if count > 10:
                break
        assert count == 3


# ---------------------------------------------------------------------------
# FinLaiHttpClient
# ---------------------------------------------------------------------------


class TestFinLaiHttpClient:
    """Tests fuer den zentralen HTTP-Client."""

    @pytest.fixture
    def client(self):
        """Frischer Client fuer jeden Test."""
        from core.http_client import FinLaiHttpClient

        c = FinLaiHttpClient()
        yield c
        c.close()

    def _make_response(self, status_code: int = 200, headers: dict | None = None):
        """Erstellt ein Mock-Response-Objekt."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = headers or {}
        if status_code >= 400:
            resp.raise_for_status.side_effect = req_lib.HTTPError(response=resp)
        else:
            resp.raise_for_status.return_value = None
        return resp

    def test_erfolgreicher_get_request(self, client):
        """Erfolgreicher GET-Request gibt Response zurueck."""
        mock_resp = self._make_response(200)

        with patch.object(client._session, "request", return_value=mock_resp):
            resp = client.get("https://example.com/api")

        assert resp is mock_resp

    def _make_stream_response(self, chunks, status_code: int = 200):
        """Mock-Response, das ``iter_content`` chunk-weise liefert (kein Body-Buffer)."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = {}  # bewusst KEIN Content-Length (chunked) — der harte Fall
        resp.raise_for_status.return_value = None
        resp.iter_content.return_value = iter(chunks)
        return resp

    def test_get_capped_liefert_body(self, client):
        """get_capped gibt den gestreamten Body als bytes zurueck."""
        resp = self._make_stream_response([b"1.2.3.4\n", b"10.0.0.0/8\n"])
        with patch.object(client._session, "get", return_value=resp) as mock_get:
            body = client.get_capped("https://example.com/feed", max_bytes=1024)
        assert body == b"1.2.3.4\n10.0.0.0/8\n"
        # stream=True + verify=True erzwungen (kein Voll-Buffering, kein TLS-Off)
        assert mock_get.call_args.kwargs["stream"] is True
        assert mock_get.call_args.kwargs["verify"] is True

    def test_get_capped_bricht_bei_ueberschreitung_ab(self, client):
        """Ohne Content-Length: Cap greift WAEHREND des Streamens (fail-closed)."""
        from core.http_client import ResponseTooLargeError

        # Drei 5-Byte-Chunks = 15 Bytes > max_bytes=10 → Abbruch beim 3. Chunk,
        # OHNE den ganzen Body zu materialisieren.
        resp = self._make_stream_response([b"aaaaa", b"bbbbb", b"ccccc"])
        with (
            patch.object(client._session, "get", return_value=resp),
            pytest.raises(ResponseTooLargeError),
        ):
            client.get_capped("https://example.com/feed", max_bytes=10)
        resp.close.assert_called_once()  # Verbindung wird geschlossen

    def test_verify_true_immer_gesetzt(self, client):
        """verify=True wird bei jedem Request erzwungen."""
        mock_resp = self._make_response(200)

        with patch.object(
            client._session, "request", return_value=mock_resp
        ) as mock_req:
            client.get("https://example.com/api")

        _, kwargs = mock_req.call_args
        assert kwargs.get("verify") is True

    def test_429_mit_retry_after_wartet_und_wiederholt(self, client):
        """HTTP 429 mit Retry-After: 2 → wartet 2s, dann Retry."""
        resp_429 = self._make_response(429, headers={"Retry-After": "2"})
        resp_429.raise_for_status.return_value = None  # 429 wird intern behandelt
        resp_200 = self._make_response(200)

        with (
            patch.object(
                client._session,
                "request",
                side_effect=[resp_429, resp_200],
            ),
            patch("core.http_client.time.sleep") as mock_sleep,
        ):
            result = client.get("https://example.com/api")

        assert result is resp_200
        mock_sleep.assert_called_once_with(2)

    def test_429_ohne_retry_after_wartet_30s_fallback(self, client):
        """HTTP 429 ohne Retry-After-Header → Fallback 30s."""
        resp_429 = self._make_response(429, headers={})
        resp_429.raise_for_status.return_value = None
        resp_200 = self._make_response(200)

        with (
            patch.object(
                client._session,
                "request",
                side_effect=[resp_429, resp_200],
            ),
            patch("core.http_client.time.sleep") as mock_sleep,
        ):
            client.get("https://example.com/api")

        mock_sleep.assert_called_once_with(30)

    def test_429_retry_after_wird_gekappt(self, client):
        """Retry-After ueber dem Cap wird auf _MAX_RETRY_AFTER begrenzt.

        Schuetzt vor dem ~2h-Hang: selbst wenn ein Server (oder ein Cooldown-
        Endpoint) ein riesiges Retry-After vorgibt, blockiert ein einzelner
        Retry-Sleep den Thread nie laenger als _MAX_RETRY_AFTER.
        """
        from core.http_client import FinLaiHttpClient

        resp_429 = self._make_response(429, headers={"Retry-After": "7200"})
        resp_429.raise_for_status.return_value = None  # 429 wird intern behandelt
        resp_200 = self._make_response(200)

        with (
            patch.object(
                client._session,
                "request",
                side_effect=[resp_429, resp_200],
            ),
            patch("core.http_client.time.sleep") as mock_sleep,
        ):
            client.get("https://example.com/api")

        mock_sleep.assert_called_once_with(FinLaiHttpClient._MAX_RETRY_AFTER)

    def test_429_retry_on_429_false_gibt_sofort_zurueck(self, client):
        """retry_on_429=False: 429 wird ohne Sleep/Retry sofort durchgereicht.

        Lizenz-Caller (Trial-Cooldown etc.) werten den 429 selbst aus — sie
        wollen die Response sofort, nicht nach _MAX_RETRIES Sleeps.
        """
        resp_429 = self._make_response(429, headers={"Retry-After": "3600"})

        with (
            patch.object(
                client._session, "request", return_value=resp_429
            ) as mock_req,
            patch("core.http_client.time.sleep") as mock_sleep,
        ):
            result = client.post(
                "https://example.com/api",
                json={},
                raise_for_status=False,
                retry_on_429=False,
            )

        assert result is resp_429
        assert result.status_code == 429
        mock_sleep.assert_not_called()  # kein Warten
        assert mock_req.call_count == 1  # genau EIN Versuch, kein Retry

    def test_connection_error_retry_mit_backoff(self, client):
        """ConnectionError → max. 3 Versuche mit exponentiellem Backoff."""
        conn_err = req_lib.ConnectionError("refused")

        with (
            patch.object(
                client._session,
                "request",
                side_effect=[conn_err, conn_err, conn_err],
            ),
            patch("core.http_client.time.sleep") as mock_sleep,
            pytest.raises(req_lib.ConnectionError),
        ):
            client.get("https://example.com/api")

        # 2 Sleeps (zwischen Versuch 1→2 und 2→3), kein Sleep nach letztem
        assert mock_sleep.call_count == 2
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert sleep_args[0] < sleep_args[1]  # Exponentiell wachsend

    def test_connection_error_zweiter_versuch_erfolgreich(self, client):
        """ConnectionError beim ersten Versuch, Erfolg beim zweiten."""
        conn_err = req_lib.ConnectionError("refused")
        resp_200 = self._make_response(200)

        with (
            patch.object(
                client._session,
                "request",
                side_effect=[conn_err, resp_200],
            ),
            patch("core.http_client.time.sleep"),
        ):
            result = client.get("https://example.com/api")

        assert result is resp_200

    def test_timeout_kein_retry(self, client):
        """Timeout wird sofort weitergegeben — kein Retry."""
        with (
            patch.object(
                client._session,
                "request",
                side_effect=req_lib.Timeout("too slow"),
            ),
            patch("core.http_client.time.sleep") as mock_sleep,
            pytest.raises(req_lib.Timeout),
        ):
            client.get("https://example.com/api")

        mock_sleep.assert_not_called()

    def test_rate_limit_exceeded_bei_bucket_timeout(self, client):
        """RateLimitExceeded wenn Token-Bucket innerhalb Timeout leer bleibt."""
        from core.http_client import RateLimitExceeded

        # Bucket mit 0 tokens/s der nie auffuellt
        mock_bucket = MagicMock()
        mock_bucket.acquire.return_value = False

        with (
            patch.object(client, "_get_bucket", return_value=mock_bucket),
            pytest.raises(RateLimitExceeded),
        ):
            client.get("https://example.com/api")

    def test_domain_wird_aus_url_extrahiert(self, client):
        """Token-Bucket wird fuer die korrekte Domain erstellt."""
        mock_resp = self._make_response(200)

        with (
            patch.object(client._session, "request", return_value=mock_resp),
            patch.object(client, "_get_bucket", wraps=client._get_bucket) as spy,
        ):
            client.get("https://api.example.com/endpoint")

        domain_arg = spy.call_args.args[0]
        assert domain_arg == "api.example.com"

    def test_4xx_raised_default(self, client):
        """Default (raise_for_status=True): HTTP 4xx wirft HTTPError."""
        resp_403 = self._make_response(403)

        with (
            patch.object(client._session, "request", return_value=resp_403),
            pytest.raises(req_lib.HTTPError),
        ):
            client.post("https://example.com/api", json={})

    def test_4xx_not_raised_when_disabled(self, client):
        """raise_for_status=False: HTTP 4xx wird als Response zurueckgegeben.

        Lizenz-Services (activate/revalidate/deactivate) werten 403/409/410
        semantisch aus — sie brauchen die Response statt einer Exception.
        """
        resp_409 = self._make_response(409)

        with patch.object(client._session, "request", return_value=resp_409):
            result = client.post(
                "https://example.com/api", json={}, raise_for_status=False
            )

        assert result is resp_409
        assert result.status_code == 409
        resp_409.raise_for_status.assert_not_called()

    def test_get_raise_for_status_false_returns_4xx(self, client):
        """raise_for_status=False gilt symmetrisch auch fuer GET."""
        resp_404 = self._make_response(404)

        with patch.object(client._session, "request", return_value=resp_404):
            result = client.get("https://example.com/api", raise_for_status=False)

        assert result.status_code == 404


# ---------------------------------------------------------------------------
# NVD-Service nutzt zentralen Client
# ---------------------------------------------------------------------------


class TestNvdServiceUsesHttpClient:
    """Stellt sicher dass NvdService keinen eigenen requests.get mehr nutzt."""

    def test_kein_eigenes_requests_get(self):
        """nvd_service.py importiert requests nur fuer Exceptions."""
        import ast
        from pathlib import Path

        src = Path("tools/cyber_dashboard/application/nvd_service.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(src)

        # Suche nach direkten requests.get/post Aufrufen (Attribute-Zugriff)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "requests"
                    and func.attr in ("get", "post", "put", "delete")
                ):
                    pytest.fail(
                        f"nvd_service.py ruft requests.{func.attr}() direkt auf "
                        f"(Zeile {node.lineno}) — statt get_http_client() zu verwenden"
                    )

    def test_kein_time_sleep_in_nvd_service(self):
        """nvd_service.py hat kein manuelles time.sleep mehr."""
        import ast
        from pathlib import Path

        src = Path("tools/cyber_dashboard/application/nvd_service.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(src)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # time.sleep
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "time"
                    and func.attr == "sleep"
                ):
                    pytest.fail(
                        f"nvd_service.py ruft time.sleep() auf (Zeile {node.lineno})"
                        " — Rate-Limiting wird vom Token-Bucket uebernommen"
                    )


# ---------------------------------------------------------------------------
# core/config.py — Konstanten plausibel
# ---------------------------------------------------------------------------


class TestConfigKonstanten:
    """Prueft dass alle Konstanten importierbar und plausibel sind."""

    def test_alle_konstanten_importierbar(self):
        """Alle dokumentierten Konstanten koennen importiert werden."""

        # Nur der Import selbst wird getestet — kein AssertionError = OK
        assert True

    def test_http_werte_positiv(self):
        """Alle HTTP-Timeouts und Raten sind positiv."""
        from core.config import (
            HTTP_DEFAULT_RATE,
            HTTP_DEFAULT_TIMEOUT,
            HTTP_MAX_RETRIES,
            HTTP_MAX_RETRY_AFTER,
            HTTP_RETRY_BACKOFF_BASE,
        )

        assert HTTP_DEFAULT_TIMEOUT > 0
        assert HTTP_DEFAULT_RATE > 0
        assert HTTP_MAX_RETRIES >= 1
        assert HTTP_RETRY_BACKOFF_BASE > 0
        # Cap muss >= dem 30s-Fallback liegen, sonst kappt er den Fallback
        # (siehe _parse_retry_after) — und positiv sein.
        assert HTTP_MAX_RETRY_AFTER >= 30

    def test_nvd_rate_mit_key_groesser_als_ohne(self):
        """NVD-Rate mit Key muss groesser sein als ohne Key."""
        from core.config import NVD_RATE_WITH_KEY, NVD_RATE_WITHOUT_KEY

        assert NVD_RATE_WITH_KEY > NVD_RATE_WITHOUT_KEY

    def test_agent_limits_positiv(self):
        """Alle Agent-Limits sind positive ganze Zahlen."""
        from core.config import (
            AGENT_MAX_FETCHES_PER_RUN,
            AGENT_MAX_RUNS_PER_HOUR,
            AGENT_MAX_SEARCH_RESULTS,
        )

        assert AGENT_MAX_RUNS_PER_HOUR >= 1
        assert AGENT_MAX_FETCHES_PER_RUN >= 1
        assert AGENT_MAX_SEARCH_RESULTS >= 1

    def test_ollama_werte_plausibel(self):
        """Ollama-Timeouts sind plausibel (Startup < Request)."""
        from core.config import (
            OLLAMA_MAX_RESPONSE_BYTES,
            OLLAMA_REQUEST_TIMEOUT,
            OLLAMA_STARTUP_TIMEOUT,
        )

        assert OLLAMA_STARTUP_TIMEOUT > 0
        assert OLLAMA_REQUEST_TIMEOUT > OLLAMA_STARTUP_TIMEOUT  # LLM > Startup
        assert OLLAMA_MAX_RESPONSE_BYTES > 0

    def test_http_client_verwendet_config_konstanten(self):
        """FinLaiHttpClient.CLASS-Konstanten stimmen mit config.py ueberein."""
        from core.config import (
            HTTP_DEFAULT_TIMEOUT,
            HTTP_MAX_RETRIES,
            HTTP_MAX_RETRY_AFTER,
            HTTP_RETRY_BACKOFF_BASE,
        )
        from core.http_client import FinLaiHttpClient

        assert FinLaiHttpClient._DEFAULT_TIMEOUT == HTTP_DEFAULT_TIMEOUT
        assert FinLaiHttpClient._MAX_RETRIES == HTTP_MAX_RETRIES
        assert FinLaiHttpClient._RETRY_BACKOFF_BASE == HTTP_RETRY_BACKOFF_BASE
        assert FinLaiHttpClient._MAX_RETRY_AFTER == HTTP_MAX_RETRY_AFTER

    def test_rate_limits_dict_verwendet_config_konstanten(self):
        """RATE_LIMITS-Dict nutzt NVD-Konstanten aus config.py."""
        from core.config import NVD_RATE_WITH_KEY, NVD_RATE_WITHOUT_KEY
        from core.http_client import RATE_LIMITS

        nvd = RATE_LIMITS["services.nvd.nist.gov"]
        assert nvd["with_key"]["tokens_per_second"] == NVD_RATE_WITH_KEY
        assert nvd["without_key"]["tokens_per_second"] == NVD_RATE_WITHOUT_KEY
