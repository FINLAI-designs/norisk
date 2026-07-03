"""test_nvd_server_error_degradation — graziöse Degradation bei NVD-5xx (NVD-503).

Prüft, dass ein transienter Server-Fehler (503/502/500/504) beim Bulk-Fetch
NICHT als ``log.ERROR`` durchschlägt, wenn ein Cache als Notlösung dient, und
dass dabei ein präziser:class:`NvdStatus.SERVER_ERROR` gesetzt wird (statt
fälschlich ``CACHE_STALE_OFFLINE``/``RATE_LIMIT``). Ergänzt wird der
Hint-Mapper des:class:`VulnerabilityOverviewService`.

Author: Patrick Riederich
Version: 1.0 (NVD-503)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import requests

from tools.cyber_dashboard.application.nvd_service import NvdService, NvdStatus
from tools.cyber_dashboard.application.vulnerability_overview_service import (
    VulnerabilityOverviewService,
)
from tools.cyber_dashboard.data.nvd_cache_repository import NvdCacheEntry

# ---------------------------------------------------------------------------
# Helfer
# ---------------------------------------------------------------------------


def _http_error_response(status: int) -> MagicMock:
    """Baut eine Mock-Response, deren ``raise_for_status`` einen 5xx wirft."""
    resp = MagicMock()
    resp.status_code = status
    err = requests.HTTPError(f"{status} Server Error")
    err.response = MagicMock()
    err.response.status_code = status
    resp.raise_for_status.side_effect = err
    return resp


def _cache_entry(*, stale: bool, age_hours: int = 12) -> NvdCacheEntry:
    """Baut einen Cache-Eintrag mit definiertem Stale-Zustand."""
    return NvdCacheEntry(
        data=[],
        fetched_at=datetime.now(UTC) - timedelta(hours=age_hours),
        is_stale=stale,
    )


def _make_service_with_cache(entry: NvdCacheEntry) -> tuple[NvdService, MagicMock]:
    """``NvdService`` mit gemocktem Cache, der ``entry`` liefert."""
    cache = MagicMock()
    cache.get.return_value = entry
    svc = NvdService(cache=cache)
    svc._api_key = "test-key"
    return svc, cache


# ---------------------------------------------------------------------------
# Service-Pfad: 503 mit vorhandenem Cache
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_with_cache_sets_server_error_status(status: int) -> None:
    """5xx + vorhandener (stale) Cache → Status SERVER_ERROR, nicht STALE/RATE_LIMIT."""
    svc, _ = _make_service_with_cache(_cache_entry(stale=True))

    with patch(
        "tools.cyber_dashboard.application.nvd_service.get_http_client"
    ) as mock_client:
        mock_client.return_value.get.return_value = _http_error_response(status)
        svc.lade_neueste_cves(tage=7)

    assert svc.last_status == NvdStatus.SERVER_ERROR
    assert svc.last_status != NvdStatus.CACHE_STALE_OFFLINE
    assert svc.last_status != NvdStatus.RATE_LIMIT
    # Cache-Stand bleibt erhalten (für den UI-Hinweis 'aus Cache vom...').
    assert svc.last_fetched_at is not None


def test_5xx_with_cache_logs_warning_not_error(caplog: pytest.LogCaptureFixture) -> None:
    """5xx + Cache: kein log.ERROR — bei Cache-Fallback kein echter Nutzerfehler."""
    svc, _ = _make_service_with_cache(_cache_entry(stale=True))

    with (
        patch(
            "tools.cyber_dashboard.application.nvd_service.get_http_client"
        ) as mock_client,
        caplog.at_level(logging.DEBUG, logger="tools.cyber_dashboard.application.nvd_service"),
    ):
        mock_client.return_value.get.return_value = _http_error_response(503)
        svc.lade_neueste_cves(tage=7)

    nvd_records = [
        r for r in caplog.records if r.name.endswith("nvd_service")
    ]
    assert nvd_records, "Es sollte mindestens ein NVD-Log-Record entstehen"
    assert all(r.levelno < logging.ERROR for r in nvd_records), (
        "Kein Log-Record darf ERROR-Level haben (transienter 5xx mit Cache)"
    )
    # Mindestens eine WARNING dokumentiert den transienten Server-Fehler.
    assert any(r.levelno == logging.WARNING for r in nvd_records)


def test_is_offline_true_for_server_error() -> None:
    """SERVER_ERROR zählt als 'nicht live' → is_offline True (UI-Banner-Steuerung)."""
    svc, _ = _make_service_with_cache(_cache_entry(stale=True))
    with patch(
        "tools.cyber_dashboard.application.nvd_service.get_http_client"
    ) as mock_client:
        mock_client.return_value.get.return_value = _http_error_response(503)
        svc.lade_neueste_cves(tage=7)
    assert svc.is_offline() is True


def test_5xx_without_cache_stays_offline_no_cache() -> None:
    """5xx OHNE Cache → OFFLINE_NO_CACHE (kein SERVER_ERROR ohne Anzeige-Daten)."""
    cache = MagicMock()
    cache.get.return_value = None
    svc = NvdService(cache=cache)
    svc._api_key = "test-key"

    with patch(
        "tools.cyber_dashboard.application.nvd_service.get_http_client"
    ) as mock_client:
        mock_client.return_value.get.return_value = _http_error_response(503)
        result = svc.lade_neueste_cves(tage=7)

    assert result == []
    assert svc.last_status == NvdStatus.OFFLINE_NO_CACHE


def test_transient_flag_reset_between_requests() -> None:
    """Ein voriger 5xx darf nicht in einen späteren erfolgreichen Fetch durchschlagen."""
    svc, _ = _make_service_with_cache(_cache_entry(stale=True))

    with patch(
        "tools.cyber_dashboard.application.nvd_service.get_http_client"
    ) as mock_client:
        mock_client.return_value.get.return_value = _http_error_response(503)
        svc.lade_neueste_cves(tage=7)
    assert svc.last_status == NvdStatus.SERVER_ERROR

    # Zweiter Lauf: jetzt liefert NVD erfolgreich → Status ONLINE, Flag weg.
    ok_resp = MagicMock()
    ok_resp.json.return_value = {"vulnerabilities": []}
    ok_resp.raise_for_status.return_value = None
    svc._cache.get.return_value = None  # frischer Fetch erzwingen
    with patch(
        "tools.cyber_dashboard.application.nvd_service.get_http_client"
    ) as mock_client:
        mock_client.return_value.get.return_value = ok_resp
        svc.lade_neueste_cves(tage=7)
    assert svc.last_status == NvdStatus.ONLINE


# ---------------------------------------------------------------------------
# Overview-Service-Hint
# ---------------------------------------------------------------------------


def test_overview_hint_server_error() -> None:
    """Overview-Service liefert den 'NVD nicht erreichbar — Cache'-Text bei 5xx."""
    nvd = MagicMock()
    nvd.last_status = NvdStatus.SERVER_ERROR
    nvd.last_fetched_at = datetime(2026, 6, 21, 9, 5, tzinfo=UTC)
    svc = VulnerabilityOverviewService(nvd_service=nvd)

    hint = svc.nvd_status_hint()
    assert hint is not None
    assert "nicht erreichbar" in hint
    assert "Cache" in hint
    assert "21.06.2026" in hint


def test_overview_hint_online_returns_none() -> None:
    """Bei ONLINE gibt es keinen Cache-Hinweis."""
    nvd = MagicMock()
    nvd.last_status = NvdStatus.ONLINE
    svc = VulnerabilityOverviewService(nvd_service=nvd)
    assert svc.nvd_status_hint() is None


def test_overview_hint_no_nvd_returns_none() -> None:
    """Ohne injizierten NvdService keine Exception, kein Hinweis."""
    svc = VulnerabilityOverviewService(nvd_service=None)
    assert svc.nvd_status_hint() is None
