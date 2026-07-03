"""test_nvd_status_hint — User-facing Hinweis-Text fuer NVD-Status.

Prueft:meth:`DashboardService.nvd_status_hint` mit gemockten
NvdService-Status-Werten. GUI-Integration laeuft separat in
``tests/gui/test_cyber_dashboard*``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.application.nvd_service import NvdStatus


@pytest.fixture()
def service_with_mock_nvd() -> tuple[DashboardService, MagicMock]:
    """``DashboardService`` mit gemocktem NvdService — minimal genug."""
    nvd = MagicMock()
    nvd.api_key_gesetzt.return_value = True
    nvd.last_status = NvdStatus.ONLINE
    svc = DashboardService(rss=MagicMock(), cache=MagicMock(), nvd=nvd)
    return svc, nvd


class TestNvdStatusHint:
    """Mapping NvdStatus -> User-Hinweis-Text."""

    def test_no_nvd_returns_none(self) -> None:
        """Ohne injizierten NvdService gibt es keinen Hinweis."""
        svc = DashboardService(rss=MagicMock(), cache=MagicMock(), nvd=None)
        assert svc.nvd_status_hint() is None

    def test_no_api_key_returns_hint(self) -> None:
        """Fehlender API-Key liefert einen klaren Einstellungs-Verweis."""
        nvd = MagicMock()
        nvd.api_key_gesetzt.return_value = False
        svc = DashboardService(rss=MagicMock(), cache=MagicMock(), nvd=nvd)
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "API-Key" in hint
        assert "Einstellungen" in hint

    def test_online_returns_none(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        """Bei ``ONLINE`` ist kein User-Hinweis noetig."""
        svc, _ = service_with_mock_nvd
        assert svc.nvd_status_hint() is None

    def test_rate_limit_returns_user_hint(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        """``RATE_LIMIT`` liefert klaren Hinweis (statt stillem 'leere Liste')."""
        svc, nvd = service_with_mock_nvd
        nvd.last_status = NvdStatus.RATE_LIMIT
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "Rate-Limit" in hint
        assert "spaeter" in hint.lower()

    def test_offline_no_cache(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        svc, nvd = service_with_mock_nvd
        nvd.last_status = NvdStatus.OFFLINE_NO_CACHE
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "nicht erreichbar" in hint

    def test_cache_stale_offline(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        svc, nvd = service_with_mock_nvd
        nvd.last_status = NvdStatus.CACHE_STALE_OFFLINE
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "Cache" in hint

    def test_server_error_returns_cache_hint(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        """NVD-503: transienter Server-Fehler liefert den 'Cache'-Hinweis.

        Wichtig: NICHT 'veraltet' (der Cache ist hier frisch), sondern der
        präzise 'gerade nicht erreichbar — Anzeige aus Cache vom <Stand>'.
        """
        svc, nvd = service_with_mock_nvd
        nvd.last_status = NvdStatus.SERVER_ERROR
        nvd.last_fetched_at = datetime(2026, 6, 21, 14, 30, tzinfo=UTC)
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "nicht erreichbar" in hint
        assert "Cache" in hint
        assert "veraltet" not in hint
        # Der formatierte Cache-Stand erscheint im Hinweis.
        assert "21.06.2026" in hint

    def test_server_error_hint_without_fetched_at(
        self, service_with_mock_nvd: tuple[DashboardService, MagicMock]
    ) -> None:
        """Ohne bekanntes Cache-Datum bleibt der Hinweis robust ('unbekannt')."""
        svc, nvd = service_with_mock_nvd
        nvd.last_status = NvdStatus.SERVER_ERROR
        nvd.last_fetched_at = None
        hint = svc.nvd_status_hint()
        assert hint is not None
        assert "unbekannt" in hint
