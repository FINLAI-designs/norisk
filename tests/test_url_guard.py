"""
test_url_guard — Tests fuer ``core.url_guard.open_external_url``.

Die Scheme-Whitelist ist die zentrale Mitigation gegen
``file://`` / ``javascript:`` / ``ms-msdt:`` (Follina-Klasse) aus
nicht-vertrauenswuerdigen Eingaben (RSS-Feeds). Security-Bezug:
 follow-up P1 + (Phishing-Radar P0-S2).
"""

from __future__ import annotations

from unittest.mock import patch

from core.url_guard import open_external_url


class TestOpenExternalUrl:
    def test_https_wird_geoeffnet(self) -> None:
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("https://watchlist-internet.at/x") is True
            mock_open.assert_called_once()

    def test_http_wird_geoeffnet(self) -> None:
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("http://example.com") is True
            mock_open.assert_called_once()

    def test_file_scheme_blockiert(self) -> None:
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("file:///C:/Windows/System32/cmd.exe") is False
            mock_open.assert_not_called()

    def test_javascript_scheme_blockiert(self) -> None:
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("javascript:alert(1)") is False
            mock_open.assert_not_called()

    def test_ms_msdt_scheme_blockiert(self) -> None:
        """Follina-Klasse — ms-msdt: wuerde Code-Execution triggern."""
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("ms-msdt:/id PCWDiagnostic /skip force") is False
            mock_open.assert_not_called()

    def test_leere_url_no_op(self) -> None:
        with patch("core.url_guard.QDesktopServices.openUrl") as mock_open:
            assert open_external_url("") is False
            mock_open.assert_not_called()
