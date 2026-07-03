"""test_custom_source_checker — Tests fuer Stop-Step B.

Deckt:
* check Happy-Path (Regex matcht → available_version)
* Markup-Bruch (kein Match) → ERR_VERSION_NOT_FOUND
* ungueltiger Regex → ERR_INVALID_REGEX (kein Fetch)
* non-http URL → ERR_NON_HTTP (kein Fetch)
* Fetch-Exception → ERR_UNREACHABLE, alte available_version bleibt
* Regex ohne Capture-Group → group(0)
* is_update_available-Semantik

Der HTTP-Fetch wird via ``fetch``-Injection ersetzt — kein echter Netzwerk-Call.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from core.patch_custom_source import CustomSource, Platform
from tools.patch_monitor.application.custom_source_checker import (
    ERR_INVALID_REGEX,
    ERR_NON_HTTP,
    ERR_UNREACHABLE,
    ERR_VERSION_NOT_FOUND,
    CustomSourceChecker,
    is_update_available,
)


def _source(
    *,
    vendor_url: str = "https://example.com/download",
    version_regex: str = r"Version (\d+\.\d+)",
    installed_version: str | None = "1.0",
    available_version: str | None = None,
    last_error: str | None = None,
) -> CustomSource:
    return CustomSource(
        id="cs1",
        name="Vendor-Tool",
        vendor_url=vendor_url,
        version_regex=version_regex,
        platform=Platform.WINDOWS,
        installed_version=installed_version,
        available_version=available_version,
        last_checked_at=None,
        last_error=last_error,
        notes=None,
        created_at=datetime.now(tz=UTC),
    )


class TestCheck:
    def test_happy_path_setzt_version(self) -> None:
        fetch = MagicMock(return_value="<html>Version 2.5 ist da</html>")
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source())
        assert result.available_version == "2.5"
        assert result.last_error is None
        assert result.last_checked_at is not None
        fetch.assert_called_once_with("https://example.com/download")

    def test_kein_match_liefert_fehler(self) -> None:
        fetch = MagicMock(return_value="<html>kein Versionsstring</html>")
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source())
        assert result.last_error == ERR_VERSION_NOT_FOUND
        assert result.available_version is None

    def test_ungueltiger_regex_ohne_fetch(self) -> None:
        fetch = MagicMock()
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source(version_regex=r"Version (\d+"))  # offene Gruppe
        assert result.last_error == ERR_INVALID_REGEX
        fetch.assert_not_called()

    def test_non_http_url_ohne_fetch(self) -> None:
        fetch = MagicMock()
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source(vendor_url="file:///etc/passwd"))
        assert result.last_error == ERR_NON_HTTP
        fetch.assert_not_called()

    def test_fetch_exception_behaelt_alte_version(self) -> None:
        fetch = MagicMock(side_effect=ConnectionError("boom"))
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source(available_version="2.0"))
        assert result.last_error == ERR_UNREACHABLE
        assert result.available_version == "2.0"  # nicht ueberschrieben
        assert result.last_checked_at is not None

    def test_regex_ohne_capture_group_nutzt_group0(self) -> None:
        fetch = MagicMock(return_value="aktuell: 9.9.9 stable")
        checker = CustomSourceChecker(fetch=fetch)
        result = checker.check(_source(version_regex=r"\d+\.\d+\.\d+"))
        assert result.available_version == "9.9.9"


class TestIsUpdateAvailable:
    def test_true_bei_abweichung(self) -> None:
        src = _source(installed_version="1.0", available_version="1.1")
        assert is_update_available(src) is True

    def test_false_bei_gleichstand(self) -> None:
        src = _source(installed_version="1.1", available_version="1.1")
        assert is_update_available(src) is False

    def test_false_ohne_available(self) -> None:
        src = _source(installed_version="1.0", available_version=None)
        assert is_update_available(src) is False

    def test_false_bei_fehler(self) -> None:
        src = _source(
            installed_version="1.0",
            available_version="1.1",
            last_error=ERR_UNREACHABLE,
        )
        assert is_update_available(src) is False
