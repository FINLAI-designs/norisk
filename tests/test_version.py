"""
tests/test_version.py — Tests für core/version.py (zentrale Versionierung).

Prüft:
  - __version__ hat gültiges SemVer-Format (MAJOR.MINOR.PATCH)
  - __build_date__ hat gültiges ISO-Format (YYYY-MM-DD)
  - get_version_info gibt dict mit den erwarteten Schlüsseln zurück
  - get_version_info übernimmt app_id korrekt
  - AppConfig.version ist identisch mit core.version.__version__
  - __version__ ist der einzige Ort — AppConfig und get_version_info lesen von dort
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------------------
# Tests: core.version
# ---------------------------------------------------------------------------


class TestVersionModule:
    def test_version_is_string(self):
        from core.version import __version__

        assert isinstance(__version__, str)

    def test_version_semver_format(self):
        """__version__ muss MAJOR.MINOR.PATCH Format haben."""
        from core.version import __version__

        assert _SEMVER_RE.match(__version__), (
            f"__version__='{__version__}' ist kein gültiges SemVer (MAJOR.MINOR.PATCH)"
        )

    def test_version_components_are_integers(self):
        """Alle drei SemVer-Komponenten müssen integer-parsierbar sein."""
        from core.version import __version__

        major, minor, patch = __version__.split(".")
        assert int(major) >= 0
        assert int(minor) >= 0
        assert int(patch) >= 0

    def test_build_date_format(self):
        """__build_date__ muss YYYY-MM-DD Format haben."""
        from core.version import __build_date__

        assert isinstance(__build_date__, str)
        assert _DATE_RE.match(__build_date__), (
            f"__build_date__='{__build_date__}' ist kein gültiges ISO-Datum"
        )


class TestGetVersionInfo:
    def test_returns_dict(self):
        from core.version import get_version_info

        result = get_version_info()
        assert isinstance(result, dict)

    def test_contains_required_keys(self):
        from core.version import get_version_info

        result = get_version_info()
        assert "version" in result
        assert "build_date" in result
        assert "app_id" in result

    def test_version_matches_module_variable(self):
        from core.version import __version__, get_version_info

        assert get_version_info()["version"] == __version__

    def test_build_date_matches_module_variable(self):
        from core.version import __build_date__, get_version_info

        assert get_version_info()["build_date"] == __build_date__

    def test_app_id_default_empty(self):
        from core.version import get_version_info

        assert get_version_info()["app_id"] == ""

    def test_app_id_passed_through(self):
        from core.version import get_version_info

        assert get_version_info("finlai")["app_id"] == "finlai"
        assert get_version_info("automate")["app_id"] == "automate"
        assert get_version_info("norisk")["app_id"] == "norisk"

    def test_version_value_is_semver(self):
        from core.version import get_version_info

        version = get_version_info("test")["version"]
        assert _SEMVER_RE.match(version)


# ---------------------------------------------------------------------------
# Tests: AppConfig.version — Single Source of Truth
# ---------------------------------------------------------------------------


class TestAppConfigVersion:
    """Prüft dass AppConfig.version aus core.version.__version__ kommt."""

    def test_appconfig_version_matches_core_version(self):
        from apps.app_config import AppConfig

        from core.version import __version__

        cfg = AppConfig(
            app_id="test",
            app_name="Test",
            app_slogan="",
            window_title="TEST",
            icon_path="",
            accent_color="#000000",
        )
        assert cfg.version == __version__

    def test_appconfig_version_is_semver(self):
        from apps.app_config import AppConfig

        cfg = AppConfig(
            app_id="test",
            app_name="Test",
            app_slogan="",
            window_title="TEST",
            icon_path="",
            accent_color="#000000",
        )
        assert _SEMVER_RE.match(cfg.version)

    def test_norisk_config_version(self):
        from apps.app_config import NORISK_CONFIG

        from core.version import __version__

        assert NORISK_CONFIG.version == __version__

    def test_version_can_be_overridden(self):
        """AppConfig.version kann explizit überschrieben werden (z.B. Kunden-Build)."""
        from apps.app_config import AppConfig

        cfg = AppConfig(
            app_id="test",
            app_name="Test",
            app_slogan="",
            window_title="TEST",
            icon_path="",
            accent_color="#000000",
            version="2.3.4",
        )
        assert cfg.version == "2.3.4"
