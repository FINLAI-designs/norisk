"""test_window_geometry_persistence UISettings Window-Geometry."""

from __future__ import annotations

import json
from unittest.mock import patch

from core.ui_settings import UISettings


def _patch_settings_path(tmp_path):
    """Hilfsfunktion: patcht ``_SETTINGS_FILE`` auf einen tmp_path-Eintrag."""
    settings_file = tmp_path / "ui_settings.json"
    return patch("core.ui_settings._SETTINGS_FILE", settings_file), settings_file


class TestWindowGeometryDefaults:
    """Beim Erst-Start sind alle Geometry-Werte Sentinels ('nicht gesetzt')."""

    def test_default_values(self) -> None:
        s = UISettings()
        assert s.window_width == 0  # Sentinel: nicht gesetzt
        assert s.window_height == 0
        assert s.window_x == -1  # OS positioniert
        assert s.window_y == -1
        assert s.window_maximized is False


class TestWindowGeometryRoundtrip:
    """Save → Load erhaelt alle 5 Geometry-Felder."""

    def test_save_load_roundtrip(self, tmp_path) -> None:
        patcher, settings_file = _patch_settings_path(tmp_path)
        with patcher:
            s1 = UISettings(
                window_width=1600,
                window_height=900,
                window_x=100,
                window_y=200,
                window_maximized=False,
            )
            s1.save()

            assert settings_file.exists()

            s2 = UISettings.load()
            assert s2.window_width == 1600
            assert s2.window_height == 900
            assert s2.window_x == 100
            assert s2.window_y == 200
            assert s2.window_maximized is False

    def test_maximized_flag_persisted(self, tmp_path) -> None:
        patcher, _ = _patch_settings_path(tmp_path)
        with patcher:
            UISettings(
                window_width=1920,
                window_height=1080,
                window_maximized=True,
            ).save()
            loaded = UISettings.load()
            assert loaded.window_maximized is True


class TestBackwardCompat:
    """Alte ui_settings.json ohne window_*-Felder laedt mit Sentinel-Defaults."""

    def test_alte_settings_ohne_window_felder(self, tmp_path) -> None:
        patcher, settings_file = _patch_settings_path(tmp_path)
        with patcher:
            # Simuliere alte Settings-Datei (vor)
            old_data = {
                "sidebar_width": 220,
                "sidebar_collapsed": False,
                "ollama_base_url": "http://localhost:11434",
                "dock_state": "",
                "theme": "dark",
            }
            settings_file.write_text(json.dumps(old_data), encoding="utf-8")

            loaded = UISettings.load()
            assert loaded.sidebar_width == 220  # alte Felder erhalten
            assert loaded.window_width == 0  # neue Felder = Default
            assert loaded.window_x == -1
            assert loaded.window_maximized is False
