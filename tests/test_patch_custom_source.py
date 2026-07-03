"""test_patch_custom_source — Tests fuer core.patch_custom_source.

Deckt das ``Platform``-StrEnum + ``DEFAULT_PLATFORM`` und die
``CustomSource``-Frozen-Dataclass ab.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from core.patch_custom_source import (
    DEFAULT_PLATFORM,
    CustomSource,
    Platform,
)


class TestPlatform:
    def test_werte(self) -> None:
        assert Platform.WINDOWS.value == "win"
        assert Platform.MACOS.value == "mac"
        assert Platform.LINUX.value == "linux"

    def test_strenum_ist_str(self) -> None:
        assert Platform.WINDOWS == "win"
        assert str(Platform.LINUX) == "linux"

    def test_parse_aus_string_ist_singleton(self) -> None:
        assert Platform("win") is Platform.WINDOWS

    def test_unbekannter_wert_raised(self) -> None:
        with pytest.raises(ValueError):
            Platform("amiga")

    def test_default_ist_windows(self) -> None:
        assert DEFAULT_PLATFORM is Platform.WINDOWS


class TestCustomSource:
    def test_ist_frozen(self) -> None:
        src = CustomSource(
            id="x",
            name="Tool",
            vendor_url="https://example.com",
            version_regex=r"(\d+\.\d+)",
            platform=Platform.WINDOWS,
            installed_version=None,
            available_version=None,
            last_checked_at=None,
            last_error=None,
            notes=None,
            created_at=datetime.now(tz=UTC),
        )
        with pytest.raises(FrozenInstanceError):
            src.name = "Anders"  # type: ignore[misc]
