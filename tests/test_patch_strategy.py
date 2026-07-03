"""test_patch_strategy — Tests fuer core.patch_strategy.

Deckt das Domain-Enum:class:`PatchStrategy` und den Default-Konstanten
:data:`DEFAULT_PATCH_STRATEGY` ab: Werte, StrEnum-Verhalten (DB-/UI-String),
Parsing und Fehlerpfad bei unbekannten Werten.
"""

from __future__ import annotations

import pytest

from core.patch_strategy import DEFAULT_PATCH_STRATEGY, PatchStrategy


class TestPatchStrategy:
    def test_werte(self) -> None:
        assert PatchStrategy.LATEST.value == "latest"
        assert PatchStrategy.STABLE.value == "stable"
        assert PatchStrategy.NONE.value == "none"

    def test_strenum_ist_str(self) -> None:
        # StrEnum-Mitglieder sind ihr eigener String — Persistenz ohne Mapping.
        assert PatchStrategy.STABLE == "stable"
        assert str(PatchStrategy.LATEST) == "latest"

    def test_parse_aus_string_ist_singleton(self) -> None:
        assert PatchStrategy("stable") is PatchStrategy.STABLE
        assert PatchStrategy("none") is PatchStrategy.NONE

    def test_unbekannter_wert_raised(self) -> None:
        with pytest.raises(ValueError):
            PatchStrategy("nightly")

    def test_default_ist_stable(self) -> None:
        assert DEFAULT_PATCH_STRATEGY is PatchStrategy.STABLE
