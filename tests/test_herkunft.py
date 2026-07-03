"""Tests für core.herkunft.Herkunft E5 — Provenance-Wertobjekt)."""

from __future__ import annotations

import json

import pytest

from core.herkunft import Herkunft


class TestWerteUndSerialisierung:
    def test_stabile_value_strings(self) -> None:
        # Die value-Strings sind der Persistenz-Vertrag — dürfen nicht driften.
        assert Herkunft.GEMESSEN.value == "gemessen"
        assert Herkunft.ERFASST.value == "erfasst"
        assert Herkunft.DEKLARIERT.value == "deklariert"

    def test_ist_str_enum_json_serialisierbar(self) -> None:
        # str-Enum -> direkt JSON-serialisierbar als sein value-String.
        assert json.dumps({"h": Herkunft.ERFASST}) == '{"h": "erfasst"}'


class TestAnzeige:
    @pytest.mark.parametrize("h", list(Herkunft))
    def test_badge_und_beschreibung_nicht_leer(self, h: Herkunft) -> None:
        assert h.badge.strip()
        assert h.beschreibung.strip()

    def test_deklariert_badge(self) -> None:
        assert Herkunft.DEKLARIERT.badge == "selbst deklariert"


class TestBeweiswert:
    def test_ist_gemessen_nur_fuer_gemessen(self) -> None:
        assert Herkunft.GEMESSEN.ist_gemessen is True
        assert Herkunft.ERFASST.ist_gemessen is False
        assert Herkunft.DEKLARIERT.ist_gemessen is False

    def test_beweiswert_ordnung(self) -> None:
        assert (
            Herkunft.GEMESSEN.beweiswert_rang
            > Herkunft.ERFASST.beweiswert_rang
            > Herkunft.DEKLARIERT.beweiswert_rang
        )


class TestFromValue:
    @pytest.mark.parametrize(
        ("roh", "erwartet"),
        [
            ("gemessen", Herkunft.GEMESSEN),
            ("erfasst", Herkunft.ERFASST),
            ("deklariert", Herkunft.DEKLARIERT),
            ("  GEMESSEN  ", Herkunft.GEMESSEN),  # trim + case-insensitive
            ("Erfasst", Herkunft.ERFASST),
        ],
    )
    def test_bekannte_werte(self, roh: str, erwartet: Herkunft) -> None:
        assert Herkunft.from_value(roh) is erwartet

    def test_passthrough_enum(self) -> None:
        assert Herkunft.from_value(Herkunft.GEMESSEN) is Herkunft.GEMESSEN

    def test_unbekannt_faellt_fail_closed_auf_deklariert(self) -> None:
        # Leitplanke E5: ohne eindeutige Herkunft NIE gemessen.
        assert Herkunft.from_value("schwurbel") is Herkunft.DEKLARIERT
        assert Herkunft.from_value("") is Herkunft.DEKLARIERT
        assert Herkunft.from_value(None) is Herkunft.DEKLARIERT

    def test_eigener_default(self) -> None:
        assert Herkunft.from_value("x", default=Herkunft.ERFASST) is Herkunft.ERFASST

    def test_default_gemessen_verboten(self) -> None:
        with pytest.raises(ValueError, match="nicht GEMESSEN"):
            Herkunft.from_value("x", default=Herkunft.GEMESSEN)
