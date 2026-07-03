"""
test_help_display_mode — Tests fuer das easy/expert-HelpContent-Schema.

Deckt den Enum, die Resolver-Fallbacks (kein Easy-Override → Bestand) und die
key-weisen Overrides ab. Stellt sicher, dass das additive Schema die ~17
Bestands-Einträge nicht bricht (Migrations-Impact null).
"""

from __future__ import annotations

from core.help.display_mode import DisplayMode
from core.help.help_content import ALL_HELP_CONTENTS, HelpContent

EASY = DisplayMode.EASY
EXPERT = DisplayMode.EXPERT


def _content(**overrides) -> HelpContent:
    """Baut eine HelpContent mit Pflichtfeldern + optionalen Overrides."""

    base = {
        "tool_name": "Test-Tool",
        "nav_key": "test",
        "short_description": "Kurz expert.",
        "purpose": "Zweck expert.",
        "when_to_use": "Wann expert.",
        "steps": ["Schritt 1 expert", "Schritt 2 expert"],
        "result_explanation": "Ergebnis expert.",
        "next_steps": "Danach expert.",
        "tooltips": {"btn": "Tooltip expert", "feld": "Feld expert"},
        "explanations": {"btn": "Erklaerung expert"},
    }
    base.update(overrides)
    return HelpContent(**base)


class TestDisplayModeEnum:
    def test_werte(self) -> None:
        assert DisplayMode.EASY == "easy"
        assert DisplayMode.EXPERT == "expert"

    def test_from_value_none_ist_easy(self) -> None:
        assert DisplayMode.from_value(None) is DisplayMode.EASY

    def test_from_value_invalid_ist_easy(self) -> None:
        assert DisplayMode.from_value("quatsch") is DisplayMode.EASY

    def test_from_value_gueltig(self) -> None:
        assert DisplayMode.from_value("expert") is DisplayMode.EXPERT


class TestResolverFallback:
    """Ohne Easy-Override liefert auch der Easy-Modus den Bestandstext."""

    def test_langtext_fallback(self) -> None:
        c = _content()
        for mode in (EASY, EXPERT):
            assert c.purpose_for(mode) == "Zweck expert."
            assert c.short_description_for(mode) == "Kurz expert."
            assert c.when_to_use_for(mode) == "Wann expert."
            assert c.result_explanation_for(mode) == "Ergebnis expert."
            assert c.next_steps_for(mode) == "Danach expert."
            assert c.steps_for(mode) == ["Schritt 1 expert", "Schritt 2 expert"]

    def test_tooltip_fallback(self) -> None:
        c = _content()
        assert c.tooltip_for("btn", EASY) == "Tooltip expert"
        assert c.tooltip_for("btn", EXPERT) == "Tooltip expert"

    def test_unbekannter_key_leer(self) -> None:
        c = _content()
        assert c.tooltip_for("gibtsnicht", EASY) == ""
        assert c.explanation_for("gibtsnicht", EXPERT) == ""


class TestResolverOverride:
    """Mit Easy-Override liefert EASY den Easy-Text, EXPERT den Bestand."""

    def test_langtext_override(self) -> None:
        c = _content(
            purpose_easy="Zweck einfach.",
            steps_easy=["Mach das einfach"],
        )
        assert c.purpose_for(EASY) == "Zweck einfach."
        assert c.purpose_for(EXPERT) == "Zweck expert."
        assert c.steps_for(EASY) == ["Mach das einfach"]
        assert c.steps_for(EXPERT) == ["Schritt 1 expert", "Schritt 2 expert"]

    def test_tooltip_keyweiser_override(self) -> None:
        # Nur 'btn' hat eine Easy-Variante; 'feld' faellt auf Bestand zurueck.
        c = _content(tooltips_easy={"btn": "Tooltip einfach"})
        assert c.tooltip_for("btn", EASY) == "Tooltip einfach"
        assert c.tooltip_for("btn", EXPERT) == "Tooltip expert"
        assert c.tooltip_for("feld", EASY) == "Feld expert"  # kein Override → Bestand

    def test_explanation_override(self) -> None:
        c = _content(explanations_easy={"btn": "Erklaerung einfach"})
        assert c.explanation_for("btn", EASY) == "Erklaerung einfach"
        assert c.explanation_for("btn", EXPERT) == "Erklaerung expert"


class TestBestandUnveraendert:
    """Das additive Schema bricht keinen der bestehenden Einträge."""

    def test_alle_eintraege_instanziierbar_und_resolvebar(self) -> None:
        assert len(ALL_HELP_CONTENTS) > 0
        for hc in ALL_HELP_CONTENTS:
            # Profi-Modus liefert unveraendert den Bestand (additives Schema).
            assert hc.purpose_for(EXPERT) == hc.purpose
            assert hc.short_description_for(EXPERT) == hc.short_description
            # Easy-Inhalte sind seit befuellt -> Resolver liefert nicht-leer.
            assert hc.purpose_for(EASY)
            # tooltips_easy ist (noch) nicht befuellt -> Tooltip-Fallback gilt.
            assert hc.tooltips_easy == {}
            for key, text in hc.tooltips.items():
                assert hc.tooltip_for(key, EASY) == text
                assert hc.tooltip_for(key, EXPERT) == text
