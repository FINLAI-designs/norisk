"""/267: jedes Tool hat Einfach-Inhalte + der Resolver schaltet korrekt.

Sichert, dass (a) alle HelpContent-Einträge vollständige ``*_easy``-Felder tragen
(kein leerer Einfach-Modus mehr) und (b) der Mode-Resolver im Einfach-Modus den
Easy-Text liefert, im Profi-Modus den Profi-Text — mit Fallback wenn easy fehlt.
"""

from __future__ import annotations

import pytest

from core.help.display_mode import DisplayMode
from core.help.help_content import ALL_HELP_CONTENTS, HelpContent


@pytest.mark.parametrize(
    "content", ALL_HELP_CONTENTS, ids=lambda c: c.nav_key
)
def test_jedes_tool_hat_einfach_inhalte(content: HelpContent) -> None:
    assert content.short_description_easy, content.nav_key
    assert content.purpose_easy, content.nav_key
    assert content.when_to_use_easy, content.nav_key
    assert content.result_explanation_easy, content.nav_key
    assert content.next_steps_easy, content.nav_key
    assert content.steps_easy and len(content.steps_easy) >= 1, content.nav_key


@pytest.mark.parametrize(
    "content", ALL_HELP_CONTENTS, ids=lambda c: c.nav_key
)
def test_resolver_schaltet_easy_vs_expert(content: HelpContent) -> None:
    # Easy-Modus liefert den Einfach-Text, Profi-Modus den Profi-Text.
    assert content.purpose_for(DisplayMode.EASY) == content.purpose_easy
    assert content.purpose_for(DisplayMode.EXPERT) == content.purpose
    assert content.steps_for(DisplayMode.EASY) == content.steps_easy
    assert content.steps_for(DisplayMode.EXPERT) == content.steps
    # Einfach und Profi unterscheiden sich tatsächlich (kein Copy-Paste).
    assert content.purpose_for(DisplayMode.EASY) != content.purpose_for(
        DisplayMode.EXPERT
    ), content.nav_key


def test_fallback_auf_expert_wenn_easy_fehlt() -> None:
    c = HelpContent(
        tool_name="X",
        nav_key="x",
        short_description="kurz",
        purpose="profi-zweck",
        when_to_use="profi-wann",
        steps=["a"],
        result_explanation="profi-ergebnis",
        next_steps="profi-danach",
    )
    # Ohne *_easy fällt der Easy-Modus auf den Profi-Text zurück (kein Leerlauf).
    assert c.purpose_for(DisplayMode.EASY) == "profi-zweck"
    assert c.steps_for(DisplayMode.EASY) == ["a"]
