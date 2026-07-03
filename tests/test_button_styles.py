"""Tests fuer die zentralen Button-QSS-Factories.

Regressionsnetz gegen die Hover-Bug-Klasse/: Eine globale
``QPushButton:hover``-Regel setzte ``color`` auf einen dunklen Wert, der
Teal-Fill wurde auf Kind-Buttons unter Container-Stylesheets aber nicht
gemalt -> dunkle Schrift auf dunklem Grund. Die Factories muessen deshalb
in JEDEM State ``color`` + ``background-color`` + ``border`` explizit
setzen (Coding-Rule R26).
"""

from __future__ import annotations

import re

import pytest

from core import theme
from core.widgets import button_styles

_FACTORIES = [
    button_styles.link_button_qss,
    button_styles.primary_button_qss,
    button_styles.outline_button_qss,
    button_styles.toolbar_button_qss,
    button_styles.danger_button_qss,
    button_styles.secondary_button_qss,
]

_STATE_PATTERN = re.compile(r"QPushButton(:hover|:pressed|:disabled)?\s*\{([^}]*)\}")
# Textfarbe — matcht "color:" aber nicht "background-color:"/"border-color:".
_TEXT_COLOR = re.compile(r"(?<![-\w])color\s*:")
_BG_COLOR = re.compile(r"background-color\s*:")
# Echte Border — matcht "border:" aber nicht "border-radius:".
_BORDER = re.compile(r"(?<![-\w])border\s*:")


def _state_blocks(qss: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for match in _STATE_PATTERN.finditer(qss):
        state = match.group(1) or "normal"
        blocks[state] = match.group(2)
    return blocks


@pytest.mark.parametrize("factory", _FACTORIES, ids=lambda f: f.__name__)
def test_alle_vier_states_definiert(factory) -> None:
    """Jede Variante definiert normal,:hover,:pressed und:disabled."""
    blocks = _state_blocks(factory())
    assert set(blocks) == {"normal", ":hover", ":pressed", ":disabled"}


@pytest.mark.parametrize("factory", _FACTORIES, ids=lambda f: f.__name__)
def test_jeder_state_setzt_color_background_und_border(factory) -> None:
    """In jedem State stehen color, background-color und border GEMEINSAM."""
    for state, body in _state_blocks(factory()).items():
        assert _TEXT_COLOR.search(body), f"{factory.__name__} {state}: color fehlt"
        assert _BG_COLOR.search(body), (
            f"{factory.__name__} {state}: background-color fehlt"
        )
        assert _BORDER.search(body), f"{factory.__name__} {state}: border fehlt"


def test_link_hover_schrift_ist_helles_teal_nicht_dunkel() -> None:
    """Der Link-Hover nutzt helles Teal — nie die dunkle Fill-Schriftfarbe.

    Exakt die-Regression: global wurde beim Hover ``color: BG_DARK``
    gesetzt, ohne dass der Teal-Fill gemalt wurde.
    """
    blocks = _state_blocks(button_styles.link_button_qss())
    hover = blocks[":hover"]
    assert theme.ACCENT_HOVER in hover
    assert "text-decoration: underline" in hover
    c = theme.get()
    assert c.BG_DARK not in hover
    assert theme.TEXT_ON_ACCENT_DEEP not in hover


def test_link_normal_ist_teal_ohne_rahmen() -> None:
    """Link-Variante: Teal-Schrift, transparenter Grund, keine Border."""
    blocks = _state_blocks(button_styles.link_button_qss())
    normal = blocks["normal"]
    assert theme.get().ACCENT in normal
    assert "background-color: transparent" in normal
    assert "border: none" in normal


def test_outline_hover_paart_fill_mit_dunkler_schrift() -> None:
    """Outline-Hover: Teal-Fill UND dunkle Schrift im selben Block."""
    blocks = _state_blocks(button_styles.outline_button_qss())
    hover = blocks[":hover"]
    c = theme.get()
    assert f"background-color: {c.ACCENT}" in hover
    assert c.BG_DARK in hover


def test_danger_nutzt_danger_palette() -> None:
    """Danger-Variante: rote Toene + weisse Schrift aus dem Theme."""
    qss = button_styles.danger_button_qss()
    c = theme.get()
    assert c.DANGER in qss
    assert c.DANGER_HOVER in qss
    assert c.DANGER_PRESSED in qss
    assert theme.TEXT_ON_DANGER in qss
