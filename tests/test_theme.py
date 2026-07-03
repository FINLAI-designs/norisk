"""
tests/test_theme.py — Tests für das Dark Theme-System.

Prüft: Vollständigkeit aller Felder, korrekte Werte,
set_theme, Backward-Compat-Shims, Accent-Color-Injection.
"""

from __future__ import annotations

from dataclasses import fields

from core import theme
from core.theme import DARK, ThemeColors

# ---------------------------------------------------------------------------
# Hilfsfunktion
# ---------------------------------------------------------------------------

# Leer-Tokens sind verboten (QColor("") = ungültig -> schwarzer Text).
# Die Severity-MEDIUM-Tokens waren früher absichtlich leer — nie wieder.
_OPTIONAL_EMPTY_FIELDS: frozenset[str] = frozenset()


def _all_fields_filled(t: ThemeColors) -> bool:
    return all(
        bool(getattr(t, f.name))
        for f in fields(ThemeColors)
        if f.name not in _OPTIONAL_EMPTY_FIELDS
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_dark_theme_alle_felder():
    """Alle ThemeColors-Felder im Dark-Look sind befüllt."""
    assert _all_fields_filled(DARK)


def test_dark_theme_dunkler_bg():
    """Dark-Look hat einen dunklen Haupthintergrund."""
    # BG_MAIN beginnt mit #1 (dunkles Grau)
    assert DARK.BG_MAIN.lower().startswith("#1")


def test_set_theme():
    """set_theme aktiviert immer Dark."""
    theme.set_theme("dark")
    assert theme._current_name == "dark"
    assert theme.get() is theme.DARK


def test_unbekannter_look_fallback():
    """Ein unbekannter Look-Name bleibt bei Dark."""
    theme.set_theme("neon-pink")
    assert theme._current_name == "dark"
    assert theme.get() is theme.DARK


def test_backward_compat_shims():
    """set_dark und set_light funktionieren weiterhin (beide → dark)."""
    theme.set_dark()
    assert theme._current_name == "dark"
    assert theme.is_dark() is True

    theme.set_light()
    # set_light ist jetzt ein Shim auf Dark — Light-Theme wurde entfernt
    assert theme._current_name == "dark"
    assert theme.is_dark() is True


def test_get_ohne_argument():
    """get ohne Argument gibt DARK zurück."""
    theme.set_theme("dark")
    assert theme.get() is theme.DARK


def test_get_mit_beliebigem_name():
    """get(name) gibt immer DARK zurück — es gibt nur einen Look."""
    assert theme.get("dark") is theme.DARK
    assert theme.get("hell") is theme.DARK
    assert theme.get("whatever") is theme.DARK


# ---------------------------------------------------------------------------
# set_accent_color — White-Label-Injection
# ---------------------------------------------------------------------------

import pytest  # noqa: E402


@pytest.fixture(autouse=False)
def restore_accent():
    """Stellt den Default-Akzent nach jedem Test wieder her."""
    original_accent = theme.DARK.ACCENT
    yield
    theme.set_accent_color(original_accent)


def test_darken_hex_15_prozent():
    """_darken_hex mit Faktor 0.85 liefert erwarteten Wert."""
    result = theme._darken_hex("#51dacf", 0.85)
    assert result.startswith("#")
    # Ursprung: R=0x51=81, G=0xda=218, B=0xcf=207
    # * 0.85 → R=69, G=185, B=176
    r = int(result[1:3], 16)
    g = int(result[3:5], 16)
    b = int(result[5:7], 16)
    assert r < 81
    assert g < 218
    assert b < 207


def test_darken_hex_ungueltige_eingabe():
    """_darken_hex gibt den Ursprungswert zurück bei zu kurzem Hex."""
    assert theme._darken_hex("#abc", 0.5) == "#abc"


def test_set_accent_color_aktualisiert_dark(restore_accent):
    """set_accent_color ändert ACCENT im DARK-Theme."""
    theme.set_accent_color("#ff4444")
    assert theme.DARK.ACCENT == "#ff4444"


def test_set_accent_color_dim_dunkler_als_accent(restore_accent):
    """ACCENT_DIM ist nach set_accent_color dunkler als ACCENT."""
    theme.set_accent_color("#51dacf")
    accent_brightness = sum(int(theme.DARK.ACCENT[i : i + 2], 16) for i in (1, 3, 5))
    dim_brightness = sum(int(theme.DARK.ACCENT_DIM[i : i + 2], 16) for i in (1, 3, 5))
    assert dim_brightness < accent_brightness


def test_set_accent_color_aktualisiert_current(restore_accent):
    """_current spiegelt den neuen Akzent wider."""
    theme.set_theme("dark")
    theme.set_accent_color("#ff5500")
    assert theme._current.ACCENT == "#ff5500"


def test_set_accent_color_leer_kein_effekt():
    """set_accent_color('') ändert den Akzent nicht."""
    before = theme.DARK.ACCENT
    theme.set_accent_color("")
    assert before == theme.DARK.ACCENT


def test_set_accent_color_none_kein_effekt():
    """set_accent_color(None) ändert den Akzent nicht."""
    before = theme.DARK.ACCENT
    theme.set_accent_color(None)  # type: ignore[arg-type]
    assert before == theme.DARK.ACCENT


def test_set_accent_color_kurzer_hex_kein_effekt():
    """set_accent_color ignoriert zu kurze Hex-Strings."""
    before = theme.DARK.ACCENT
    theme.set_accent_color("#abc")
    assert before == theme.DARK.ACCENT


def test_set_accent_color_laesst_border_sidebar_neutral(restore_accent):
    """set_accent_color lässt BORDER_SIDEBAR neutral (Shell-Hairline)."""
    theme.set_accent_color("#ff4444")
    assert theme.DARK.BORDER_SIDEBAR == theme.DARK.BORDER
    assert theme.DARK.BORDER_SIDEBAR != theme.DARK.ACCENT


def test_set_accent_color_aktualisiert_bg_sidebar_selected(restore_accent):
    """BG_SIDEBAR_SELECTED wird auf den neuen Accent gesetzt."""
    theme.set_accent_color("#51dacf")
    assert theme.DARK.BG_SIDEBAR_SELECTED == "#51dacf"


def test_set_accent_color_aktualisiert_bg_sidebar_hover(restore_accent):
    """set_accent_color setzt BG_SIDEBAR_HOVER auf ACCENT_DIM."""
    theme.set_accent_color("#51dacf")
    expected_dim = theme._darken_hex("#51dacf", 0.85)
    assert expected_dim == theme.DARK.BG_SIDEBAR_HOVER


def test_set_accent_color_konsistenz_dark_sidebar(restore_accent):
    """Nach set_accent_color sind Sidebar-Felder und ACCENT konsistent.

    BORDER_SIDEBAR bleibt bewusst außen vor — die Shell-Hairline ist
    accent-unabhängig, siehe eigener Test oben).
    """
    theme.set_accent_color("#ff4444")
    assert theme.DARK.BG_SIDEBAR_SELECTED == theme.DARK.ACCENT
    assert theme.DARK.BG_SIDEBAR_HOVER == theme.DARK.ACCENT_DIM


def test_generate_qss_tonale_schale():
    """Shell-QSS nach: kein Akzent-Separator, neutrale Hairlines.

    Sichert die drei QSS-Eckpunkte der tonalen Schale ab: der
    sidebar_separator-Block ist entfernt, die TitleBar trägt eine
    1px-Hairline in BORDER_SIDEBAR, die Sidebar hat keinen border-right.
    """
    qss = theme.generate_qss(theme.DARK)
    assert "sidebar_separator" not in qss
    assert f"border-bottom: 1px solid {theme.DARK.BORDER_SIDEBAR}" in qss
    assert "border-right: 2px" not in qss


def test_shell_ist_dunkler_als_content():
    """Tonale Schale: Sidebar/TitleBar liegen eine Tonstufe unter BG_MAIN."""
    shell = int(theme.DARK.BG_SIDEBAR.lstrip("#"), 16)
    content = int(theme.DARK.BG_MAIN.lstrip("#"), 16)
    assert shell < content
    assert theme.DARK.BG_TITLEBAR == theme.DARK.BG_SIDEBAR


def test_accent_line_default_ist_gedimmtes_teal():
    """ACCENT_LINE ist eine rgba-Linie mit ~25% Alpha AP2)."""
    assert theme.DARK.ACCENT_LINE == "rgba(81, 218, 207, 64)"


def test_set_accent_color_leitet_accent_line_ab(restore_accent):
    """set_accent_color berechnet ACCENT_LINE als rgba aus dem Accent."""
    theme.set_accent_color("#ff4444")
    assert theme.DARK.ACCENT_LINE == "rgba(255, 68, 68, 64)"


def test_accent_line_rgba_fail_closed():
    """_accent_line_rgba fällt bei kaputtem Hex auf den Teal-Default."""
    assert theme._accent_line_rgba("#abc") == theme.DARK_ACCENT_LINE
