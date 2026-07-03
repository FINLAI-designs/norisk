"""
test_theme — Tests für das FINLAI Theme-System.

Prüft Dark-Look, Farbwerte und Invarianten.
Keine QApplication notwendig — Theme ist pure Python.
"""

import pytest

from core import theme

pytestmark = pytest.mark.gui


class TestTheme:
    """Testet das Theme-System."""

    def test_dark_theme_standard(self):
        """Dark-Look ist Standard und einzig verfügbarer Look."""
        theme.set_dark()
        assert theme.is_dark()
        assert theme.get() is theme.DARK

    def test_set_light_shim_bleibt_dark(self):
        """set_light ist ein Shim — bleibt bei Dark (Light-Theme entfernt)."""
        theme.set_light()
        assert theme.is_dark()
        assert theme.get() is theme.DARK

    def test_accent_farbe_vorhanden(self):
        """Dark-Look hat einen definierten Akzent-Farbwert."""
        theme.set_dark()
        assert theme.get().ACCENT == "#51dacf"  # FINLAI Brand Teal

    def test_dark_text_hell(self):
        """Text ist im Dark-Look hell."""
        theme.set_dark()
        text = theme.get().TEXT_MAIN
        r = int(text[1:3], 16)
        assert r > 180

    def test_dark_hauptbereich_dunkel(self):
        """Hauptbereich ist im Dark-Look dunkel."""
        theme.set_dark()
        bg = theme.get().BG_MAIN
        r = int(bg[1:3], 16)
        assert r < 50

    def teardown_method(self):
        """Reset auf Dark-Look nach jedem Test."""
        theme.set_dark()
