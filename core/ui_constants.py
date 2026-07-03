"""
ui_constants — Statische UI-Magic-Numbers für FINLAI.

Sammlung von wiederverwendeten Pixelwerten, die sonst als Magic Numbers
über Widgets verstreut wären (Coding Rule R1). Zur Laufzeit nicht
veränderbar — wer User-Preferences persistieren will, nutzt
:mod:`core.ui_settings`.

Beispiel::

    from core import ui_constants
    btn.setFixedHeight(ui_constants.BUTTON_HEIGHT_LARGE)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Button-Höhen
# ---------------------------------------------------------------------------

# Primärer/CTA-Button — z. B. "Speichern", "Anmelden", "Neu anlegen".
BUTTON_HEIGHT_LARGE = 32

# Sekundärer/Inline-Tabellen-Button — z. B. Edit/Delete-Icons in Tabellenzeilen.
BUTTON_HEIGHT_SMALL = 26


# ---------------------------------------------------------------------------
# Form-Input-Höhen
# ---------------------------------------------------------------------------

# Standard-Höhe für QLineEdit / QComboBox in Formularen.
FORM_INPUT_HEIGHT = 34
