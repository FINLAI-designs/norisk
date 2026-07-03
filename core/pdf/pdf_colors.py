"""
pdf_colors — Reportlab-Farbobjekte für FINLAI-Reports (Light-Schema).

Früher das FINLAI Dark Theme; seit der PDF-Vereinheitlichung auf das
kanonische helle Report-Schema umgestellt (core/pdf/pdf_light_colors.py).
Gedruckte und geteilte Reports haben einen WEISSEN Seitenhintergrund mit
dunklem Text — alle ``DarkReportBuilder``-Reports erben diese Palette zentral
über diese Aliase, ohne dass jeder Tool-Exporter angefasst werden muss.

Der FINLAI-Teal-Akzent bleibt identisch zum Dark Theme (Branding); die
Kontraste sind in ``pdf_light_colors`` für weißen Hintergrund austariert.
Die PDF-Palette ist BEWUSST von den GUI-``DARK_*``-Tokens entkoppelt — die
App-Oberfläche bleibt dunkel, nur die Reports sind hell.

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 2.0 (Light-Report-Vereinheitlichung)
"""

from __future__ import annotations

from reportlab.lib import colors as _c

from core.pdf.pdf_light_colors import (
    LIGHT_ACCENT,
    LIGHT_ACCENT_DEEP,
    LIGHT_BG_CARD,
    LIGHT_BG_PAGE,
    LIGHT_BG_SUBTLE,
    LIGHT_BORDER,
    LIGHT_DANGER,
    LIGHT_ERROR,
    LIGHT_SUCCESS,
    LIGHT_TABLE_HEADER_BG,
    LIGHT_TABLE_HEADER_TEXT,
    LIGHT_TABLE_ROW_EVEN,
    LIGHT_TABLE_ROW_ODD,
    LIGHT_TEXT_PRIMARY,
    LIGHT_TEXT_SECONDARY,
    LIGHT_WARNING,
    light_risk_color,
    light_score_color,
)

# ---------------------------------------------------------------------------
# Hintergründe (hell)
# ---------------------------------------------------------------------------
PDF_BG_PAGE: _c.Color = LIGHT_BG_PAGE  # Seiten-Hintergrund (weiß)
PDF_BG_CARD: _c.Color = LIGHT_BG_CARD  # Karten / Panel / Zebra-Zeile
PDF_BG_DEEP: _c.Color = LIGHT_BG_SUBTLE  # Dezenter Block-Hintergrund

# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------
PDF_TEXT_PRIMARY: _c.Color = LIGHT_TEXT_PRIMARY  # Haupttext (dunkel)
PDF_TEXT_SECONDARY: _c.Color = LIGHT_TEXT_SECONDARY  # Sekundärtext
PDF_WHITE: _c.Color = _c.white  # nur für Text auf Teal-/Farbflächen

# ---------------------------------------------------------------------------
# Akzent — FINLAI Teal
# ---------------------------------------------------------------------------
PDF_ACCENT: _c.Color = LIGHT_ACCENT  # Teal — Flächen/Linien (Header-BG, Trenner)
PDF_ACCENT_DIM: _c.Color = LIGHT_ACCENT_DEEP  # tieferes Teal — Akzent-TEXT auf Weiß

# ---------------------------------------------------------------------------
# Status-Farben (Light-tauglich, auf Weiß lesbar)
# ---------------------------------------------------------------------------
PDF_SUCCESS: _c.Color = LIGHT_SUCCESS  # Grün — Niedrig/OK
PDF_WARNING: _c.Color = LIGHT_WARNING  # Orange — Mittel
PDF_ERROR: _c.Color = LIGHT_ERROR  # Rot — Hoch
PDF_DANGER: _c.Color = LIGHT_DANGER  # Dunkelrot — Kritisch

# ---------------------------------------------------------------------------
# Rahmen
# ---------------------------------------------------------------------------
PDF_BORDER: _c.Color = LIGHT_BORDER  # Allgemeine Trennlinien

# ---------------------------------------------------------------------------
# Tabellen-Komfort-Aliase
# ---------------------------------------------------------------------------
PDF_TABLE_HEADER_BG: _c.Color = LIGHT_TABLE_HEADER_BG  # Teal
PDF_TABLE_HEADER_TEXT: _c.Color = LIGHT_TABLE_HEADER_TEXT  # Weiß auf Teal
PDF_TABLE_ROW_ODD: _c.Color = LIGHT_TABLE_ROW_ODD  # weiß
PDF_TABLE_ROW_EVEN: _c.Color = LIGHT_TABLE_ROW_EVEN  # dezentes Grau (Zebra)


def risk_color(risk_level: str) -> _c.Color:
    """Gibt die Farbe für eine Risikostufe zurück (Light-Schema).

    Args:
        risk_level: "Niedrig", "Mittel", "Hoch" oder "Kritisch".

    Returns:
        Reportlab-Color für die Risikostufe (auf Weiß lesbar).
    """
    return light_risk_color(risk_level)


def score_color(score: float) -> _c.Color:
    """Gibt die Farbe für einen numerischen Score zurück (Light-Schema).

    Args:
        score: Score 0–100.

    Returns:
        Reportlab-Color passend zum Score-Niveau (auf Weiß lesbar).
    """
    return light_score_color(score)
