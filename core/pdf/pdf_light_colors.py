"""
pdf_light_colors — Light-Theme-Palette für Compliance-PDFs.

Wird vom Dashboard-PDF-Report (und perspektivisch weiteren Light-Reports)
genutzt. Teal-Akzent bleibt identisch zum Dark Theme (``DARK_ACCENT``), die
Kontraste werden jedoch für weißen Hintergrund austariert.

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0 (Dashboard-Phase 3)
"""

from __future__ import annotations

from reportlab.lib import colors as _c

from core.theme import DARK_ACCENT, DARK_ACCENT_DIM

# ---------------------------------------------------------------------------
# Hintergründe
# ---------------------------------------------------------------------------
LIGHT_BG_PAGE: _c.Color = _c.white
LIGHT_BG_CARD: _c.Color = _c.HexColor("#f7f8f9")
LIGHT_BG_SUBTLE: _c.Color = _c.HexColor("#eceff1")

# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------
LIGHT_TEXT_PRIMARY: _c.Color = _c.HexColor("#1a1e24")
LIGHT_TEXT_SECONDARY: _c.Color = _c.HexColor("#5a6472")
LIGHT_TEXT_MUTED: _c.Color = _c.HexColor("#8a92a0")

# ---------------------------------------------------------------------------
# Teal-Akzent (identisch Dark Theme, kräftig genug auf Weiß)
# ---------------------------------------------------------------------------
LIGHT_ACCENT: _c.Color = _c.HexColor(DARK_ACCENT)
LIGHT_ACCENT_DEEP: _c.Color = _c.HexColor(DARK_ACCENT_DIM)

# ---------------------------------------------------------------------------
# Status-Farben (Light-tauglich)
# ---------------------------------------------------------------------------
LIGHT_SUCCESS: _c.Color = _c.HexColor("#2e7d32")
LIGHT_WARNING: _c.Color = _c.HexColor("#ed6c02")
LIGHT_ERROR: _c.Color = _c.HexColor("#d32f2f")
LIGHT_DANGER: _c.Color = _c.HexColor("#b71c1c")

# ---------------------------------------------------------------------------
# Rahmen
# ---------------------------------------------------------------------------
LIGHT_BORDER: _c.Color = _c.HexColor("#d9dde3")
LIGHT_BORDER_STRONG: _c.Color = _c.HexColor("#b8bec8")

# ---------------------------------------------------------------------------
# Tabellen-Komfort-Aliase
# ---------------------------------------------------------------------------
LIGHT_TABLE_HEADER_BG: _c.Color = LIGHT_ACCENT
LIGHT_TABLE_HEADER_TEXT: _c.Color = _c.white
LIGHT_TABLE_ROW_ODD: _c.Color = LIGHT_BG_PAGE
LIGHT_TABLE_ROW_EVEN: _c.Color = LIGHT_BG_CARD


def light_risk_color(risk_level: str) -> _c.Color:
    """Gibt die Light-Theme-Farbe für eine Risikostufe zurück.

    Args:
        risk_level: "Niedrig", "Mittel", "Hoch" oder "Kritisch".

    Returns:
        Reportlab-Color passend zur Risikostufe.
    """
    return {
        "Niedrig": LIGHT_SUCCESS,
        "Mittel": LIGHT_WARNING,
        "Hoch": LIGHT_ERROR,
        "Kritisch": LIGHT_DANGER,
    }.get(risk_level, LIGHT_TEXT_PRIMARY)


def light_score_color(score: float) -> _c.Color:
    """Gibt die Light-Theme-Farbe für einen numerischen Score zurück.

    Args:
        score: Score 0–100.

    Returns:
        Reportlab-Color passend zum Score-Niveau.
    """
    if score >= 75.0:
        return LIGHT_SUCCESS
    if score >= 55.0:
        return LIGHT_WARNING
    if score >= 35.0:
        return LIGHT_ERROR
    return LIGHT_DANGER


def scan_status_color(status: str) -> _c.Color:
    """Farbe für Scan-Status in der Heatmap."""
    return {
        "ok": LIGHT_SUCCESS,
        "warn": LIGHT_WARNING,
        "fail": LIGHT_ERROR,
        "missing": LIGHT_BORDER_STRONG,
    }.get(status, LIGHT_BORDER_STRONG)
