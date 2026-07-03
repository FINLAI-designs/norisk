"""
pdf_light_styles — ParagraphStyles für Light-Theme-Compliance-PDFs.

Farben aus ``pdf_light_colors.py``, Fonts aus ``pdf_fonts.py``.
Gemeinsame Grund-Styles, spezifisch für mehrseitige Dashboard-/Compliance-
Reports mit Raleway als Primär-Font und JetBrains Mono für Zahlen.

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0 (Dashboard-Phase 3)
"""

from __future__ import annotations

from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

from core.pdf.pdf_fonts import (
    FONT_MONO,
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
    FONT_RALEWAY_LIGHT,
)
from core.pdf.pdf_light_colors import (
    LIGHT_ACCENT_DEEP,
    LIGHT_DANGER,
    LIGHT_SUCCESS,
    LIGHT_TEXT_MUTED,
    LIGHT_TEXT_PRIMARY,
    LIGHT_TEXT_SECONDARY,
    LIGHT_WARNING,
)


def build_light_styles() -> dict[str, ParagraphStyle]:
    """Erstellt alle Paragraph-Styles für Light-Theme-Reports.

    Returns:
        Dict Name → ParagraphStyle.
    """
    base = getSampleStyleSheet()

    def s(name: str, **kwargs: object) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base["Normal"], **kwargs)

    return {
        # --- Deckblatt / Titel ---
        "title": s(
            "LightTitle",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=24,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=28,
            spaceAfter=6,
        ),
        "subtitle": s(
            "LightSubtitle",
            fontName=FONT_RALEWAY_LIGHT,
            fontSize=13,
            textColor=LIGHT_ACCENT_DEEP,
            leading=16,
            spaceAfter=10,
        ),
        "meta": s(
            "LightMeta",
            fontName=FONT_MONO,
            fontSize=9,
            textColor=LIGHT_TEXT_SECONDARY,
            leading=12,
            spaceAfter=2,
        ),
        # --- Überschriften ---
        "h1": s(
            "LightH1",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=16,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=20,
            spaceBefore=6,
            spaceAfter=6,
        ),
        "h2": s(
            "LightH2",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=12,
            textColor=LIGHT_ACCENT_DEEP,
            leading=16,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "h3": s(
            "LightH3",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=13,
            spaceBefore=4,
            spaceAfter=2,
        ),
        # --- Fließtext ---
        "body": s(
            "LightBody",
            fontName=FONT_RALEWAY,
            fontSize=10,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=14,
            spaceAfter=4,
        ),
        "body_dim": s(
            "LightBodyDim",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=LIGHT_TEXT_SECONDARY,
            leading=12,
            spaceAfter=3,
        ),
        "body_muted": s(
            "LightBodyMuted",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=LIGHT_TEXT_MUTED,
            leading=12,
        ),
        "mono": s(
            "LightMono",
            fontName=FONT_MONO,
            fontSize=10,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=12,
        ),
        "mono_big": s(
            "LightMonoBig",
            fontName=FONT_MONO,
            fontSize=22,
            textColor=LIGHT_ACCENT_DEEP,
            leading=24,
            alignment=TA_CENTER,
        ),
        # --- Tabellen ---
        "table_header": s(
            "LightTableHeader",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=9,
            textColor=_white(),
            alignment=TA_LEFT,
            leading=11,
        ),
        "table_cell": s(
            "LightTableCell",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=12,
        ),
        "table_cell_dim": s(
            "LightTableCellDim",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=LIGHT_TEXT_SECONDARY,
            leading=12,
        ),
        "table_cell_mono": s(
            "LightTableCellMono",
            fontName=FONT_MONO,
            fontSize=9,
            textColor=LIGHT_TEXT_PRIMARY,
            leading=12,
            alignment=TA_CENTER,
        ),
        # --- Badges (Änderungen) ---
        "badge_new": s(
            "LightBadgeNew",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=8,
            textColor=LIGHT_SUCCESS,
            leading=10,
        ),
        "badge_changed": s(
            "LightBadgeChanged",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=8,
            textColor=LIGHT_WARNING,
            leading=10,
        ),
        "badge_deleted": s(
            "LightBadgeDeleted",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=8,
            textColor=LIGHT_DANGER,
            leading=10,
        ),
        # --- Management-Summary-Box ---
        "summary_label": s(
            "LightSummaryLabel",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=LIGHT_TEXT_SECONDARY,
            alignment=TA_CENTER,
            leading=11,
        ),
        "summary_value": s(
            "LightSummaryValue",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=18,
            textColor=LIGHT_ACCENT_DEEP,
            alignment=TA_CENTER,
            leading=22,
        ),
        # --- Footer / Disclaimer ---
        "footer": s(
            "LightFooter",
            fontName=FONT_RALEWAY,
            fontSize=8,
            textColor=LIGHT_TEXT_SECONDARY,
            alignment=TA_CENTER,
            leading=10,
        ),
        "footer_left": s(
            "LightFooterLeft",
            fontName=FONT_RALEWAY,
            fontSize=8,
            textColor=LIGHT_TEXT_SECONDARY,
            alignment=TA_LEFT,
            leading=10,
        ),
        "disclaimer": s(
            "LightDisclaimer",
            fontName=FONT_RALEWAY,
            fontSize=8,
            textColor=LIGHT_TEXT_SECONDARY,
            leading=11,
            spaceAfter=4,
        ),
        "confidential": s(
            "LightConfidential",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=8,
            textColor=LIGHT_ACCENT_DEEP,
            alignment=TA_LEFT,
            leading=10,
        ),
    }


def _white():
    """Lazy import von reportlab.lib.colors.white."""
    from reportlab.lib import colors as _c

    return _c.white
