"""
pdf_styles — ParagraphStyles für FINLAI-Reports (Light-Schema).

Weißer Seitenhintergrund, dunkler Text; Header-Text steht auf Teal-Flächen
(daher weiß). Alle Farben aus pdf_colors.py, alle Fonts aus pdf_fonts.py.

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

from core.pdf.pdf_colors import (
    PDF_ACCENT_DIM,
    PDF_DANGER,
    PDF_SUCCESS,
    PDF_TEXT_PRIMARY,
    PDF_TEXT_SECONDARY,
    PDF_WARNING,
    PDF_WHITE,
)
from core.pdf.pdf_fonts import (
    FONT_MONO,
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
    FONT_RALEWAY_LIGHT,
)


def build_styles() -> dict[str, ParagraphStyle]:
    """Erstellt alle PDF-Paragraph-Styles für das Dark Theme.

    Returns:
        Dict mit Style-Schlüssel → ParagraphStyle.
    """
    base = getSampleStyleSheet()

    def s(name: str, **kwargs: object) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base["Normal"], **kwargs)

    return {
        # --- Deckblatt ---
        "cover_title": s(
            "CoverTitle",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=28,
            textColor=PDF_TEXT_PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=8,
            leading=34,
        ),
        "cover_subtitle": s(
            "CoverSubtitle",
            fontName=FONT_RALEWAY_LIGHT,
            fontSize=15,
            textColor=PDF_ACCENT_DIM,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "cover_company": s(
            "CoverCompany",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=22,
            textColor=PDF_TEXT_PRIMARY,
            alignment=TA_CENTER,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "cover_meta": s(
            "CoverMeta",
            fontName=FONT_MONO,
            fontSize=11,
            textColor=PDF_TEXT_SECONDARY,
            alignment=TA_CENTER,
            spaceAfter=3,
        ),
        "cover_slogan": s(
            "CoverSlogan",
            fontName=FONT_RALEWAY_LIGHT,
            fontSize=11,
            textColor=PDF_ACCENT_DIM,
            alignment=TA_CENTER,
        ),
        # --- Überschriften ---
        "h1": s(
            "DarkH1",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=18,
            textColor=PDF_TEXT_PRIMARY,
            spaceBefore=20,
            spaceAfter=10,
            leading=22,
        ),
        "h2": s(
            "DarkH2",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=14,
            textColor=PDF_ACCENT_DIM,
            spaceBefore=14,
            spaceAfter=8,
            leading=18,
        ),
        "h3": s(
            "DarkH3",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=12,
            textColor=PDF_TEXT_PRIMARY,
            spaceBefore=10,
            spaceAfter=6,
        ),
        # --- Fließtext ---
        "body": s(
            "DarkBody",
            fontName=FONT_RALEWAY,
            fontSize=11,
            textColor=PDF_TEXT_PRIMARY,
            leading=16,
            spaceAfter=6,
        ),
        "body_dim": s(
            "DarkBodyDim",
            fontName=FONT_RALEWAY,
            fontSize=10,
            textColor=PDF_TEXT_SECONDARY,
            leading=14,
            spaceAfter=4,
        ),
        "mono": s(
            "DarkMono",
            fontName=FONT_MONO,
            fontSize=11,
            textColor=PDF_TEXT_PRIMARY,
        ),
        # --- Tabellen ---
        "table_header": s(
            "DarkTableHeader",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=PDF_WHITE,
            alignment=TA_LEFT,
        ),
        "table_cell": s(
            "DarkTableCell",
            fontName=FONT_RALEWAY,
            fontSize=10,
            textColor=PDF_TEXT_PRIMARY,
            leading=13,
        ),
        "table_cell_center": s(
            "DarkTableCellCenter",
            fontName=FONT_RALEWAY,
            fontSize=10,
            textColor=PDF_TEXT_PRIMARY,
            alignment=TA_CENTER,
            leading=13,
        ),
        "table_cell_mono": s(
            "DarkTableCellMono",
            fontName=FONT_MONO,
            fontSize=10,
            textColor=PDF_TEXT_PRIMARY,
            alignment=TA_CENTER,
        ),
        # --- Empfehlungen (Prioritäts-Badges) ---
        "rec_critical": s(
            "RecCritical",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=PDF_DANGER,
        ),
        "rec_high": s(
            "RecHigh",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=PDF_WARNING,
        ),
        "rec_medium": s(
            "RecMedium",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=PDF_ACCENT_DIM,
        ),
        "rec_low": s(
            "RecLow",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=10,
            textColor=PDF_SUCCESS,
        ),
        "rec_title": s(
            "RecTitle",
            fontName=FONT_RALEWAY_BOLD,
            fontSize=11,
            textColor=PDF_TEXT_PRIMARY,
            spaceAfter=2,
        ),
        "rec_description": s(
            "RecDescription",
            fontName=FONT_RALEWAY,
            fontSize=10,
            textColor=PDF_TEXT_SECONDARY,
            leading=14,
            leftIndent=14,
            spaceAfter=8,
        ),
        "rec_category": s(
            "RecCategory",
            fontName=FONT_MONO,
            fontSize=9,
            textColor=PDF_TEXT_SECONDARY,
            leftIndent=14,
            spaceAfter=4,
        ),
        # --- Footer / Disclaimer ---
        "footer": s(
            "DarkFooter",
            fontName=FONT_RALEWAY,
            fontSize=9,
            textColor=PDF_TEXT_SECONDARY,
            alignment=TA_CENTER,
            spaceAfter=3,
        ),
        "disclaimer": s(
            "DarkDisclaimer",
            fontName=FONT_RALEWAY,
            fontSize=8,
            textColor=PDF_TEXT_SECONDARY,
            leading=11,
            spaceAfter=4,
        ),
    }
