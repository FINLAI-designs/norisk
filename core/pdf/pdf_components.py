"""
pdf_components — Wiederverwendbare Drawing-Komponenten für den FINLAI PDF-Report.

Alle Komponenten geben reportlab Drawing-Objekte zurück.
Farben aus pdf_colors.py — niemals hardcoden.

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from reportlab.graphics.shapes import Drawing, Ellipse, Rect, String

from core.pdf.pdf_colors import (
    PDF_ACCENT,
    PDF_BG_CARD,
    PDF_BG_PAGE,
    PDF_BORDER,
    PDF_TEXT_PRIMARY,
    PDF_TEXT_SECONDARY,
    risk_color,
    score_color,
)
from core.pdf.pdf_fonts import (
    FONT_MONO,
    FONT_MONO_BOLD,
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
)


def score_gauge_drawing(
    score: float,
    risk_level: str,
    size: float = 140,
) -> Drawing:
    """Erstellt einen kreisförmigen Score-Gauge als Drawing.

    Design:
      - Dunkler Kreis-Hintergrund mit Teal-Außenring
      - Farbiger Innenring je nach Risikostufe
      - Score-Zahl (JetBrains Mono, groß) zentriert
      - Risikostufe als Label darunter

    Args:
        score: Numerischer Score 0–100.
        risk_level: Risikostufe ("Niedrig"/"Mittel"/"Hoch"/"Kritisch").
        size: Seitenlänge des quadratischen Zeichenbereichs.

    Returns:
        Drawing-Objekt zum Einbetten in den Platypus-Flow.
    """
    r_color = risk_color(risk_level)
    d = Drawing(size, size)
    cx, cy = size / 2, size / 2
    r_outer = size / 2 - 4
    r_inner = size / 2 - 14

    # Äußerer Teal-Ring
    d.add(
        Ellipse(
            cx,
            cy,
            r_outer,
            r_outer,
            strokeColor=PDF_ACCENT,
            strokeWidth=3,
            fillColor=PDF_BG_CARD,
        )
    )
    # Innerer farbiger Ring (Risikostufe)
    d.add(
        Ellipse(
            cx,
            cy,
            r_inner,
            r_inner,
            strokeColor=r_color,
            strokeWidth=6,
            fillColor=PDF_BG_CARD,
        )
    )
    # Score-Zahl
    d.add(
        String(
            cx,
            cy + 10,
            f"{score:.0f}",
            textAnchor="middle",
            fontSize=36,
            fontName=FONT_MONO_BOLD,
            fillColor=PDF_TEXT_PRIMARY,
        )
    )
    # "/ 100" Label
    d.add(
        String(
            cx,
            cy - 6,
            "/ 100",
            textAnchor="middle",
            fontSize=10,
            fontName=FONT_MONO,
            fillColor=PDF_TEXT_SECONDARY,
        )
    )
    # Risikostufe
    d.add(
        String(
            cx,
            cy - 26,
            risk_level,
            textAnchor="middle",
            fontSize=12,
            fontName=FONT_RALEWAY_BOLD,
            fillColor=r_color,
        )
    )
    return d


def category_bar_drawing(
    score: float,
    width: float = 200,
    height: float = 10,
) -> Drawing:
    """Erstellt einen horizontalen Score-Fortschrittsbalken.

    Args:
        score: Score 0–100.
        width: Balkenbreite in Punkten.
        height: Balkenhöhe in Punkten.

    Returns:
        Drawing mit Hintergrund- und Füllbalken.
    """
    fill_c = score_color(score)
    d = Drawing(width, height)
    # Hintergrund
    d.add(
        Rect(
            0,
            0,
            width,
            height,
            fillColor=PDF_BORDER,
            strokeColor=None,
            rx=3,
            ry=3,
        )
    )
    # Füllung
    fill_w = max(4.0, width * score / 100.0)
    d.add(
        Rect(
            0,
            0,
            fill_w,
            height,
            fillColor=fill_c,
            strokeColor=None,
            rx=3,
            ry=3,
        )
    )
    return d


def status_dot_drawing(
    status: str,
    size: float = 10,
) -> Drawing:
    """Erstellt einen farbigen Status-Punkt (Ampel-Design).

    Args:
        status: "aktiv"/"ok"/"Niedrig" → Grün;
                "inaktiv"/"Hoch"/"Mittel" → Orange/Rot;
                sonst → Grau.
        size: Durchmesser in Punkten.

    Returns:
        Drawing mit einfarbigem Kreis.
    """
    status_lower = status.lower()
    if status_lower in ("aktiv", "ok", "niedrig", "ja"):
        color = score_color(80.0)  # Grün
    elif status_lower in ("inaktiv", "kritisch", "nein"):
        color = score_color(10.0)  # Rot
    elif status_lower in ("mittel", "hoch", "teilweise"):
        color = score_color(45.0)  # Orange/Rot
    else:
        color = PDF_TEXT_SECONDARY  # Grau

    d = Drawing(size, size)
    r = size / 2
    d.add(
        Ellipse(
            r,
            r,
            r - 1,
            r - 1,
            strokeColor=None,
            fillColor=color,
        )
    )
    return d


def mini_score_box_drawing(
    score: float,
    risk_level: str,
    width: float = 80,
    height: float = 40,
) -> Drawing:
    """Erstellt eine kompakte Score-Box für Kategorie-Header.

    Args:
        score: Score 0–100.
        risk_level: Risikostufe.
        width: Breite in Punkten.
        height: Höhe in Punkten.

    Returns:
        Drawing mit Score-Zahl und Risikostufe.
    """
    r_color = risk_color(risk_level)
    d = Drawing(width, height)
    # Hintergrund
    d.add(
        Rect(
            0,
            0,
            width,
            height,
            fillColor=PDF_BG_PAGE,
            strokeColor=r_color,
            strokeWidth=1.5,
            rx=4,
            ry=4,
        )
    )
    # Score
    d.add(
        String(
            width / 2,
            height * 0.50,
            f"{score:.0f}",
            textAnchor="middle",
            fontSize=16,
            fontName=FONT_MONO_BOLD,
            fillColor=r_color,
        )
    )
    # Risikostufe
    d.add(
        String(
            width / 2,
            height * 0.15,
            risk_level,
            textAnchor="middle",
            fontSize=8,
            fontName=FONT_RALEWAY,
            fillColor=PDF_TEXT_SECONDARY,
        )
    )
    return d
