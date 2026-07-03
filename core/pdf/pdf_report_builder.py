"""
pdf_report_builder — FINLAI PDF-Report-Builder (Light-Schema).

Erstellt mehrseitige A4-Reports mit weißem Seitenhintergrund und dunklem Text.
Verwendet reportlab SimpleDocTemplate mit weißem Seiten-Background-Callback.

Farben: core/pdf/pdf_colors.py (aus core/theme.py)
Fonts: core/pdf/pdf_fonts.py (aus assets/fonts/)
Styles: core/pdf/pdf_styles.py

Schichtzugehörigkeit: core/ — keine Tool-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.escape import escape_html
from core.exceptions import ConfigurationError
from core.logger import get_logger
from core.pdf.pdf_colors import (
    PDF_ACCENT,
    PDF_BG_PAGE,
    PDF_BORDER,
    PDF_TABLE_HEADER_BG,
    PDF_TABLE_HEADER_TEXT,
    PDF_TABLE_ROW_EVEN,
    PDF_TABLE_ROW_ODD,
    risk_color,
)
from core.pdf.pdf_components import (
    category_bar_drawing,
    mini_score_box_drawing,
    score_gauge_drawing,
    status_dot_drawing,
)
from core.pdf.pdf_fonts import (
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
    register_fonts,
)
from core.pdf.pdf_styles import build_styles

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Layout-Konstanten
# ---------------------------------------------------------------------------
_PAGE_W, _PAGE_H = A4
_MARGIN = 2.0 * cm
_INNER_W = _PAGE_W - 2 * _MARGIN
# Light-Schema: dunkles Logo (finlai_logo_light = schwarze Variante für hellen
# Hintergrund). Das frühere finlai_logo.png ist die helle Dark-Theme-Variante
# und wäre auf Weiß unsichtbar.
_LOGO_PATH = (
    Path(__file__).parent.parent.parent / "assets" / "logo" / "finlai_logo_light.png"
)
_LOGO_MAX_W = 8 * cm
_LOGO_MAX_H = 2.5 * cm

_DISCLAIMER_TEXT = (
    "Dieser Report wurde maschinell erstellt und dient ausschließlich "
    "internen Informationszwecken. Alle Angaben ohne Gewähr. "
    "Der Report ersetzt keine professionelle Sicherheitsberatung. "
    "NoRisk by FINLAI übernimmt keine Haftung für Vollständigkeit "
    "oder Richtigkeit der erhobenen Daten."
)


# ---------------------------------------------------------------------------
# Dunkler Seiten-Hintergrund (Canvas-Callback)
# ---------------------------------------------------------------------------


def _draw_page_background(canvas, doc) -> None:  # noqa: ANN001
    """Zeichnet den weißen Seitenhintergrund (Canvas-Callback).

    Wird als onFirstPage/onLaterPages an SimpleDocTemplate.build übergeben.
    ``PDF_BG_PAGE`` ist im Light-Schema weiß — der explizite Rect stellt den
    Hintergrund deterministisch sicher (unabhängig vom Viewer-Default).

    Args:
        canvas: Reportlab Canvas-Objekt.
        doc: SimpleDocTemplate-Instanz.
    """
    canvas.saveState()
    canvas.setFillColor(PDF_BG_PAGE)
    canvas.rect(0, 0, _PAGE_W, _PAGE_H, fill=1, stroke=0)
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Hilfs-Flowables
# ---------------------------------------------------------------------------


def _teal_line(width: float = _INNER_W, thickness: float = 1.5) -> HRFlowable:
    """Gibt eine Teal-Trennlinie zurück.

    Args:
        width: Linienbreite in Punkten.
        thickness: Linienstärke in Punkten.

    Returns:
        HRFlowable in FINLAI Teal.
    """
    return HRFlowable(
        width=width,
        thickness=thickness,
        color=PDF_ACCENT,
        spaceAfter=8,
        spaceBefore=8,
    )


def _spacer(h: float = 0.5) -> Spacer:
    """Erstellt einen vertikalen Spacer.

    Args:
        h: Höhe in cm.

    Returns:
        Spacer-Objekt.
    """
    return Spacer(1, h * cm)


# ---------------------------------------------------------------------------
# Haupt-Builder
# ---------------------------------------------------------------------------


class DarkReportBuilder:
    """Erstellt PDF-Reports im FINLAI Dark Theme.

    Typische Nutzung:
        builder = DarkReportBuilder("/pfad/zum/report.pdf", title="Security Report")
        builder.add_cover(date_str="06.04.2026", report_id="REP-001")
        builder.add_executive_summary(score=72.5, risk_level="Mittel", categories=[...])
        builder.add_recommendations(recommendations=[...])
        builder.add_footer_page
        builder.build

    Attributes:
        _output_path: Ausgabepfad für die PDF-Datei.
        _title: Report-Titel.
        _subtitle: Report-Untertitel.
        _company: Optionaler Firmenname (für Kunden-Assessment).
        _story: Liste der Platypus-Flowables.
        _styles: Dict mit ParagraphStyles.
    """

    def __init__(
        self,
        output_path: str | Path,
        title: str = "Security Assessment Report",
        subtitle: str = "NoRisk by FINLAI",
        company: str = "",
    ) -> None:
        """Initialisiert den Builder.

        Args:
            output_path: Pfad zur Ausgabe-PDF-Datei.
            title: Report-Titel (Deckblatt).
            subtitle: Untertitel (Deckblatt).
            company: Optionaler Firmenname des Kunden.
        """
        register_fonts()
        self._output_path = Path(output_path)
        self._title = title
        self._subtitle = subtitle
        self._company = company
        self._story: list = []
        self._styles = build_styles()

    # ------------------------------------------------------------------
    # Öffentliche Builder-Methoden
    # ------------------------------------------------------------------

    def add_cover(
        self,
        date_str: str = "",
        report_id: str = "",
    ) -> DarkReportBuilder:
        """Fügt das Deckblatt hinzu.

        Args:
            date_str: Erstellungsdatum (z.B. "06.04.2026").
            report_id: Berichtsnummer (z.B. "REP-2026-001").

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles

        # Großer Spacer oben (Logo-Position)
        self._story.append(_spacer(3.5))

        # Logo (falls vorhanden)
        if _LOGO_PATH.exists():
            try:
                logo = Image(str(_LOGO_PATH), width=_LOGO_MAX_W, height=_LOGO_MAX_H)
                logo.hAlign = "CENTER"
                self._story.append(logo)
                self._story.append(_spacer(0.8))
            except (OSError, ValueError, RuntimeError) as exc:
                log.warning("Logo konnte nicht geladen werden: %s", exc)

        self._story.append(_teal_line())
        self._story.append(_spacer(0.6))

        # Titel
        self._story.append(Paragraph(self._title, st["cover_title"]))
        # Untertitel
        self._story.append(Paragraph(self._subtitle, st["cover_subtitle"]))

        # Firmenname (optional)
        if self._company:
            self._story.append(_spacer(0.4))
            self._story.append(Paragraph(self._company, st["cover_company"]))

        self._story.append(_spacer(1.0))
        self._story.append(_teal_line())
        self._story.append(_spacer(0.5))

        # Metadaten
        if date_str:
            self._story.append(Paragraph(f"Erstellt: {date_str}", st["cover_meta"]))
        if report_id:
            self._story.append(
                Paragraph(f"Berichtsnummer: {report_id}", st["cover_meta"])
            )

        # Großer Spacer zum Seitenende
        self._story.append(_spacer(4.0))
        # Slogan
        self._story.append(
            Paragraph("weil Sicherheit kein Zufall ist", st["cover_slogan"])
        )
        self._story.append(PageBreak())
        return self

    def add_executive_summary(
        self,
        overall_score: float,
        risk_level: str,
        category_scores: list[dict],
        summary_text: str = "",
    ) -> DarkReportBuilder:
        """Fügt die Executive-Summary-Seite hinzu.

        Args:
            overall_score: Gesamtscore 0–100.
            risk_level: Risikostufe.
            category_scores: Liste von Dicts mit "name", "score", "label".
            summary_text: Optionaler Zusammenfassungstext.

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles
        self._story.append(Paragraph("Executive Summary", st["h1"]))
        self._story.append(_teal_line())
        self._story.append(_spacer(0.4))

        # Score-Gauge + Kategorien-Balken nebeneinander als Tabelle
        gauge = score_gauge_drawing(overall_score, risk_level, size=150)

        # Kategorie-Balken-Block aufbauen
        bar_story: list = []
        for cat in category_scores:
            cat_name = cat.get("name", "")
            cat_score = float(cat.get("score", 0))
            cat_label = cat.get("label", "")
            bar = category_bar_drawing(cat_score, width=220, height=10)
            r_col = risk_color(cat_label)

            bar_story.append(
                Paragraph(
                    f'<font color="#{_hex_str(r_col)}">'
                    f"{cat_name}  {cat_score:.0f}/100  ({cat_label})"
                    f"</font>",
                    st["body"],
                )
            )
            bar_story.append(bar)
            bar_story.append(_spacer(0.15))

        cat_table_data = [[gauge, bar_story]]
        cat_table = Table(
            cat_table_data,
            colWidths=[_INNER_W * 0.38, _INNER_W * 0.62],
        )
        cat_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("BACKGROUND", (0, 0), (-1, -1), PDF_BG_PAGE),
                ]
            )
        )
        self._story.append(cat_table)

        # Summary-Text
        if summary_text:
            self._story.append(_spacer(0.5))
            self._story.append(Paragraph(summary_text, st["body"]))

        self._story.append(PageBreak())
        return self

    def add_category_details(
        self,
        category_name: str,
        category_score: float,
        category_risk: str,
        rows: list[dict],
    ) -> DarkReportBuilder:
        """Fügt eine Kategorie-Detail-Seite hinzu.

        Args:
            category_name: Name der Kategorie.
            category_score: Score der Kategorie.
            category_risk: Risikostufe der Kategorie.
            rows: Liste von Dicts mit "label", "value", "status".

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles

        # Kategorie-Header
        score_box = mini_score_box_drawing(
            category_score, category_risk, width=80, height=40
        )
        header_table = Table(
            [[Paragraph(category_name, st["h2"]), score_box]],
            colWidths=[_INNER_W - 90, 90],
        )
        header_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("BACKGROUND", (0, 0), (-1, -1), PDF_BG_PAGE),
                ]
            )
        )
        self._story.append(header_table)
        self._story.append(_teal_line())

        if not rows:
            self._story.append(Paragraph("Keine Einträge vorhanden.", st["body_dim"]))
            return self

        # Tabelle aufbauen
        table_data = [
            [
                Paragraph("Prüfpunkt", st["table_header"]),
                Paragraph("Status", st["table_header"]),
                Paragraph("Wert / Details", st["table_header"]),
            ]
        ]
        for row in rows:
            label = str(row.get("label", ""))
            value = str(row.get("value", ""))
            status = str(row.get("status", ""))
            dot = status_dot_drawing(status, size=10)
            table_data.append(
                [
                    Paragraph(label, st["table_cell"]),
                    dot,
                    Paragraph(value, st["table_cell"]),
                ]
            )

        col_widths = [_INNER_W * 0.35, 20, _INNER_W * 0.62]
        tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(self._detail_table_style(len(table_data)))
        self._story.append(tbl)
        self._story.append(_spacer(0.5))
        return self

    def add_recommendations(
        self,
        recommendations: list[str],
    ) -> DarkReportBuilder:
        """Fügt die Handlungsempfehlungs-Seite hinzu.

        Erwartet Empfehlungen im Format:
            "[Kritisch] Kategorie: Titel — Beschreibung"
        oder einfache Strings.

        Args:
            recommendations: Liste von Empfehlungs-Strings.

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles
        self._story.append(Paragraph("Handlungsempfehlungen", st["h1"]))
        self._story.append(_teal_line())
        self._story.append(_spacer(0.3))

        if not recommendations:
            self._story.append(
                Paragraph(
                    "Keine Handlungsempfehlungen — alle Bereiche sind optimal konfiguriert.",
                    st["body"],
                )
            )
            return self

        prio_styles = {
            "Kritisch": st["rec_critical"],
            "Hoch": st["rec_high"],
            "Mittel": st["rec_medium"],
            "Niedrig": st["rec_low"],
        }

        for rec_str in recommendations:
            # Format: "[Priorität] Kategorie: Titel — Beschreibung"
            prio, title_part, desc_part = _parse_recommendation(rec_str)
            prio_style = prio_styles.get(prio, st["body"])

            # Prioritäts-Badge
            self._story.append(Paragraph(f"[{prio}]", prio_style))
            # Titel
            self._story.append(Paragraph(title_part, st["rec_title"]))
            # Beschreibung
            if desc_part:
                self._story.append(Paragraph(desc_part, st["rec_description"]))
            self._story.append(_teal_line(thickness=0.5))

        self._story.append(PageBreak())
        return self

    def add_compliance_section(
        self,
        title: str,
        disclaimer: str,
        table_rows: list[list[str]],
    ) -> DarkReportBuilder:
        """Fuegt eine indikative Regulatorik-Sektion hinzu (Heading + Disclaimer + Tabelle).

        Anders als:meth:`add_category_details` OHNE Score-Box — eine Norm-Zuordnung
        hat keinen numerischen Score. Alle Zellen werden ge-escaped (die Norm-Labels
        enthalten ``&``, das ReportLab sonst als Markup interpretiert).

        Args:
            title: Sektions-Ueberschrift (z.B. "Regulatorik-Bezug (indikativ)").
            disclaimer: Pflicht-Disclaimer (prominent vor der Tabelle).
            table_rows: ``[[header...], [row...],...]`` (erste Zeile = Kopf).

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles
        self._story.append(Paragraph(escape_html(title), st["h1"]))
        self._story.append(_teal_line())
        self._story.append(_spacer(0.2))
        self._story.append(Paragraph(escape_html(disclaimer), st["body_dim"]))
        self._story.append(_spacer(0.3))
        if not table_rows or len(table_rows) <= 1:
            self._story.append(
                Paragraph(
                    "Keine offenen Haertungs-Befunde mit Norm-Bezug.", st["body_dim"]
                )
            )
            self._story.append(PageBreak())
            return self
        header, *body = table_rows
        data = [[Paragraph(escape_html(str(c)), st["table_header"]) for c in header]]
        for row in body:
            data.append([Paragraph(escape_html(str(c)), st["table_cell"]) for c in row])
        col_widths = [
            _INNER_W * 0.28,
            _INNER_W * 0.12,
            _INNER_W * 0.34,
            _INNER_W * 0.12,
            _INNER_W * 0.14,
        ]
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(self._detail_table_style(len(data)))
        self._story.append(tbl)
        self._story.append(PageBreak())
        return self

    def add_image(
        self,
        png_bytes: bytes,
        *,
        caption: str = "",
        width_cm: float = 12.0,
    ) -> DarkReportBuilder:
        """Bettet ein PNG (z.B. die Risikomatrix) zentriert ein.

        Args:
            png_bytes: PNG-Bytes (z.B. aus ``render_risk_matrix_png``).
            caption: Optionale Bildunterschrift (wird escaped).
            width_cm: Zielbreite in cm; die Höhe folgt dem Seitenverhältnis.

        Returns:
            self (Builder-Pattern). Fail-soft: ein nicht ladbares Bild wird
            übersprungen (kein Crash des Reports).
        """
        from io import BytesIO  # noqa: PLC0415

        st = self._styles
        try:
            img = Image(BytesIO(png_bytes))
            aspect = (img.drawHeight / img.drawWidth) if img.drawWidth else 0.8
            img.drawWidth = width_cm * cm
            img.drawHeight = width_cm * cm * aspect
            img.hAlign = "CENTER"
            self._story.append(img)
        except (OSError, ValueError, RuntimeError) as exc:
            log.warning("Bild konnte nicht eingebettet werden: %s", type(exc).__name__)
            return self
        if caption:
            self._story.append(_spacer(0.15))
            self._story.append(Paragraph(escape_html(caption), st["body_dim"]))
        self._story.append(_spacer(0.3))
        return self

    def add_footer_page(
        self,
        contact_info: str = "",
    ) -> DarkReportBuilder:
        """Fügt die Abschluss-/Disclaimer-Seite hinzu.

        Args:
            contact_info: Optionaler Kontakttext.

        Returns:
            self (Builder-Pattern).
        """
        st = self._styles
        self._story.append(_spacer(3.0))
        self._story.append(_teal_line())
        self._story.append(_spacer(0.5))

        # Logo (klein)
        if _LOGO_PATH.exists():
            try:
                logo = Image(str(_LOGO_PATH), width=4 * cm, height=1.3 * cm)
                logo.hAlign = "CENTER"
                self._story.append(logo)
                self._story.append(_spacer(0.3))
            except (OSError, ValueError, RuntimeError) as exc:
                log.warning("Logo (Footer) konnte nicht geladen werden: %s", exc)

        self._story.append(Paragraph("Erstellt mit NoRisk by FINLAI", st["footer"]))
        if contact_info:
            self._story.append(Paragraph(contact_info, st["footer"]))

        self._story.append(_spacer(1.0))
        self._story.append(Paragraph("Haftungsausschluss", st["h3"]))
        self._story.append(Paragraph(_DISCLAIMER_TEXT, st["disclaimer"]))
        return self

    def build(self) -> Path:
        """Erstellt die PDF-Datei.

        Returns:
            Pfad zur erzeugten PDF-Datei.

        Raises:
            OSError: Bei Schreibfehlern.
            RuntimeError: Wenn keine Seiten hinzugefügt wurden.
        """
        if not self._story:
            raise ConfigurationError(
                "Keine Seiten definiert — build() vor add_*() aufgerufen?"
            )

        doc = SimpleDocTemplate(
            str(self._output_path),
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=_MARGIN,
            bottomMargin=_MARGIN,
            title=self._title,
            author="NoRisk by FINLAI",
        )
        doc.build(
            self._story,
            onFirstPage=_draw_page_background,
            onLaterPages=_draw_page_background,
        )
        log.info("PDF-Report erstellt: %s", self._output_path)
        return self._output_path

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------

    @staticmethod
    def _detail_table_style(num_rows: int) -> TableStyle:
        """Erstellt den Dark-Theme-TableStyle für Detail-Tabellen.

        Args:
            num_rows: Gesamtzahl der Tabellenzeilen.

        Returns:
            TableStyle-Objekt.
        """
        base = [
            # Header-Zeile
            ("BACKGROUND", (0, 0), (-1, 0), PDF_TABLE_HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), PDF_TABLE_HEADER_TEXT),
            ("FONTNAME", (0, 0), (-1, 0), FONT_RALEWAY_BOLD),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("LEFTPADDING", (0, 0), (-1, 0), 8),
            # Daten-Zeilen: abwechselnde Hintergründe
            ("FONTNAME", (0, 1), (-1, -1), FONT_RALEWAY),
            ("FONTSIZE", (0, 1), (-1, -1), 10),
            ("TOPPADDING", (0, 1), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
            ("LEFTPADDING", (0, 1), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            # Rahmen
            ("LINEBELOW", (0, 0), (-1, 0), 1, PDF_ACCENT),
            ("LINEBELOW", (0, 1), (-1, -1), 0.5, PDF_BORDER),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [PDF_TABLE_ROW_ODD, PDF_TABLE_ROW_EVEN],
            ),
        ]
        return TableStyle(base)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _hex_str(color) -> str:  # noqa: ANN001
    """Konvertiert eine reportlab-Color in einen Hex-String (ohne #).

    Args:
        color: Reportlab Color-Objekt.

    Returns:
        6-stelliger Hex-String ohne Prefix.
    """
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except AttributeError:
        return "26a69a"  # Fallback Teal


def _parse_recommendation(rec_str: str) -> tuple[str, str, str]:
    """Parst einen Empfehlungs-String in (Priorität, Titel, Beschreibung).

    Erwartet Format: "[Priorität] Kategorie: Titel — Beschreibung"

    Args:
        rec_str: Empfehlungs-String.

    Returns:
        Tuple (prio, titel_mit_kategorie, beschreibung).
    """
    prio = "Mittel"
    if rec_str.startswith("["):
        try:
            end_bracket = rec_str.index("]")
            prio = rec_str[1:end_bracket]
            rest = rec_str[end_bracket + 2 :].strip()
        except ValueError:
            rest = rec_str
    else:
        rest = rec_str

    if " — " in rest:
        parts = rest.split(" — ", 1)
        return prio, parts[0].strip(), parts[1].strip()
    return prio, rest, ""
