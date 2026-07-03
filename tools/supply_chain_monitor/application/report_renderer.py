"""
report_renderer — PDF-Renderer fuer Supply-Chain-Reports.

Iter 2d-ii-ii, 2026-05-15): Zwei Reports:

-:func:`render_gvsc_compliance_report` — Compliance-Matrix nach
  NIST CSF 2.0 GV.SC + BSI Grundschutz OPS.2.3 + ORP.5 mit Coverage-
  Stufen (COVERED / PARTIAL / GAP / MANUAL_REVIEW) und Evidenz-
  Begruendung pro Anforderung.
-:func:`render_avv_status_report` — Liste aller AVV-Dokumente mit
  Vendor / Gueltigkeitsdatum / Renewal-Status / Art-28-Check-Quote.

Beide nutzen ``reportlab.platypus`` mit einfachem A4-Layout. Wir nutzen
NICHT den DarkReportBuilder, weil der score-orientiert ist und nicht zur
Compliance-Matrix passt.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1-ii, 2026-05-15)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
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

from core.logger import get_logger
from core.pdf.pdf_colors import (
    PDF_ACCENT,
    PDF_BORDER,
    PDF_TEXT_SECONDARY,
)
from core.pdf.pdf_fonts import (
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
    FONT_RALEWAY_LIGHT,
    register_fonts,
)
from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.compliance_assessor import (
    ComplianceReport,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.domain.models import (
    ComplianceCoverage,
    ComplianceFramework,
    RenewalStatus,
)

# FINLAI-Logo fuer Report-Header. Wenn die Datei fehlt (z. B. in CI), faellt
# der Header auf reinen Text-Header zurueck.
_LOGO_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "assets"
    / "logo"
    / "finlai_logo.png"
)
_LOGO_MAX_W = 5 * cm
_LOGO_MAX_H = 1.6 * cm

# Print-freundliche FINLAI-Farben:
# - Akzent (Teal) fuer Linien + Titel,
# - dunkles Anthrazit fuer Body-Text statt reines Schwarz.
_TEXT_PRIMARY_PRINT = colors.HexColor("#1f2933")
_FOOTER_TEXT = "NoRisk by FINLAI — financial-analytics.eu"

_log = get_logger(__name__)


_FRAMEWORK_LABELS: dict[ComplianceFramework, str] = {
    ComplianceFramework.NIST_CSF_GVSC: "NIST CSF 2.0 — GV.SC (Supply-Chain-Governance)",
    ComplianceFramework.BSI_OPS_2_3: "BSI Grundschutz — OPS.2.3 (Cloud-Nutzung)",
    ComplianceFramework.BSI_ORP_5: "BSI Grundschutz — ORP.5 (Compliance-Mgmt)",
}

_COVERAGE_LABELS: dict[ComplianceCoverage, str] = {
    ComplianceCoverage.COVERED: "COVERED",
    ComplianceCoverage.PARTIAL: "PARTIAL",
    ComplianceCoverage.GAP: "GAP",
    ComplianceCoverage.MANUAL_REVIEW: "MANUAL",
}

_COVERAGE_BG: dict[ComplianceCoverage, colors.Color] = {
    ComplianceCoverage.COVERED: colors.HexColor("#c8e6c9"),  # gruen-pastell
    ComplianceCoverage.PARTIAL: colors.HexColor("#fff59d"),  # gelb-pastell
    ComplianceCoverage.GAP: colors.HexColor("#ffcdd2"),  # rot-pastell
    ComplianceCoverage.MANUAL_REVIEW: colors.HexColor("#e0e0e0"),  # neutral
}

_RENEWAL_LABELS: dict[RenewalStatus, str] = {
    RenewalStatus.OK: "OK",
    RenewalStatus.EXPIRING_SOON: "LAEUFT AB",
    RenewalStatus.OVERDUE: "UEBERFAELLIG",
}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_styles() -> dict[str, ParagraphStyle]:
    """Liefert die FINLAI-Style-Paragraph-Styles.

    Fonts: Raleway (Headlines), Raleway-Light (Body). Farbig: Akzent-Teal
    fuer Titel, Anthrazit fuer Body, gedaempfter Sekundaer-Ton fuer Meta-
    Zeilen. Wird nach:func:`register_fonts` aufgerufen, damit Raleway
    geladen ist.
    """
    register_fonts()
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        name="Title",
        parent=base["Title"],
        fontName=FONT_RALEWAY_BOLD,
        fontSize=20,
        leading=24,
        spaceAfter=6,
        textColor=PDF_ACCENT,
    )
    subtitle = ParagraphStyle(
        name="Subtitle",
        parent=base["BodyText"],
        fontName=FONT_RALEWAY_LIGHT,
        fontSize=11,
        leading=14,
        textColor=PDF_TEXT_SECONDARY,
        spaceAfter=4,
    )
    h1 = ParagraphStyle(
        name="H1",
        parent=base["Heading1"],
        fontName=FONT_RALEWAY_BOLD,
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
        textColor=PDF_ACCENT,
    )
    h2 = ParagraphStyle(
        name="H2",
        parent=base["Heading2"],
        fontName=FONT_RALEWAY_BOLD,
        fontSize=11,
        leading=14,
        spaceBefore=8,
        spaceAfter=4,
        textColor=_TEXT_PRIMARY_PRINT,
    )
    body = ParagraphStyle(
        name="Body",
        parent=base["BodyText"],
        fontName=FONT_RALEWAY,
        fontSize=9,
        leading=12,
        spaceAfter=6,
        textColor=_TEXT_PRIMARY_PRINT,
    )
    meta = ParagraphStyle(
        name="Meta",
        parent=base["BodyText"],
        fontName=FONT_RALEWAY_LIGHT,
        fontSize=8,
        leading=10,
        textColor=PDF_TEXT_SECONDARY,
    )
    return {
        "title": title,
        "subtitle": subtitle,
        "h1": h1,
        "h2": h2,
        "body": body,
        "meta": meta,
    }


def _german_date(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%d.%m.%Y")


def _finlai_header(
    story: list, styles: dict[str, ParagraphStyle], *, title: str, subtitle: str
) -> None:
    """Fuegt den FINLAI-Header (Logo + Titel + Teal-Linie) in die Story ein.

    Wenn die Logo-Datei fehlt, wird nur der Text-Header gerendert — so
    funktioniert der Report auch in CI ohne Asset-Bundle.
    """
    if _LOGO_PATH.exists():
        try:
            logo = Image(
                str(_LOGO_PATH), width=_LOGO_MAX_W, height=_LOGO_MAX_H
            )
            logo.hAlign = "LEFT"
            story.append(logo)
            story.append(Spacer(1, 0.3 * cm))
        except (OSError, ValueError, RuntimeError) as exc:
            _log.warning("FINLAI-Logo konnte nicht geladen werden: %s", exc)
    story.append(Paragraph(title, styles["title"]))
    story.append(Paragraph(subtitle, styles["subtitle"]))
    story.append(
        HRFlowable(
            width="100%",
            thickness=1.5,
            color=PDF_ACCENT,
            spaceBefore=4,
            spaceAfter=10,
        )
    )


def _finlai_footer_canvas(canvas, doc) -> None:  # noqa: ANN001 — reportlab callback
    """Page-Footer mit Teal-Trennlinie + Branding + Seitenzahl."""
    canvas.saveState()
    canvas.setStrokeColor(PDF_BORDER)
    canvas.setLineWidth(0.5)
    page_w, _ = A4
    margin = 2 * cm
    y = 1.4 * cm
    canvas.line(margin, y, page_w - margin, y)
    canvas.setFillColor(PDF_TEXT_SECONDARY)
    register_fonts()
    canvas.setFont(FONT_RALEWAY_LIGHT, 7.5)
    canvas.drawString(margin, y - 14, _FOOTER_TEXT)
    canvas.drawRightString(
        page_w - margin, y - 14, f"Seite {doc.page}"
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# GV.SC-Compliance-Report
# ---------------------------------------------------------------------------


def render_gvsc_compliance_report(
    output_path: Path,
    report: ComplianceReport,
    *,
    customer_name: str = "",
) -> Path:
    """Rendert den Compliance-Report als PDF.

    Args:
        output_path: Zieldatei. Wird ueberschrieben.
        report::class:`ComplianceReport` vom:class:`ComplianceAssessor`.
        customer_name: Optionaler Firmenname fuer das Deckblatt.

    Returns:
        Der Output-Pfad (zur Bequemlichkeit fuer Aufrufer).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.2 * cm,
        title="GV.SC-Compliance-Report",
        author="NoRisk by FINLAI",
    )
    styles = _make_styles()
    story: list = []

    # ── Header (FINLAI-Style: Logo + Teal-Akzent + Raleway) ───────────
    _finlai_header(
        story,
        styles,
        title="GV.SC-Compliance-Report",
        subtitle="Supply-Chain-Governance gegen NIST CSF 2.0 + BSI Grundschutz",
    )
    meta_lines = [f"Erstellt: {datetime.now(UTC).strftime('%d.%m.%Y %H:%M UTC')}"]
    if customer_name:
        meta_lines.append(f"Kunde: {customer_name}")
    for line in meta_lines:
        story.append(Paragraph(line, styles["meta"]))
    story.append(Spacer(1, 0.4 * cm))

    # ── Executive Summary ─────────────────────────────────────────────
    counts = report.counts()
    summary = report.snapshot_summary
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(
        Paragraph(
            f"Erfasste Vendoren: <b>{summary.get('vendor_count', 0)}</b> "
            f"(davon kritisch: <b>{summary.get('critical_vendor_count', 0)}</b>), "
            f"aktive AVVs: <b>{summary.get('active_avvs', 0)}</b> "
            f"(ueberfaellig: <b>{summary.get('overdue_avvs', 0)}</b>), "
            f"Subprocessors: <b>{summary.get('subprocessor_count', 0)}</b> "
            f"(konzentriert: <b>{summary.get('concentrated_subprocessors', 0)}</b>), "
            f"abgeschlossene Off-Boardings: <b>{summary.get('completed_offboardings', 0)}</b>.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            f"Compliance-Verteilung: "
            f"<b>{counts[ComplianceCoverage.COVERED]}</b> COVERED, "
            f"<b>{counts[ComplianceCoverage.PARTIAL]}</b> PARTIAL, "
            f"<b>{counts[ComplianceCoverage.GAP]}</b> GAP, "
            f"<b>{counts[ComplianceCoverage.MANUAL_REVIEW]}</b> MANUAL_REVIEW.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    # ── Methodik & Datenquellen ───────────────────────────────
    # Macht im Audit-Dokument selbst nachvollziehbar, WIE die Status-Werte
    # zustande kommen — die Bewertung wird deterministisch aus den im
    # Supply-Chain-Tool erfassten Daten abgeleitet, NICHT aus einer externen
    # Quelle. Jede Anforderung zeigt unten zusaetzlich ihre konkrete Begruendung.
    story.append(Paragraph("Methodik &amp; Datenquellen", styles["h1"]))
    story.append(
        Paragraph(
            "Die Status-Werte (COVERED / PARTIAL / GAP / MANUAL_REVIEW) werden "
            "<b>automatisch und deterministisch</b> aus den in NoRisk erfassten "
            "Supply-Chain-Daten abgeleitet — es fliessen keine externen Daten ein. "
            "Datengrundlage zum Erstellungszeitpunkt:",
            styles["body"],
        )
    )
    for quelle in (
        "<b>Vendoren</b> (Anzahl, Kritikalitaets-Einstufung 1–5, Kategorie) — "
        "aus der Lieferanten-Liste.",
        "<b>AVVs</b> (aktiv/abgelaufen/ueberfaellig) inkl. der Art.-28-"
        "Pflichtklausel-Checklisten je AVV.",
        "<b>Subprozessoren</b> inkl. Konzentrations-Analyse (mehrere Vendoren "
        "auf demselben Subprozessor).",
        "<b>Erkennungen</b> aus dem Tech-Stack-/Detection-Abgleich.",
        "<b>Off-Boardings</b> (angelegt / abgeschlossen).",
    ):
        story.append(Paragraph(f"&bull; {quelle}", styles["body"]))
    story.append(
        Paragraph(
            "Aus diesen Zahlen leitet je Anforderung eine feste Heuristik den "
            "Status ab; die konkrete Begruendung steht jeweils unter der "
            "Anforderung. <b>MANUAL_REVIEW</b> kennzeichnet prozedurale "
            "Anforderungen, die sich nicht automatisch aus Tool-Daten bewerten "
            "lassen und extern zu dokumentieren sind. Der Report ist eine "
            "Selbsteinschaetzung/Hilfestellung und ersetzt keine Zertifizierung.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    # ── Pro Framework ─────────────────────────────────────────────────
    for framework in ComplianceFramework:
        section_assessments = report.by_framework(framework)
        if not section_assessments:
            continue
        story.append(PageBreak())
        story.append(Paragraph(_FRAMEWORK_LABELS[framework], styles["h1"]))
        story.append(
            Paragraph(
                f"{len(section_assessments)} Anforderungen.",
                styles["meta"],
            )
        )
        story.append(Spacer(1, 0.2 * cm))

        for assessment in section_assessments:
            req = assessment.requirement
            story.append(
                Paragraph(f"{req.identifier}: {req.title}", styles["h2"])
            )
            story.append(Paragraph(req.description, styles["body"]))

            # Status-Tabelle (1 Zeile, 2 Spalten: Label / Begruendung)
            table_data = [
                [
                    Paragraph(
                        f"<b>{_COVERAGE_LABELS[assessment.coverage]}</b>",
                        styles["body"],
                    ),
                    Paragraph(assessment.evidence, styles["body"]),
                ]
            ]
            table = Table(table_data, colWidths=[3 * cm, 14 * cm])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0),
                         _COVERAGE_BG[assessment.coverage]),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 0.3 * cm))

    doc.build(
        story,
        onFirstPage=_finlai_footer_canvas,
        onLaterPages=_finlai_footer_canvas,
    )
    _log.info("gvsc_report_rendered path=%s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# AVV-Status-Report
# ---------------------------------------------------------------------------


def render_avv_status_report(
    output_path: Path,
    avv_service: AvvService,
    vendor_service: VendorService,
    *,
    customer_name: str = "",
) -> Path:
    """Rendert den AVV-Status-Report als PDF.

    Listet alle AVVs mit Vendor / Datei / Gueltig-bis / Renewal-Status /
    Art-28-Check-Quote (erledigte Defaults von 10).

    Args:
        output_path: Zieldatei.
        avv_service: Liefert AVVs + Checklisten.
        vendor_service: Liefert Vendor-Namen.
        customer_name: Optional fuer das Deckblatt.

    Returns:
        Der Output-Pfad.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.2 * cm,
        title="AVV-Status-Report",
        author="NoRisk by FINLAI",
    )
    styles = _make_styles()
    story: list = []

    _finlai_header(
        story,
        styles,
        title="AVV-Status-Report",
        subtitle="Auftragsverarbeitungsvertraege nach DSGVO Art. 28",
    )
    meta_lines = [f"Erstellt: {datetime.now(UTC).strftime('%d.%m.%Y %H:%M UTC')}"]
    if customer_name:
        meta_lines.append(f"Kunde: {customer_name}")
    for line in meta_lines:
        story.append(Paragraph(line, styles["meta"]))
    story.append(Spacer(1, 0.4 * cm))

    avvs = avv_service.list_all()
    vendors = vendor_service.list_vendors()
    vendor_map = {v.id: v.name for v in vendors if v.id is not None}

    if not avvs:
        story.append(
            Paragraph(
                "Keine AVV-Dokumente erfasst. Bitte AVV pro Vendor im "
                "Tab 'AVV-Tracker' hochladen.",
                styles["body"],
            )
        )
        doc.build(
            story,
            onFirstPage=_finlai_footer_canvas,
            onLaterPages=_finlai_footer_canvas,
        )
        return output_path

    # Summary
    overdue = sum(1 for a in avvs if a.renewal_status() is RenewalStatus.OVERDUE)
    expiring = sum(
        1 for a in avvs if a.renewal_status() is RenewalStatus.EXPIRING_SOON
    )
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(
        Paragraph(
            f"<b>{len(avvs)}</b> AVV-Dokumente erfasst, "
            f"<b>{overdue}</b> ueberfaellig, "
            f"<b>{expiring}</b> laufen in den naechsten 90 Tagen ab.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    # Detail-Tabelle
    story.append(Paragraph("AVV-Detail", styles["h1"]))
    header_row = [
        Paragraph("<b>Vendor</b>", styles["body"]),
        Paragraph("<b>Datei</b>", styles["body"]),
        Paragraph("<b>Gueltig bis</b>", styles["body"]),
        Paragraph("<b>Renewal</b>", styles["body"]),
        Paragraph("<b>Art-28</b>", styles["body"]),
    ]
    rows: list[list] = [header_row]
    # Sortierung: Renewal-Status absteigend (OVERDUE > EXPIRING > OK), dann
    # nach valid_until aufsteigend.
    rank = {
        RenewalStatus.OVERDUE: 0,
        RenewalStatus.EXPIRING_SOON: 1,
        RenewalStatus.OK: 2,
    }
    sorted_avvs = sorted(
        avvs,
        key=lambda a: (rank[a.renewal_status()], a.valid_until),
    )
    for avv in sorted_avvs:
        vendor_name = vendor_map.get(avv.vendor_id, f"Vendor #{avv.vendor_id}")
        if avv.id is None:
            check_text = "-"
        else:
            checklist = avv_service.get_checklist(avv.id)
            default_done = sum(
                1 for e in checklist if not e.is_custom and e.is_present is True
            )
            check_text = f"{default_done}/10"
        rows.append(
            [
                Paragraph(vendor_name, styles["body"]),
                Paragraph(avv.original_filename, styles["body"]),
                Paragraph(_german_date(avv.valid_until), styles["body"]),
                Paragraph(_RENEWAL_LABELS[avv.renewal_status()], styles["body"]),
                Paragraph(check_text, styles["body"]),
            ]
        )
    table = Table(
        rows,
        colWidths=[4.0 * cm, 4.5 * cm, 2.5 * cm, 3.0 * cm, 2.0 * cm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cfd8dc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(table)

    doc.build(
        story,
        onFirstPage=_finlai_footer_canvas,
        onLaterPages=_finlai_footer_canvas,
    )
    _log.info("avv_status_report_rendered path=%s avv_count=%s", output_path, len(avvs))
    return output_path
