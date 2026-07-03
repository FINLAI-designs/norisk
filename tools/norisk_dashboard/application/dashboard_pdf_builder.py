"""
dashboard_pdf_builder — Light-Theme-PDF für den NoRisk-Gesamt-Dashboard-Report.

Generiert einen 5–8-seitigen Compliance-Report aus ``DashboardData``.
Struktur:
    Seite 1: Deckblatt + Management-Summary-Box
    Seite 2: Sektion 1 — Was hat sich geändert (Badges NEU/GEÄNDERT)
    Seite 3: Sektionen 2+3 — Score kompakt + CVE-Liste + Scan-Status
    Seite 4-5: Sektion 4 — Score-Aufschlüsselung + Trend (PNG)
    Seite 6: Sektion 5 — Organisatorische Sicherheit (Tabelle)
    Seite 7: Abschluss/Impressum mit Disclaimer

Jede Seite hat einen festen Header (Logo links, Titel + Datum rechts) und
Footer (Seite X/Y, Kontakt, "Vertraulich — Kanzleieigen"), gezeichnet
per Canvas-Callback.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors as _c
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
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
from core.logger import get_logger
from core.pdf.pdf_fonts import (
    FONT_RALEWAY,
    FONT_RALEWAY_BOLD,
    register_fonts,
)
from core.pdf.pdf_light_colors import (
    LIGHT_ACCENT,
    LIGHT_ACCENT_DEEP,
    LIGHT_BG_CARD,
    LIGHT_BG_SUBTLE,
    LIGHT_BORDER,
    LIGHT_BORDER_STRONG,
    LIGHT_TEXT_MUTED,
    LIGHT_TEXT_PRIMARY,
    LIGHT_TEXT_SECONDARY,
    light_risk_color,
    light_score_color,
    scan_status_color,
)
from core.pdf.pdf_light_styles import build_light_styles
from tools.norisk_dashboard.application.dashboard_chart_export import (
    render_breakdown_png,
    render_score_trend_png,
)
from tools.norisk_dashboard.domain.models import (
    ChangeType,
    DashboardData,
    ScanStatus,
)

log = get_logger(__name__)

_PAGE_W, _PAGE_H = A4
_MARGIN_LEFT = 2.0 * cm
_MARGIN_RIGHT = 2.0 * cm
_MARGIN_TOP = 3.0 * cm
_MARGIN_BOTTOM = 2.2 * cm
_INNER_W = _PAGE_W - _MARGIN_LEFT - _MARGIN_RIGHT

_LOGO_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "assets"
    / "logo"
    / "finlai_logo_light.png"
)
_CONTACT_LINE = "FINLAI designs • Linz • financial-analytics.eu"
_CONFIDENTIAL_TAG = "Vertraulich — Kanzleieigen"


class DashboardPdfBuilder:
    """Baut den NoRisk-Dashboard-Compliance-Report als PDF.

    Nutzung::

        builder = DashboardPdfBuilder(Path("out.pdf"), data, target_name="ACME")
        builder.build

    Attributes:
        _output: Ziel-Pfad.
        _data: Aggregierter ``DashboardData``-Snapshot.
        _target_name: Scope-Bezeichner (Kundenname oder "Allgemein").
        _generated_at: Erstellungszeitpunkt — wird auch im Header angezeigt.
        _styles: Light-Theme-ParagraphStyles.
    """

    def __init__(
        self,
        output_path: str | Path,
        data: DashboardData,
        target_name: str = "Allgemein",
        generated_at: datetime | None = None,
        compliance_rows: list | None = None,
    ) -> None:
        register_fonts()
        self._output = Path(output_path)
        self._data = data
        # W3b: optionale ComplianceRow-Liste fuer die indikative
        # Regulatorik-Sektion (leer -> Sektion wird uebersprungen).
        self._compliance_rows = compliance_rows or []
        # target_name ist seit Klartext-Freitext (Subjekt = Firmenname
        # aus dem Audit) und fließt in ReportLab-Paragraphs — escapen, sonst
        # crasht schon ein legitimes "Müller & Co." den Export.
        self._target_name = escape_html(target_name or "Allgemein")
        self._generated_at = generated_at or data.generated or datetime.now()
        self._styles = build_light_styles()

    # ------------------------------------------------------------------

    def build(self) -> Path:
        """Erstellt die PDF-Datei.

        Returns:
            Pfad zur erzeugten Datei.

        Raises:
            OSError: Bei Schreibfehlern.
        """
        self._output.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(self._output),
            pagesize=A4,
            leftMargin=_MARGIN_LEFT,
            rightMargin=_MARGIN_RIGHT,
            topMargin=_MARGIN_TOP,
            bottomMargin=_MARGIN_BOTTOM,
            title="NoRisk Dashboard-Report",
            author="NoRisk by FINLAI",
        )
        story: list = []
        self._append_cover(story)
        story.append(PageBreak())
        self._append_changes(story)
        story.append(PageBreak())
        self._append_score_and_cves(story)
        story.append(PageBreak())
        self._append_breakdown_and_trend(story)
        story.append(PageBreak())
        self._append_organizational(story)
        story.append(PageBreak())
        self._append_regulatorik(story)
        self._append_imprint(story)

        draw = _HeaderFooter(self._generated_at)
        doc.build(story, onFirstPage=draw, onLaterPages=draw)
        log.info("Dashboard-PDF erstellt: %s", self._output)
        return self._output

    # ------------------------------------------------------------------
    # Seite 1 — Deckblatt + Management-Summary
    # ------------------------------------------------------------------

    def _append_cover(self, story: list) -> None:
        st = self._styles
        d = self._data

        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("NoRisk Dashboard-Report", st["title"]))
        story.append(
            Paragraph(
                f"Compliance-Nachweis für externe Prüfer — Scope: {self._target_name}",
                st["subtitle"],
            )
        )
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                f"Erstellt am: {self._generated_at:%d.%m.%Y %H:%M} Uhr",
                st["meta"],
            )
        )
        story.append(
            Paragraph(
                f"Zeitfenster: {d.time_range.label} (letzte {d.time_range.days} Tage)",
                st["meta"],
            )
        )
        story.append(Spacer(1, 0.7 * cm))

        story.append(Paragraph("Management-Summary", st["h1"]))
        story.append(self._summary_box())

        story.append(Spacer(1, 0.7 * cm))
        story.append(
            Paragraph(
                "Hinweis: Dieser Report wurde maschinell aus dem NoRisk-Dashboard "
                "erzeugt. Die Angaben spiegeln den Datenstand zum Zeitpunkt der "
                "Erstellung wider. Eine vollständige Risiko-Bewertung ersetzt er "
                "nicht — ergänzende Prüfberichte und Maßnahmen-Dokumentationen "
                "sind separat einzusehen.",
                st["body_dim"],
            )
        )

    def _summary_box(self) -> Table:
        """4 Kennzahlen: Score, Findings, Open-Org, Änderungen im Zeitraum."""
        d = self._data
        score_text = f"{d.score.current:.0f}" if d.score.current is not None else "—"
        delta = d.score.delta
        delta_text = (
            f"{delta:+.1f} Δ zur Vorperiode"
            if delta is not None
            else "Kein Vergleichswert"
        )
        org = d.org
        if org is not None:
            open_findings = sum(t.findings_open for t in org.tiles)
            scored = [t for t in org.tiles if t.score is not None]
            org_avg = (
                f"{sum(t.score for t in scored) / len(scored):.0f}" if scored else "—"
            )
        else:
            open_findings = 0
            org_avg = "—"
        change_count = len(d.changes)
        new_cves = sum(1 for c in d.changes if c.source == "cve")

        tiles = [
            ("Gesamt-Score", score_text, delta_text),
            ("Neue CVEs", f"{new_cves}", f"Gesamt-Änderungen: {change_count}"),
            (
                "Organisatorisch Ø",
                org_avg,
                f"{open_findings} offene Kriterien",
            ),
            (
                "Scanner-Abdeckung",
                self._scanner_coverage_label(),
                "Vollständige Historie im Dashboard",
            ),
        ]
        return _build_summary_tiles(tiles, self._styles)

    def _scanner_coverage_label(self) -> str:
        present = [s for s in self._data.scans if s.status != ScanStatus.MISSING]
        return f"{len(present)}/{len(self._data.scans) or 1}"

    # ------------------------------------------------------------------
    # Seite 2 — Sektion 1: Was hat sich geändert
    # ------------------------------------------------------------------

    def _append_changes(self, story: list) -> None:
        st = self._styles
        d = self._data

        story.append(Paragraph("1 · Änderungen im Zeitraum", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                f"Zeitfenster: {d.time_range.label} ({d.time_range.days} Tage)",
                st["body_dim"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))

        if not d.changes:
            story.append(
                Paragraph(
                    "Keine registrierten Änderungen im ausgewählten Zeitfenster.",
                    st["body_muted"],
                )
            )
            return

        rows = [
            [
                Paragraph("Typ", st["table_header"]),
                Paragraph("Titel", st["table_header"]),
                Paragraph("Detail", st["table_header"]),
                Paragraph("Zeitpunkt", st["table_header"]),
            ]
        ]
        for change in d.changes[:40]:
            badge_style_key = {
                ChangeType.NEW: "badge_new",
                ChangeType.CHANGED: "badge_changed",
                ChangeType.DELETED: "badge_deleted",
            }[change.change_type]
            rows.append(
                [
                    Paragraph(change.change_type.badge, st[badge_style_key]),
                    Paragraph(change.title or "—", st["table_cell"]),
                    Paragraph(change.detail or "—", st["table_cell_dim"]),
                    Paragraph(f"{change.timestamp:%d.%m.%Y}", st["table_cell_mono"]),
                ]
            )
        col_widths = [
            _INNER_W * 0.13,
            _INNER_W * 0.27,
            _INNER_W * 0.43,
            _INNER_W * 0.17,
        ]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(_light_table_style())
        story.append(table)

    # ------------------------------------------------------------------
    # Seite 3 — Sektionen 2+3: Score kompakt + CVEs + Scans
    # ------------------------------------------------------------------

    def _append_score_and_cves(self, story: list) -> None:
        st = self._styles
        d = self._data

        story.append(Paragraph("2 · Score kompakt", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))

        score_text = f"{d.score.current:.0f}" if d.score.current is not None else "—"
        prev_text = f"{d.score.previous:.0f}" if d.score.previous is not None else "—"
        delta = d.score.delta
        delta_text = f"{delta:+.1f}" if delta is not None else "—"
        ts_text = (
            f"{d.score.timestamp:%d.%m.%Y %H:%M}"
            if d.score.timestamp
            else "kein Zeitstempel"
        )

        score_rows = [
            [
                Paragraph("Aktueller Score", st["table_header"]),
                Paragraph("Vorperiode", st["table_header"]),
                Paragraph("Delta", st["table_header"]),
                Paragraph("Stand", st["table_header"]),
            ],
            [
                Paragraph(score_text, st["mono"]),
                Paragraph(prev_text, st["mono"]),
                Paragraph(delta_text, st["mono"]),
                Paragraph(ts_text, st["table_cell_mono"]),
            ],
        ]
        score_table = Table(score_rows, colWidths=[_INNER_W / 4] * 4, repeatRows=1)
        score_table.setStyle(_light_table_style())
        story.append(score_table)

        story.append(Spacer(1, 0.6 * cm))
        story.append(Paragraph("3 · CVE-Liste + Scan-Status", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("CVEs (aus Tech-Stack-Briefing)", st["h2"]))

        if not d.cves:
            story.append(
                Paragraph("Keine CVEs im Techstack-Briefing.", st["body_muted"])
            )
        else:
            cve_rows = [
                [
                    Paragraph("CVE-ID", st["table_header"]),
                    Paragraph("Produkt", st["table_header"]),
                    Paragraph("Beschreibung", st["table_header"]),
                    Paragraph("Veröffentl.", st["table_header"]),
                ]
            ]
            for cve in d.cves[:15]:
                cve_rows.append(
                    [
                        Paragraph(cve.cve_id, st["table_cell_mono"]),
                        Paragraph(cve.product or "—", st["table_cell"]),
                        Paragraph(
                            _truncate(cve.description, 140), st["table_cell_dim"]
                        ),
                        Paragraph(f"{cve.published:%d.%m.%Y}", st["table_cell_mono"]),
                    ]
                )
            cve_table = Table(
                cve_rows,
                colWidths=[
                    _INNER_W * 0.17,
                    _INNER_W * 0.20,
                    _INNER_W * 0.48,
                    _INNER_W * 0.15,
                ],
                repeatRows=1,
            )
            cve_table.setStyle(_light_table_style())
            story.append(cve_table)

        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Scanner-Status", st["h2"]))
        if not d.scans:
            story.append(Paragraph("Keine Scanner registriert.", st["body_muted"]))
            return
        scan_rows = [
            [
                Paragraph("Scanner", st["table_header"]),
                Paragraph("Status", st["table_header"]),
                Paragraph("Letzter Lauf", st["table_header"]),
            ]
        ]
        for scan in d.scans:
            status_label = _scan_status_label(scan.status)
            color = scan_status_color(scan.status.value)
            scan_rows.append(
                [
                    Paragraph(scan.tool_label, st["table_cell"]),
                    Paragraph(
                        f'<font color="#{_hex(color)}">&#9679; {status_label}</font>',
                        st["table_cell"],
                    ),
                    Paragraph(
                        f"{scan.day:%d.%m.%Y}"
                        if scan.status != ScanStatus.MISSING
                        else "—",
                        st["table_cell_mono"],
                    ),
                ]
            )
        scan_table = Table(
            scan_rows,
            colWidths=[_INNER_W * 0.4, _INNER_W * 0.35, _INNER_W * 0.25],
            repeatRows=1,
        )
        scan_table.setStyle(_light_table_style())
        story.append(scan_table)

    # ------------------------------------------------------------------
    # Seiten 4-5 — Sektion 4: Score-Aufschlüsselung + Trend
    # ------------------------------------------------------------------

    def _append_breakdown_and_trend(self, story: list) -> None:
        st = self._styles
        d = self._data

        story.append(Paragraph("4 · Score-Aufschlüsselung + Trend", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))

        story.append(Paragraph("4a · Aufschlüsselung nach Kategorie", st["h2"]))
        if d.breakdown:
            png = render_breakdown_png(d.breakdown, width_inch=6.5, height_inch=3.2)
            if png is not None:
                img = Image(io.BytesIO(png), width=_INNER_W, height=_INNER_W * 0.40)
                img.hAlign = "LEFT"
                story.append(img)
                story.append(Spacer(1, 0.2 * cm))
            story.append(self._breakdown_table())
        else:
            story.append(
                Paragraph("Noch keine Score-Komponenten berechnet.", st["body_muted"])
            )

        story.append(PageBreak())
        story.append(Paragraph("4b · Trend im ausgewählten Zeitraum", st["h2"]))
        png = render_score_trend_png(d.trend, width_inch=6.5, height_inch=3.0)
        if png is not None:
            img = Image(io.BytesIO(png), width=_INNER_W, height=_INNER_W * 0.38)
            img.hAlign = "LEFT"
            story.append(img)
        else:
            story.append(
                Paragraph(
                    "Noch nicht genug Historie für einen Trend "
                    f"({len(d.trend)} Datenpunkt(e)).",
                    st["body_muted"],
                )
            )
        story.append(Spacer(1, 0.3 * cm))
        story.append(
            Paragraph(
                f"Zeitfenster: {d.time_range.label} ({d.time_range.days} Tage) — "
                f"{len(d.trend)} erfasste Messpunkte.",
                st["body_dim"],
            )
        )

    def _breakdown_table(self) -> Table:
        st = self._styles
        rows = [
            [
                Paragraph("Kategorie", st["table_header"]),
                Paragraph("Score", st["table_header"]),
                Paragraph("Gewicht", st["table_header"]),
                Paragraph("Offene Findings (H/M)", st["table_header"]),
            ]
        ]
        for comp in self._data.breakdown:
            score = float(getattr(comp, "score", 0.0))
            color = light_score_color(score)
            rows.append(
                [
                    Paragraph(str(getattr(comp, "name", "—")), st["table_cell"]),
                    Paragraph(
                        f'<font color="#{_hex(color)}">{score:.0f}</font>',
                        st["table_cell_mono"],
                    ),
                    Paragraph(
                        f"{float(getattr(comp, 'weight', 0.0)) * 100:.0f}%",
                        st["table_cell_mono"],
                    ),
                    Paragraph(
                        f"{int(getattr(comp, 'findings_high', 0))} / "
                        f"{int(getattr(comp, 'findings_medium', 0))}",
                        st["table_cell_mono"],
                    ),
                ]
            )
        table = Table(
            rows,
            colWidths=[
                _INNER_W * 0.5,
                _INNER_W * 0.13,
                _INNER_W * 0.17,
                _INNER_W * 0.20,
            ],
            repeatRows=1,
        )
        table.setStyle(_light_table_style())
        return table

    # ------------------------------------------------------------------
    # Seite 6 — Sektion 5: Organisatorische Sicherheit
    # ------------------------------------------------------------------

    def _append_organizational(self, story: list) -> None:
        st = self._styles
        d = self._data

        story.append(Paragraph("5 · Organisatorische Sicherheit", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))

        if d.org is None or not d.org.has_assessment:
            story.append(
                Paragraph(
                    "Noch kein organisatorisches Assessment erfasst. Das "
                    "Dashboard zeigt bis zur Erstbewertung einen Platzhalter; "
                    "die Module für DSGVO, Phishing, MFA und Passwort-Manager "
                    "sind vorbereitet, aber leer.",
                    st["body_dim"],
                )
            )
            story.append(Spacer(1, 0.2 * cm))

        tiles = d.org.tiles if d.org else []
        rows = [
            [
                Paragraph("Bereich", st["table_header"]),
                Paragraph("Status", st["table_header"]),
                Paragraph("Score", st["table_header"]),
                Paragraph("Offene Kriterien", st["table_header"]),
            ]
        ]
        for tile in tiles:
            if tile.score is None:
                status_text = "Nicht bewertet"
                score_text = "—"
                color = LIGHT_BORDER_STRONG
            else:
                risk = _risk_for_score(tile.score)
                status_text = risk
                score_text = f"{tile.score:.0f}"
                color = light_risk_color(risk)
            rows.append(
                [
                    Paragraph(tile.label, st["table_cell"]),
                    Paragraph(
                        f'<font color="#{_hex(color)}">&#9679; {status_text}</font>',
                        st["table_cell"],
                    ),
                    Paragraph(score_text, st["table_cell_mono"]),
                    Paragraph(f"{tile.findings_open}", st["table_cell_mono"]),
                ]
            )
        table = Table(
            rows,
            colWidths=[
                _INNER_W * 0.4,
                _INNER_W * 0.25,
                _INNER_W * 0.15,
                _INNER_W * 0.20,
            ],
            repeatRows=1,
        )
        table.setStyle(_light_table_style())
        story.append(table)

        story.append(Spacer(1, 0.4 * cm))
        story.append(
            Paragraph(
                "Die vier Bereiche werden durch das Modul "
                "„Security-Scoring → Organisatorische Sicherheit“ bewertet. "
                "Änderungen schlagen automatisch auf das Gesamt-Dashboard durch.",
                st["body_dim"],
            )
        )

    # ------------------------------------------------------------------
    # Seite 7 — Abschluss / Impressum
    # ------------------------------------------------------------------

    def _append_regulatorik(self, story: list) -> None:
        """Sektion 6 — indikativer Regulatorik-Bezug W3b).

        No-op ohne Befunde. Rendert Heading + ENTWURF-/Disclaimer-Hinweis + eine
        Tabelle (Pruefung · Schweregrad · Norm-Bezug · Prioritaet · Aufwand). Alle
        Zellen werden ge-escaped (Norm-Labels enthalten ``&``).
        """
        if not self._compliance_rows:
            return
        from core.compliance.regulatory_mapping import (  # noqa: PLC0415
            REGULATORY_DISCLAIMER,
        )
        from tools.system_scanner.application.compliance_report_service import (  # noqa: PLC0415
            compliance_rows_to_table,
        )

        st = self._styles
        story.append(Paragraph("6 · Regulatorik-Bezug (indikativ)", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                "<b>ENTWURF — anwaltliche Pruefung ausstehend.</b> "
                + escape_html(REGULATORY_DISCLAIMER),
                st["body_dim"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))

        table_data = compliance_rows_to_table(self._compliance_rows)
        header, *body = table_data
        rows = [[Paragraph(escape_html(c), st["table_header"]) for c in header]]
        for row in body:
            rows.append([Paragraph(escape_html(c), st["table_cell"]) for c in row])
        table = Table(
            rows,
            colWidths=[
                _INNER_W * 0.28,
                _INNER_W * 0.12,
                _INNER_W * 0.34,
                _INNER_W * 0.12,
                _INNER_W * 0.14,
            ],
            repeatRows=1,
        )
        table.setStyle(_light_table_style())
        story.append(table)
        story.append(PageBreak())

    def _append_imprint(self, story: list) -> None:
        st = self._styles
        story.append(Paragraph("Abschluss & Impressum", st["h1"]))
        story.append(_teal_line(_INNER_W))
        story.append(Spacer(1, 0.2 * cm))

        data_rows = [
            ["Anbieter", "FINLAI designs (financial-analytics.eu)"],
            ["Adresse", "Linz, Oberösterreich — Einzelunternehmer"],
            ["Produkt", "NoRisk by FINLAI — Cybersecurity Suite"],
            ["Report-Version", "Dashboard-Report v0.3 (Phase 3)"],
            ["Erstellt am", f"{self._generated_at:%d.%m.%Y %H:%M} Uhr"],
            ["Scope", self._target_name],
        ]
        t = Table(
            [
                [Paragraph(k, st["table_cell_dim"]), Paragraph(v, st["table_cell"])]
                for k, v in data_rows
            ],
            colWidths=[_INNER_W * 0.28, _INNER_W * 0.72],
        )
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG_CARD),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, LIGHT_BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph("Haftungsausschluss", st["h2"]))
        story.append(
            Paragraph(
                "Dieser Report wurde maschinell aus dem NoRisk-Dashboard erzeugt "
                "und dient ausschließlich als Compliance-Nachweis gegenüber "
                "externen Prüfern (Steuerberater, Wirtschaftsprüfer, DSGVO-Auditor). "
                "Alle Angaben ohne Gewähr. Der Report ersetzt keine professionelle "
                "Sicherheitsberatung. FINLAI designs übernimmt keine Haftung für "
                "Vollständigkeit oder Richtigkeit der erhobenen Daten.",
                st["disclaimer"],
            )
        )
        story.append(Spacer(1, 0.2 * cm))
        story.append(
            Paragraph(
                "Vertraulichkeit: Der Report enthält kanzleieigene Informationen "
                "und darf ohne ausdrückliche Zustimmung des Scope-Eigentümers "
                "nicht an Dritte weitergegeben werden.",
                st["disclaimer"],
            )
        )


# ---------------------------------------------------------------------------
# Canvas-Callback: Header + Footer auf jeder Seite
# ---------------------------------------------------------------------------


class _HeaderFooter:
    """Zeichnet Logo/Titel oben und Seitenzahl/Kontakt unten auf jeder Seite."""

    def __init__(self, generated_at: datetime) -> None:
        self._generated_at = generated_at

    def __call__(self, canvas: Canvas, doc) -> None:  # noqa: ANN001
        canvas.saveState()
        try:
            self._draw_header(canvas)
            self._draw_footer(canvas, doc)
        finally:
            canvas.restoreState()

    def _draw_header(self, canvas: Canvas) -> None:
        top_y = _PAGE_H - 1.6 * cm

        # Logo links (sofern vorhanden)
        if _LOGO_PATH.exists():
            try:
                canvas.drawImage(
                    str(_LOGO_PATH),
                    _MARGIN_LEFT,
                    _PAGE_H - 2.1 * cm,
                    width=3.2 * cm,
                    height=1.1 * cm,
                    preserveAspectRatio=True,
                    mask="auto",
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("Header-Logo übersprungen: %s", exc)

        # Titel + Datum rechts
        canvas.setFont(FONT_RALEWAY_BOLD, 10)
        canvas.setFillColor(LIGHT_TEXT_PRIMARY)
        right_x = _PAGE_W - _MARGIN_RIGHT
        canvas.drawRightString(
            right_x,
            top_y,
            f"NoRisk Dashboard-Report — {self._generated_at:%d.%m.%Y}",
        )

        # Teal-Divider
        canvas.setStrokeColor(LIGHT_ACCENT)
        canvas.setLineWidth(0.8)
        canvas.line(
            _MARGIN_LEFT,
            _PAGE_H - 2.4 * cm,
            _PAGE_W - _MARGIN_RIGHT,
            _PAGE_H - 2.4 * cm,
        )

    def _draw_footer(self, canvas: Canvas, doc) -> None:  # noqa: ANN001
        # Divider
        canvas.setStrokeColor(LIGHT_BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(
            _MARGIN_LEFT,
            _MARGIN_BOTTOM - 0.5 * cm,
            _PAGE_W - _MARGIN_RIGHT,
            _MARGIN_BOTTOM - 0.5 * cm,
        )

        canvas.setFont(FONT_RALEWAY, 8)
        canvas.setFillColor(LIGHT_TEXT_SECONDARY)
        y = _MARGIN_BOTTOM - 1.0 * cm

        # Links: Vertraulich-Tag
        canvas.setFillColor(LIGHT_ACCENT_DEEP)
        canvas.setFont(FONT_RALEWAY_BOLD, 8)
        canvas.drawString(_MARGIN_LEFT, y, _CONFIDENTIAL_TAG)

        # Mitte: Kontakt
        canvas.setFont(FONT_RALEWAY, 8)
        canvas.setFillColor(LIGHT_TEXT_SECONDARY)
        canvas.drawCentredString(_PAGE_W / 2, y, _CONTACT_LINE)

        # Rechts: Seite X
        canvas.drawRightString(
            _PAGE_W - _MARGIN_RIGHT,
            y,
            f"Seite {doc.page}",
        )


# ---------------------------------------------------------------------------
# Gemeinsame Hilfs-Flowables / -Funktionen
# ---------------------------------------------------------------------------


def _teal_line(width: float) -> HRFlowable:
    return HRFlowable(
        width=width,
        thickness=1.0,
        color=LIGHT_ACCENT,
        spaceAfter=4,
        spaceBefore=2,
    )


def _light_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), _c.white),
            ("FONTNAME", (0, 0), (-1, 0), FONT_RALEWAY_BOLD),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("FONTNAME", (0, 1), (-1, -1), FONT_RALEWAY),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 0), (-1, 0), 1, LIGHT_ACCENT_DEEP),
            ("LINEBELOW", (0, 1), (-1, -1), 0.25, LIGHT_BORDER),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [_c.white, LIGHT_BG_SUBTLE],
            ),
        ]
    )


def _build_summary_tiles(tiles: list[tuple[str, str, str]], styles: dict) -> Table:
    """Baut die 4-Kachel-Management-Summary (Label / Wert / Subtext).

    Cells bekommen eine Liste von Flowables (Label, Value, Subtext) — bei
    Tabellen mit Flowable-Cells übernimmt ReportLab das Vertical-Align
    und die Paddings automatisch.
    """
    cells = []
    for label, value, subtext in tiles:
        inner = [
            Paragraph(label, styles["summary_label"]),
            Spacer(1, 0.15 * cm),
            Paragraph(value, styles["summary_value"]),
            Spacer(1, 0.1 * cm),
            Paragraph(subtext, styles["body_muted"]),
        ]
        cells.append(inner)
    table = Table(
        [cells],
        colWidths=[_INNER_W / 4] * 4,
        rowHeights=[3.0 * cm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG_CARD),
                ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_BORDER),
                ("LINEAFTER", (0, 0), (-2, -1), 0.5, LIGHT_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _hex(color) -> str:  # noqa: ANN001
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except AttributeError:
        return "45b9b0"


def _truncate(text: str, length: int) -> str:
    text = (text or "").strip()
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"


def _scan_status_label(status: ScanStatus) -> str:
    return {
        ScanStatus.OK: "OK",
        ScanStatus.WARN: "Warnung",
        ScanStatus.FAIL: "Fehlgeschlagen",
        ScanStatus.MISSING: "Kein Scan",
    }[status]


def _risk_for_score(score: float) -> str:
    if score >= 75.0:
        return "Niedrig"
    if score >= 55.0:
        return "Mittel"
    if score >= 35.0:
        return "Hoch"
    return "Kritisch"


# Re-export für Tests, die LIGHT_TEXT_MUTED oder LIGHT_BG_CARD bewusst
# prüfen wollen (vermeidet lange Import-Pfade).
__all__ = [
    "DashboardPdfBuilder",
    "LIGHT_ACCENT",
    "LIGHT_TEXT_PRIMARY",
    "LIGHT_TEXT_MUTED",
    "LIGHT_BG_CARD",
]
