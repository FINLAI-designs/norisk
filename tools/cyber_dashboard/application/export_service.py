"""
export_service — Cyberrisiko-Wochenbericht als PDF.

Erstellt einen professionellen A4-PDF-Bericht mit KI-Briefing,
kritischen CVEs und Top-Meldungen. Enthält Human-in-Loop Hinweis.
Verwendet DarkReportBuilder für konsistentes FINLAI Dark Theme Design.

Schichtzugehörigkeit: application/ — kein GUI-Import.

Author: Patrick Riederich
Version: 2.0 (Dark Theme Redesign)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from core.logger import get_logger
from tools.cyber_dashboard.domain.models import CveEintrag, CyberMeldung, Schweregrad

log = get_logger(__name__)

_RISIKO_DE: dict[str, str] = {
    "KRITISCH": "Kritisch",
    "HOCH": "Hoch",
    "MITTEL": "Mittel",
    "NIEDRIG": "Niedrig",
    "CRITICAL": "Kritisch",
    "HIGH": "Hoch",
    "MEDIUM": "Mittel",
    "LOW": "Niedrig",
}


class ExportService:
    """Erstellt PDF-Wochenberichte für das Cyberrisiko-Dashboard.

    Verwendet DarkReportBuilder für konsistentes FINLAI Dark Theme Design.
    """

    def erstelle_wochenbericht(
        self,
        meldungen: list[CyberMeldung],
        cves: list[CveEintrag],
        briefing: dict | None,
        ausgabe_pfad: Path,
    ) -> bool:
        """Erstellt einen PDF-Wochenbericht im FINLAI Dark Theme.

        Args:
            meldungen: Liste aktueller CyberMeldungen.
            cves: Liste aktueller CveEinträge.
            briefing: KI-Briefing Dict oder None.
            ausgabe_pfad: Zielpfad für die PDF-Datei.

        Returns:
            True wenn PDF erfolgreich erstellt wurde.
        """
        try:
            from reportlab.lib.units import cm  # noqa: PLC0415
            from reportlab.platypus import (  # noqa: PLC0415
                Paragraph,
                Spacer,
                Table,
                TableStyle,
            )

            from core.pdf.pdf_colors import (  # noqa: PLC0415
                PDF_BG_PAGE,
                PDF_TABLE_HEADER_BG,
                PDF_TABLE_HEADER_TEXT,
                PDF_TABLE_ROW_EVEN,
                PDF_TABLE_ROW_ODD,
                PDF_TEXT_PRIMARY,
                risk_color,
            )
            from core.pdf.pdf_fonts import (  # noqa: PLC0415
                FONT_RALEWAY,
                FONT_RALEWAY_BOLD,
            )
            from core.pdf.pdf_report_builder import DarkReportBuilder  # noqa: PLC0415

            kw = datetime.now().isocalendar()[1]
            von = (datetime.now() - timedelta(days=7)).strftime("%d.%m.%Y")
            bis = datetime.now().strftime("%d.%m.%Y")
            jetzt_str = datetime.now().strftime("%d.%m.%Y %H:%M UTC")

            builder = DarkReportBuilder(
                output_path=str(ausgabe_pfad),
                title="Cyberrisiko-Wochenbericht",
                subtitle=f"NoRisk by FINLAI  ·  KW {kw}  ·  {von} – {bis}",
            )
            builder.add_cover(date_str=jetzt_str)

            st = builder._styles  # noqa: SLF001
            story = builder._story  # noqa: SLF001

            # KEIN zusaetzlicher PageBreak hier.
            # ``add_cover`` haengt am Ende selbst einen PageBreak an
            # (pdf_report_builder.py:248). Doppelter PageBreak erzeugt
            # eine leere Seite zwischen Cover und Inhalt — Patrick im
            # Smoke gemeldet.

            # ── KI-Briefing ───────────────────────────────────────────
            if briefing:
                story.append(Paragraph("KI-Briefing", st["h2"]))

                risiko_raw = briefing.get("gesamtrisiko", "")
                risiko_de = _RISIKO_DE.get(risiko_raw.upper(), risiko_raw)
                if risiko_de:
                    sev_color = risk_color(risiko_de)
                    r = int(sev_color.red * 255)
                    g = int(sev_color.green * 255)
                    b = int(sev_color.blue * 255)
                    hex_c = f"#{r:02x}{g:02x}{b:02x}"
                    story.append(
                        Paragraph(
                            f'Gesamtrisiko: <font color="{hex_c}"><b>{risiko_de}</b></font>',
                            st["body"],
                        )
                    )
                    story.append(Spacer(1, 0.2 * cm))

                zusammenfassung = briefing.get("zusammenfassung", "")
                if zusammenfassung:
                    story.append(Paragraph(zusammenfassung, st["body_dim"]))
                    story.append(Spacer(1, 0.2 * cm))

                empfehlungen = briefing.get("empfehlungen", [])
                if empfehlungen:
                    story.append(Paragraph("Empfehlungen:", st["h3"]))
                    for emp in empfehlungen:
                        story.append(Paragraph(f"  \u2022  {emp}", st["body_dim"]))

                story.append(Spacer(1, 0.5 * cm))

            # ── Kritische CVEs ────────────────────────────────────────
            kritische_cves = [c for c in cves if c.schweregrad in ("CRITICAL", "HIGH")][
                :15
            ]

            if kritische_cves:
                story.append(Paragraph("Kritische CVEs", st["h2"]))

                col_widths = [3.0 * cm, 1.5 * cm, 2.5 * cm, 1.0 * cm, 9.5 * cm]
                header_row = [
                    Paragraph(h, st["table_header"])
                    for h in ["CVE-ID", "CVSS", "Schweregrad", "KEV", "Beschreibung"]
                ]
                table_data: list = [header_row]

                for c in kritische_cves:
                    sev_de = _RISIKO_DE.get(c.schweregrad, c.schweregrad)
                    sev_c = risk_color(sev_de)
                    r = int(sev_c.red * 255)
                    g_val = int(sev_c.green * 255)
                    b = int(sev_c.blue * 255)
                    hex_sev = f"#{r:02x}{g_val:02x}{b:02x}"
                    kev_text = "KEV" if c.cisa_kev else ""
                    desc = (
                        c.beschreibung[:120] + "…"
                        if len(c.beschreibung) > 120
                        else c.beschreibung
                    )
                    table_data.append(
                        [
                            Paragraph(c.cve_id, st["table_cell"]),
                            Paragraph(str(c.cvss_score), st["table_cell_center"]),
                            Paragraph(
                                f'<font color="{hex_sev}">{sev_de}</font>',
                                st["table_cell"],
                            ),
                            Paragraph(kev_text, st["table_cell_center"]),
                            Paragraph(desc, st["table_cell"]),
                        ]
                    )

                row_count = len(table_data)
                cve_tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
                cve_tbl.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), PDF_TABLE_HEADER_BG),
                            ("TEXTCOLOR", (0, 0), (-1, 0), PDF_TABLE_HEADER_TEXT),
                            ("FONTNAME", (0, 0), (-1, 0), FONT_RALEWAY_BOLD),
                            ("FONTSIZE", (0, 0), (-1, 0), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                            ("TOPPADDING", (0, 0), (-1, 0), 8),
                            ("FONTNAME", (0, 1), (-1, -1), FONT_RALEWAY),
                            ("FONTSIZE", (0, 1), (-1, -1), 9),
                            (
                                "ROWBACKGROUNDS",
                                (0, 1),
                                (-1, row_count - 1),
                                [PDF_TABLE_ROW_ODD, PDF_TABLE_ROW_EVEN],
                            ),
                            ("GRID", (0, 0), (-1, -1), 0.3, PDF_BG_PAGE),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 1), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                            ("TEXTCOLOR", (0, 1), (-1, -1), PDF_TEXT_PRIMARY),
                        ]
                    )
                )
                story.append(cve_tbl)
                story.append(Spacer(1, 0.5 * cm))

            # ── Top Meldungen ─────────────────────────────────────────
            top_meldungen = [
                m
                for m in meldungen
                if m.schweregrad in (Schweregrad.KRITISCH, Schweregrad.HOCH)
            ][:10]

            if top_meldungen:
                story.append(Paragraph("Wichtigste Meldungen", st["h2"]))

                m_col_widths = [1.5 * cm, 3.0 * cm, 2.5 * cm, 10.5 * cm]
                m_header = [
                    Paragraph(h, st["table_header"])
                    for h in ["Datum", "Quelle", "Schweregrad", "Meldung"]
                ]
                m_data: list = [m_header]

                for m in top_meldungen:
                    sev_de = _RISIKO_DE.get(
                        m.schweregrad.value.upper(), m.schweregrad.value
                    )
                    sev_c = risk_color(sev_de)
                    r = int(sev_c.red * 255)
                    g_val = int(sev_c.green * 255)
                    b = int(sev_c.blue * 255)
                    hex_sev = f"#{r:02x}{g_val:02x}{b:02x}"
                    m_data.append(
                        [
                            Paragraph(
                                m.veroeffentlicht.strftime("%d.%m."), st["table_cell"]
                            ),
                            Paragraph(m.quelle.value, st["table_cell"]),
                            Paragraph(
                                f'<font color="{hex_sev}">{sev_de}</font>',
                                st["table_cell"],
                            ),
                            Paragraph(m.titel, st["table_cell"]),
                        ]
                    )

                m_row_count = len(m_data)
                m_tbl = Table(m_data, colWidths=m_col_widths, repeatRows=1)
                m_tbl.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), PDF_TABLE_HEADER_BG),
                            ("TEXTCOLOR", (0, 0), (-1, 0), PDF_TABLE_HEADER_TEXT),
                            ("FONTNAME", (0, 0), (-1, 0), FONT_RALEWAY_BOLD),
                            ("FONTSIZE", (0, 0), (-1, 0), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                            ("TOPPADDING", (0, 0), (-1, 0), 8),
                            ("FONTNAME", (0, 1), (-1, -1), FONT_RALEWAY),
                            ("FONTSIZE", (0, 1), (-1, -1), 9),
                            (
                                "ROWBACKGROUNDS",
                                (0, 1),
                                (-1, m_row_count - 1),
                                [PDF_TABLE_ROW_ODD, PDF_TABLE_ROW_EVEN],
                            ),
                            ("GRID", (0, 0), (-1, -1), 0.3, PDF_BG_PAGE),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 1), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                            ("TEXTCOLOR", (0, 1), (-1, -1), PDF_TEXT_PRIMARY),
                        ]
                    )
                )
                story.append(m_tbl)
                story.append(Spacer(1, 0.5 * cm))

            # ── Disclaimer ────────────────────────────────────────────
            story.append(
                Paragraph(
                    "Dieser Report wurde automatisch erstellt und enthält KI-generierte "
                    "Inhalte. Er dient ausschliesslich internen Informationszwecken und "
                    "ersetzt keine professionelle Sicherheitsberatung. "
                    "Alle Angaben ohne Gewaehr.",
                    st["disclaimer"],
                )
            )

            builder.build()
            log.info("PDF-Wochenbericht erstellt: %s", ausgabe_pfad.name)
            return True  # noqa: TRY300

        except (OSError, RuntimeError, ValueError, ImportError, AttributeError) as exc:
            log.error("PDF-Export fehlgeschlagen: %s", type(exc).__name__)
            return False
