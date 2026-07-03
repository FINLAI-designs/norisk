"""
report_adapter — JSON- und PDF-Export für API-Security-Scan-Ergebnisse.

Implementiert IReportPort. JSON-Export ist immer verfügbar;
PDF-Export erfordert reportlab + verwendet DarkReportBuilder (FINLAI Dark Theme).

Sicherheitsdesign:
    - Ausgabepfad wird mit Path.resolve kanonisiert (kein Path-Traversal)
    - Report-Inhalte stammen ausschließlich aus dem ScanResult (keine Shell-Calls)

Schichtzugehörigkeit: data/ — darf IReportPort und Domain importieren.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from core import theme
from core.logger import get_logger
from tools.api_security.domain.interfaces import IReportPort
from tools.api_security.domain.models import (
    ScanResult,
    Severity,
)

_log = get_logger(__name__)

# Farben für Schweregrade im PDF (Severity-Deep-Palette für Reports auf hellem BG)
# Hinweis: "info" nutzt SEVERITY_SIGNAL_INFO (#888888) — ähnlich aber nicht identisch
# zum vorigen #616161; visuell vernachlässigbarer Unterschied.
_SEV_COLORS_PDF: dict[str, str] = {
    "critical": theme.SEVERITY_DEEP_CRITICAL,
    "high": theme.SEVERITY_DEEP_HIGH,
    "medium": theme.SEVERITY_DEEP_MEDIUM,
    "low": theme.SEVERITY_DEEP_LOW,
    "info": theme.SEVERITY_SIGNAL_INFO,
}


class ReportAdapter(IReportPort):
    """Exportiert ScanResult als JSON oder PDF.

    JSON ist immer verfügbar. PDF erfordert reportlab (optionale Abhängigkeit).
    PDF verwendet DarkReportBuilder — identisches Design wie alle anderen
    NoRisk-Reports.
    """

    # ------------------------------------------------------------------
    # JSON-Export
    # ------------------------------------------------------------------

    def export_json(self, result: ScanResult, path: Path) -> Path:
        """Exportiert ScanResult als formatiertes JSON.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad.

        Returns:
            Absoluter Pfad der Datei.
        """
        out = path.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "scan_time": result.scan_time,
            "duration_ms": result.duration_ms,
            "target": {
                "url": result.target.url,
                "api_type": result.target.api_type,
                "auth_type": result.target.auth_type,
            },
            "risk_score": result.risk_score(),
            "summary": {
                "total": len(result.findings),
                "critical": result.critical_count(),
                "high": result.high_count(),
                "medium": sum(
                    1 for f in result.findings if f.severity == Severity.MEDIUM
                ),
                "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in result.findings if f.severity == Severity.INFO),
            },
            "findings": [
                {
                    "code": f.code,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "owasp": f.owasp.value,
                    "owasp_description": f.owasp.description(),
                    "detail": f.detail,
                    "remediation": f.remediation,
                }
                for f in result.findings_by_severity()
            ],
            "error": result.error,
        }

        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        _log.info("JSON-Report gespeichert: %s", out)
        return out

    # ------------------------------------------------------------------
    # PDF-Export — DarkReportBuilder
    # ------------------------------------------------------------------

    def export_pdf(self, result: ScanResult, path: Path) -> Path:
        """Exportiert ScanResult als A4-PDF im FINLAI Dark Theme.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad.

        Returns:
            Absoluter Pfad der Datei.

        Raises:
            ImportError: Wenn reportlab nicht installiert ist.
        """
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
        )
        from core.pdf.pdf_fonts import FONT_RALEWAY, FONT_RALEWAY_BOLD  # noqa: PLC0415
        from core.pdf.pdf_report_builder import DarkReportBuilder  # noqa: PLC0415

        out = path.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        export_dt = datetime.now(UTC).strftime("%d.%m.%Y %H:%M UTC")
        score = result.risk_score()

        builder = DarkReportBuilder(
            output_path=str(out),
            title="API-Security Report",
            subtitle=f"NoRisk by FINLAI  ·  {export_dt}",
        )
        builder.add_cover(date_str=export_dt)

        st = builder._styles  # noqa: SLF001
        story = builder._story  # noqa: SLF001

        # --- Scan-Übersicht ---
        story.append(Paragraph("Scan-Übersicht", st["h2"]))
        story.append(
            Paragraph(
                f"Ziel: {result.target.url}  |  "
                f"API-Typ: {result.target.api_type}  |  "
                f"Scan: {result.scan_time}",
                st["body"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))

        # --- Risikoscore ---
        score_color = (
            theme.SEVERITY_DEEP_CRITICAL
            if score >= 50
            else theme.SEVERITY_DEEP_HIGH
            if score >= 25
            else theme.SEVERITY_DEEP_LOW
        )
        story.append(
            Paragraph(
                f'Risikoscore: <font color="{score_color}"><b>{score}/100</b></font>',
                st["h2"],
            )
        )
        story.append(Spacer(1, 0.4 * cm))

        # --- Zusammenfassungs-Tabelle ---
        story.append(Paragraph("Zusammenfassung", st["h2"]))
        summary_data = [
            [
                Paragraph("Schweregrad", st["table_header"]),
                Paragraph("Anzahl", st["table_header"]),
            ],
            [
                Paragraph("Kritisch", st["table_cell"]),
                Paragraph(str(result.critical_count()), st["table_cell"]),
            ],
            [
                Paragraph("Hoch", st["table_cell"]),
                Paragraph(str(result.high_count()), st["table_cell"]),
            ],
            [
                Paragraph("Mittel", st["table_cell"]),
                Paragraph(
                    str(
                        sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
                    ),
                    st["table_cell"],
                ),
            ],
            [
                Paragraph("Niedrig", st["table_cell"]),
                Paragraph(
                    str(sum(1 for f in result.findings if f.severity == Severity.LOW)),
                    st["table_cell"],
                ),
            ],
            [
                Paragraph("Info", st["table_cell"]),
                Paragraph(
                    str(sum(1 for f in result.findings if f.severity == Severity.INFO)),
                    st["table_cell"],
                ),
            ],
        ]
        summary_tbl = Table(summary_data, colWidths=[6 * cm, 3 * cm])
        summary_tbl.setStyle(
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
                        (-1, len(summary_data) - 1),
                        [PDF_TABLE_ROW_ODD, PDF_TABLE_ROW_EVEN],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.3, PDF_BG_PAGE),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 1), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                    ("TEXTCOLOR", (0, 1), (-1, -1), PDF_TEXT_PRIMARY),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ]
            )
        )
        story.append(summary_tbl)
        story.append(Spacer(1, 0.5 * cm))

        # --- Befunde-Tabelle ---
        story.append(Paragraph("Befunde nach Schweregrad", st["h2"]))

        col_widths = [2.5 * cm, 4 * cm, 2.5 * cm, 3.5 * cm, 5 * cm]
        header_row = ["Code", "Titel", "Schweregrad", "OWASP", "Maßnahme"]
        table_data: list = [[Paragraph(h, st["table_header"]) for h in header_row]]

        for finding in result.findings_by_severity():
            sev_color = _SEV_COLORS_PDF.get(
                finding.severity.value, theme.SEVERITY_SIGNAL_INFO
            )
            remediation_short = (
                finding.remediation[:120] + "…"
                if finding.remediation and len(finding.remediation) > 120
                else finding.remediation or "—"
            )
            table_data.append(
                [
                    Paragraph(finding.code, st["table_cell"]),
                    Paragraph(finding.title, st["table_cell"]),
                    Paragraph(
                        f'<font color="{sev_color}">{finding.severity.label()}</font>',
                        st["table_cell"],
                    ),
                    Paragraph(
                        f"{finding.owasp.value}",
                        st["table_cell"],
                    ),
                    Paragraph(remediation_short, st["table_cell"]),
                ]
            )

        if len(table_data) > 1:
            row_count = len(table_data)
            tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(
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
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 1), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                        ("TEXTCOLOR", (0, 1), (-1, -1), PDF_TEXT_PRIMARY),
                    ]
                )
            )
            story.append(tbl)
        else:
            story.append(
                Paragraph(
                    f'<font color="{theme.SEVERITY_SIGNAL_OK}">'
                    f"Keine Befunde — API scheint korrekt konfiguriert.</font>",
                    st["body"],
                )
            )

        builder.add_footer_page()
        builder.build()
        _log.info("PDF-Report gespeichert: %s", out)
        return out
