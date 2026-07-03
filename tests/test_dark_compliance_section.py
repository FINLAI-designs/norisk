"""Build-Smoke fuer DarkReportBuilder.add_compliance_section W3).

Baut echte (kleine) PDFs in tmp_path und prueft, dass die neue Regulatorik-
Sektion gerendert wird — insbesondere, dass ``&`` in Disclaimer/Zellen escaped
wird (Norm-Labels enthalten ``&``), sonst crasht ReportLab.
"""

from __future__ import annotations

from core.pdf.pdf_report_builder import DarkReportBuilder

_HEADER = ["Pruefung", "Schweregrad", "Norm-Bezug (indikativ)", "Prioritaet", "Aufwand"]


def test_add_compliance_section_baut_pdf(tmp_path) -> None:
    out = tmp_path / "report.pdf"
    builder = DarkReportBuilder(
        output_path=str(out),
        title="Test-Report",
        subtitle="NoRisk by FINLAI",
        company="ACME GmbH",
    )
    builder.add_cover(date_str="19.06.2026", report_id="ABCD1234")
    builder.add_compliance_section(
        "Regulatorik-Bezug (indikativ) — ENTWURF",
        "Anwaltliche Pruefung ausstehend. Indikativ & keine Rechtsberatung.",
        [
            _HEADER,
            [
                "Windows Firewall aktiv (SH-001)",
                "Kritisch",
                "Bezug zu NIS2 Art. 21 – Risikoanalyse & Sicherheitskonzepte (indikativ)",
                "95/100",
                "fixbar mit 1 Person in unter 1 Tag",
            ],
        ],
    )
    builder.add_footer_page()
    result = builder.build()
    assert result.exists()
    assert out.stat().st_size > 0


def test_add_compliance_section_nur_header_kein_crash(tmp_path) -> None:
    out = tmp_path / "empty.pdf"
    builder = DarkReportBuilder(
        output_path=str(out),
        title="Test",
        subtitle="NoRisk",
        company="ACME GmbH",
    )
    builder.add_cover(date_str="19.06.2026", report_id="X")
    builder.add_compliance_section("Regulatorik", "Disclaimer", [_HEADER])  # nur Header
    builder.add_footer_page()
    builder.build()
    assert out.stat().st_size > 0
