""" Phase D: Risikomatrix-Bild + add_image im Kunden-PDF."""

from __future__ import annotations

import pytest

from tools.customer_audit.domain.risk_entities import RiskImpact, RiskProbability


class _A:
    def __init__(self, p: int, s: int) -> None:
        self.probability = RiskProbability(p)
        self.impact = RiskImpact(s)


def test_builder_add_image_erzeugt_pdf(tmp_path) -> None:  # noqa: ANN001
    pytest.importorskip("matplotlib")
    pytest.importorskip("reportlab")
    from core.pdf.pdf_report_builder import DarkReportBuilder
    from tools.customer_audit.application.risk_matrix_export import (
        render_risk_matrix_png,
    )

    png = render_risk_matrix_png([_A(4, 4), _A(1, 1), _A(2, 3)])
    assert png is not None
    out = tmp_path / "matrix.pdf"
    b = DarkReportBuilder(output_path=out, title="T", subtitle="S", company="C")
    b.add_cover(date_str="01.01.2026", report_id="ABC")
    b.add_image(png, caption="BSI-Risikomatrix")
    b.add_footer_page()
    path = b.build()
    assert path.exists()
    assert path.stat().st_size > 1000


def test_add_image_fail_soft_bei_kaputtem_png(tmp_path) -> None:  # noqa: ANN001
    pytest.importorskip("reportlab")
    from core.pdf.pdf_report_builder import DarkReportBuilder

    out = tmp_path / "broken.pdf"
    b = DarkReportBuilder(output_path=out, title="T", subtitle="S", company="C")
    b.add_cover(date_str="01.01.2026", report_id="ABC")
    b.add_image(b"not-a-png", caption="kaputt")  # darf NICHT crashen
    b.add_footer_page()
    assert b.build().exists()
