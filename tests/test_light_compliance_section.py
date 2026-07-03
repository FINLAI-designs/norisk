"""Build-Smoke fuer die Regulatorik-Sektion im Light-Compliance-Report W3b).

Baut echte (kleine) PDFs in tmp_path und prueft, dass die optionale Regulatorik-
Sektion rendert (mit ``&`` in Norm-Labels + Scope-Name -> Escape) bzw. ohne Rows
sauber uebersprungen wird. Wiederverwendet das DashboardData-Fixture.
"""

from __future__ import annotations

from core.rules.rule_engine import RuleEngine
from core.security.severity import Severity
from tests.test_pdf_builder import _rich_dashboard_data
from tools.norisk_dashboard.application.dashboard_pdf_builder import DashboardPdfBuilder
from tools.system_scanner.application.compliance_report_service import (
    build_hardening_compliance_rows,
)
from tools.system_scanner.domain.entities import HardeningCheck


def _rows() -> list:
    return build_hardening_compliance_rows(
        [
            HardeningCheck(
                "SH-001", "Windows Firewall aktiv", False, Severity.CRITICAL, "aus"
            ),
            HardeningCheck(
                "SH-010", "BitLocker aktiv auf C:", False, Severity.MEDIUM, "aus"
            ),
        ],
        RuleEngine([]),
    )


def test_light_report_mit_regulatorik_sektion(tmp_path) -> None:
    out = tmp_path / "compliance.pdf"
    DashboardPdfBuilder(
        out,
        _rich_dashboard_data(),
        target_name="Müller & Co.",  # '&' im Scope -> Escape-Pfad
        compliance_rows=_rows(),
    ).build()
    assert out.exists()
    assert out.stat().st_size > 0


def test_light_report_ohne_rows_kein_crash(tmp_path) -> None:
    out = tmp_path / "plain.pdf"
    DashboardPdfBuilder(out, _rich_dashboard_data(), target_name="ACME GmbH").build()
    assert out.exists()
    assert out.stat().st_size > 0
