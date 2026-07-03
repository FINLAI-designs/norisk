"""
test_pdf_report — Unit-Tests für den FINLAI Dark Theme PDF-Report-Generator.

Testet:
  - PDF-Erzeugung ohne Crash (security_scoring + customer_assessment)
  - Seitenanzahl
  - Minimaler Datensatz (nur Pflichtfelder)
  - Maximaler Datensatz (alle Felder)
  - Font-Registrierung
  - Use Case: GenerateReportUseCase
  - core/pdf-Komponenten

Hinweis: PDF-Tests arbeiten auf tmp_path — keine festen Pfade.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Hilfs-Fixtures
# ---------------------------------------------------------------------------


def _make_security_score(
    target_name: str = "TestFirma GmbH",
    overall_score: float = 72.5,
    grade: str = "C",
    num_components: int = 3,
):
    """Erstellt einen minimalen SecurityScore für Tests."""
    from tools.security_scoring.domain.models import ScoreComponent, SecurityScore

    components = [
        ScoreComponent(
            name=f"Kategorie {i + 1}",
            score=60.0 + i * 10,
            weight=round(1.0 / num_components, 2),
            findings_critical=i % 2,
            findings_high=i,
            findings_medium=i * 2,
            last_scan="2026-04-06T10:00:00+00:00",
            source_tool=f"tool_{i}",
        )
        for i in range(num_components)
    ]
    return SecurityScore(
        id=str(uuid.uuid4()),
        target_name=target_name,
        timestamp="2026-04-06T10:00:00+00:00",
        overall_score=overall_score,
        grade=grade,
        components=components,
        summary="Test-Zusammenfassung",
    )


def _make_customer_result(firma: str = "Musterfirma GmbH"):
    """Erstellt ein minimales CustomerAuditResult für Tests."""
    from tools.customer_audit.domain.entities import (
        CategoryScore,
        CustomerAuditResult,
        CustomerData,
        InfrastructureData,
        NetworkData,
        OrganizationalData,
    )

    return CustomerAuditResult(
        audit_id=str(uuid.uuid4()),
        customer_data=CustomerData(
            firmenname=firma,
            ansprechpartner_name="Max Mustermann",
            ansprechpartner_email="max@musterfirma.at",
            branche="IT",
            unternehmensgroesse="11-50",
            erstellungsdatum="2026-04-06",
        ),
        infrastructure_data=InfrastructureData(
            antivirus_name="Windows Defender",
            antivirus_status="aktiv",
            firewall_name="Windows Firewall",
            firewall_status="aktiv",
            verschluesselung=["BitLocker"],
            remote_access_tools=["RDP"],
        ),
        organizational_data=OrganizationalData(
            zugangskontrollen="Ja",
            backup_strategie="Ja",
            update_management="Teilweise",
            mitarbeitersensibilisierung="Nein",
            incident_response_plan="Nein",
            dsgvo_konformitaet="Ja",
        ),
        network_data=NetworkData(
            netzwerksegmentierung="Nein",
            wlan_sicherheit="WPA2",
            offene_ports_bekannt="Ja",
            ids_ips_vorhanden="Nein",
            letzter_pentest="2024",
        ),
        category_scores=[
            CategoryScore(name="IT-Infrastruktur", score=85.0, label="Niedrig"),
            CategoryScore(
                name="Organisatorische Sicherheit", score=50.0, label="Mittel"
            ),
            CategoryScore(name="Netzwerksicherheit", score=55.0, label="Mittel"),
        ],
        overall_score=63.5,
        risk_level="Mittel",
        recommendations=[
            "[Mittel] Organisatorische Sicherheit: Mitarbeitersensibilisierung — Schulungen fehlen.",
            "[Hoch] Organisatorische Sicherheit: Incident-Response-Plan erstellen — Prozess fehlt.",
        ],
        created_at="2026-04-06T10:00:00+00:00",
    )


# ---------------------------------------------------------------------------
# Tests: Font-Registrierung
# ---------------------------------------------------------------------------


class TestFontRegistration:
    def test_register_fonts_does_not_raise(self):
        from core.pdf.pdf_fonts import register_fonts

        register_fonts()  # Kein Fehler

    def test_register_fonts_idempotent(self):
        from core.pdf.pdf_fonts import register_fonts

        register_fonts()
        register_fonts()  # Zweimal aufrufen — kein Fehler

    def test_font_names_are_strings(self):
        from core.pdf.pdf_fonts import (
            FONT_MONO,
            FONT_MONO_BOLD,
            FONT_RALEWAY,
            FONT_RALEWAY_BOLD,
            FONT_RALEWAY_LIGHT,
        )

        for name in [
            FONT_RALEWAY,
            FONT_RALEWAY_BOLD,
            FONT_RALEWAY_LIGHT,
            FONT_MONO,
            FONT_MONO_BOLD,
        ]:
            assert isinstance(name, str)
            assert len(name) > 0


# ---------------------------------------------------------------------------
# Tests: PDF-Farben
# ---------------------------------------------------------------------------


class TestPdfColors:
    def test_colors_are_reportlab_colors(self):
        from reportlab.lib.colors import Color

        from core.pdf.pdf_colors import (
            PDF_ACCENT,
            PDF_BG_CARD,
            PDF_BG_PAGE,
            PDF_DANGER,
            PDF_SUCCESS,
            PDF_TEXT_PRIMARY,
            PDF_WARNING,
            PDF_WHITE,
        )

        for color in [
            PDF_BG_PAGE,
            PDF_BG_CARD,
            PDF_TEXT_PRIMARY,
            PDF_ACCENT,
            PDF_SUCCESS,
            PDF_WARNING,
            PDF_DANGER,
            PDF_WHITE,
        ]:
            assert isinstance(color, Color)

    def test_risk_color_returns_color(self):
        from reportlab.lib.colors import Color

        from core.pdf.pdf_colors import risk_color

        for level in ["Niedrig", "Mittel", "Hoch", "Kritisch", "Unbekannt"]:
            assert isinstance(risk_color(level), Color)

    def test_score_color_thresholds(self):
        from core.pdf.pdf_colors import (
            PDF_DANGER,
            PDF_SUCCESS,
            PDF_WARNING,
            score_color,
        )

        assert score_color(80.0) == PDF_SUCCESS
        assert score_color(60.0) == PDF_WARNING
        assert score_color(20.0) == PDF_DANGER


# ---------------------------------------------------------------------------
# Tests: PDF-Styles
# ---------------------------------------------------------------------------


class TestPdfStyles:
    def test_build_styles_returns_dict(self):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_styles import build_styles

        register_fonts()
        styles = build_styles()
        assert isinstance(styles, dict)
        assert len(styles) > 0

    def test_required_keys_present(self):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_styles import build_styles

        register_fonts()
        styles = build_styles()
        required = [
            "cover_title",
            "cover_subtitle",
            "h1",
            "h2",
            "body",
            "table_header",
            "table_cell",
            "rec_critical",
            "rec_high",
            "rec_medium",
            "rec_low",
            "footer",
            "disclaimer",
        ]
        for key in required:
            assert key in styles, f"Style '{key}' fehlt"


# ---------------------------------------------------------------------------
# Tests: PDF-Komponenten
# ---------------------------------------------------------------------------


class TestPdfComponents:
    def test_score_gauge_returns_drawing(self):
        from reportlab.graphics.shapes import Drawing

        from core.pdf.pdf_components import score_gauge_drawing
        from core.pdf.pdf_fonts import register_fonts

        register_fonts()
        d = score_gauge_drawing(75.0, "Niedrig")
        assert isinstance(d, Drawing)

    def test_category_bar_returns_drawing(self):
        from reportlab.graphics.shapes import Drawing

        from core.pdf.pdf_components import category_bar_drawing

        d = category_bar_drawing(50.0)
        assert isinstance(d, Drawing)

    def test_status_dot_returns_drawing(self):
        from reportlab.graphics.shapes import Drawing

        from core.pdf.pdf_components import status_dot_drawing

        for status in ["aktiv", "inaktiv", "ok", "Hoch", "Ja", "Nein", "unbekannt"]:
            d = status_dot_drawing(status)
            assert isinstance(d, Drawing)

    def test_mini_score_box_returns_drawing(self):
        from reportlab.graphics.shapes import Drawing

        from core.pdf.pdf_components import mini_score_box_drawing

        d = mini_score_box_drawing(65.0, "Mittel")
        assert isinstance(d, Drawing)


# ---------------------------------------------------------------------------
# Tests: DarkReportBuilder
# ---------------------------------------------------------------------------


class TestDarkReportBuilder:
    def test_build_raises_without_pages(self, tmp_path: Path):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_report_builder import DarkReportBuilder

        register_fonts()
        builder = DarkReportBuilder(tmp_path / "empty.pdf")
        with pytest.raises(RuntimeError):
            builder.build()

    def test_build_creates_pdf(self, tmp_path: Path):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_report_builder import DarkReportBuilder

        register_fonts()
        output = tmp_path / "test.pdf"
        builder = DarkReportBuilder(output, title="Test Report", company="TestCo")
        builder.add_cover(date_str="06.04.2026", report_id="TEST-001")
        builder.add_footer_page()
        result_path = builder.build()
        assert result_path.exists()
        assert result_path.stat().st_size > 1000

    def test_full_report_build(self, tmp_path: Path):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_report_builder import DarkReportBuilder

        register_fonts()
        output = tmp_path / "full.pdf"
        builder = DarkReportBuilder(
            output, title="Full Report", company="Vollständige GmbH"
        )
        builder.add_cover(date_str="06.04.2026", report_id="FULL-001")
        builder.add_executive_summary(
            overall_score=68.0,
            risk_level="Mittel",
            category_scores=[
                {"name": "IT-Infrastruktur", "score": 80.0, "label": "Niedrig"},
                {"name": "Org. Sicherheit", "score": 55.0, "label": "Mittel"},
                {"name": "Netzwerk", "score": 45.0, "label": "Hoch"},
            ],
            summary_text="Zusammenfassung des Assessments.",
        )
        builder.add_category_details(
            category_name="IT-Infrastruktur",
            category_score=80.0,
            category_risk="Niedrig",
            rows=[
                {"label": "Antivirus", "value": "Windows Defender", "status": "aktiv"},
                {"label": "Firewall", "value": "aktiviert", "status": "aktiv"},
            ],
        )
        builder.add_recommendations(
            [
                "[Hoch] IT-Infrastruktur: Verschlüsselung aktivieren — BitLocker fehlt.",
                "[Mittel] Org. Sicherheit: Schulungen — Security Awareness fehlt.",
            ]
        )
        builder.add_footer_page()
        path = builder.build()
        assert path.exists()
        assert path.stat().st_size > 1000

    def test_pdf_is_valid_pdf_header(self, tmp_path: Path):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_report_builder import DarkReportBuilder

        register_fonts()
        output = tmp_path / "header_test.pdf"
        builder = DarkReportBuilder(output)
        builder.add_cover(date_str="06.04.2026")
        builder.add_footer_page()
        builder.build()
        # PDFs beginnen mit %PDF-
        content = output.read_bytes()
        assert content[:5] == b"%PDF-"

    def test_empty_recommendations_handled(self, tmp_path: Path):
        from core.pdf.pdf_fonts import register_fonts
        from core.pdf.pdf_report_builder import DarkReportBuilder

        register_fonts()
        output = tmp_path / "no_recs.pdf"
        builder = DarkReportBuilder(output)
        builder.add_cover()
        builder.add_recommendations([])
        builder.add_footer_page()
        path = builder.build()
        assert path.exists()


# ---------------------------------------------------------------------------
# Tests: SecurityReportGenerator
# ---------------------------------------------------------------------------


class TestSecurityReportGenerator:
    def test_generate_creates_pdf(self, tmp_path: Path):
        from tools.security_scoring.data.report_generator import SecurityReportGenerator

        score = _make_security_score()
        gen = SecurityReportGenerator()
        output = str(tmp_path / "security_report.pdf")
        gen.generate(score, output)
        assert Path(output).exists()
        assert Path(output).stat().st_size > 1000

    def test_generate_uses_hardening_score_in_executive_summary(
        self, tmp_path: Path
    ):
        # mit hardening= zeigt die Executive-Summary den
        # Hardening-Score (85) + Stage statt des Legacy-Scores (69).
        from unittest.mock import patch

        import tools.security_scoring.data.report_generator as rg
        from tools.security_scoring.domain.hardening_score import (
            compute_hardening_score,
        )
        from tools.security_scoring.domain.models import ScoreComponent

        score = _make_security_score(overall_score=69.0, grade="C")
        comps = [
            ScoreComponent(name="X", score=85.0, weight=0.5, source_tool=tool)
            for tool in (
                "cve_exposure",
                "network_scanner",
                "password_policy",
                "api_security",
                "system_scanner",
            )
        ]
        hardening = compute_hardening_score(comps)  # overall 85.0, Secure

        with patch.object(rg, "DarkReportBuilder") as builder_cls:
            builder = builder_cls.return_value
            rg.SecurityReportGenerator().generate(
                score, str(tmp_path / "h.pdf"), hardening=hardening
            )

        builder.add_executive_summary.assert_called_once()
        kwargs = builder.add_executive_summary.call_args.kwargs
        assert kwargs["overall_score"] == 85.0
        # Risiko-Label = deutsche Stufe (fuer Gauge-Farbe), nicht der
        # englische Stage — der steht im Summary-Text.
        from tools.security_scoring.data.report_generator import _score_to_risk

        assert kwargs["risk_level"] == _score_to_risk(85.0)  # "Niedrig"
        assert hardening.stage.label in kwargs["summary_text"]  # "Secure"
        # Schulnote A–F bleibt als Sekundaer-Angabe §8).
        assert "C" in kwargs["summary_text"]
        # Legacy-69 taucht in der Summary nicht mehr auf.
        assert "69" not in kwargs["summary_text"]

    def test_generate_without_hardening_uses_legacy(self, tmp_path: Path):
        # Default ``hardening=None`` → Legacy-Score (Backwards-Compat).
        from unittest.mock import patch

        import tools.security_scoring.data.report_generator as rg

        score = _make_security_score(overall_score=69.0, grade="C")
        with patch.object(rg, "DarkReportBuilder") as builder_cls:
            builder = builder_cls.return_value
            rg.SecurityReportGenerator().generate(score, str(tmp_path / "l.pdf"))

        kwargs = builder.add_executive_summary.call_args.kwargs
        assert kwargs["overall_score"] == 69.0

    def test_generate_minimal_score(self, tmp_path: Path):
        from tools.security_scoring.data.report_generator import SecurityReportGenerator
        from tools.security_scoring.domain.models import SecurityScore

        score = SecurityScore(
            id=str(uuid.uuid4()),
            target_name="Minimal GmbH",
            timestamp="2026-04-06T10:00:00+00:00",
            overall_score=50.0,
            grade="D",
            components=[],
        )
        gen = SecurityReportGenerator()
        output = str(tmp_path / "minimal_security.pdf")
        gen.generate(score, output, include_details=False)
        assert Path(output).exists()

    def test_generate_with_critical_findings(self, tmp_path: Path):
        from tools.security_scoring.data.report_generator import SecurityReportGenerator
        from tools.security_scoring.domain.models import ScoreComponent, SecurityScore

        score = SecurityScore(
            id=str(uuid.uuid4()),
            target_name="Kritisch GmbH",
            timestamp="2026-04-06T10:00:00+00:00",
            overall_score=20.0,
            grade="F",
            components=[
                ScoreComponent(
                    name="API Security",
                    score=15.0,
                    weight=1.0,
                    findings_critical=5,
                    findings_high=3,
                    findings_medium=10,
                )
            ],
        )
        gen = SecurityReportGenerator()
        output = str(tmp_path / "critical_security.pdf")
        gen.generate(score, output)
        assert Path(output).exists()

    def test_generate_without_details(self, tmp_path: Path):
        from tools.security_scoring.data.report_generator import SecurityReportGenerator

        score = _make_security_score(num_components=5)
        gen = SecurityReportGenerator()
        output = str(tmp_path / "no_details.pdf")
        gen.generate(score, output, include_details=False)
        assert Path(output).exists()


# ---------------------------------------------------------------------------
# Tests: CustomerReportGenerator
# ---------------------------------------------------------------------------


class TestCustomerReportGenerator:
    def test_generate_creates_pdf(self, tmp_path: Path):
        from tools.customer_audit.data.report_generator import (
            CustomerReportGenerator,
        )

        result = _make_customer_result()
        gen = CustomerReportGenerator()
        output = tmp_path / "customer_report.pdf"
        saved = gen.generate(result, output)
        assert saved.exists()
        assert saved.stat().st_size > 1000

    def test_generate_returns_path(self, tmp_path: Path):
        from tools.customer_audit.data.report_generator import (
            CustomerReportGenerator,
        )

        result = _make_customer_result("Rückgabe GmbH")
        gen = CustomerReportGenerator()
        output = tmp_path / "return_test.pdf"
        saved = gen.generate(result, output)
        assert saved == output

    def test_generate_minimal_result(self, tmp_path: Path):
        from tools.customer_audit.data.report_generator import (
            CustomerReportGenerator,
        )
        from tools.customer_audit.domain.entities import (
            CustomerAuditResult,
            CustomerData,
            InfrastructureData,
            NetworkData,
            OrganizationalData,
        )

        result = CustomerAuditResult(
            audit_id=str(uuid.uuid4()),
            customer_data=CustomerData(firmenname="Minimal GmbH"),
            infrastructure_data=InfrastructureData(),
            organizational_data=OrganizationalData(),
            network_data=NetworkData(),
            overall_score=0.0,
            risk_level="Kritisch",
        )
        gen = CustomerReportGenerator()
        output = tmp_path / "minimal_customer.pdf"
        saved = gen.generate(result, output)
        assert saved.exists()

    def test_generate_maximal_result(self, tmp_path: Path):
        from tools.customer_audit.data.report_generator import (
            CustomerReportGenerator,
        )
        from tools.customer_audit.domain.entities import (
            CategoryScore,
            CustomerAuditResult,
            CustomerData,
            InfrastructureData,
            NetworkData,
            OrganizationalData,
        )

        result = CustomerAuditResult(
            audit_id=str(uuid.uuid4()),
            customer_data=CustomerData(
                firmenname="Maximum AG",
                ansprechpartner_name="Hans Huber",
                ansprechpartner_email="hans@maximum.at",
                ansprechpartner_telefon="+43 1 234 5678",
                branche="IT",
                unternehmensgroesse="1000+",
                erstellungsdatum="2026-04-06",
            ),
            infrastructure_data=InfrastructureData(
                betriebssysteme=["Windows 11", "Windows Server", "Linux"],
                os_patch_stand="Automatisch, Windows Update",
                antivirus_name="Microsoft Defender for Endpoint",
                antivirus_status="aktiv",
                firewall_name="Palo Alto NGFW",
                firewall_status="aktiv",
                verschluesselung=["BitLocker", "LUKS"],
                vpn_loesung="WireGuard",
                browser="Chrome 122, Firefox 124",
                server_infrastruktur="Hybrid (Azure + On-Premise)",
                remote_access_tools=["SSH", "RDP"],
            ),
            organizational_data=OrganizationalData(
                zugangskontrollen="Ja",
                backup_strategie="Ja",
                update_management="Ja",
                mitarbeitersensibilisierung="Ja",
                incident_response_plan="Ja",
                dsgvo_konformitaet="Ja",
            ),
            network_data=NetworkData(
                netzwerksegmentierung="Ja",
                wlan_sicherheit="WPA3",
                offene_ports_bekannt="Ja",
                ids_ips_vorhanden="Ja",
                letzter_pentest="2025",
            ),
            category_scores=[
                CategoryScore(name="IT-Infrastruktur", score=95.0, label="Niedrig"),
                CategoryScore(
                    name="Organisatorische Sicherheit", score=100.0, label="Niedrig"
                ),
                CategoryScore(name="Netzwerksicherheit", score=92.0, label="Niedrig"),
            ],
            overall_score=95.8,
            risk_level="Niedrig",
            recommendations=[],
            created_at="2026-04-06T10:00:00+00:00",
        )
        gen = CustomerReportGenerator()
        output = tmp_path / "maximum_customer.pdf"
        saved = gen.generate(result, output)
        assert saved.exists()
        assert saved.stat().st_size > 1000

    def test_generate_is_valid_pdf(self, tmp_path: Path):
        from tools.customer_audit.data.report_generator import (
            CustomerReportGenerator,
        )

        result = _make_customer_result()
        gen = CustomerReportGenerator()
        output = tmp_path / "valid_pdf_test.pdf"
        gen.generate(result, output)
        content = output.read_bytes()
        assert content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Tests: GenerateReportUseCase
# ---------------------------------------------------------------------------


class TestGenerateReportUseCase:
    def test_generate_for_id_calls_repository(self, tmp_path: Path):
        from tools.customer_audit.application.generate_report_use_case import (
            GenerateReportUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = _make_customer_result()
        use_case = GenerateReportUseCase(repo)
        output = tmp_path / "via_id.pdf"
        saved = use_case.generate_for_id("test-id", output)
        repo.load_by_id.assert_called_once_with("test-id")
        assert saved.exists()

    def test_generate_for_id_raises_if_not_found(self, tmp_path: Path):
        from tools.customer_audit.application.generate_report_use_case import (
            GenerateReportUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = None
        use_case = GenerateReportUseCase(repo)
        with pytest.raises(ValueError, match="nicht gefunden"):
            use_case.generate_for_id("nonexistent-id", tmp_path / "nope.pdf")

    def test_generate_for_result_creates_pdf(self, tmp_path: Path):
        from tools.customer_audit.application.generate_report_use_case import (
            GenerateReportUseCase,
        )

        repo = MagicMock()
        use_case = GenerateReportUseCase(repo)
        result = _make_customer_result()
        output = tmp_path / "direct_result.pdf"
        saved = use_case.generate_for_result(result, output)
        assert saved.exists()
