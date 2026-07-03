"""
test_pdf_builder — Tests für den Dashboard-PDF-Builder (Phase 3).

Abdeckung:
- Builder erzeugt valide PDF-Datei mit Header %PDF-
- Seitenzahl liegt im Korridor 5 – 8
- Dateigröße > 50 KB und < 5 MB
- Alle fünf Sektions-Überschriften erscheinen im Text
- Management-Summary enthält Scope, Datum, Scan-Coverage
- Audit-Event ``DASHBOARD_PDF_EXPORTED`` wird mit pseudonymisierten
  Feldern geloggt
- Leerer DashboardData-Fall fällt sauber auf Platzhalter zurück

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tools.norisk_dashboard.domain.models import (
    ChangeEntry,
    ChangeType,
    CveListEntry,
    DashboardData,
    OrgSnapshot,
    OrgTile,
    ScanEntry,
    ScanStatus,
    ScoreSnapshot,
    TimeRange,
)
from tools.security_scoring.domain.models import ScoreComponent


def _rich_dashboard_data() -> DashboardData:
    now = datetime(2026, 4, 20, 10, 0, 0)
    return DashboardData(
        time_range=TimeRange.MONTH,
        changes=[
            ChangeEntry(
                ChangeType.NEW,
                "CVE-2026-1234",
                "OpenSSL Buffer-Overflow in TLS-Handshake",
                now - timedelta(days=2),
                "cve",
            ),
            ChangeEntry(
                ChangeType.CHANGED,
                "Score 72.5",
                "Delta +1.8 Punkte gegenueber Vorperiode",
                now - timedelta(days=5),
                "score",
            ),
            ChangeEntry(
                ChangeType.NEW,
                "System-Scanner",
                "Neuer Scan-Lauf abgeschlossen",
                now - timedelta(days=1),
                "scan",
            ),
        ],
        score=ScoreSnapshot(
            current=72.5,
            previous=70.7,
            timestamp=now,
            target="ACME GmbH",
        ),
        cves=[
            CveListEntry(
                "CVE-2026-1234",
                "OpenSSL 3.0",
                "Buffer-Overflow",
                now - timedelta(days=2),
            ),
            CveListEntry(
                "CVE-2026-5555",
                "Postgres 16",
                "Privilege-Escalation",
                now - timedelta(days=10),
            ),
        ],
        scans=[
            ScanEntry("sys", "System-Scanner", now - timedelta(days=1), ScanStatus.OK),
            ScanEntry(
                "net",
                "Netzwerk-Scanner",
                now - timedelta(days=3),
                ScanStatus.OK,
            ),
            ScanEntry("api", "API-Security", now, ScanStatus.MISSING),
        ],
        breakdown=[
            ScoreComponent(
                name="IT-Infrastruktur",
                score=82.0,
                weight=0.3,
                findings_high=1,
                findings_medium=3,
            ),
            ScoreComponent(
                name="Netzwerk",
                score=65.0,
                weight=0.25,
                findings_high=2,
                findings_medium=5,
            ),
            ScoreComponent(
                name="Organisatorisch",
                score=55.0,
                weight=0.2,
                findings_high=4,
                findings_medium=2,
            ),
            ScoreComponent(
                name="API-Sicherheit",
                score=72.0,
                weight=0.25,
                findings_high=1,
                findings_medium=1,
            ),
        ],
        trend=[
            (now - timedelta(days=i * 3), 65.0 + i * 1.5) for i in range(8, 0, -1)
        ],
        org=OrgSnapshot(
            tiles=[
                OrgTile("dsgvo", "DSGVO-Compliance", 78.0, 2),
                OrgTile("phishing", "Phishing-Schutz", 62.0, 3),
                OrgTile("mfa", "Multi-Factor Auth", 85.0, 0),
                OrgTile("passwort_manager", "Passwort-Manager", 70.0, 1),
            ],
            has_assessment=True,
        ),
        generated=now,
    )


def _extract_pdf_text(path: Path) -> str:
    """Extrahiert den Gesamttext aus einem PDF (per pypdf)."""
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    parts = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    return "\n".join(parts)


def _count_pages(path: Path) -> int:
    from pypdf import PdfReader

    return len(PdfReader(str(path)).pages)


class TestDashboardPdfBuilder:
    def test_build_erzeugt_gueltiges_pdf(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "dashboard.pdf"
        builder = DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH")
        result = builder.build()
        assert result.exists()
        assert result.read_bytes()[:5] == b"%PDF-"

    def test_seitenzahl_im_korridor(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "pages.pdf"
        DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH").build()
        pages = _count_pages(out)
        assert 5 <= pages <= 8, f"Unerwartete Seitenzahl: {pages}"

    def test_dateigroesse_im_korridor(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "size.pdf"
        DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH").build()
        size = out.stat().st_size
        assert size > 50 * 1024, f"PDF zu klein: {size} B"
        assert size < 5 * 1024 * 1024, f"PDF zu gross: {size} B"

    def test_alle_sektionen_im_text(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "text.pdf"
        DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH").build()
        text = _extract_pdf_text(out)
        assert "Management-Summary" in text
        assert "Änderungen" in text or "nderungen" in text
        assert "Score" in text
        assert "CVE" in text
        assert "Scanner" in text
        assert "Trend" in text
        assert "Organisatorische Sicherheit" in text
        assert "Impressum" in text or "Abschluss" in text

    def test_footer_enthaelt_vertraulich_und_kontakt(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "footer.pdf"
        DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH").build()
        text = _extract_pdf_text(out)
        assert "Vertraulich" in text
        assert "financial-analytics" in text
        assert "Seite" in text

    def test_header_enthaelt_titel_und_datum(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        out = tmp_path / "header.pdf"
        DashboardPdfBuilder(out, _rich_dashboard_data(), "ACME GmbH").build()
        text = _extract_pdf_text(out)
        assert "NoRisk Dashboard-Report" in text
        assert "20.04.2026" in text  # Datum aus _rich_dashboard_data

    def test_leere_daten_fallen_auf_platzhalter(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        empty = DashboardData(
            time_range=TimeRange.WEEK,
            score=ScoreSnapshot(target="Allgemein"),
            generated=datetime(2026, 4, 21, 12, 0, 0),
        )
        out = tmp_path / "empty.pdf"
        DashboardPdfBuilder(out, empty, "Allgemein").build()
        text = _extract_pdf_text(out)
        assert "Keine registrierten" in text or "Kein" in text
        assert _count_pages(out) >= 5

    def test_missing_org_snapshot_wird_toleriert(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )

        data = _rich_dashboard_data()
        data.org = None
        out = tmp_path / "no_org.pdf"
        DashboardPdfBuilder(out, data, "ACME GmbH").build()
        text = _extract_pdf_text(out)
        assert "Organisatorische Sicherheit" in text


class TestPdfExportService:
    def test_export_schreibt_audit_eintrag(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.pdf_export_service import (
            PdfExportService,
        )

        events: list[tuple[str, dict, str | None]] = []

        class _StubAudit:
            def log_action(self, action, details=None, tool=None):  # noqa: ANN001
                events.append((action, details or {}, tool))

        service = PdfExportService(audit=_StubAudit())
        out = tmp_path / "service.pdf"
        result = service.export(_rich_dashboard_data(), out, "ACME GmbH")
        assert result.exists()
        assert len(events) == 1
        action, details, tool = events[0]
        assert action == "DASHBOARD_PDF_EXPORTED"
        assert tool == "norisk_dashboard"
        # Klartext-Pfad darf NICHT im Audit stehen (Pseudonymisierung)
        assert "ACME GmbH" not in str(details)
        assert out.name not in str(details)
        # Hashes + Metadaten
        assert "target_scope_hash" in details
        assert "filename_hash" in details
        assert details["time_range"] == "month"
        assert details["section_counts"]["changes"] == 3
        assert details["section_counts"]["trend_points"] == 8

    def test_default_filename_enthaelt_zeitstempel(self) -> None:
        from tools.norisk_dashboard.application.pdf_export_service import (
            default_filename,
        )

        name = default_filename(datetime(2026, 4, 21, 15, 30))
        assert name == "NoRisk-Dashboard-Report_2026-04-21_1530.pdf"

    def test_default_output_dir_existiert(self) -> None:
        from tools.norisk_dashboard.application.pdf_export_service import (
            default_output_dir,
        )

        path = default_output_dir()
        assert path.exists()
        assert path.name == "NoRisk-Reports"

    def test_audit_fehler_blockiert_export_nicht(self, tmp_path: Path) -> None:
        """Wenn das Audit-Log crasht, soll die PDF trotzdem existieren."""
        from tools.norisk_dashboard.application.pdf_export_service import (
            PdfExportService,
        )

        class _BrokenAudit:
            def log_action(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
                raise RuntimeError("audit kaputt")

        service = PdfExportService(audit=_BrokenAudit())
        out = tmp_path / "robust.pdf"
        result = service.export(_rich_dashboard_data(), out, "ACME GmbH")
        assert result.exists()


@pytest.mark.parametrize(
    "tr,days", [(TimeRange.WEEK, 7), (TimeRange.MONTH, 30), (TimeRange.QUARTER, 90)]
)
def test_pdf_mit_jedem_zeitfilter(tmp_path: Path, tr: TimeRange, days: int) -> None:
    from tools.norisk_dashboard.application.dashboard_pdf_builder import (
        DashboardPdfBuilder,
    )

    data = _rich_dashboard_data()
    data.time_range = tr
    out = tmp_path / f"tr_{tr.value}.pdf"
    DashboardPdfBuilder(out, data, "ACME GmbH").build()
    text = _extract_pdf_text(out)
    assert str(days) in text
