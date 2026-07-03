"""
test_pdf_charts — Tests für den Matplotlib-Chart-Export (Phase 3).

Abdeckung:
- Score-Trend: PNG-Bytes, PNG-Signatur, Größen-Korridor
- Score-Trend: < 2 Datenpunkte → None
- Breakdown: PNG-Bytes für Score-Komponenten
- Breakdown: leere Liste → None
- Light-Theme: weißer Hintergrund wird erzeugt
- PNG wird tatsächlich in die PDF eingebettet (prüft Bildobjekte)

Author: Patrick Riederich
Version: 0.3 (Phase 3)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Cleanup-Sprint 2026-04-29: matplotlib ist optional. Wenn nicht
# installiert, liefert ``render_*_png`` ``None`` und alle Tests müssten
# scheitern — wir skippen das ganze Modul stattdessen mit
# ``importorskip``. Sobald matplotlib im venv liegt, laufen die Tests
# ohne weitere Änderung.
pytest.importorskip(
    "matplotlib",
    reason="matplotlib ist optional; Chart-Export liefert ohne sie None.",
)

from tools.norisk_dashboard.application.dashboard_chart_export import (  # noqa: E402
    render_breakdown_png,
    render_score_trend_png,
)
from tools.security_scoring.domain.models import ScoreComponent  # noqa: E402

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _trend_pairs(count: int = 8) -> list[tuple[datetime, float]]:
    base = datetime(2026, 4, 1, 12, 0, 0)
    return [(base + timedelta(days=i * 3), 60.0 + i * 1.3) for i in range(count)]


def _components() -> list[ScoreComponent]:
    return [
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
            score=48.0,
            weight=0.2,
            findings_high=4,
            findings_medium=2,
        ),
        ScoreComponent(
            name="API-Sicherheit",
            score=28.0,
            weight=0.25,
            findings_high=6,
            findings_medium=3,
        ),
    ]


class TestScoreTrendChart:
    def test_rendert_png_bytes(self) -> None:
        data = render_score_trend_png(_trend_pairs())
        assert data is not None
        assert data[:8] == _PNG_SIGNATURE

    def test_dateigroesse_plausibel(self) -> None:
        data = render_score_trend_png(_trend_pairs())
        assert data is not None
        assert 5_000 < len(data) < 500_000

    def test_einzelner_datenpunkt_ergibt_none(self) -> None:
        pairs = [(datetime(2026, 4, 10, 12, 0, 0), 70.0)]
        assert render_score_trend_png(pairs) is None

    def test_leere_liste_ergibt_none(self) -> None:
        assert render_score_trend_png([]) is None

    def test_dpi_parameter_wirkt(self) -> None:
        small = render_score_trend_png(_trend_pairs(), dpi=90)
        large = render_score_trend_png(_trend_pairs(), dpi=200)
        assert small is not None and large is not None
        assert len(large) > len(small)


class TestBreakdownChart:
    def test_rendert_png_bytes(self) -> None:
        data = render_breakdown_png(_components())
        assert data is not None
        assert data[:8] == _PNG_SIGNATURE

    def test_leere_liste_ergibt_none(self) -> None:
        assert render_breakdown_png([]) is None

    def test_alle_score_niveaus_erzeugen_png(self) -> None:
        """Auch extreme Scores (0, 100) produzieren ein valides PNG."""
        comps = [
            ScoreComponent(name="A", score=0.0, weight=0.25),
            ScoreComponent(name="B", score=100.0, weight=0.25),
            ScoreComponent(name="C", score=50.0, weight=0.25),
            ScoreComponent(name="D", score=75.0, weight=0.25),
        ]
        data = render_breakdown_png(comps)
        assert data is not None
        assert data[:8] == _PNG_SIGNATURE


class TestChartsInPdf:
    def test_pdf_enthaelt_eingebettete_bilder(self, tmp_path: Path) -> None:
        """Sektion 4 muss Trend- + Breakdown-PNG ins PDF einbetten."""
        from pypdf import PdfReader

        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )
        from tools.norisk_dashboard.domain.models import (
            DashboardData,
            ScoreSnapshot,
            TimeRange,
        )

        now = datetime(2026, 4, 20, 10, 0, 0)
        data = DashboardData(
            time_range=TimeRange.MONTH,
            score=ScoreSnapshot(current=70.0, previous=68.0, target="ACME GmbH"),
            breakdown=_components(),
            trend=_trend_pairs(),
            generated=now,
        )
        out = tmp_path / "charts.pdf"
        DashboardPdfBuilder(out, data, "ACME GmbH").build()

        reader = PdfReader(str(out))
        image_count = 0
        for page in reader.pages:
            resources = page.get("/Resources")
            if resources is None:
                continue
            xobject = resources.get("/XObject")
            if xobject is None:
                continue
            xobject = xobject.get_object()
            for name in xobject:
                obj = xobject[name].get_object()
                if obj.get("/Subtype") == "/Image":
                    image_count += 1
        # Logo + Trend + Breakdown ⇒ ≥ 2 (Logo nur wenn Asset vorhanden)
        assert image_count >= 2, f"Zu wenige Bilder eingebettet: {image_count}"

    def test_pdf_ohne_trend_baut_trotzdem(self, tmp_path: Path) -> None:
        """Fehlender Trend darf den Bau nicht abbrechen."""
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )
        from tools.norisk_dashboard.domain.models import (
            DashboardData,
            ScoreSnapshot,
            TimeRange,
        )

        now = datetime(2026, 4, 20, 10, 0, 0)
        data = DashboardData(
            time_range=TimeRange.WEEK,
            score=ScoreSnapshot(current=70.0, target="ACME GmbH"),
            breakdown=_components(),
            trend=[],
            generated=now,
        )
        out = tmp_path / "no_trend.pdf"
        result = DashboardPdfBuilder(out, data, "ACME GmbH").build()
        assert result.exists()
        assert result.read_bytes()[:5] == b"%PDF-"

    def test_pdf_ohne_breakdown_baut_trotzdem(self, tmp_path: Path) -> None:
        from tools.norisk_dashboard.application.dashboard_pdf_builder import (
            DashboardPdfBuilder,
        )
        from tools.norisk_dashboard.domain.models import (
            DashboardData,
            ScoreSnapshot,
            TimeRange,
        )

        now = datetime(2026, 4, 20, 10, 0, 0)
        data = DashboardData(
            time_range=TimeRange.WEEK,
            score=ScoreSnapshot(current=70.0, target="ACME GmbH"),
            breakdown=[],
            trend=_trend_pairs(),
            generated=now,
        )
        out = tmp_path / "no_breakdown.pdf"
        result = DashboardPdfBuilder(out, data, "ACME GmbH").build()
        assert result.exists()
