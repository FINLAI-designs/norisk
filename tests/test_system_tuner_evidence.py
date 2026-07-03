"""
test_system_tuner_evidence — NIS2/DSGVO-Nachweis + Empfehlungspaket (Phase 2b).

Pure Inhalts-Tests (build + Markdown) gegen einen echten ScanReport
(MockHardeningProbe + gebuendelter Katalog) + ein PDF-Smoke.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.probes.mock_hardening_probe import MockHardeningProbe
from tools.system_tuner.application.catalog_loader import YamlTweakCatalog
from tools.system_tuner.application.evidence_service import (
    EvidenceExporter,
    build_evidence_report,
    render_markdown,
)
from tools.system_tuner.application.tuner_scan_use_case import TunerScanUseCase

_TS = "2026-06-17 00:00 UTC"


def _report():
    scan = TunerScanUseCase(MockHardeningProbe(), YamlTweakCatalog()).scan()
    return build_evidence_report(scan, generated_at=_TS)


class TestBuild:
    def test_report_has_lines_for_all_tweaks(self):
        report = _report()
        assert len(report.lines) >= 6
        assert report.generated_at == _TS

    def test_instructions_derived(self):
        report = _report()
        instructions = " ".join(ln.instruction for ln in report.lines)
        assert "Registry:" in instructions
        assert "sc config" in instructions


class TestMarkdown:
    def test_markdown_structure(self):
        md = render_markdown(_report())
        assert "# NoRisk — Datenschutz-/Telemetrie-Nachweis" in md
        assert "## Befunde" in md
        assert "## Empfehlungspaket" in md
        assert "Privacy-Score" in md

    def test_compliance_framing_feature_level(self):
        md = render_markdown(_report())
        # R1: Art. 30 / NIS2 Art. 21 gehoeren auf die FEATURE-Ebene (hier korrekt)
        assert "Art. 30" in md
        assert "NIS2 Art. 21" in md
        assert "Art. 32" in md
        assert "Art. 5" in md

    def test_no_overclaim_wording(self):
        # R2: kein "konform"-Claim im Nachweis
        assert "konform" not in render_markdown(_report()).lower()


class TestPdf:
    def test_pdf_smoke(self, tmp_path: Path):
        pytest.importorskip("reportlab")
        out = tmp_path / "evidence.pdf"
        try:
            ok = EvidenceExporter().export_pdf(_report(), out)
        except (OSError, RuntimeError, ImportError) as exc:
            pytest.skip(f"PDF-Stack nicht verfuegbar: {exc}")
        assert ok
        assert out.exists()
        assert out.stat().st_size > 0
