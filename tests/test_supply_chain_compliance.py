"""
test_supply_chain_compliance-ii.

Tests fuer Domain (ComplianceRequirement / ComplianceAssessment),
ComplianceAssessor-Heuristik und PDF-Renderer (Smoke: PDF wird erstellt
und enthaelt erwartete Mindestgroesse).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tools.supply_chain_monitor.application.avv_service import AvvService
from tools.supply_chain_monitor.application.compliance_assessor import (
    COMPLIANCE_REQUIREMENTS,
    ComplianceAssessor,
)
from tools.supply_chain_monitor.application.report_renderer import (
    render_avv_status_report,
    render_gvsc_compliance_report,
)
from tools.supply_chain_monitor.application.subprocessor_service import (
    SubprocessorService,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.data.avv_repository import AvvRepository
from tools.supply_chain_monitor.data.subprocessor_repository import (
    SubprocessorRepository,
)
from tools.supply_chain_monitor.data.vendor_detection_repository import (
    VendorDetectionRepository,
)
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import (
    ComplianceCoverage,
    ComplianceFramework,
    ComplianceRequirement,
    VendorCategory,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


def _make_pdf(path: Path) -> Path:
    path.write_bytes(b"X" * 256)
    return path


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class TestComplianceRequirement:
    def test_leerer_identifier_wirft(self) -> None:
        with pytest.raises(ValueError, match="identifier"):
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF_GVSC,
                identifier="   ",
                title="X",
                description="Y",
            )

    def test_leerer_title_wirft(self) -> None:
        with pytest.raises(ValueError, match="title"):
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF_GVSC,
                identifier="GV.SC-99",
                title="   ",
                description="Y",
            )


class TestCatalog:
    def test_16_anforderungen_im_catalog(self) -> None:
        # 10 NIST GV.SC + 4 BSI OPS + 2 BSI ORP = 16
        assert len(COMPLIANCE_REQUIREMENTS) == 16

    def test_nist_gvsc_01_bis_10_vorhanden(self) -> None:
        ids = {r.identifier for r in COMPLIANCE_REQUIREMENTS}
        for i in range(1, 11):
            assert f"GV.SC-{i:02d}" in ids

    def test_bsi_ops_a4_und_a10(self) -> None:
        ids = {r.identifier for r in COMPLIANCE_REQUIREMENTS}
        assert "OPS.2.3.A4" in ids
        assert "OPS.2.3.A10" in ids

    def test_eindeutige_identifier(self) -> None:
        ids = [r.identifier for r in COMPLIANCE_REQUIREMENTS]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Assessor
# ---------------------------------------------------------------------------


@pytest.fixture
def assessor(tmp_path: Path) -> tuple[ComplianceAssessor, VendorService, AvvService]:
    db = _InMemoryDB()
    vs = VendorService(repository=VendorRepository(db=db))
    av = AvvService(repository=AvvRepository(db=db), storage_root=tmp_path)
    ss = SubprocessorService(repository=SubprocessorRepository(db=db))
    det_repo = VendorDetectionRepository(db=db)
    a = ComplianceAssessor(
        vendor_service=vs,
        avv_service=av,
        subprocessor_service=ss,
        offboarding_service=None,
        detection_repository=det_repo,
    )
    return a, vs, av


class TestAssess:
    def test_leeres_repo_liefert_meist_gap(
        self, assessor: tuple[ComplianceAssessor, VendorService, AvvService]
    ) -> None:
        a, _vs, _av = assessor
        report = a.assess_all()
        counts = report.counts()
        # 8 manual-review-Eintraege + 8 daten-getriebene → bei leerem Repo
        # MANUAL_REVIEW + GAP, KEINE COVERED.
        assert counts[ComplianceCoverage.COVERED] == 0
        assert counts[ComplianceCoverage.MANUAL_REVIEW] == 8
        assert counts[ComplianceCoverage.GAP] + counts[ComplianceCoverage.PARTIAL] == 8

    def test_vendoren_mit_avv_loesen_covered_aus(
        self,
        assessor: tuple[ComplianceAssessor, VendorService, AvvService],
        tmp_path: Path,
    ) -> None:
        a, vs, av = assessor
        # 3 Vendoren, davon 1 kritisch (Microsoft mit score=4)
        vs.add_vendor(
            name="DATEV",
            category=VendorCategory.KANZLEISOFTWARE,
            criticality_score=5,
        )
        vs.add_vendor(
            name="Microsoft", category=VendorCategory.CLOUD, criticality_score=4
        )
        vs.add_vendor(
            name="Hetzner", category=VendorCategory.MSP, criticality_score=3
        )
        # AVV fuer alle 3 (damit AVV-Quote 100%)
        now = datetime.now(UTC)
        for i in (1, 2, 3):
            pdf = _make_pdf(tmp_path / f"avv_{i}.pdf")
            av.upload_avv(
                vendor_id=i,
                source_path=pdf,
                valid_from=now - timedelta(days=30),
                valid_until=now + timedelta(days=400),
            )

        report = a.assess_all()
        by_id = {x.requirement.identifier: x for x in report.assessments}
        # GV.SC-04 (>=3 vendoren + 1 critical) → COVERED
        assert by_id["GV.SC-04"].coverage is ComplianceCoverage.COVERED
        # GV.SC-05 (AVV-Quote 100%) → COVERED
        assert by_id["GV.SC-05"].coverage is ComplianceCoverage.COVERED

    def test_gvsc_07_braucht_subprocessor_und_complete_checklist(
        self,
        assessor: tuple[ComplianceAssessor, VendorService, AvvService],
        tmp_path: Path,
    ) -> None:
        a, vs, av = assessor
        vs.add_vendor(
            name="DATEV",
            category=VendorCategory.KANZLEISOFTWARE,
            criticality_score=5,
        )
        # Kein Subprocessor, kein AVV → GAP/PARTIAL.
        report = a.assess_all()
        by_id = {x.requirement.identifier: x for x in report.assessments}
        assert by_id["GV.SC-07"].coverage in (
            ComplianceCoverage.GAP,
            ComplianceCoverage.PARTIAL,
        )

    def test_manual_review_anforderungen(
        self, assessor: tuple[ComplianceAssessor, VendorService, AvvService]
    ) -> None:
        a, _vs, _av = assessor
        report = a.assess_all()
        manual_ids = {
            x.requirement.identifier
            for x in report.assessments
            if x.coverage is ComplianceCoverage.MANUAL_REVIEW
        }
        # Strategie/Rollen/Integration sind procedural — immer MANUAL_REVIEW.
        assert "GV.SC-01" in manual_ids
        assert "GV.SC-02" in manual_ids
        assert "GV.SC-03" in manual_ids
        assert "GV.SC-08" in manual_ids
        assert "GV.SC-09" in manual_ids
        assert "OPS.2.3.A2" in manual_ids
        assert "OPS.2.3.A6" in manual_ids
        assert "ORP.5.A6" in manual_ids

    def test_by_framework_filtert(
        self, assessor: tuple[ComplianceAssessor, VendorService, AvvService]
    ) -> None:
        a, _vs, _av = assessor
        report = a.assess_all()
        nist = report.by_framework(ComplianceFramework.NIST_CSF_GVSC)
        bsi_ops = report.by_framework(ComplianceFramework.BSI_OPS_2_3)
        bsi_orp = report.by_framework(ComplianceFramework.BSI_ORP_5)
        assert len(nist) == 10
        assert len(bsi_ops) == 4
        assert len(bsi_orp) == 2


# ---------------------------------------------------------------------------
# Renderer (PDF-Smoke — wir pruefen Existenz + Mindestgroesse, nicht Inhalt)
# ---------------------------------------------------------------------------


class TestRenderer:
    def test_gvsc_pdf_wird_erstellt(
        self,
        assessor: tuple[ComplianceAssessor, VendorService, AvvService],
        tmp_path: Path,
    ) -> None:
        a, _vs, _av = assessor
        report = a.assess_all()
        out = tmp_path / "gvsc.pdf"
        render_gvsc_compliance_report(out, report, customer_name="Demo-Kanzlei")
        assert out.exists()
        assert out.stat().st_size > 2000  # PDF mit 16 Reqs muss > 2 KB sein
        # PDF-Magic-Bytes pruefen
        assert out.read_bytes()[:4] == b"%PDF"

    def test_avv_pdf_wird_erstellt(
        self,
        assessor: tuple[ComplianceAssessor, VendorService, AvvService],
        tmp_path: Path,
    ) -> None:
        a, vs, av = assessor
        vs.add_vendor(
            name="DATEV",
            category=VendorCategory.KANZLEISOFTWARE,
            criticality_score=5,
        )
        pdf = _make_pdf(tmp_path / "src.pdf")
        now = datetime.now(UTC)
        av.upload_avv(
            vendor_id=1,
            source_path=pdf,
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=400),
        )
        out = tmp_path / "avv.pdf"
        render_avv_status_report(out, av, vs, customer_name="Demo")
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"

    def test_avv_pdf_ohne_avvs_baut_trotzdem(
        self,
        assessor: tuple[ComplianceAssessor, VendorService, AvvService],
        tmp_path: Path,
    ) -> None:
        _a, vs, av = assessor
        out = tmp_path / "avv_empty.pdf"
        render_avv_status_report(out, av, vs)
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"
