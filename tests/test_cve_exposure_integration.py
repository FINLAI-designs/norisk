"""
test_cve_exposure_integration — Integrations-Tests für die cve_exposure-Anbindung.

Deckt die vier Domain-/Application-/Data-/Scoring-Aspekte ab:
  - Penalty-Formel (Domain).
  - Status-Ableitung (Domain).
  - Aggregation inkl. No-Data-Verhalten (Application).
  - Techstack-Filterung & Read-Only-Garantie (Data).
  - Einbindung in ScoringService (Application, 7. Komponente).

Schichtzugehörigkeit: tests/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.cyber_dashboard.domain.models import CveEintrag
from tools.security_scoring.application.cve_exposure_service import (
    CveExposureService,
)
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.data.cve_exposure_repository import (
    CveExposureRepository,
)
from tools.security_scoring.domain.cve_exposure import (
    CveExposureData,
    berechne_exposure_score,
    status_from_score,
)
from tools.security_scoring.domain.scoring_engine import DEFAULT_WEIGHTS
from tools.security_scoring.domain.tech_stack.entities import (
    BrowserEntry,
    OSEntry,
    SystemProfile,
    TechStack,
)
from tools.security_scoring.domain.tech_stack.enums import SystemType

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


def _make_cve(
    cve_id: str,
    cvss: float,
    kev: bool = False,
    produkte: list[str] | None = None,
) -> CveEintrag:
    """Erzeugt einen CveEintrag mit sinnvollen Default-Werten.

    ``produkte=None`` erzeugt einen generischen Windows-Match; eine
    explizit leere Liste bleibt leer (für Negativ-Tests).
    """
    now = datetime.now(UTC)
    return CveEintrag(
        cve_id=cve_id,
        beschreibung="Test-Beschreibung",
        schweregrad="CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM",
        cvss_score=cvss,
        veroeffentlicht=now,
        geaendert=now,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        cisa_kev=kev,
        cisa_frist="",
        betroffene_produkte=(
            produkte if produkte is not None else ["Microsoft Windows 11"]
        ),
    )


def _make_advisory(advisory_id: str, severity: str) -> CsafAdvisory:
    """Erzeugt ein CsafAdvisory mit gegebener Severity."""
    return CsafAdvisory(
        id=advisory_id,
        title=f"Test Advisory {advisory_id}",
        publisher="TestCERT",
        tracking_id=f"T-{advisory_id}",
        tracking_version="1",
        initial_release="2026-01-01",
        current_release="2026-01-01",
        severity=severity,
        cvss_score=None,
    )


def _make_match(advisory_id: str) -> AdvisoryMatch:
    """Erzeugt einen AdvisoryMatch für eine gegebene Advisory-ID."""
    return AdvisoryMatch(
        id=f"match-{advisory_id}",
        advisory_id=advisory_id,
        matched_component="test-component",
        matched_version="1.0",
        confidence=0.9,
        action_required="monitor",
        matched_at="2026-04-24T12:00:00+00:00",
    )


def _profile_mit_stack(**stack_overrides) -> SystemProfile:
    """Erzeugt ein SystemProfile mit einem TechStack aus den Overrides."""
    stack = TechStack(**stack_overrides)
    return SystemProfile(
        id="test-id",
        name="Mein System",
        system_type=SystemType.EIGENES,
        tech_stack=stack,
    )


# ---------------------------------------------------------------------------
# Domain: Penalty + Status
# ---------------------------------------------------------------------------


class TestExposureScore:
    def test_exposure_score_no_cves(self):
        """Keine CVEs → Penalty 0 → Score 100 → Status OK."""
        score = berechne_exposure_score(0, 0, 0, 0, 0)
        assert score == 100
        assert status_from_score(score) == "OK"

    def test_exposure_score_critical_cves(self):
        """2× Critical (CVSS 9.5, nicht KEV) → Penalty 30 → Score 70 → Warnung."""
        score = berechne_exposure_score(critical=2, high=0, medium=0, kev=0, advisories=0)
        assert score == 70
        assert status_from_score(score) == "Warnung"

    def test_exposure_score_kev_penalty(self):
        """1× Critical + 1× KEV → Penalty 15+20 = 35 → Score 65."""
        score = berechne_exposure_score(critical=1, high=0, medium=0, kev=1, advisories=0)
        assert score == 65
        assert status_from_score(score) == "Warnung"

    def test_exposure_score_capping(self):
        """Sehr viele kritische KEV-CVEs → Score gedeckelt bei 0."""
        score = berechne_exposure_score(
            critical=20, high=0, medium=0, kev=20, advisories=10
        )
        assert score == 0
        assert status_from_score(score) == "Kritisch"

    def test_exposure_score_advisory_penalty(self):
        """3× Advisory-Match → Penalty 30 → Score 70."""
        score = berechne_exposure_score(0, 0, 0, 0, 3)
        assert score == 70

    def test_status_from_score_no_data(self):
        """score=None → Status 'Keine Daten'."""
        assert status_from_score(None) == "Keine Daten"

    def test_status_from_score_boundaries(self):
        """Schwellwerte: 80 = OK, 79 = Warnung, 60 = Warnung, 59 = Kritisch."""
        assert status_from_score(80) == "OK"
        assert status_from_score(79) == "Warnung"
        assert status_from_score(60) == "Warnung"
        assert status_from_score(59) == "Kritisch"


# ---------------------------------------------------------------------------
# Application: CveExposureService
# ---------------------------------------------------------------------------


class TestCveExposureService:
    def test_no_data_returns_none_score(self):
        """Keine CVEs und keine Advisories → score=None, Status 'Keine Daten'."""
        repo = MagicMock()
        repo.lade_techstack_cves.return_value = []
        repo.zaehle_betroffene_advisories.return_value = 0
        repo.letzte_aktualisierung.return_value = ""

        service = CveExposureService(repository=repo)
        data = service.get_current_exposure()

        assert data.score is None
        assert data.status == "Keine Daten"
        assert data.total_cves == 0
        assert data.affected_advisories == 0

    def test_aggregates_cve_buckets(self):
        """CVEs werden nach CVSS-Bucket korrekt gezählt."""
        repo = MagicMock()
        repo.lade_techstack_cves.return_value = [
            _make_cve("CVE-A", 9.8),  # Critical
            _make_cve("CVE-B", 8.5),  # High
            _make_cve("CVE-C", 5.0),  # Medium
            _make_cve("CVE-D", 9.0, kev=True),  # Critical + KEV
        ]
        repo.zaehle_betroffene_advisories.return_value = 1
        repo.letzte_aktualisierung.return_value = "2026-04-24T10:00:00+00:00"

        service = CveExposureService(repository=repo)
        data = service.get_current_exposure()

        assert data.total_cves == 4
        assert data.critical_count == 2
        assert data.high_count == 1
        assert data.medium_count == 1
        assert data.kev_count == 1
        assert data.affected_advisories == 1
        # Penalty: 2*15 + 1*8 + 1*3 + 1*20 + 1*10 = 71 → Score 29
        assert data.score == 29
        assert data.status == "Kritisch"


# ---------------------------------------------------------------------------
# Data: Repository-Filter und Read-Only
# ---------------------------------------------------------------------------


class TestCveExposureRepositoryFilter:
    def test_techstack_filter_matches_only_relevant_cves(self):
        """Cache enthält 4 CVEs, Stack hat 2 Produkte → nur passende zurück."""
        cache = MagicMock()
        cache.lade_cves.return_value = [
            _make_cve(
                "CVE-1", 9.5, produkte=["Microsoft Windows 11"]
            ),  # matcht "Windows 11"
            _make_cve(
                "CVE-2", 8.0, produkte=["Google Chrome 124"]
            ),  # matcht "Chrome"
            _make_cve(
                "CVE-3", 9.0, produkte=["Adobe Photoshop 25"]
            ),  # kein Match
            _make_cve("CVE-4", 6.0, produkte=[]),  # kein Match (leer)
        ]
        advisory = MagicMock()
        advisory.list_matches.return_value = []
        advisory.list_advisories.return_value = []
        ts = MagicMock()
        ts.get_own_system.return_value = _profile_mit_stack(
            operating_systems=[OSEntry(name="Windows 11", version="23H2")],
            browsers=[BrowserEntry(name="Chrome", version="124")],
        )

        repo = CveExposureRepository(
            cache_repo=cache, advisory_repo=advisory, tech_stack_repo=ts
        )
        cves = repo.lade_techstack_cves()

        ids = {cve.cve_id for cve in cves}
        assert ids == {"CVE-1", "CVE-2"}

    def test_empty_techstack_returns_no_cves(self):
        """Leerer TechStack → keine Treffer, auch wenn Cache voll ist."""
        cache = MagicMock()
        cache.lade_cves.return_value = [_make_cve("CVE-1", 9.5)]
        ts = MagicMock()
        ts.get_own_system.return_value = _profile_mit_stack()

        repo = CveExposureRepository(
            cache_repo=cache,
            advisory_repo=MagicMock(),
            tech_stack_repo=ts,
        )

        assert repo.lade_techstack_cves() == []

    def test_repository_does_not_write(self):
        """Der Service ruft keine schreibenden Cache-/Advisory-Methoden auf."""
        cache = MagicMock()
        cache.lade_cves.return_value = [
            _make_cve("CVE-1", 9.5, produkte=["Windows 11"])
        ]
        advisory = MagicMock()
        advisory.list_matches.return_value = []
        advisory.list_advisories.return_value = []
        ts = MagicMock()
        ts.get_own_system.return_value = _profile_mit_stack(
            operating_systems=[OSEntry(name="Windows 11")],
        )

        repo = CveExposureRepository(
            cache_repo=cache, advisory_repo=advisory, tech_stack_repo=ts
        )
        service = CveExposureService(repository=repo)
        service.get_current_exposure()

        cache.speichere_cves.assert_not_called()
        advisory.save_advisory.assert_not_called()
        advisory.save_match.assert_not_called()
        advisory.clear_matches.assert_not_called()

    def test_csaf_severity_normalization(self):
        """CSAF-Severity wird case-insensitive ausgewertet."""
        cache = MagicMock()
        cache.lade_cves.return_value = []
        advisory = MagicMock()
        advisory.list_matches.return_value = [
            _make_match("A"),  # → "critical" (lowercase)
            _make_match("B"),  # → "HIGH" (uppercase) — muss trotzdem zählen
            _make_match("C"),  # → "medium" — darf nicht zählen
        ]
        advisory.list_advisories.return_value = [
            _make_advisory("A", "critical"),
            _make_advisory("B", "HIGH"),
            _make_advisory("C", "medium"),
        ]
        ts = MagicMock()
        ts.get_own_system.return_value = _profile_mit_stack()

        repo = CveExposureRepository(
            cache_repo=cache, advisory_repo=advisory, tech_stack_repo=ts
        )
        assert repo.zaehle_betroffene_advisories() == 2


# ---------------------------------------------------------------------------
# Integration: Einbindung in ScoringService
# ---------------------------------------------------------------------------


class TestCveExposureInScoringService:
    def test_component_appears_with_configured_weight(self):
        """ScoringService fügt genau eine cve_exposure-Komponente mit Gewicht 0.15 ein."""
        cve_exposure_service = MagicMock()
        cve_exposure_service.get_current_exposure.return_value = CveExposureData(
            total_cves=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            kev_count=0,
            affected_advisories=0,
            score=74,
            status="Warnung",
            last_updated="2026-04-24T12:00:00+00:00",
        )
        service = ScoringService(
            score_repo=None,
            cve_exposure_service=cve_exposure_service,
        )
        score = service.berechne_score("Mein System")

        cve_components = [
            c for c in score.components if c.source_tool == "cve_exposure"
        ]
        assert len(cve_components) == 1
        comp = cve_components[0]
        assert comp.weight == DEFAULT_WEIGHTS["cve_exposure"]
        assert comp.data_available is True
        assert comp.score == pytest.approx(74.0)
        assert "3 CVEs" in comp.details

    def test_no_data_component_is_flagged(self):
        """Bei score=None entsteht ein data_available=False-Eintrag."""
        cve_exposure_service = MagicMock()
        cve_exposure_service.get_current_exposure.return_value = CveExposureData(
            total_cves=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            kev_count=0,
            affected_advisories=0,
            score=None,
            status="Keine Daten",
            last_updated="",
        )
        service = ScoringService(
            score_repo=None,
            cve_exposure_service=cve_exposure_service,
        )
        score = service.berechne_score("Mein System")

        cve_components = [
            c for c in score.components if c.source_tool == "cve_exposure"
        ]
        assert len(cve_components) == 1
        comp = cve_components[0]
        assert comp.data_available is False
        assert comp.details == "Techstack-Scan erforderlich"

    def test_no_data_does_not_drag_overall_score(self):
        """No-Data-Komponente wird aus Gewichtssummen ausgeschlossen."""
        cve_exposure_service = MagicMock()
        cve_exposure_service.get_current_exposure.return_value = CveExposureData(
            total_cves=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            kev_count=0,
            affected_advisories=0,
            score=None,
            status="Keine Daten",
            last_updated="",
        )
        service_with = ScoringService(
            score_repo=None, cve_exposure_service=cve_exposure_service
        )
        service_without = ScoringService(score_repo=None)
        score_with = service_with.berechne_score("Mein System")
        score_without = service_without.berechne_score("Mein System")
        # Beide haben keine aktiven Komponenten → 0.0
        assert score_with.overall_score == score_without.overall_score
