"""
test_hardening_score — pytest-Tests fuer
``tools.security_scoring.domain.hardening_score``.

Phase 1.4 des Hardening-Score-Sprints. Integration der Phase-1.1-1.3-
Bausteine in die finale Public-API ``compute_hardening_score``.

Test-Bereiche:
    * Happy-Path: 5 Kategorien voll → erwarteter Score + Stage.
    * Fehlende Kategorie: Redistribute wirkt korrekt.
    * Leere Inputs / alle data_available=False → 0.0 Critical.
    * Per-Category-Weighted-Average: korrekte Berechnung pro Kategorie.
    * data_available=False filtert die Komponente raus.
    * weight=0 verhindert Division-by-Zero.
    * category_scores in Kanon-Reihenfolge.
    * missing_categories liefert die fehlenden Kategorien.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.security_scoring.domain.hardening_categories import HardeningCategory
from tools.security_scoring.domain.hardening_score import (
    CategoryScore,
    HardeningScoreResult,
    build_hardening_summary,
    compute_hardening_score,
)
from tools.security_scoring.domain.hardening_stages import ScoreStage, score_to_stage
from tools.security_scoring.domain.models import ScoreComponent

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


def _comp(
    source_tool: str,
    score: float,
    *,
    weight: float = 0.5,
    data_available: bool = True,
    name: str = "X",
) -> ScoreComponent:
    """Builder fuer ScoreComponent-Test-Daten."""
    return ScoreComponent(
        name=name,
        score=score,
        weight=weight,
        source_tool=source_tool,
        data_available=data_available,
    )


# ===========================================================================
# Edge-Cases
# ===========================================================================


class TestEmptyInput:
    """Leere ScoreComponent-Liste oder nur unavailable Components."""

    def test_empty_list_yields_zero_critical(self):
        result = compute_hardening_score([])
        assert result.overall_score == 0.0
        assert result.stage.label == "Critical"
        assert result.category_scores == ()
        # Alle 5 Kategorien sind missing
        assert len(result.missing_categories) == 5
        assert set(result.missing_categories) == set(HardeningCategory)

    def test_all_data_unavailable_yields_zero_critical(self):
        comps = [
            _comp("cve_exposure", 90.0, data_available=False),
            _comp("network_scanner", 80.0, data_available=False),
        ]
        result = compute_hardening_score(comps)
        assert result.overall_score == 0.0
        assert result.stage.label == "Critical"
        assert result.category_scores == ()

    def test_only_zero_weight_components_yields_zero(self):
        # weight=0 in allen Comps → keine Division moeglich → leer
        comps = [
            _comp("cve_exposure", 90.0, weight=0.0),
            _comp("api_security", 85.0, weight=0.0),
        ]
        result = compute_hardening_score(comps)
        assert result.overall_score == 0.0
        assert result.category_scores == ()


# ===========================================================================
# Happy-Path: 5 Kategorien voll
# ===========================================================================


class TestFullCoverage:
    """Alle 5 Kategorien haben mindestens eine aktive Komponente."""

    def test_all_categories_score_100_yields_overall_100(self):
        # Jede Kategorie mit Score 100 → Overall 100 → Secure
        comps = [
            _comp("cve_exposure",    100.0),
            _comp("network_scanner", 100.0),
            _comp("password_policy", 100.0),
            _comp("api_security",    100.0),
            _comp("system_scanner",  100.0),
        ]
        result = compute_hardening_score(comps)
        assert result.overall_score == 100.0
        assert result.stage.label == "Secure"
        assert len(result.category_scores) == 5
        assert result.missing_categories == ()

    def test_all_categories_score_0_yields_overall_0(self):
        comps = [
            _comp("cve_exposure",    0.0),
            _comp("network_scanner", 0.0),
            _comp("password_policy", 0.0),
            _comp("api_security",    0.0),
            _comp("system_scanner",  0.0),
        ]
        result = compute_hardening_score(comps)
        assert result.overall_score == 0.0
        assert result.stage.label == "Critical"

    def test_full_coverage_weighted_average(self):
        # Gewichte 30/20/15/15/20 — exakte-Verteilung
        # Wenn jede Kategorie genau einen Score liefert, ist das
        # gewichteter Mittel.
        comps = [
            _comp("cve_exposure",    80.0),   # 0.30
            _comp("network_scanner", 70.0),   # 0.20
            _comp("password_policy", 90.0),   # 0.15
            _comp("api_security",    60.0),   # 0.15
            _comp("system_scanner",  50.0),   # 0.20
        ]
        # 80*0.30 + 70*0.20 + 90*0.15 + 60*0.15 + 50*0.20
        # = 24 + 14 + 13.5 + 9 + 10 = 70.5
        result = compute_hardening_score(comps)
        assert result.overall_score == 70.5
        assert result.stage.label == "Moderate"


# ===========================================================================
# Fehlende Kategorie + Redistribute
# ===========================================================================


class TestMissingCategory:
    """Wenn eine Kategorie fehlt, wird ihr Gewicht umverteilt."""

    def test_system_hardening_missing_redistribute(self):
        # System-Hardening (E, 0.20) fehlt — A:B:C:D bleibt 30:20:15:15
        # bei Normierung auf 1.0: 0.375: 0.250: 0.1875: 0.1875
        comps = [
            _comp("cve_exposure",    80.0),
            _comp("network_scanner", 80.0),
            _comp("password_policy", 80.0),
            _comp("api_security",    80.0),
            # Kein system_scanner
        ]
        result = compute_hardening_score(comps)
        # Da alle aktiven Kategorien Score 80 haben, ist gewichteter Mittel 80
        assert result.overall_score == 80.0
        assert result.stage.label == "Moderate"
        assert len(result.category_scores) == 4
        assert result.missing_categories == (HardeningCategory.SYSTEM_HARDENING,)

    def test_missing_category_redistribute_preserves_ratios(self):
        # Nur 2 Kategorien anwesend: CVE (0.30) und API (0.15)
        # Verhaeltnis 30:15 = 2:1, normiert: 0.6667: 0.3333
        comps = [
            _comp("cve_exposure", 90.0),
            _comp("api_security", 30.0),
        ]
        result = compute_hardening_score(comps)
        # 90 * (30/45) + 30 * (15/45) = 60 + 10 = 70
        assert result.overall_score == 70.0

        # Breakdown enthaelt 2 Eintraege
        assert len(result.category_scores) == 2
        cve_score = next(
            cs for cs in result.category_scores if cs.category == HardeningCategory.CVE_PATCH
        )
        api_score = next(
            cs for cs in result.category_scores if cs.category == HardeningCategory.API_SECURITY
        )
        # Adjusted weights: 0.30/0.45 = 0.6667, 0.15/0.45 = 0.3333
        assert cve_score.weight == pytest.approx(0.30 / 0.45, abs=1e-9)
        assert api_score.weight == pytest.approx(0.15 / 0.45, abs=1e-9)


# ===========================================================================
# Per-Category-Weighted-Average
# ===========================================================================


class TestPerCategoryAverage:
    """Mehrere Components in einer Kategorie ergeben gewichteten Mittel."""

    def test_three_cve_components_weighted(self):
        # Kategorie A hat 3 Quellen: cve_exposure + dependency_auditor + tech_stack
        # weight 0.5 + 0.3 + 0.2 = 1.0
        # scores 90, 60, 30
        # avg = (90*0.5 + 60*0.3 + 30*0.2) / 1.0 = 45 + 18 + 6 = 69
        comps = [
            _comp("cve_exposure",       90.0, weight=0.5),
            _comp("dependency_auditor", 60.0, weight=0.3),
            _comp("tech_stack",         30.0, weight=0.2),
        ]
        result = compute_hardening_score(comps)
        # Nur CVE-Patch hat Daten → 100% Gewicht
        assert result.overall_score == 69.0
        cve_score = result.category_scores[0]
        assert cve_score.category == HardeningCategory.CVE_PATCH
        assert cve_score.score == 69.0
        assert cve_score.components_count == 3

    def test_unavailable_component_excluded_from_average(self):
        # Eine Component mit data_available=False zaehlt nicht
        comps = [
            _comp("cve_exposure",       100.0),  # zaehlt
            _comp("dependency_auditor", 0.0,   data_available=False),  # ignoriert
        ]
        result = compute_hardening_score(comps)
        # Nur cve_exposure zaehlt → avg = 100
        assert result.overall_score == 100.0
        cve = result.category_scores[0]
        assert cve.components_count == 1

    def test_zero_weight_component_excluded(self):
        # weight=0 wird ignoriert (sonst Division durch Null)
        comps = [
            _comp("cve_exposure",       100.0, weight=0.5),
            _comp("dependency_auditor", 0.0,   weight=0.0),  # ignoriert
        ]
        result = compute_hardening_score(comps)
        assert result.overall_score == 100.0


# ===========================================================================
# Result-Struktur (Kanon-Reihenfolge etc.)
# ===========================================================================


class TestResultStructure:
    """HardeningScoreResult enthaelt die richtigen Strukturen."""

    def test_category_scores_in_canonical_order(self):
        # Reihenfolge in result.category_scores = HardeningCategory-Enum-Reihenfolge
        comps = [
            _comp("api_security",    80.0),
            _comp("cve_exposure",    80.0),
            _comp("system_scanner",  80.0),
            _comp("network_scanner", 80.0),
            _comp("password_policy", 80.0),
        ]
        result = compute_hardening_score(comps)
        labels = [cs.category for cs in result.category_scores]
        assert labels == [
            HardeningCategory.CVE_PATCH,
            HardeningCategory.NETWORK,
            HardeningCategory.PASSWORD,
            HardeningCategory.API_SECURITY,
            HardeningCategory.SYSTEM_HARDENING,
        ]

    def test_result_is_immutable(self):
        result = compute_hardening_score([_comp("cve_exposure", 50.0)])
        with pytest.raises(Exception):  # noqa: B017, BLE001 — FrozenInstanceError
            result.overall_score = 99.0  # type: ignore[misc]

    def test_category_score_is_immutable(self):
        result = compute_hardening_score([_comp("cve_exposure", 50.0)])
        cs = result.category_scores[0]
        with pytest.raises(Exception):  # noqa: B017, BLE001
            cs.score = 99.0  # type: ignore[misc]

    def test_stage_returned_is_scorestage(self):
        result = compute_hardening_score([_comp("cve_exposure", 50.0)])
        assert isinstance(result.stage, ScoreStage)

    def test_missing_and_present_are_disjoint(self):
        result = compute_hardening_score(
            [_comp("cve_exposure", 80.0), _comp("api_security", 80.0)]
        )
        present_cats = {cs.category for cs in result.category_scores}
        missing_cats = set(result.missing_categories)
        # Schnittmenge muss leer sein
        assert present_cats & missing_cats == set()
        # Vereinigung deckt alle 5 ab
        assert present_cats | missing_cats == set(HardeningCategory)


# ===========================================================================
# Integration-Smoke mit Org-Security
# ===========================================================================


class TestOrgSecurityIntegration:
    """org_security-Sub-Metriken werden korrekt aufgeteilt."""

    def test_mfa_lands_in_password_category(self):
        comps = [
            ScoreComponent(
                name="Multi-Factor Authentication",
                score=70.0,
                weight=0.5,
                source_tool="org_security",
            ),
        ]
        result = compute_hardening_score(comps)
        # Nur Password-Kategorie hat Daten → 100 % Gewicht
        assert result.overall_score == 70.0
        password_cs = result.category_scores[0]
        assert password_cs.category == HardeningCategory.PASSWORD

    def test_dsgvo_excluded_from_score(self):
        # DSGVO-Metrik soll keinen Score-Beitrag liefern
        comps = [
            ScoreComponent(
                name="DSGVO-Compliance",
                score=50.0,
                weight=0.5,
                source_tool="org_security",
            ),
        ]
        result = compute_hardening_score(comps)
        # DSGVO wurde gefiltert → keine aktiven Daten
        assert result.overall_score == 0.0
        assert result.stage.label == "Critical"
        assert result.category_scores == ()


# ===========================================================================
# Dataclass-Test
# ===========================================================================


class TestDataclasses:
    def test_category_score_construct(self):
        cs = CategoryScore(
            category=HardeningCategory.NETWORK,
            score=75.5,
            weight=0.2,
            components_count=2,
        )
        assert cs.category == HardeningCategory.NETWORK
        assert cs.score == 75.5

    def test_hardening_score_result_construct(self):
        from tools.security_scoring.domain.hardening_stages import score_to_stage

        result = HardeningScoreResult(
            overall_score=42.0,
            stage=score_to_stage(42),
            category_scores=(),
            missing_categories=tuple(HardeningCategory),
        )
        assert result.overall_score == 42.0
        assert result.stage.label == "At Risk"


# ===========================================================================
# build_hardening_summary — Subtitle-/PDF-Single-Source
# ===========================================================================


class TestBuildHardeningSummary:
    """Der Summary-Text wird ausschliesslich aus dem Result abgeleitet."""

    def test_basis_text_enthaelt_stage_und_score(self):
        # Alle 5 Kategorien Score 100 → Secure, 100/100, kein Cap, nichts fehlt.
        comps = [
            _comp("cve_exposure",    100.0),
            _comp("network_scanner", 100.0),
            _comp("password_policy", 100.0),
            _comp("api_security",    100.0),
            _comp("system_scanner",  100.0),
        ]
        text = build_hardening_summary(compute_hardening_score(comps))
        assert "Secure" in text
        assert "100/100" in text
        # Kein Cap, nichts fehlt → keine Zusatz-Segmente.
        assert "gedeckelt" not in text
        assert "ohne Daten" not in text

    def test_coverage_hinweis_bei_fehlenden_kategorien(self):
        # Nur CVE-Patch hat Daten → 4 von 5 Bereichen fehlen.
        text = build_hardening_summary(
            compute_hardening_score([_comp("cve_exposure", 80.0)])
        )
        assert "4 von 5 Bereichen noch ohne Daten" in text

    def test_cap_hinweis_wenn_raw_ueber_gecappt(self):
        # Direkt konstruiert: Rohscore 87, gedeckelt auf 25 (Hard-Cap).
        result = HardeningScoreResult(
            overall_score=25.0,
            stage=score_to_stage(25),
            category_scores=(),
            missing_categories=(),
            raw_weighted_score=87.0,
        )
        text = build_hardening_summary(result)
        assert "Critical" in text
        assert "25/100" in text
        assert "gedeckelt von 87" in text

    def test_kein_cap_hinweis_wenn_raw_gleich_score(self):
        result = HardeningScoreResult(
            overall_score=70.0,
            stage=score_to_stage(70),
            category_scores=(),
            missing_categories=(),
            raw_weighted_score=70.0,
        )
        assert "gedeckelt" not in build_hardening_summary(result)
