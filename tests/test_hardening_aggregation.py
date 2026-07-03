"""
test_hardening_aggregation — pytest-Tests fuer
``tools.security_scoring.domain.hardening_aggregation``.

Phase 1.2 des Hardening-Score-Sprints. Pure Logik, keine I/O.

Test-Bereiche:
    * bundle_components_to_categories: Sortierung in 5 Buckets,
      org_security-Reverse-Lookup, DSGVO-Drop, Unknown-Tool-Errors.
    * redistribute_unavailable_weights: Σ=1.0 nach Umverteilung,
      proportionale Skalierung, Edge-Cases (alle present, eine present,
      leer, base-sum-zero).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.security_scoring.domain.hardening_aggregation import (
    bundle_components_to_categories,
    redistribute_unavailable_weights,
)
from tools.security_scoring.domain.hardening_categories import (
    CATEGORY_WEIGHTS,
    HardeningCategory,
)
from tools.security_scoring.domain.models import ScoreComponent

# ---------------------------------------------------------------------------
# Test-Helpers
# ---------------------------------------------------------------------------


def _comp(name: str, source_tool: str, score: float = 80.0) -> ScoreComponent:
    """Builder fuer ScoreComponent-Test-Daten."""
    return ScoreComponent(
        name=name,
        score=score,
        weight=0.20,  # irrelevant fuer Bundle/Redistribute
        source_tool=source_tool,
    )


def _comp_org(display_name: str, score: float = 80.0) -> ScoreComponent:
    """Helper: ScoreComponent fuer org_security mit echtem Anzeigenamen."""
    return ScoreComponent(
        name=display_name,
        score=score,
        weight=0.10,
        source_tool="org_security",
    )


# ===========================================================================
# bundle_components_to_categories
# ===========================================================================


class TestBundleHappyPath:
    """Happy-Path: eindeutige Source-Tools landen in den korrekten Buckets."""

    def test_empty_input_yields_five_empty_buckets(self):
        result = bundle_components_to_categories([])
        assert set(result.keys()) == set(HardeningCategory)
        assert all(len(bucket) == 0 for bucket in result.values())

    def test_single_component_lands_in_correct_bucket(self):
        c = _comp("API Security", "api_security")
        result = bundle_components_to_categories([c])
        assert result[HardeningCategory.API_SECURITY] == [c]
        # Andere Buckets sollten leer sein
        for cat, bucket in result.items():
            if cat != HardeningCategory.API_SECURITY:
                assert bucket == []

    def test_multiple_components_same_category(self):
        # CVE-Patch hat 3 Quellen: cve_exposure, dependency_auditor, tech_stack
        c1 = _comp("CVE", "cve_exposure")
        c2 = _comp("Deps", "dependency_auditor")
        c3 = _comp("TechStack", "tech_stack")
        result = bundle_components_to_categories([c1, c2, c3])
        assert result[HardeningCategory.CVE_PATCH] == [c1, c2, c3]
        assert result[HardeningCategory.NETWORK] == []

    def test_all_five_categories_filled(self):
        comps = [
            _comp("CVE", "cve_exposure"),
            _comp("Net", "network_scanner"),
            _comp("Pwd", "password_policy"),
            _comp("API", "api_security"),
            _comp("Sys", "system_scanner"),
        ]
        result = bundle_components_to_categories(comps)
        for cat in HardeningCategory:
            assert len(result[cat]) == 1, f"Kategorie {cat} hat falsche Anzahl"


# ===========================================================================
# Org-Security-Reverse-Lookup
# ===========================================================================


class TestOrgSecurityReverseLookup:
    """org_security-Komponenten werden ueber name auf Kategorien gemappt."""

    def test_mfa_lands_in_password(self):
        c = _comp("Multi-Factor Authentication", "org_security")
        result = bundle_components_to_categories([c])
        assert result[HardeningCategory.PASSWORD] == [c]

    def test_passwort_manager_lands_in_password(self):
        c = _comp("Passwort-Manager", "org_security")
        result = bundle_components_to_categories([c])
        assert result[HardeningCategory.PASSWORD] == [c]

    def test_phishing_lands_in_network(self):
        c = _comp("Phishing-Schutz", "org_security")
        result = bundle_components_to_categories([c])
        assert result[HardeningCategory.NETWORK] == [c]

    def test_dsgvo_dropped_from_score(self):
        # DSGVO-Compliance ist Report-Layer, kein technischer Score
        c = _comp("DSGVO-Compliance", "org_security")
        result = bundle_components_to_categories([c])
        for bucket in result.values():
            assert c not in bucket

    def test_unknown_org_security_name_raises(self):
        c = _comp("Unbekannte-Metrik-Anzeige", "org_security")
        with pytest.raises(ValueError, match="unbekanntem Anzeigenamen"):
            bundle_components_to_categories([c])


# ===========================================================================
# Unknown Source-Tool
# ===========================================================================


class TestBundleUnknownTool:
    def test_unknown_source_tool_raises_key_error(self):
        c = _comp("Mystery", "new_tool_not_in_mapping")
        with pytest.raises(KeyError, match="Unbekanntes source_tool"):
            bundle_components_to_categories([c])


# ===========================================================================
# redistribute_unavailable_weights
# ===========================================================================


class TestRedistributeAllPresent:
    """Wenn alle 5 Kategorien anwesend sind, ist Output = Basis."""

    def test_all_five_yields_base_weights(self):
        present = set(HardeningCategory)
        result = redistribute_unavailable_weights(present)
        assert result == pytest.approx(dict(CATEGORY_WEIGHTS), abs=1e-9)

    def test_all_five_sum_is_one(self):
        result = redistribute_unavailable_weights(set(HardeningCategory))
        assert sum(result.values()) == pytest.approx(1.0, abs=1e-9)


class TestRedistributeMissingCategory:
    """Wenn eine Kategorie fehlt, wird ihr Gewicht proportional umverteilt."""

    def test_system_hardening_missing_yields_sum_one(self):
        # E (system_hardening, 0.20) fehlt — A+B+C+D sollten auf 1.0 normieren
        present = {
            HardeningCategory.CVE_PATCH,
            HardeningCategory.NETWORK,
            HardeningCategory.PASSWORD,
            HardeningCategory.API_SECURITY,
        }
        result = redistribute_unavailable_weights(present)
        assert sum(result.values()) == pytest.approx(1.0, abs=1e-9)
        assert HardeningCategory.SYSTEM_HARDENING not in result

    def test_system_hardening_missing_preserves_ratios(self):
        # A:B:C:D bleibt 0.30:0.20:0.15:0.15 — Anteile 30:20:15:15 von 80 sind
        # 0.375:0.250:0.1875:0.1875 nach Normierung auf 1.0
        present = {
            HardeningCategory.CVE_PATCH,
            HardeningCategory.NETWORK,
            HardeningCategory.PASSWORD,
            HardeningCategory.API_SECURITY,
        }
        result = redistribute_unavailable_weights(present)
        # 0.30 / 0.80 = 0.375
        assert result[HardeningCategory.CVE_PATCH] == pytest.approx(0.375, abs=1e-9)
        # 0.20 / 0.80 = 0.25
        assert result[HardeningCategory.NETWORK] == pytest.approx(0.25, abs=1e-9)
        # 0.15 / 0.80 = 0.1875
        assert result[HardeningCategory.PASSWORD] == pytest.approx(0.1875, abs=1e-9)
        assert result[HardeningCategory.API_SECURITY] == pytest.approx(0.1875, abs=1e-9)

    def test_single_category_present(self):
        # Edge: nur eine Kategorie hat Daten — sie bekommt 100 % Gewicht
        present = {HardeningCategory.CVE_PATCH}
        result = redistribute_unavailable_weights(present)
        assert result == {HardeningCategory.CVE_PATCH: pytest.approx(1.0, abs=1e-9)}


class TestRedistributeEdgeCases:
    def test_empty_present_raises(self):
        with pytest.raises(ValueError, match="present_categories ist leer"):
            redistribute_unavailable_weights(set())

    def test_zero_base_sum_raises(self):
        # Mit Custom-Base, wo alle "present" Kategorien 0-Gewicht haben
        zero_base = {cat: 0.0 for cat in HardeningCategory}
        with pytest.raises(ValueError, match="Summe der Basis-Gewichte"):
            redistribute_unavailable_weights(
                {HardeningCategory.CVE_PATCH}, base_weights=zero_base
            )

    def test_custom_base_weights(self):
        # Tests koennen eigene Basis injizieren
        custom_base = {
            HardeningCategory.CVE_PATCH: 0.50,
            HardeningCategory.NETWORK: 0.50,
        }
        present = {HardeningCategory.CVE_PATCH, HardeningCategory.NETWORK}
        result = redistribute_unavailable_weights(present, base_weights=custom_base)
        assert result == pytest.approx(custom_base, abs=1e-9)


# ===========================================================================
# Integration-Smoke
# ===========================================================================


class TestIntegrationSmoke:
    """Sanity-Check: typischer Aufruf-Pfad Bundle → Redistribute."""

    def test_bundle_then_redistribute_typical_scenario(self):
        # Realistisch: alle Kategorien ausser System-Hardening haben Daten
        comps = [
            _comp("CVE", "cve_exposure"),
            _comp("Net", "network_scanner"),
            _comp("Cert", "cert_monitor"),
            _comp_org("Multi-Factor Authentication", 90.0),
            _comp("API", "api_security"),
            # Keine system_scanner-Komponente — Phase 3 noch nicht fertig
        ]

        buckets = bundle_components_to_categories(comps)
        present = {cat for cat, bucket in buckets.items() if bucket}

        assert HardeningCategory.SYSTEM_HARDENING not in present
        weights = redistribute_unavailable_weights(present)
        assert sum(weights.values()) == pytest.approx(1.0, abs=1e-9)
        assert HardeningCategory.SYSTEM_HARDENING not in weights
