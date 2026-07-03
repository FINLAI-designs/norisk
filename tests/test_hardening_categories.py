"""
test_hardening_categories — pytest-Tests fuer
``tools.security_scoring.domain.hardening_categories``.

Phase 1 des Hardening-Score-Sprints. Pure Logik, keine I/O, keine
Side-Effects — Tests sind schnell + deterministisch.

Test-Bereiche:
    * HardeningCategory-Enum-Werte sind stabil (Schema-Vertrag).
    * CATEGORY_WEIGHTS summieren exakt auf 1.0.
    * Source-Tool → Kategorie-Mapping deckt alle bekannten Tools ab.
    * Org-Security-Sub-Metriken werden korrekt aufgesplittet.
    * Unbekannte Tools / Metriken werfen klare Exceptions.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.security_scoring.domain.hardening_categories import (
    CATEGORY_WEIGHTS,
    SOURCE_TOOL_TO_CATEGORY,
    HardeningCategory,
    map_source_tool_to_category,
    validate_weights_sum_to_one,
)

# ===========================================================================
# Enum-Vertrag
# ===========================================================================


class TestHardeningCategoryEnum:
    """Enum-Werte sind stabile DB-Identifier (Schema-Vertrag)."""

    def test_five_categories_exist(self):
        assert len(HardeningCategory) == 5

    def test_stable_string_values(self):
        # Wenn diese Werte sich aendern, bricht die Score-History-DB.
        assert HardeningCategory.CVE_PATCH.value == "cve_patch"
        assert HardeningCategory.NETWORK.value == "network"
        assert HardeningCategory.PASSWORD.value == "password"
        assert HardeningCategory.API_SECURITY.value == "api_security"
        assert HardeningCategory.SYSTEM_HARDENING.value == "system_hardening"

    def test_enum_is_string_subclass(self):
        # StrEnum erlaubt direkte String-Vergleiche
        assert HardeningCategory.CVE_PATCH == "cve_patch"


# ===========================================================================
# Gewichte
# ===========================================================================


class TestCategoryWeights:
    """Gewichtssumme + Verteilung gemaess v2."""

    def test_weights_sum_to_one_exact(self):
        total = sum(CATEGORY_WEIGHTS.values())
        assert total == pytest.approx(1.0, abs=1e-9)

    def test_validate_weights_helper_does_not_raise(self):
        # Bei korrekt geladenem Modul: kein AssertionError.
        validate_weights_sum_to_one()

    def test_validate_weights_with_strict_tolerance_passes(self):
        # Float-Default-Toleranz reicht fuer die definierten Werte.
        validate_weights_sum_to_one(tolerance=1e-12)

    def test_specific_weight_values(self):
        # v2 Verbindlich: 30/20/15/15/20
        assert CATEGORY_WEIGHTS[HardeningCategory.CVE_PATCH] == 0.30
        assert CATEGORY_WEIGHTS[HardeningCategory.NETWORK] == 0.20
        assert CATEGORY_WEIGHTS[HardeningCategory.PASSWORD] == 0.15
        assert CATEGORY_WEIGHTS[HardeningCategory.API_SECURITY] == 0.15
        assert CATEGORY_WEIGHTS[HardeningCategory.SYSTEM_HARDENING] == 0.20

    def test_weights_dict_is_immutable(self):
        # MappingProxyType verhindert versehentliche Modifikation
        with pytest.raises(TypeError):
            CATEGORY_WEIGHTS[HardeningCategory.CVE_PATCH] = 0.99  # type: ignore[index]

    def test_all_categories_have_weights(self):
        # Kein Eintrag in der Enum darf ohne Gewicht sein.
        for cat in HardeningCategory:
            assert cat in CATEGORY_WEIGHTS, f"Fehlendes Gewicht fuer {cat}"


# ===========================================================================
# Source-Tool → Category-Mapping
# ===========================================================================


class TestSourceToolMapping:
    """Per-Tool-Quellen werden korrekt auf Kategorien abgebildet."""

    @pytest.mark.parametrize(
        ("source_tool", "expected"),
        [
            ("cve_exposure",       HardeningCategory.CVE_PATCH),
            ("dependency_auditor", HardeningCategory.CVE_PATCH),
            ("tech_stack",         HardeningCategory.CVE_PATCH),
            ("network_scanner",    HardeningCategory.NETWORK),
            ("cert_monitor",       HardeningCategory.NETWORK),
            ("password_policy",    HardeningCategory.PASSWORD),
            ("api_security",       HardeningCategory.API_SECURITY),
            ("system_scanner",     HardeningCategory.SYSTEM_HARDENING),
        ],
    )
    def test_known_tool_maps_to_expected_category(self, source_tool, expected):
        assert map_source_tool_to_category(source_tool) == expected

    def test_unknown_tool_raises_key_error(self):
        with pytest.raises(KeyError, match="Unbekanntes source_tool"):
            map_source_tool_to_category("brand_new_tool_xyz")

    def test_mapping_table_is_immutable(self):
        with pytest.raises(TypeError):
            SOURCE_TOOL_TO_CATEGORY["foo"] = HardeningCategory.NETWORK  # type: ignore[index]


# ===========================================================================
# Org-Security-Split
# ===========================================================================


class TestOrgSecuritySplit:
    """org_security wird via Sub-Metrik auf Kategorien aufgesplittet."""

    def test_mfa_metric_maps_to_password(self):
        assert (
            map_source_tool_to_category("org_security", org_metric="mfa")
            == HardeningCategory.PASSWORD
        )

    def test_passwort_manager_metric_maps_to_password(self):
        assert (
            map_source_tool_to_category("org_security", org_metric="passwort_manager")
            == HardeningCategory.PASSWORD
        )

    def test_phishing_metric_maps_to_network(self):
        assert (
            map_source_tool_to_category("org_security", org_metric="phishing")
            == HardeningCategory.NETWORK
        )

    def test_dsgvo_metric_returns_none_for_report_layer(self):
        # DSGVO ist Compliance-Notiz, kein technischer Score-Beitrag
        result = map_source_tool_to_category("org_security", org_metric="dsgvo")
        assert result is None

    def test_org_security_without_metric_raises(self):
        with pytest.raises(ValueError, match="erfordert org_metric"):
            map_source_tool_to_category("org_security")

    def test_unknown_org_metric_raises(self):
        with pytest.raises(ValueError, match="Unbekannte org_security-Metrik"):
            map_source_tool_to_category("org_security", org_metric="unknown_metric")


# ===========================================================================
# Integration-Smoke
# ===========================================================================


class TestIntegrationSmoke:
    """Sanity-Check: Mapping deckt alle 10-Datenquellen ab."""

    def test_all_ten_datasources_mapped(self):
        # Aus [[NoRisk_LICENSE_PHASE2_SPRINT]] §4: 10 Datenquellen → 5 Kategorien.
        # DSGVO ist Report-Layer, daher 9 technische Quellen.
        technical_sources = [
            ("cve_exposure",       None),
            ("dependency_auditor", None),
            ("tech_stack",         None),
            ("network_scanner",    None),
            ("cert_monitor",       None),
            ("org_security",       "phishing"),
            ("password_policy",    None),
            ("org_security",       "mfa"),
            ("org_security",       "passwort_manager"),
            ("api_security",       None),
            ("system_scanner",     None),
        ]

        seen_categories: set[HardeningCategory] = set()
        for tool, metric in technical_sources:
            cat = map_source_tool_to_category(tool, org_metric=metric)
            assert cat is not None, f"{tool}/{metric} darf nicht None liefern"
            seen_categories.add(cat)

        # Alle 5 Kategorien sollten von technischen Quellen abgedeckt sein.
        assert seen_categories == set(HardeningCategory)

    def test_dsgvo_excluded_from_technical_score(self):
        # Pflicht-Test fuer-Compliance-Trennung.
        assert (
            map_source_tool_to_category("org_security", org_metric="dsgvo")
            is None
        )
