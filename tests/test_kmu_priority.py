"""Tests fuer KMU-Priorisierung, Aufwands-Schaetzung und Compliance-Sicht.

Deckt ab: compute_kmu_priority (Formel + Clamping + Validierung),
estimate_person_weeks/format_capacity (Buckets, Wording), build_compliance_view
(Integration mit dem Mapping) und den Determinismus aller Funktionen.
"""

from __future__ import annotations

import pytest

from core.compliance.kmu_priority import (
    ComplianceView,
    build_compliance_view,
    compute_kmu_priority,
)
from core.compliance.regulatory_mapping import (
    REGULATORY_DISCLAIMER,
    REGULATORY_INDICATIVE_PREFIX,
    RegReference,
)
from core.rules.classifier import estimate_person_weeks, format_capacity
from core.security.severity import Severity
from tests.test_regulatory_mapping import _FORBIDDEN_CLAIM_TOKENS


class TestComputeKmuPriority:
    def test_critical_quick_mit_regbezug(self) -> None:
        # 4*20 + 15 - 0 = 95
        assert compute_kmu_priority(Severity.CRITICAL, "quick", reg_pflicht=True) == 95

    def test_critical_langfrist_ohne_regbezug(self) -> None:
        # 4*20 + 0 - 15 = 65
        assert (
            compute_kmu_priority(Severity.CRITICAL, "langfrist", reg_pflicht=False)
            == 65
        )

    def test_high_mittel_mit_regbezug(self) -> None:
        # 3*20 + 15 - 5 = 70
        assert compute_kmu_priority(Severity.HIGH, "mittel", reg_pflicht=True) == 70

    def test_info_langfrist_clampt_auf_null(self) -> None:
        # 0*20 + 0 - 15 = -15 -> 0
        assert compute_kmu_priority(Severity.INFO, "langfrist", reg_pflicht=False) == 0

    def test_regbezug_hebt_prioritaet(self) -> None:
        ohne = compute_kmu_priority(Severity.MEDIUM, "mittel", reg_pflicht=False)
        mit = compute_kmu_priority(Severity.MEDIUM, "mittel", reg_pflicht=True)
        assert mit == ohne + 15

    def test_quick_schlaegt_langfrist_bei_gleicher_severity(self) -> None:
        q = compute_kmu_priority(Severity.HIGH, "quick", reg_pflicht=False)
        lang = compute_kmu_priority(Severity.HIGH, "langfrist", reg_pflicht=False)
        assert q > lang

    def test_clamp_obergrenze(self) -> None:
        assert compute_kmu_priority(Severity.CRITICAL, "quick", reg_pflicht=True) <= 100

    def test_unbekannte_urgency_wirft(self) -> None:
        with pytest.raises(ValueError, match="Effort-Klasse"):
            compute_kmu_priority(Severity.HIGH, "sofort", reg_pflicht=True)

    def test_deterministisch(self) -> None:
        a = compute_kmu_priority(Severity.HIGH, "mittel", reg_pflicht=True)
        b = compute_kmu_priority(Severity.HIGH, "mittel", reg_pflicht=True)
        assert a == b


class TestEstimatePersonWeeks:
    def test_mittel_single_asset(self) -> None:
        assert estimate_person_weeks("mittel", 1) == 0.5

    def test_mittel_mehrere_assets_skaliert(self) -> None:
        assert estimate_person_weeks("mittel", 10) == 1.0

    def test_langfrist_single(self) -> None:
        assert estimate_person_weeks("langfrist", 1) == 6.0

    def test_langfrist_viele_assets(self) -> None:
        assert estimate_person_weeks("langfrist", 100) == 24.0

    def test_quick_single_unter_einem_tag(self) -> None:
        assert estimate_person_weeks("quick", 1) < 0.2

    def test_asset_buckets_grenzen(self) -> None:
        # Bucket 1 / 2-50 / >50 (wie H2/H6/H12).
        assert estimate_person_weeks("mittel", 2) == 1.0
        assert estimate_person_weeks("mittel", 50) == 1.0
        assert estimate_person_weeks("mittel", 51) == 2.0

    def test_unbekannte_urgency_wirft(self) -> None:
        with pytest.raises(ValueError, match="Effort-Klasse"):
            estimate_person_weeks("sofort", 1)

    def test_asset_count_unter_eins_wirft(self) -> None:
        with pytest.raises(ValueError, match="asset_count"):
            estimate_person_weeks("mittel", 0)


class TestFormatCapacity:
    def test_sehr_klein_unter_einem_tag(self) -> None:
        assert format_capacity(0.1) == "fixbar mit 1 Person in unter 1 Tag"

    def test_eine_woche_singular(self) -> None:
        assert format_capacity(1.0) == "fixbar mit 1 Person in ca. 1 Woche"

    def test_mehrere_wochen_plural(self) -> None:
        assert format_capacity(6.0) == "fixbar mit 1 Person in ca. 6 Wochen"

    def test_dezimal_mit_komma(self) -> None:
        assert format_capacity(0.5) == "fixbar mit 1 Person in ca. 0,5 Wochen"


class TestBuildComplianceView:
    def test_system_hardening_mit_check_override(self) -> None:
        view = build_compliance_view(
            "system_hardening", Severity.CRITICAL, "quick", check_id="SH-001"
        )
        assert isinstance(view, ComplianceView)
        assert view.reg_refs == (
            RegReference.NIS2_ART21_2A,
            RegReference.ITSIG_BSIG_8A_ABS1,
        )
        assert len(view.reg_labels) == 2
        assert view.kmu_priority == 95  # CRITICAL + reg + quick
        assert view.capacity_hint == "fixbar mit 1 Person in unter 1 Tag"
        assert view.disclaimer == REGULATORY_DISCLAIMER

    def test_kategorie_ohne_check(self) -> None:
        view = build_compliance_view("cve_patch", Severity.HIGH, "mittel")
        assert view.check_id is None
        assert RegReference.NIS2_ART21_2D in view.reg_refs
        assert view.kmu_priority == 70  # HIGH(60) + reg(15) - mittel(5)

    def test_unbekannte_kategorie_leer_aber_valide(self) -> None:
        view = build_compliance_view("gibts-nicht", Severity.LOW, "quick")
        assert view.reg_refs == ()
        assert view.reg_labels == ()
        # Ohne Norm-Bezug -> kein reg_bonus: LOW(1*20) - quick(0) = 20
        assert view.kmu_priority == 20
        assert view.disclaimer  # Disclaimer trotzdem immer mitgefuehrt

    def test_view_ist_immutable(self) -> None:
        view = build_compliance_view("network", Severity.MEDIUM, "mittel")
        with pytest.raises(Exception):  # noqa: B017,PT011 — frozen dataclass
            view.kmu_priority = 0  # type: ignore[misc]

    def test_uwg_kein_konformitaets_wording_im_gesamten_output(self) -> None:
        # Auflage 3 (Legal-Lens): KEIN String-Feld einer realen View darf eine
        # Konformitaets-Behauptung enthalten — geprueft ueber mehrere Pfade
        # (Kategorie, Check-Override, Leer-Mapping) und ALLE Felder, gegen die
        # KANONISCHE Token-Liste (kein zweiter, driftender Satz).
        views = [
            build_compliance_view(
                "system_hardening", Severity.CRITICAL, "quick", check_id="SH-001"
            ),
            build_compliance_view("cve_patch", Severity.HIGH, "mittel"),
            build_compliance_view(
                "api_security", Severity.HIGH, "langfrist", asset_count=80
            ),
            build_compliance_view("gibts-nicht", Severity.LOW, "quick"),
        ]
        for view in views:
            felder = [view.capacity_hint, view.disclaimer, *view.reg_labels]
            for text in felder:
                low = text.lower()
                for token in _FORBIDDEN_CLAIM_TOKENS:
                    assert token not in low, f"verbotenes Wort {token!r} in {text!r}"

    def test_indikativ_prefix_ist_disclaimer_anfang(self) -> None:
        # Drift-Guard: der Prefix ist bewusst der Disclaimer-Anfang.
        assert REGULATORY_DISCLAIMER.startswith(REGULATORY_INDICATIVE_PREFIX)

    def test_deterministisch(self) -> None:
        # SH-007 ist ein Kategorie-E-Check (system_hardening) — realistische Kombi.
        a = build_compliance_view(
            "system_hardening", Severity.HIGH, "mittel", check_id="SH-007"
        )
        b = build_compliance_view(
            "system_hardening", Severity.HIGH, "mittel", check_id="SH-007"
        )
        assert a == b
