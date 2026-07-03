"""Tests fuer das deterministische Regulatorik-Mapping.

Deckt ab: Kategorie- + check_id-Mapping, Override-Logik, Lueckentoleranz,
Label/Framework-Vollstaendigkeit, Modul-Lade-Invariante, UWG-Negativtest und
einen Drift-Guard gegen das echte ``HardeningCategory``-Enum (Schicht-Bruecke).
"""

from __future__ import annotations

from core.compliance.regulatory_mapping import (
    _EXPECTED_CATEGORY_VALUES,
    CATEGORY_TO_REGULATORY,
    CHECK_ID_TO_REGULATORY,
    REGREF_FRAMEWORK,
    REGREF_LABELS,
    REGULATORY_DISCLAIMER,
    REGULATORY_INDICATIVE_PREFIX,
    RegFramework,
    RegReference,
    map_finding_to_regulatory,
    regulatory_framework,
    regulatory_label,
    validate_mapping_integrity,
)

# Positive Konformitaets-Behauptungen, die NIE erscheinen duerfen (UWG, Auflage 3).
_FORBIDDEN_CLAIM_TOKENS = (
    "konform",
    "erfüllt",
    "erfuellt",
    "rechtssicher",
    "gesetzeskonform",
    "compliant",
)


class TestMapFindingToRegulatory:
    def test_kategorie_default(self) -> None:
        refs = map_finding_to_regulatory("cve_patch")
        assert refs == (
            RegReference.NIS2_ART21_2A,
            RegReference.NIS2_ART21_2C,
            RegReference.NIS2_ART21_2D,
            RegReference.NIS2_ART21_2E,
        )

    def test_system_hardening_ohne_check_nutzt_kategorie(self) -> None:
        refs = map_finding_to_regulatory("system_hardening")
        assert RegReference.NIS2_ART21_2A in refs
        assert RegReference.TISAX_INFO_HANDLING in refs

    def test_check_id_override_gewinnt(self) -> None:
        # SH-010 = BitLocker -> Kryptografie/DSGVO, NICHT das Kategorie-Default.
        refs = map_finding_to_regulatory("system_hardening", check_id="SH-010")
        assert refs == (RegReference.NIS2_ART21_2H, RegReference.DSGVO_ART32)
        assert refs != map_finding_to_regulatory("system_hardening")

    def test_unbekannter_check_faellt_auf_kategorie(self) -> None:
        refs = map_finding_to_regulatory("system_hardening", check_id="SH-999")
        assert refs == map_finding_to_regulatory("system_hardening")

    def test_unbekannte_kategorie_leeres_tuple(self) -> None:
        assert map_finding_to_regulatory("gibts-nicht") == ()
        assert map_finding_to_regulatory("gibts-nicht", check_id="SH-999") == ()

    def test_alle_check_ids_sh001_bis_sh010(self) -> None:
        for n in range(1, 11):
            cid = f"SH-{n:03d}"
            assert cid in CHECK_ID_TO_REGULATORY
            assert map_finding_to_regulatory("system_hardening", check_id=cid)


class TestLabelsUndFramework:
    def test_label_fuer_jede_referenz(self) -> None:
        for ref in RegReference:
            assert regulatory_label(ref)  # nicht leer
            assert ref in REGREF_LABELS

    def test_framework_fuer_jede_referenz(self) -> None:
        for ref in RegReference:
            assert isinstance(regulatory_framework(ref), RegFramework)

    def test_nis2_referenzen_haben_nis2_framework(self) -> None:
        assert regulatory_framework(RegReference.NIS2_ART21_2A) is RegFramework.NIS2
        assert regulatory_framework(RegReference.DSGVO_ART32) is RegFramework.DSGVO


class TestUwgWording:
    def test_labels_enthalten_keine_konformitaets_behauptung(self) -> None:
        for ref, label in REGREF_LABELS.items():
            low = label.lower()
            for token in _FORBIDDEN_CLAIM_TOKENS:
                assert token not in low, (
                    f"{ref.value}: verbotenes Wort {token!r} in Label"
                )
            assert "indikativ" in low, (
                f"{ref.value}: Label muss 'indikativ' kennzeichnen"
            )

    def test_indikativ_prefix_ohne_behauptung(self) -> None:
        low = REGULATORY_INDICATIVE_PREFIX.lower()
        assert "indikativ" in low
        for token in _FORBIDDEN_CLAIM_TOKENS:
            assert token not in low

    def test_disclaimer_ist_vorhanden_und_warnt(self) -> None:
        assert REGULATORY_DISCLAIMER
        assert "2555" in REGULATORY_DISCLAIMER
        low = REGULATORY_DISCLAIMER.lower()
        assert "keine rechts" in low
        # Der Disclaimer darf selbst keine Erfuellungs-Behauptung machen.
        assert "konform" not in low
        assert "rechtssicher" not in low


class TestIntegritaet:
    def test_validate_mapping_integrity_passt(self) -> None:
        validate_mapping_integrity()  # darf nicht werfen

    def test_alle_erwarteten_kategorien_gemappt(self) -> None:
        for cat in _EXPECTED_CATEGORY_VALUES:
            assert cat in CATEGORY_TO_REGULATORY
            assert CATEGORY_TO_REGULATORY[cat]  # nicht leer

    def test_keine_verwaiste_referenz_in_tabellen(self) -> None:
        used: set[RegReference] = set()
        for refs in CATEGORY_TO_REGULATORY.values():
            used.update(refs)
        for refs in CHECK_ID_TO_REGULATORY.values():
            used.update(refs)
        for ref in used:
            assert ref in REGREF_LABELS
            assert ref in REGREF_FRAMEWORK


class TestDriftGuard:
    """Schicht-Bruecke: das Mapping schluesselt ueber HardeningCategory-STRINGS
    (kein core->tools-Import). Dieser Test (darf tools importieren) sichert ab,
    dass die hartcodierten Strings exakt dem echten Enum entsprechen."""

    def test_expected_values_decken_hardening_category_enum(self) -> None:
        from tools.security_scoring.domain.hardening_categories import HardeningCategory

        enum_values = {c.value for c in HardeningCategory}
        assert set(_EXPECTED_CATEGORY_VALUES) == enum_values
        # Jeder echte Enum-Wert hat ein Mapping.
        for value in enum_values:
            assert value in CATEGORY_TO_REGULATORY

    def test_check_ids_existieren_im_scanner(self) -> None:
        # Drift-Guard gegen die echten SH-Konstanten (kein erfundener Check).
        from tools.system_scanner.application import windows_hardening_scanner as whs

        scanner_ids = {
            whs.SH_001_FIREWALL,
            whs.SH_002_UAC,
            whs.SH_003_RDP,
            whs.SH_004_AUTO_UPDATE,
            whs.SH_005_SMBV1,
            whs.SH_006_GUEST_ACCOUNT,
            whs.SH_007_PASSWORD_POLICY,
            whs.SH_008_AUTORUN,
            whs.SH_009_LOCAL_ADMINS,
            whs.SH_010_BITLOCKER,
        }
        assert set(CHECK_ID_TO_REGULATORY) == scanner_ids
