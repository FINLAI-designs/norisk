"""regulatory_mapping — deterministisches Regulatorik-Mapping je Finding.

Bildet die fixen Hardening-Kategorien und — fuer Kategorie E — die
einzelnen Hardening-Checks (SH-001..SH-010) auf ein **festes Enum** von
Norm-Referenzen ab (NIS2 Art. 21 Abs. 2, exemplarisch IT-SiG 2.0 / DSGVO /
TISAX). Baut Phase 5 (NIS2-Mapping) aus.

Designprinzipien-Auflagen):

* **Deterministisch + tabellengetrieben** — reine Lookups ueber frozen
  ``MappingProxyType``-Tabellen, KEINE Heuristik, KEIN LLM, KEIN Freitext.
  Eine KI darf das Ergebnis dieser Funktionen NIE ueberschreiben.
* **Festes Enum** (:class:`RegReference`) statt Freitext — Werte sind stabile
  snake_case-Identifier (kuenftige DB-/Export-Identifier, Aenderung = breaking).
* **Indikativ, keine Rechtsberatung** — die Label-Funktion liefert ausschliesslich
  *Bezuege* ("indikativ"), NIE eine Erfuellungs-/Konformitaets-Aussage. Es gibt
  bewusst KEINE Funktion, die einen Boolean ``compliant`` liefert (UWG, Auflage 3).
* **Schichtrein** — ``core/`` ohne Import aus ``tools/``: das Mapping schluesselt
  ueber den **String-Wert** der Hardening-Kategorie (``"cve_patch"`` etc.), nicht
  ueber den importierten ``HardeningCategory``-Typ. Ein Drift-Test (tests/) prueft,
  dass die hier erwarteten Werte exakt der ``HardeningCategory``-Enum entsprechen.

DSGVO bleibt — wie im Hardening-Score (``hardening_categories.py``) — ein
Report-Layer-Bezug; das Mapping beeinflusst den Score NICHT (additiv).
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class RegFramework(StrEnum):
    """Regulatorische Rahmenwerke, auf die:class:`RegReference` verweist."""

    NIS2 = "nis2"
    ITSIG = "it_sig_2"
    DSGVO = "dsgvo"
    TISAX = "tisax"


class RegReference(StrEnum):
    """Festes Enum der Norm-Referenzen (Werte = stabile DB-/Export-Identifier).

    NIS2 Art. 21 Abs. 2 lit. a-i sind vollstaendig abgebildet (Pflicht);
    IT-SiG 2.0 / DSGVO / TISAX exemplarisch fuer die DACH-KMU-Zielgruppe.
    """

    # NIS2 (EU-Richtlinie 2022/2555) Art. 21 Abs. 2 lit. a-i
    NIS2_ART21_2A = "nis2_art21_2a"  # Risikoanalyse + Sicherheitskonzepte
    NIS2_ART21_2B = "nis2_art21_2b"  # Bewaeltigung von Sicherheitsvorfaellen
    NIS2_ART21_2C = "nis2_art21_2c"  # Aufrechterhaltung des Betriebs / Backup
    NIS2_ART21_2D = "nis2_art21_2d"  # Sicherheit der Lieferkette
    NIS2_ART21_2E = "nis2_art21_2e"  # Erwerb/Entwicklung/Wartung + Schwachstellen
    NIS2_ART21_2F = "nis2_art21_2f"  # Bewertung der Wirksamkeit der Massnahmen
    NIS2_ART21_2G = "nis2_art21_2g"  # Cyberhygiene + Schulungen
    NIS2_ART21_2H = "nis2_art21_2h"  # Kryptografie und Verschluesselung
    NIS2_ART21_2I = "nis2_art21_2i"  # Personalsicherheit + Zugriffskontrolle
    # IT-SiG 2.0 / BSIG (exemplarisch)
    ITSIG_BSIG_8A_ABS1 = "itsig_bsig_8a_abs1"  # Massnahmen Stand der Technik
    ITSIG_BSIG_8B_ABS4A = "itsig_bsig_8b_abs4a"  # Systeme zur Angriffserkennung
    # DSGVO (exemplarisch; Report-Layer, kein Score-Einfluss)
    DSGVO_ART32 = "dsgvo_art32"  # Sicherheit der Verarbeitung (TOM)
    DSGVO_ART25 = "dsgvo_art25"  # Datenschutz durch Technikgestaltung
    # TISAX / ISO-27001-Anlehnung (exemplarisch)
    TISAX_INFO_HANDLING = "tisax_info_handling"  # Umgang mit Informationssicherheit
    TISAX_ACCESS_CONTROL = "tisax_access_control"  # Zugriffssteuerung


#: Zuordnung jeder Referenz zu ihrem Rahmenwerk (fuer Gruppierung/Filter).
REGREF_FRAMEWORK: Final[MappingProxyType[RegReference, RegFramework]] = (
    MappingProxyType(
        {
            RegReference.NIS2_ART21_2A: RegFramework.NIS2,
            RegReference.NIS2_ART21_2B: RegFramework.NIS2,
            RegReference.NIS2_ART21_2C: RegFramework.NIS2,
            RegReference.NIS2_ART21_2D: RegFramework.NIS2,
            RegReference.NIS2_ART21_2E: RegFramework.NIS2,
            RegReference.NIS2_ART21_2F: RegFramework.NIS2,
            RegReference.NIS2_ART21_2G: RegFramework.NIS2,
            RegReference.NIS2_ART21_2H: RegFramework.NIS2,
            RegReference.NIS2_ART21_2I: RegFramework.NIS2,
            RegReference.ITSIG_BSIG_8A_ABS1: RegFramework.ITSIG,
            RegReference.ITSIG_BSIG_8B_ABS4A: RegFramework.ITSIG,
            RegReference.DSGVO_ART32: RegFramework.DSGVO,
            RegReference.DSGVO_ART25: RegFramework.DSGVO,
            RegReference.TISAX_INFO_HANDLING: RegFramework.TISAX,
            RegReference.TISAX_ACCESS_CONTROL: RegFramework.TISAX,
        }
    )
)

#: Menschenlesbare, **indikative** Labels (Sie-Form-tauglich, GUI/PDF).
#: BEWUSST nur "Bezug zu..." — NIE "konform"/"erfuellt" (UWG, Auflage 3).
REGREF_LABELS: Final[MappingProxyType[RegReference, str]] = MappingProxyType(
    {
        RegReference.NIS2_ART21_2A: "Bezug zu NIS2 Art. 21 Abs. 2 lit. a – Risikoanalyse & Sicherheitskonzepte (indikativ)",
        RegReference.NIS2_ART21_2B: "Bezug zu NIS2 Art. 21 Abs. 2 lit. b – Bewaeltigung von Sicherheitsvorfaellen (indikativ)",
        RegReference.NIS2_ART21_2C: "Bezug zu NIS2 Art. 21 Abs. 2 lit. c – Aufrechterhaltung des Betriebs/Backup (indikativ)",
        RegReference.NIS2_ART21_2D: "Bezug zu NIS2 Art. 21 Abs. 2 lit. d – Sicherheit der Lieferkette (indikativ)",
        RegReference.NIS2_ART21_2E: "Bezug zu NIS2 Art. 21 Abs. 2 lit. e – Wartung & Schwachstellenmanagement (indikativ)",
        RegReference.NIS2_ART21_2F: "Bezug zu NIS2 Art. 21 Abs. 2 lit. f – Bewertung der Wirksamkeit (indikativ)",
        RegReference.NIS2_ART21_2G: "Bezug zu NIS2 Art. 21 Abs. 2 lit. g – Cyberhygiene & Schulungen (indikativ)",
        RegReference.NIS2_ART21_2H: "Bezug zu NIS2 Art. 21 Abs. 2 lit. h – Kryptografie & Verschluesselung (indikativ)",
        RegReference.NIS2_ART21_2I: "Bezug zu NIS2 Art. 21 Abs. 2 lit. i – Zugriffskontrolle & Personalsicherheit (indikativ)",
        RegReference.ITSIG_BSIG_8A_ABS1: "Bezug zu IT-SiG 2.0 / BSIG § 8a Abs. 1 – Massnahmen nach Stand der Technik (indikativ)",
        RegReference.ITSIG_BSIG_8B_ABS4A: "Bezug zu IT-SiG 2.0 / BSIG § 8b – Systeme zur Angriffserkennung (indikativ)",
        RegReference.DSGVO_ART32: "Bezug zu DSGVO Art. 32 – Sicherheit der Verarbeitung (indikativ)",
        RegReference.DSGVO_ART25: "Bezug zu DSGVO Art. 25 – Datenschutz durch Technikgestaltung (indikativ)",
        RegReference.TISAX_INFO_HANDLING: "Bezug zu TISAX/VDA-ISA – Umgang mit Informationssicherheit (indikativ)",
        RegReference.TISAX_ACCESS_CONTROL: "Bezug zu TISAX/VDA-ISA – Zugriffssteuerung (indikativ)",
    }
)

#: Erwartete Hardening-Kategorie-Werte (Spiegel von ``HardeningCategory``-VALUES,
#: bewusst als Strings dupliziert, um core->tools-Import zu vermeiden; ein
#: Drift-Test in tests/ prueft die Gleichheit gegen das echte Enum).
_EXPECTED_CATEGORY_VALUES: Final[tuple[str, ...]] = (
    "cve_patch",
    "network",
    "password",
    "api_security",
    "system_hardening",
)

#: PRIMAER-Mapping pro Hardening-Kategorie (deckt JEDES Finding ab, da jede
#: ScoreComponent ueber SOURCE_TOOL_TO_CATEGORY eindeutig in eine Kategorie faellt).
#: Schluessel = HardeningCategory-StrEnum-VALUE (String, kein Typ-Import).
#: Quelle: Brain Phase-5-Tabelle (NoRisk_HARDENING_SCORE.md).
CATEGORY_TO_REGULATORY: Final[MappingProxyType[str, tuple[RegReference, ...]]] = (
    MappingProxyType(
        {
            "cve_patch": (
                RegReference.NIS2_ART21_2A,
                RegReference.NIS2_ART21_2C,
                RegReference.NIS2_ART21_2D,
                RegReference.NIS2_ART21_2E,
            ),
            "network": (
                RegReference.NIS2_ART21_2B,
                RegReference.ITSIG_BSIG_8B_ABS4A,
            ),
            "password": (
                RegReference.NIS2_ART21_2I,
                RegReference.NIS2_ART21_2G,
                RegReference.TISAX_ACCESS_CONTROL,
            ),
            "api_security": (
                RegReference.NIS2_ART21_2H,
                RegReference.DSGVO_ART32,
            ),
            "system_hardening": (
                RegReference.NIS2_ART21_2A,
                RegReference.ITSIG_BSIG_8A_ABS1,
                RegReference.TISAX_INFO_HANDLING,
            ),
        }
    )
)

#: OPTIONALE Verfeinerung pro Hardening-Check (nur Kategorie E, die einzigen
#: stabilen Per-Finding-IDs im Code: tools/system_scanner SH-001..SH-010).
#: Gewinnt fuer Kategorie E gegen das Kategorie-Default. KEINE erfundenen IDs.
CHECK_ID_TO_REGULATORY: Final[MappingProxyType[str, tuple[RegReference, ...]]] = (
    MappingProxyType(
        {
            "SH-001": (
                RegReference.NIS2_ART21_2A,
                RegReference.ITSIG_BSIG_8A_ABS1,
            ),  # Firewall
            "SH-002": (RegReference.NIS2_ART21_2I, RegReference.NIS2_ART21_2A),  # UAC
            "SH-003": (RegReference.NIS2_ART21_2I,),  # RDP deaktiviert
            "SH-004": (RegReference.NIS2_ART21_2E,),  # Automatische Updates
            "SH-005": (RegReference.NIS2_ART21_2E, RegReference.NIS2_ART21_2A),  # SMBv1
            "SH-006": (RegReference.NIS2_ART21_2I,),  # Gastkonto deaktiviert
            "SH-007": (
                RegReference.NIS2_ART21_2I,
                RegReference.NIS2_ART21_2G,
            ),  # PW-Mindestlaenge
            "SH-008": (RegReference.NIS2_ART21_2A,),  # Autorun deaktiviert
            "SH-009": (RegReference.NIS2_ART21_2I,),  # Lokale Admins begrenzt
            "SH-010": (
                RegReference.NIS2_ART21_2H,
                RegReference.DSGVO_ART32,
            ),  # BitLocker
        }
    )
)

#: Pflicht-Disclaimer (Auflage 2). Zentral, nicht dupliziert.
REGULATORY_DISCLAIMER: Final[str] = (
    "Indikatives Mapping nach EU-Richtlinie 2022/2555 (NIS2) sowie nationalen/"
    "branchenspezifischen Normen. Keine Rechts- oder Compliance-Beratung; vor einer "
    "verbindlichen Bewertung ist eine anwaltliche Pruefung erforderlich."
)

#: Indikativ-Praefix fuer UI-Texte (Auflage 3 — nie "konform").
REGULATORY_INDICATIVE_PREFIX: Final[str] = (
    "Indikatives Mapping nach EU-Richtlinie 2022/2555"
)


def map_finding_to_regulatory(
    category_value: str, *, check_id: str | None = None
) -> tuple[RegReference, ...]:
    """Liefert die indikativen Norm-Referenzen eines Findings (deterministisch).

    Args:
        category_value: ``HardeningCategory``-Wert des Findings (String, z.B.
            ``"cve_patch"``). Quelle: ``map_source_tool_to_category`` (security_scoring).
        check_id: Optionaler Hardening-Check-Identifier (``"SH-001"``...). Ist er
            gesetzt UND bekannt, ueberstimmt die feinere Check-Zuordnung das
            ``category_value`` **vollstaendig** — die SH-IDs sind ausschliesslich
            Kategorie-E-Checks (``system_hardening``), daher ist diese Verengung
            korrekt. Die Check-Refs DUERFEN bewusst eine Teilmenge des Kategorie-
            Defaults sein (z.B. SH-003/RDP -> nur Zugriffskontrolle).

    Returns:
        Ein (ggf. leeres) Tuple fester:class:`RegReference`-Member. Leer, wenn
        weder ``check_id`` noch ``category_value`` bekannt sind (Lueckentoleranz —
        ein Finding ohne Mapping ist zulaessig und darf nicht crashen).
    """
    if check_id is not None and check_id in CHECK_ID_TO_REGULATORY:
        return CHECK_ID_TO_REGULATORY[check_id]
    return CATEGORY_TO_REGULATORY.get(category_value, ())


def regulatory_label(ref: RegReference) -> str:
    """Liefert das menschenlesbare, **indikative** Label einer Referenz.

    Args:
        ref: Die Norm-Referenz.

    Returns:
        Der indikative Label-Text (nie eine Erfuellungs-/Konformitaets-Aussage).
    """
    return REGREF_LABELS[ref]


def regulatory_framework(ref: RegReference) -> RegFramework:
    """Liefert das Rahmenwerk einer Norm-Referenz."""
    return REGREF_FRAMEWORK[ref]


def validate_mapping_integrity() -> None:
    """Modul-Lade-Invariante: alle Kategorien gemappt + alle Referenzen vollstaendig.

    Prueft:
        1. Jede der 5 erwarteten Hardening-Kategorien hat einen Eintrag.
        2. Jede in den Tabellen verwendete:class:`RegReference` hat ein Label
           UND ein Rahmenwerk (kein verwaister Member).

    Raises:
        AssertionError: Wenn eine Invariante verletzt ist (bricht den Import).
    """
    missing_cats = [
        c for c in _EXPECTED_CATEGORY_VALUES if c not in CATEGORY_TO_REGULATORY
    ]
    if missing_cats:
        msg = f"CATEGORY_TO_REGULATORY fehlen Kategorien: {missing_cats}"
        raise AssertionError(msg)

    used: set[RegReference] = set()
    for refs in CATEGORY_TO_REGULATORY.values():
        used.update(refs)
    for refs in CHECK_ID_TO_REGULATORY.values():
        used.update(refs)
    missing_labels = sorted(r.value for r in used if r not in REGREF_LABELS)
    if missing_labels:
        msg = f"RegReference ohne Label: {missing_labels}"
        raise AssertionError(msg)
    missing_fw = sorted(r.value for r in used if r not in REGREF_FRAMEWORK)
    if missing_fw:
        msg = f"RegReference ohne Rahmenwerk: {missing_fw}"
        raise AssertionError(msg)


# Modul-Lade-Pruefung — bricht den Import, wenn das Mapping unvollstaendig editiert wird.
validate_mapping_integrity()
