"""core.security_subject.scoping_constants — Sektoren/Rollen fürs Einstiegs-Scoping.

Reine, I/O-freie Domänen-Konstanten + Mapping für das First-Run-Scoping des
eigenen Systems. Liegt in ``core/``, damit der First-Run-Wizard (ebenfalls
``core/``) sie ohne ``tools/``-Import nutzen kann: kein core→tools).

Die Sektor-Liste bildet die NIS2-Anhänge ab:
- Anhang I = hochkritische Sektoren (Voraussetzung für "wesentliche Einrichtung")
- Anhang II = sonstige kritische Sektoren (höchstens "wichtige Einrichtung")

Das eigentliche Betroffenheits-Verdikt (Größen-Schwellen × Anhang) ist NICHT
hier, sondern bewusst späterem W0/-Code vorbehalten — dieses Modul liefert
nur die Stammdaten-Bausteine.

Schichtzugehörigkeit: core/ — keine I/O, keine Imports aus tools/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

# NIS2-Anhang-Kennungen (denormalisiert in system_profiles.nis2_anhang).
ANHANG_I = "I"
ANHANG_II = "II"
ANHANG_KEINER = ""


@dataclass(frozen=True)
class Sektor:
    """Ein wählbarer Wirtschaftssektor mit NIS2-Anhang-Zuordnung.

    Attributes:
        key: Stabiler, persistierter Schlüssel (ändert sich nie).
        label: Anzeigetext für das Dropdown.
        anhang: NIS2-Anhang (:data:`ANHANG_I` |:data:`ANHANG_II` |
:data:`ANHANG_KEINER`).
    """

    key: str
    label: str
    anhang: str


# Reihenfolge = Anzeigereihenfolge im Dropdown. Anhang I zuerst (hochkritisch),
# dann Anhang II, zuletzt "keiner".
SEKTOREN: tuple[Sektor, ...] = (
    # --- Anhang I (hochkritische Sektoren) ---
    Sektor("energie", "Energie (Strom, Gas, Öl, Fernwärme, Wasserstoff)", ANHANG_I),
    Sektor("verkehr", "Verkehr (Luft, Schiene, Schiff, Straße)", ANHANG_I),
    Sektor("bankwesen", "Bankwesen", ANHANG_I),
    Sektor("finanzmarkt", "Finanzmarktinfrastrukturen", ANHANG_I),
    Sektor("gesundheit", "Gesundheitswesen (inkl. Labore, Pharma)", ANHANG_I),
    Sektor("trinkwasser", "Trinkwasserversorgung", ANHANG_I),
    Sektor("abwasser", "Abwasserentsorgung", ANHANG_I),
    Sektor(
        "digitale_infrastruktur",
        "Digitale Infrastruktur (DNS, IXP, Cloud, Rechenzentren)",
        ANHANG_I,
    ),
    Sektor("ikt_dienste", "Verwaltung von IKT-Diensten (MSP/MSSP)", ANHANG_I),
    Sektor("oeffentliche_verwaltung", "Öffentliche Verwaltung", ANHANG_I),
    Sektor("weltraum", "Weltraum", ANHANG_I),
    # --- Anhang II (sonstige kritische Sektoren) ---
    Sektor("post_kurier", "Post- und Kurierdienste", ANHANG_II),
    Sektor("abfallwirtschaft", "Abfallbewirtschaftung", ANHANG_II),
    Sektor("chemie", "Produktion/Handel mit chemischen Stoffen", ANHANG_II),
    Sektor("lebensmittel", "Lebensmittel (Produktion, Verarbeitung, Vertrieb)", ANHANG_II),
    Sektor(
        "verarbeitendes_gewerbe",
        "Verarbeitendes Gewerbe (Medizinprodukte, Elektronik, Maschinen-/Fahrzeugbau)",
        ANHANG_II,
    ),
    Sektor(
        "digitale_dienste",
        "Anbieter digitaler Dienste (Marktplätze, Suchmaschinen, soziale Netzwerke)",
        ANHANG_II,
    ),
    Sektor("forschung", "Forschungseinrichtungen", ANHANG_II),
    # --- Kein NIS2-Sektor ---
    Sektor("keiner", "Keiner / nicht aufgeführt", ANHANG_KEINER),
)


# Rollen der erfassenden Person (Stammdaten, keine UI-Verzweigung).
ROLLEN: tuple[str, ...] = (
    "Geschäftsführung / Inhaber:in",
    "IT-Leitung / IT-Verantwortung",
    "Datenschutzbeauftragte:r",
    "Sachbearbeitung",
    "Sonstige",
)


def anhang_fuer(sektor_key: str) -> str:
    """Gibt den NIS2-Anhang zu einem Sektor-Schlüssel zurück.

    Args:
        sektor_key: Schlüssel eines:class:`Sektor` (oder leer/unbekannt).

    Returns:
:data:`ANHANG_I`,:data:`ANHANG_II` oder:data:`ANHANG_KEINER`
        (auch für leere/unbekannte Schlüssel).
    """
    for sektor in SEKTOREN:
        if sektor.key == sektor_key:
            return sektor.anhang
    return ANHANG_KEINER
