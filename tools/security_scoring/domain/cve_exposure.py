"""
cve_exposure — Domain-Logik für die CVE-Exposure-Scoring-Komponente.

Aggregiertes Exposure-Modell:
    CveExposureData — Eingangswerte + berechneter Score für die Anzeige.
    berechne_exposure_score — Reine Penalty-Funktion (keine Seiteneffekte).
    status_from_score — Score → Status-Text-Mapping.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Penalty-Konstanten
# ---------------------------------------------------------------------------

PENALTY_CRITICAL: int = 15
PENALTY_HIGH: int = 8
PENALTY_MEDIUM: int = 3
PENALTY_KEV: int = 20
PENALTY_ADVISORY: int = 10

MAX_PENALTY: int = 100

_STATUS_OK_THRESHOLD: int = 80
_STATUS_WARN_THRESHOLD: int = 60

STATUS_OK: str = "OK"
STATUS_WARNUNG: str = "Warnung"
STATUS_KRITISCH: str = "Kritisch"
STATUS_KEINE_DATEN: str = "Keine Daten"

# CVSS-Schwellen
CVSS_CRITICAL: float = 9.0
CVSS_HIGH: float = 7.0
CVSS_MEDIUM: float = 4.0


@dataclass(frozen=True)
class CveExposureData:
    """Aggregierte CVE-Exposure-Kennzahlen eines Systems.

    Attributes:
        total_cves: Anzahl aller Techstack-gefilterten CVEs.
        critical_count: Anzahl CVEs mit CVSS >= 9.0.
        high_count: Anzahl CVEs mit CVSS 7.0–8.9.
        medium_count: Anzahl CVEs mit CVSS 4.0–6.9.
        kev_count: Anzahl CVEs die gleichzeitig in CISA KEV stehen.
        affected_advisories: Anzahl CSAF-Matches mit Severity critical/high.
        score: Exposure-Score 0–100 oder None wenn keine Daten.
        status: Text-Status: "OK"/"Warnung"/"Kritisch"/"Keine Daten".
        last_updated: ISO-Timestamp der jüngsten Quelldaten oder "".
    """

    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    kev_count: int
    affected_advisories: int
    score: int | None
    status: str
    last_updated: str = ""


def berechne_exposure_score(
    critical: int,
    high: int,
    medium: int,
    kev: int,
    advisories: int,
) -> int:
    """Berechnet den Exposure-Score aus den CVE-/Advisory-Zählwerten.

    Penalty-Modell (auslan cve-exposure-anbindung):
        +15 pro Critical-CVE (CVSS >= 9.0)
        +8 pro High-CVE (CVSS 7.0–8.9)
        +3 pro Medium-CVE (CVSS 4.0–6.9)
        +20 pro KEV-markierter CVE (zusätzlich zur CVSS-Penalty)
        +10 pro CSAF-Advisory-Match mit Severity critical/high

    Die Gesamt-Penalty wird bei 100 gedeckelt, der Score fällt nicht unter 0.

    Args:
        critical: Anzahl Critical-CVEs (nicht gleichzeitig KEV-zählung).
        high: Anzahl High-CVEs.
        medium: Anzahl Medium-CVEs.
        kev: Anzahl KEV-markierter CVEs (unabhängig vom CVSS-Bucket).
        advisories: Anzahl betroffener CSAF-Advisories (critical/high).

    Returns:
        Integer-Score 0–100, je höher desto besser.
    """
    penalty = (
        critical * PENALTY_CRITICAL
        + high * PENALTY_HIGH
        + medium * PENALTY_MEDIUM
        + kev * PENALTY_KEV
        + advisories * PENALTY_ADVISORY
    )
    return max(0, 100 - min(penalty, MAX_PENALTY))


def status_from_score(score: int | None) -> str:
    """Leitet den Status-Text aus dem numerischen Score ab.

    Args:
        score: Exposure-Score 0–100 oder None.

    Returns:
        "Keine Daten" wenn score is None, sonst "OK"/"Warnung"/"Kritisch"
        anhand der definierten Schwellwerte.
    """
    if score is None:
        return STATUS_KEINE_DATEN
    if score >= _STATUS_OK_THRESHOLD:
        return STATUS_OK
    if score >= _STATUS_WARN_THRESHOLD:
        return STATUS_WARNUNG
    return STATUS_KRITISCH
