"""nis2_maturity — Reifegrad-Roll-up je NIS2-Art.-21(2)-Control (IA-Welle 2, Phase 2).

Aggregiert Befunde (aus beliebigen Tools) ueber das bestehende, deterministische
Befund->Control-Mapping (:func:`core.compliance.regulatory_mapping.map_finding_to_regulatory`,
) zu einem Reifegrad 0..3 je der neun NIS2-Art.-21(2)-Controls (a..i). Damit
wird NIS2 von der reinen Vorfalls-Sicht (Incident-Tracker) zu einer Reifegrad-
Ampel ("Bin ich NIS2-konform?") — als prominente Cockpit-Kachel.

Konsistenz mit: NUR MESSBARE Befunde zaehlen. Ein Control ohne messbare
Befunde ist ``UNKNOWN`` (grau), NICHT ``NONE`` (rot) — "nicht erhoben" ist nicht
dasselbe wie "nicht erfuellt".

Schicht: ``core/compliance`` — pur, kein Qt, keine DB, tool-agnostisch (nimmt
einen generischen:class:`ControlFinding`-Input, importiert NICHT aus ``tools``).
Wichtig: rein indikativ (wie) — keine Konformitaets-Zusage.

Author: Patrick Riederich
Version: 1.0 (IA-Welle 2 Phase 2)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

from core.compliance.regulatory_mapping import (
    RegReference,
    map_finding_to_regulatory,
    regulatory_label,
)

#: Die neun NIS2-Art.-21(2)-Controls (a..i) — Reihenfolge = Anzeige-Reihenfolge.
ALL_NIS2_CONTROLS: tuple[RegReference, ...] = (
    RegReference.NIS2_ART21_2A,
    RegReference.NIS2_ART21_2B,
    RegReference.NIS2_ART21_2C,
    RegReference.NIS2_ART21_2D,
    RegReference.NIS2_ART21_2E,
    RegReference.NIS2_ART21_2F,
    RegReference.NIS2_ART21_2G,
    RegReference.NIS2_ART21_2H,
    RegReference.NIS2_ART21_2I,
)


class MaturityLevel(IntEnum):
    """Reifegrad eines Controls (hoeher = besser). ``UNKNOWN`` = nicht erhoben."""

    UNKNOWN = -1
    NONE = 0
    BASIC = 1
    INTERMEDIATE = 2
    ADVANCED = 3

    @property
    def label(self) -> str:
        """Deutsches Anzeige-Label."""
        return {
            MaturityLevel.UNKNOWN: "Nicht erhoben",
            MaturityLevel.NONE: "Kritisch",
            MaturityLevel.BASIC: "Anfang",
            MaturityLevel.INTERMEDIATE: "Fortgeschritten",
            MaturityLevel.ADVANCED: "Reif",
        }[self]


@dataclass(frozen=True, slots=True)
class ControlFinding:
    """Generischer, tool-agnostischer Befund-Input fuer das Maturity-Roll-up.

    Attributes:
        category: ``HardeningCategory``-Wert (z.B. ``"system_hardening"``).
        check_id: Optionaler Check-Identifier (``"SH-001"``...) — verfeinert das
            Mapping (CHECK_ID_TO_REGULATORY ueberstimmt die Kategorie).
        passed: Erfuellt der Befund das Kriterium?
        measurable: Konnte der Zustand ermittelt werden? Nicht messbare
            Befunde zaehlen NICHT in den Reifegrad.
    """

    category: str
    check_id: str | None
    passed: bool
    measurable: bool = True


@dataclass(frozen=True, slots=True)
class ControlMaturity:
    """Reifegrad-Ergebnis fuer ein einzelnes NIS2-Control.

    Attributes:
        control: Das NIS2-Control (RegReference).
        level: Abgeleiteter Reifegrad.
        passed: Anzahl erfuellter messbarer Befunde fuer dieses Control.
        total: Anzahl messbarer Befunde fuer dieses Control.
        label: Indikatives NIS2-Norm-Label (aus, "... (indikativ)").
    """

    control: RegReference
    level: MaturityLevel
    passed: int
    total: int
    label: str


def _level_for_ratio(passed: int, total: int) -> MaturityLevel:
    """Leitet den Reifegrad aus dem Erfuellungsverhaeltnis ab."""
    if total == 0:
        return MaturityLevel.UNKNOWN
    ratio = passed / total
    if ratio >= 1.0:
        return MaturityLevel.ADVANCED
    if ratio >= 2 / 3:
        return MaturityLevel.INTERMEDIATE
    if ratio >= 1 / 3:
        return MaturityLevel.BASIC
    return MaturityLevel.NONE


def compute_nis2_maturity(
    findings: Iterable[ControlFinding],
) -> dict[RegReference, ControlMaturity]:
    """Berechnet den Reifegrad je NIS2-Control aus den Befunden.

    Nur messbare Befunde fliessen ein. Jeder Befund wird ueber
:func:`map_finding_to_regulatory` seinen Controls zugeordnet (1:N moeglich).

    Args:
        findings: Generische, tool-agnostische Befunde.

    Returns:
        Dict fuer ALLE neun NIS2-Controls (Controls ohne messbaren Befund ->
        ``MaturityLevel.UNKNOWN``).
    """
    passed_by: dict[RegReference, int] = {c: 0 for c in ALL_NIS2_CONTROLS}
    total_by: dict[RegReference, int] = {c: 0 for c in ALL_NIS2_CONTROLS}

    for finding in findings:
        if not finding.measurable:
            continue
        refs = map_finding_to_regulatory(finding.category, check_id=finding.check_id)
        for ref in refs:
            if ref not in total_by:  # nur NIS2-Controls, ITSiG/DSGVO/TISAX ignorieren
                continue
            total_by[ref] += 1
            if finding.passed:
                passed_by[ref] += 1

    return {
        control: ControlMaturity(
            control=control,
            level=_level_for_ratio(passed_by[control], total_by[control]),
            passed=passed_by[control],
            total=total_by[control],
            label=regulatory_label(control),
        )
        for control in ALL_NIS2_CONTROLS
    }


@dataclass(frozen=True, slots=True)
class Nis2MaturitySummary:
    """Cockpit-Roll-up ueber alle Controls.

    Attributes:
        overall: Durchschnittlicher Reifegrad ueber die ERHOBENEN Controls
            (gerundet); ``UNKNOWN`` wenn kein Control erhoben ist.
        assessed_controls: Anzahl Controls mit messbaren Befunden.
        total_controls: Gesamtzahl Controls (immer 9).
        per_level: Anzahl Controls je Reifegrad (fuer die Ampel-Verteilung).
    """

    overall: MaturityLevel
    assessed_controls: int
    total_controls: int
    per_level: dict[MaturityLevel, int]


def summarize_nis2_maturity(
    maturities: dict[RegReference, ControlMaturity],
) -> Nis2MaturitySummary:
    """Verdichtet die Control-Reifegrade zu einem Cockpit-Roll-up.

    ``overall`` ist der gerundete Mittelwert der erhobenen Controls (UNKNOWN
    bleibt aussen vor). So zieht ein einzelnes nicht-erhobenes Control den
    Gesamt-Reifegrad nicht faelschlich nach unten.
    """
    per_level: dict[MaturityLevel, int] = {lvl: 0 for lvl in MaturityLevel}
    assessed_levels: list[int] = []
    for cm in maturities.values():
        per_level[cm.level] += 1
        if cm.level is not MaturityLevel.UNKNOWN:
            assessed_levels.append(int(cm.level))

    if not assessed_levels:
        overall = MaturityLevel.UNKNOWN
    else:
        overall = MaturityLevel(round(sum(assessed_levels) / len(assessed_levels)))

    return Nis2MaturitySummary(
        overall=overall,
        assessed_controls=len(assessed_levels),
        total_controls=len(ALL_NIS2_CONTROLS),
        per_level=per_level,
    )


__all__ = [
    "ALL_NIS2_CONTROLS",
    "ControlFinding",
    "ControlMaturity",
    "MaturityLevel",
    "Nis2MaturitySummary",
    "compute_nis2_maturity",
    "summarize_nis2_maturity",
]
