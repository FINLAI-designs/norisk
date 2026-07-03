"""kmu_priority — deterministische KMU-Priorisierung + Compliance-Sicht je Finding.

Kombiniert drei bereits vorhandene, deterministische Signale zu einer
KMU-tauglichen Priorisierung — OHNE neue Heuristik, OHNE KI:

* ``severity`` (kanonisch,:class:`core.security.severity.Severity`) — technischer Schweregrad,
* ``urgency`` (Effort ``quick``/``mittel``/``langfrist`` aus:mod:`core.rules.classifier`) — Aufwand,
* ``reg_pflicht`` — ob ein indikativer Norm-Bezug existiert (:mod:`core.compliance.regulatory_mapping`).

Eine KMU-Prio ist faktisch *Schweregrad + Regulatorik-Bezug − Aufwand* (billige,
regulatorisch relevante Quick-Wins zuerst). Alle Gewichte sind feste Konstanten —
reproduzierbar; eine KI darf die berechneten Werte NIE ueberschreiben-Auflage 1).

Schicht: ``core/`` — pure, framework-/DB-frei. Persistiert nichts (alle Werte sind
zur Laufzeit aus bereits gespeicherten Feldern ableitbar).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from core.compliance.regulatory_mapping import (
    REGULATORY_DISCLAIMER,
    RegReference,
    map_finding_to_regulatory,
    regulatory_label,
)
from core.rules.classifier import estimate_person_weeks, format_capacity
from core.security.severity import Severity

#: Aufwands-Abschlag je Effort-Klasse (billige Quick-Wins nach oben — KMU-Kapazitaet).
_EFFORT_PENALTY: Final[dict[str, int]] = {
    "quick": 0,
    "mittel": 5,
    "langfrist": 15,
}

#: Punktgewinn, wenn ein indikativer Norm-Bezug existiert (Regulatorik hebt Prio an).
_REG_BONUS: Final[int] = 15

#: Skalierung des Schweregrads (sort_index 0..4) -> 0..80.
_SEVERITY_FACTOR: Final[int] = 20

_PRIORITY_MIN: Final[int] = 0
_PRIORITY_MAX: Final[int] = 100


def compute_kmu_priority(severity: Severity, urgency: str, reg_pflicht: bool) -> int:
    """Berechnet die deterministische KMU-Prioritaet (0..100, hoeher = zuerst).

    Formel: ``severity.sort_index*20 + (15 wenn Norm-Bezug) − Effort-Abschlag``,
    geclampt auf [0, 100]. Bewusst NICHT:func:`severity_class_distribution`
    (das ist nur ein Fallback und widerspraeche der kuratierten Effort-Kaskade).

    Args:
        severity: Kanonischer Schweregrad des Findings.
        urgency: Effort-Klasse ``quick``/``mittel``/``langfrist``.
        reg_pflicht: True, wenn fuer das Finding ein indikativer Norm-Bezug existiert.

    Returns:
        Prioritaet als Ganzzahl in [0, 100].

    Raises:
        ValueError: Bei unbekannter ``urgency``.
    """
    if urgency not in _EFFORT_PENALTY:
        msg = (
            f"Unbekannte Effort-Klasse: {urgency!r} (erwartet quick/mittel/langfrist)."
        )
        raise ValueError(msg)
    raw = (
        severity.sort_index() * _SEVERITY_FACTOR
        + (_REG_BONUS if reg_pflicht else 0)
        - _EFFORT_PENALTY[urgency]
    )
    return max(_PRIORITY_MIN, min(_PRIORITY_MAX, raw))


@dataclass(frozen=True, slots=True)
class ComplianceView:
    """Deterministische Compliance-/Prioritaets-Sicht auf ein einzelnes Finding.

    Reines Berechnungs-Ergebnis (keine Persistenz). Traegt den Pflicht-Disclaimer
    immer mit, damit nachgelagerte Anzeigen ihn nicht vergessen koennen.

    Attributes:
        category_value: Hardening-Kategorie-Wert des Findings.
        check_id: Optionaler Hardening-Check-Identifier (Kategorie E).
        reg_refs: Indikative Norm-Referenzen (festes Enum), ggf. leer.
        reg_labels: Menschenlesbare indikative Labels zu ``reg_refs``.
        kmu_priority: KMU-Prioritaet 0..100.
        person_weeks: Geschaetzter Aufwand in Personen-Wochen (ca.).
        capacity_hint: KMU-Kapazitaets-Satz ("fixbar mit 1 Person in...").
        disclaimer: Pflicht-Disclaimer (keine Rechtsberatung).
    """

    category_value: str
    check_id: str | None
    reg_refs: tuple[RegReference, ...]
    reg_labels: tuple[str, ...]
    kmu_priority: int
    person_weeks: float
    capacity_hint: str
    disclaimer: str = field(default=REGULATORY_DISCLAIMER)


def build_compliance_view(
    category_value: str,
    severity: Severity,
    urgency: str,
    *,
    check_id: str | None = None,
    asset_count: int = 1,
) -> ComplianceView:
    """Baut die vollstaendige, deterministische Compliance-Sicht eines Findings.

    Args:
        category_value: ``HardeningCategory``-Wert (String) des Findings.
        severity: Kanonischer Schweregrad.
        urgency: Effort-Klasse ``quick``/``mittel``/``langfrist``.
        check_id: Optionaler Hardening-Check-Identifier (Kategorie-E-Verfeinerung).
        asset_count: Geschaetzte Asset-Menge (>= 1) fuer die Aufwands-Schaetzung.

    Returns:
        Eine:class:`ComplianceView` mit Norm-Bezuegen, Labels, KMU-Prioritaet,
        Aufwands-Schaetzung und Pflicht-Disclaimer. Eine KI darf diese Werte NIE
        ueberschreiben (Auflage 1).
    """
    refs = map_finding_to_regulatory(category_value, check_id=check_id)
    labels = tuple(regulatory_label(ref) for ref in refs)
    person_weeks = estimate_person_weeks(urgency, asset_count)
    return ComplianceView(
        category_value=category_value,
        check_id=check_id,
        reg_refs=refs,
        reg_labels=labels,
        kmu_priority=compute_kmu_priority(severity, urgency, bool(refs)),
        person_weeks=person_weeks,
        capacity_hint=format_capacity(person_weeks),
    )
