"""
privacy_score — Pure Berechnung des Konfigurations-Haertungs-Scores.

Eigener 0-100-Score (NICHT der Hardening-Score). Basis: Anteil der bereits
im Soll befindlichen Tweaks an den ermittelbaren (APPLIED/NOT_APPLIED).
UNKNOWN (z. B. nicht lesbar / nicht-Windows) zaehlt nicht in den Nenner —
der Score behauptet nichts ueber das, was nicht gemessen werden konnte.

Schichtzugehoerigkeit: domain/ — reine Funktion, kein I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from tools.system_tuner.domain.entities import TweakState
from tools.system_tuner.domain.enums import TweakStatus
from tools.system_tuner.domain.scan_entities import PrivacyScore

#: Schwellen (Untergrenze inklusive) -> Label. Absteigend geprueft.
_LABELS: tuple[tuple[int, str], ...] = (
    (85, "Gut"),
    (65, "Solide"),
    (40, "Ausbaufaehig"),
    (0, "Schwach"),
)


def compute_privacy_score(states: Iterable[TweakState]) -> PrivacyScore:
    """Berechnet den Privacy-Score aus den Scan-Zustaenden.

    Args:
        states: Ergebnis des Scans (ein:class:`TweakState` pro Tweak).

    Returns:
:class:`PrivacyScore`. Sind keine Zustaende ermittelbar (alle
        UNKNOWN), wird ``value=0`` mit Label ``"Unbekannt"`` geliefert
        (statt einer irrefuehrenden 0-von-0-Wertung).
    """
    applicable = [
        s
        for s in states
        if s.status in (TweakStatus.APPLIED, TweakStatus.NOT_APPLIED)
    ]
    applied = sum(1 for s in applicable if s.status is TweakStatus.APPLIED)
    total = len(applicable)
    if total == 0:
        return PrivacyScore(value=0, applied=0, applicable=0, label_de="Unbekannt")
    value = round(100 * applied / total)
    label = next(lbl for threshold, lbl in _LABELS if value >= threshold)
    return PrivacyScore(
        value=value, applied=applied, applicable=total, label_de=label
    )
