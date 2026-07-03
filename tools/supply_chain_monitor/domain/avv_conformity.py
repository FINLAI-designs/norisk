"""
avv_conformity — Vollstaendigkeits-/Konformitaets-Pruefung der Art.-28-AVV-
Pflichtinhalte.

Rein deskriptive Vollstaendigkeits-Pruefung der 10 Art.-28-Abs.-3-Pflichtklauseln
einer AVV-Checkliste: Welche sind als *dokumentiert* (``is_present is True``)
markiert, welche fehlen, und welche fehlenden zaehlen als sicherheits-/
compliance-kritisch.

**Bewusst KEINE Rechtsberatung** (Patrick-Vorgabe): die Funktion bewertet
NICHT, ob eine konkrete Klausel inhaltlich rechtswirksam formuliert ist — sie
prueft nur, ob der User den jeweiligen Pflichtinhalt als vorhanden markiert hat.
Das Ergebnis ist eine Checklisten-Auswertung / Hilfestellung, kein
Rechtsgutachten.

Schichtzugehoerigkeit: ``domain/`` — reine Logik, nur Stdlib + Domain-Modelle.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
)

#: Sicherheits-/compliance-kritische Art.-28-Klauseln. Ihr Fehlen ist ein
#: konkretes, benennbares Risiko (kein Rechtsurteil): ohne dokumentierte TOM,
#: Subunternehmer-Regelung, Loesch-/Rueckgabe-Pflicht oder Drittland-Klauseln
#: ist die Auftragsverarbeitung praktisch nicht abgesichert. Reihenfolge =
#: Anzeige-Reihenfolge.
SECURITY_CRITICAL_CLAUSES: tuple[Art28Check, ...] = (
    Art28Check.TOMS,  # Art. 28(3)(c) — Technisch/Organisatorische Massnahmen
    Art28Check.SUB_AUFTRAGNEHMER,  # Art. 28(3)(d) — Subunternehmer-Regelung
    Art28Check.LOESCHUNG,  # Art. 28(3)(g) — Rueckgabe/Loeschung bei Vertragsende
    Art28Check.EU_STANDARDVERTRAGSKLAUSELN,  # Drittland-Transfer (SCC)
)

#: Verdict-Werte (stabile Strings — die GUI mappt sie auf Labels/Farben).
VERDICT_COMPLETE = "vollstaendig"
VERDICT_GAPS = "lueckenhaft"
VERDICT_CRITICAL = "kritisch"


@dataclass(frozen=True)
class AvvConformity:
    """Ergebnis der Art.-28-Vollstaendigkeits-Pruefung einer AVV.

    Attributes:
        present_count: Anzahl als dokumentiert markierter Pflichtklauseln.
        total: Gesamtzahl der Pflichtklauseln (10, fix).
        missing: Nicht dokumentierte Pflichtklauseln (``is_present`` !=
                       True, inkl. ``None``/ungeprueft).
        security_gaps: Teilmenge von ``missing``, die als sicherheits-/
                       compliance-kritisch gilt (:data:`SECURITY_CRITICAL_CLAUSES`).
        verdict::data:`VERDICT_COMPLETE` /:data:`VERDICT_GAPS` /
:data:`VERDICT_CRITICAL`.
    """

    present_count: int
    total: int
    missing: tuple[Art28Check, ...]
    security_gaps: tuple[Art28Check, ...]
    verdict: str

    @property
    def is_complete(self) -> bool:
        """``True`` wenn alle Pflichtklauseln dokumentiert sind."""
        return not self.missing


def assess_art28_conformity(
    entries: Iterable[AvvChecklistEntry],
) -> AvvConformity:
    """Wertet eine AVV-Checkliste auf Art.-28-Vollstaendigkeit aus.

    Custom-Eintraege zaehlen NICHT zur Pflichtinhalts-Quote (sie haben keinen
    Art.-28-Bezug). ``is_present is None`` (ungeprueft) zaehlt wie ``False`` —
    nur explizit als vorhanden markierte Klauseln gelten als dokumentiert.

    Args:
        entries: Die Checklisten-Eintraege einer AVV.

    Returns:
        Eine:class:`AvvConformity` mit Quote, fehlenden + kritischen Klauseln
        und einem Verdict.
    """
    present: set[Art28Check] = {
        e.art28_check
        for e in entries
        if not e.is_custom
        and e.art28_check is not None
        and e.is_present is True
    }
    total = len(Art28Check)
    missing = tuple(c for c in Art28Check if c not in present)
    security_gaps = tuple(
        c for c in SECURITY_CRITICAL_CLAUSES if c not in present
    )
    if not missing:
        verdict = VERDICT_COMPLETE
    elif security_gaps:
        verdict = VERDICT_CRITICAL
    else:
        verdict = VERDICT_GAPS
    return AvvConformity(
        present_count=len(present),
        total=total,
        missing=missing,
        security_gaps=security_gaps,
        verdict=verdict,
    )


__all__ = [
    "SECURITY_CRITICAL_CLAUSES",
    "VERDICT_COMPLETE",
    "VERDICT_CRITICAL",
    "VERDICT_GAPS",
    "AvvConformity",
    "assess_art28_conformity",
]
