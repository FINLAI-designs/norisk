"""score_abweichung — Abweichung zwischen Selbsteinschätzung und Messung E1).

Vergleicht die zwei NIE gemittelten Score-Dimensionen eines Subjekts —
„Selbsteinschätzung (Audit)" und „Messung (Hardening)" — und markiert eine
drastische Abweichung für die Prüfung. Es wird **nichts überschrieben und nichts
gemischt** (E1): die reine Funktion liefert nur einen Hinweis, der Beweiswert
(gemessen ≠ deklariert) bleibt getrennt.

Schichtzugehörigkeit: domain/ — pure, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

#: Ab dieser Punktedifferenz (0–100) gilt eine Abweichung als „drastisch" und
#: wird im Cockpit als Hinweis markiert (Eingabefehler-/Fehleinschätzungs-Indiz).
DRASTISCH_SCHWELLE: float = 25.0


@dataclass(frozen=True, slots=True)
class ScoreAbweichung:
    """Ergebnis des Abgleichs zweier Score-Dimensionen.

    Attributes:
        audit_score: Selbsteinschätzung (Audit), 0–100.
        hardening_score: Messung/Erfassung (Hardening), 0–100.
        differenz: Absolute Punktedifferenz.
        drastisch: True, wenn ``differenz >= DRASTISCH_SCHWELLE``.
        richtung: ``"ueberschaetzt"`` (Audit > Messung), ``"unterschaetzt"``
            (Audit < Messung) oder ``"deckungsgleich"``.
        hinweis: Laienverständlicher Sie-Form-Hinweis.
    """

    audit_score: float
    hardening_score: float
    differenz: float
    drastisch: bool
    richtung: str
    hinweis: str


def bewerte_score_abweichung(
    audit_score: float | None,
    hardening_score: float | None,
    *,
    schwelle: float = DRASTISCH_SCHWELLE,
) -> ScoreAbweichung | None:
    """Vergleicht Selbsteinschätzung (Audit) und Messung (Hardening).

    Args:
        audit_score: Audit-Gesamtscore 0–100 oder ``None`` (kein Audit).
        hardening_score: Hardening-Gesamtscore 0–100 oder ``None`` (keine Messung).
        schwelle: Ab welcher Differenz die Abweichung „drastisch" ist.

    Returns:
        Eine:class:`ScoreAbweichung`, oder ``None`` wenn eine der beiden
        Dimensionen fehlt (dann ist kein Abgleich möglich — kein Hinweis).
    """
    if audit_score is None or hardening_score is None:
        return None

    differenz = round(abs(audit_score - hardening_score), 1)
    drastisch = differenz >= schwelle

    if audit_score > hardening_score:
        richtung = "ueberschaetzt"
    elif audit_score < hardening_score:
        richtung = "unterschaetzt"
    else:
        richtung = "deckungsgleich"

    if not drastisch:
        hinweis = (
            "Selbsteinschätzung und Messung liegen nahe beieinander "
            f"(Differenz {differenz:.0f} Punkte)."
        )
    elif richtung == "ueberschaetzt":
        hinweis = (
            f"Ihre Selbsteinschätzung ({audit_score:.0f}) liegt {differenz:.0f} "
            f"Punkte ÜBER der Messung ({hardening_score:.0f}). Bitte prüfen — "
            "möglicherweise zu optimistisch eingeschätzt oder Eingabefehler."
        )
    else:  # unterschaetzt
        hinweis = (
            f"Ihre Selbsteinschätzung ({audit_score:.0f}) liegt {differenz:.0f} "
            f"Punkte UNTER der Messung ({hardening_score:.0f}). Bitte prüfen — "
            "möglicherweise zu vorsichtig eingeschätzt oder Eingabefehler."
        )

    return ScoreAbweichung(
        audit_score=float(audit_score),
        hardening_score=float(hardening_score),
        differenz=differenz,
        drastisch=drastisch,
        richtung=richtung,
        hinweis=hinweis,
    )
