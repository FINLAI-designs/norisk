"""
hardening_stages — Ampel-Stufen fuer den NoRisk Hardening Score (Phase 1.3).

Lynis-inspirierte 4-Stufen-Klassifikation (Secure / Moderate / At Risk /
Critical) mit Farbverweis auf:data:`core.theme.SCORE_STAGE_COLORS`.

Die existierende:func:`tools.security_scoring.domain.scoring_engine.score_to_grade`
(Schulnoten A-F) bleibt als Sekundaer-Anzeige im PDF-Report erhalten —
Stages sind die Primaer-Kommunikation im Dashboard (siehe v2 §3).

Architektur-Prinzip wie Phase 1.1+1.2: **additiv**. Pure-Logik-Modul ohne
GUI-/I/O-Abhaengigkeit, leicht testbar. Stage-Farben werden ueber den
``color_key`` referenziert — der konkrete Hex-Wert lebt in
``core/theme.py:SCORE_STAGE_COLORS`` (R1-konform, kein hardcoded Hex
im Domain-Modul).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class ScoreStage:
    """Eine der 4 Hardening-Score-Ampel-Stufen.

    Frozen + slots: unveraenderbar, speicherarm, hashable — kann als
    Dict-Key oder Set-Member verwendet werden.

    Attributes:
        label: Anzeige-String (z.B. ``"Secure"``). Bewusst englisch
            (kein ``"Sicher"``), weil Lynis-Hardening-Index als
            Industrie-Standard englisch ist und das die Vergleichbarkeit
            erleichtert.
        color_key: Lookup-Key in:data:`core.theme.SCORE_STAGE_COLORS`.
            GUI/PDF resolved den Hex-Wert via Theme-Modul — Domain-Modul
            kennt keine Hex-Werte (R1-konform).
        min_score: Untere Schwelle (inklusiv). Default 0.
        max_score: Obere Schwelle (inklusiv). Default 100.
    """

    label: str
    color_key: str
    min_score: int
    max_score: int

    def contains(self, score: int) -> bool:
        """True wenn ``score`` in der Stage-Bandbreite liegt (inklusiv)."""
        return self.min_score <= score <= self.max_score


# ---------------------------------------------------------------------------
# Stufen-Definition v2 §3)
# ---------------------------------------------------------------------------

#: Die 4 Hardening-Score-Stufen — Reihenfolge absteigend (Secure zuerst).
#:
#: Schwellen:
#: * Secure: 85-100
#: * Moderate: 65-84
#: * At Risk: 40-64
#: * Critical: 0-39
#:
#: Aenderungen erfordern Update der Anzeige-Logik in GUI + PDF + Tests.
SCORE_STAGES: Final[tuple[ScoreStage, ...]] = (
    ScoreStage(label="Secure",   color_key="score_secure",   min_score=85, max_score=100),
    ScoreStage(label="Moderate", color_key="score_moderate", min_score=65, max_score=84),
    ScoreStage(label="At Risk",  color_key="score_at_risk",  min_score=40, max_score=64),
    ScoreStage(label="Critical", color_key="score_critical", min_score=0,  max_score=39),
)

#: Benannte Referenzen auf die 4 Stages (Reihenfolge wie SCORE_STAGES).
STAGE_SECURE, STAGE_MODERATE, STAGE_AT_RISK, STAGE_CRITICAL = SCORE_STAGES


def cap_stage(stage: ScoreStage, ceiling: ScoreStage) -> ScoreStage:
    """Begrenzt eine Stage nach oben auf ``ceiling`` — gibt die SCHLECHTERE zurueck.

    "Schlechter" = niedrigeres ``min_score``. Genutzt vom Coverage-Stage-Guard: bei zu geringer Mess-Abdeckung darf die Ampel nicht besser als
    ``ceiling`` (At Risk) sein, egal wie hoch der Score des gemessenen Teils ist
    — ein 100%-Score auf 40% Coverage ist kein "Secure".

    Args:
        stage: Die aus dem Score abgeleitete Stage.
        ceiling: Die maximal erlaubte (beste) Stage.

    Returns:
        ``stage`` wenn sie ``ceiling`` nicht uebertrifft, sonst ``ceiling``.
    """
    return stage if stage.min_score <= ceiling.min_score else ceiling


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_to_stage(score: float) -> ScoreStage:
    """Bildet einen Score (0-100) auf die zugehoerige:class:`ScoreStage` ab.

    Float-Inputs werden vor dem Vergleich auf int gerundet, weil die
    Stage-Schwellen integer sind (85/65/40). Werte ausserhalb [0, 100]
    werden geclampt:

      * ``score < 0`` → Critical (entspricht 0)
      * ``score > 100`` → Secure (entspricht 100)

    Args:
        score: Hardening-Score-Wert. Typischerweise 0-100 als float
            (z.B. ``87.5``), int oder float akzeptiert.

    Returns:
        Die passende:class:`ScoreStage`. Niemals ``None`` — Output
        ist garantiert eine der 4 Stages aus:data:`SCORE_STAGES`.
    """
    clamped = max(0, min(100, int(round(score))))
    for stage in SCORE_STAGES:
        if stage.contains(clamped):
            return stage
    # Defensive: per Stages-Definition oben deckt 0-100 lueckenlos ab.
    # Falls jemand SCORE_STAGES editiert und ein Loch laesst, fail-loud
    # statt silent None.
    msg = (
        f"score_to_stage: Score {score!r} (clamped={clamped}) wurde von "
        "keiner Stage abgedeckt. Pruefe SCORE_STAGES auf Luecken in den "
        "Schwellen."
    )
    raise AssertionError(msg)


def validate_stages_cover_full_range() -> None:
    """Verifiziert, dass die 4 Stages lueckenlos 0-100 abdecken.

    Pflicht-Invariante:
      * Jeder Score 0-100 mappt auf genau eine Stage.
      * Keine Stage-Bandbreiten ueberlappen (sonst waere die Reihenfolge
        in:data:`SCORE_STAGES` ergebnisrelevant — Code-Smell).

    Raises:
        AssertionError: Bei Luecken oder Ueberlappungen in den
            ``min_score``/``max_score``-Bereichen.
    """
    # Stages absteigend sortiert, also iterieren und Schwellen pruefen.
    sorted_stages = sorted(SCORE_STAGES, key=lambda s: s.min_score)

    # 1. Niedrigste Stage muss bei 0 beginnen
    if sorted_stages[0].min_score != 0:
        msg = (
            f"Niedrigste Stage beginnt bei {sorted_stages[0].min_score}, "
            "muss aber bei 0 starten."
        )
        raise AssertionError(msg)

    # 2. Hoechste Stage muss bei 100 enden
    if sorted_stages[-1].max_score != 100:
        msg = (
            f"Hoechste Stage endet bei {sorted_stages[-1].max_score}, "
            "muss aber bei 100 enden."
        )
        raise AssertionError(msg)

    # 3. Aufeinanderfolgende Stages muessen lueckenlos aneinander grenzen
    for prev, nxt in zip(sorted_stages, sorted_stages[1:], strict=False):
        expected_min = prev.max_score + 1
        if nxt.min_score != expected_min:
            msg = (
                f"Stage-Schwellen-Luecke: {prev.label} endet bei "
                f"{prev.max_score}, {nxt.label} beginnt bei {nxt.min_score} "
                f"(erwartet: {expected_min})."
            )
            raise AssertionError(msg)


# Modul-Lade-Pruefung — bricht den Modul-Import, wenn jemand die
# Stage-Bandbreiten falsch editiert.
validate_stages_cover_full_range()
