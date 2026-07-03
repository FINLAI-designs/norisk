"""
scoring_engine — Gewichtete Score-Berechnung (pure Logik).

Enthält ausschließlich reine Funktionen ohne Seiteneffekte.
Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.security_scoring.domain.models import ScoreComponent

# ---------------------------------------------------------------------------
# Standardgewichtungen der Komponenten
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, float] = {
    "api_security": 0.25,
    "network_scanner": 0.20,
    "dependency_auditor": 0.15,
    "cert_monitor": 0.15,
    "password_policy": 0.10,
    "cve_exposure": 0.15,
}


def calculate_self_assessment_score(anzahl_erfuellt: int, anzahl_gesamt: int) -> float:
    """Berechnet den Score einer Self-Assessment-Metrik.

    Jede Frage zählt gleich. ``anzahl_erfuellt`` umfasst auch
    automatisch erkannte positive Befunde.

    Args:
        anzahl_erfuellt: Anzahl mit „Ja" beantworteter Fragen.
        anzahl_gesamt: Gesamtzahl an Fragen.

    Returns:
        Score 0–100 oder 0.0 wenn keine Fragen vorliegen.
    """
    if anzahl_gesamt <= 0:
        return 0.0
    return max(0.0, min(100.0, anzahl_erfuellt / anzahl_gesamt * 100.0))


def calculate_component_score(
    findings_critical: int,
    findings_high: int,
    findings_medium: int,
    findings_low: int = 0,
) -> float:
    """Berechnet den Score einer Komponente (0–100).

    Startet bei 100 und zieht pro Finding ab:
    - KRITISCH: −25 Punkte
    - HOCH: −15 Punkte
    - MITTEL: −5 Punkte
    - NIEDRIG: −1 Punkt

    Args:
        findings_critical: Anzahl kritischer Findings.
        findings_high: Anzahl hoher Findings.
        findings_medium: Anzahl mittlerer Findings.
        findings_low: Anzahl niedriger Findings.

    Returns:
        Score zwischen 0.0 und 100.0.
    """
    score = 100.0
    score -= findings_critical * 25
    score -= findings_high * 15
    score -= findings_medium * 5
    score -= findings_low * 1
    return max(0.0, score)


def calculate_coverage(components: list[ScoreComponent]) -> float:
    """Berechnet den Coverage-Anteil aktiver Komponenten (0.0–1.0).

 (c, 2026-05-08): Bisher hat ``calculate_overall_score`` Komponenten
    mit ``data_available=False`` komplett ignoriert — der Gesamtscore stieg
    dadurch unangemessen hoch (Patrick beobachtete 96/100, obwohl ohne
    TechStack-Daten ein wesentlicher Bereich fehlte). Coverage ist der
    Anteil der gewichteten Komponenten mit Daten.

    Args:
        components: Liste der Teilkomponenten.

    Returns:
        Coverage-Anteil ``sum(active_weight) / sum(all_weight)`` zwischen
        0.0 und 1.0. Bei keinen Komponenten oder Gesamtgewicht 0: 0.0.
    """
    if not components:
        return 0.0
    total_weight = sum(c.weight for c in components)
    if total_weight == 0:
        return 0.0
    active_weight = sum(c.weight for c in components if c.data_available)
    return active_weight / total_weight


def calculate_overall_score(components: list[ScoreComponent]) -> float:
    """Berechnet den gewichteten Gesamtscore aller aktiven Komponenten.

 (c, 2026-05-08): Score wird durch die Coverage gecappt — fehlen
    Daten in einem wesentlichen Bereich, kann der Gesamtscore nicht
    fälschlich hoch sein. Konkret: ``score = min(weighted_avg, coverage * 100)``.

    Beispiel:
      - 4 von 6 gewichteten Komponenten haben Daten (Coverage = 67%).
      - Gewichteter Durchschnitt der aktiven Komponenten: 96.0.
      - Cap: ``96.0 vs. 67.0`` → Endscore = 67.0.
      - User sieht klar: "Score limitiert weil ~33% Daten fehlen."

    Komponenten mit ``data_available=False`` werden weiterhin nicht in den
    Mittelwert eingerechnet (sie haben keinen sinnvollen Score), aber sie
    deckeln das Endergebnis durch ihren Weight-Anteil.

    **Edge-Case P2, 2026-05-09):** Mischung aus aktiven Komponenten
    mit ``weight=0`` und inaktiven Komponenten mit ``weight>0`` ergibt
    ``coverage=0.0`` (active_weight ist 0 von positiv) → Score = 0.0.
    Das ist mathematisch korrekt (keine gewichtete Datenabdeckung), aber
    visuell verwirrend wenn aktive Komponenten existieren. Konvention:
    **alle Komponenten muessen ``weight >= 1`` haben** (siehe DEFAULT_WEIGHTS).
    Eine ``weight=0``-Komponente ist semantisch "deaktiviert" — sie sollte
    gar nicht erst in der Komponenten-Liste auftauchen, sondern weggefiltert
    werden. Wenn das doch passiert, ist Score=0.0 ein klares Symptom.

    Args:
        components: Liste der Teilkomponenten mit Score und Weight (>=1).

    Returns:
        Gewichteter Durchschnitt 0.0–100.0, gecappt durch Coverage.
        0.0 wenn keine aktiven Komponenten vorhanden sind.
    """
    active = [c for c in components if c.data_available]
    if not active:
        return 0.0
    active_weight = sum(c.weight for c in active)
    if active_weight == 0:
        return 0.0
    weighted_avg = sum(c.score * c.weight for c in active) / active_weight
    coverage = calculate_coverage(components)
    coverage_cap = coverage * 100.0
    return min(weighted_avg, coverage_cap)


def score_to_grade(score: float) -> str:
    """Wandelt einen Score in eine Schulnote um.

    Args:
        score: Score zwischen 0.0 und 100.0.

    Returns:
        Note: A (≥90), B (≥75), C (≥60), D (≥40), F (<40).
    """
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
