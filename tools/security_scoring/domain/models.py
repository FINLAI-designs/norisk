"""
models — Domain-Datenmodelle für das Security-Scoring-Dashboard.

Enthält reine Daten-Klassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.herkunft import Herkunft


@dataclass(frozen=True)
class ScoreComponent:
    """Ein Teilbereich des Security-Scores.

    Attributes:
        name: Anzeigename, z.B. "API Security".
        score: Teilscore 0–100. Wird bei data_available=False ignoriert.
        weight: Gewichtung (alle aktiven Weights summieren auf 1.0).
        findings_critical: Anzahl kritischer Findings.
        findings_high: Anzahl hoher Findings.
        findings_medium: Anzahl mittlerer Findings.
        last_scan: ISO-Datetime des letzten Scans.
        source_tool: Bezeichner des Quell-Tools, z.B. "api_security".
        data_available: False wenn keine Quelldaten vorhanden sind —
                            calculate_overall_score ignoriert solche
                            Komponenten bei Summe und Gewicht. Das Widget
                            zeigt stattdessen einen grauen No-Data-Balken.
        details: Freier Zusatztext (z.B. "12 CVEs · 2 KEV").
                            Leerer String wenn nicht gesetzt.
    """

    name: str
    score: float
    weight: float
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    last_scan: str = ""
    source_tool: str = ""
    data_available: bool = True
    details: str = ""


@dataclass(frozen=True)
class SecurityScore:
    """Gesamtscore einer Security-Bewertung.

    Attributes:
        id: UUID.
        target_name: Kundenname oder Ziel-Bezeichnung (Anzeige/Back-Compat).
        timestamp: ISO-Datetime der Berechnung.
        overall_score: Gewichteter Gesamtscore 0–100.
        grade: Schulnote A/B/C/D/F.
        components: Liste der Teilkomponenten.
        summary: Optionale Kurzbeschreibung.
        subject_id: UUID des kanonischen Subjekts. Leer
            für Scores vor der Subjekt-Konsolidierung bzw. wenn kein
            SubjectStore verfügbar war (fail-soft). Join-/Retention-Schlüssel.
        herkunft: Provenance E5). ``GEMESSEN`` für eine
            Live-Messung des eigenen Systems (Default), ``ERFASST`` für manuell
            für einen Kunden erfasste Werte. Nie mischen (Beweiswert getrennt).
    """

    id: str
    target_name: str
    timestamp: str
    overall_score: float
    grade: str
    components: list[ScoreComponent] = field(default_factory=list)
    summary: str = ""
    subject_id: str = ""
    herkunft: Herkunft = Herkunft.GEMESSEN
