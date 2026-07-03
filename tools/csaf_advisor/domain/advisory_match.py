"""
advisory_match — Domain-Entity für einen Advisory-Treffer.

Ein Treffer entsteht wenn ein CSAF Advisory eine Softwarekomponente
aus dem erfassten Inventar des Users betrifft.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdvisoryMatch:
    """Treffer: Ein Advisory betrifft eine erfasste Softwarekomponente.

    Attributes:
        id: Eindeutiger Bezeichner (advisory_id + "_" + component_name).
        advisory_id: Referenz auf das betroffene CsafAdvisory.
        matched_component: Name der betroffenen Softwarekomponente.
        matched_version: Installierte Version der Komponente.
        confidence: Treffsicherheit des Matchings (0.0–1.0).
        action_required: Empfohlene Maßnahme: "update", "workaround", "monitor".
        matched_at: ISO-Zeitstempel des Treffer-Zeitpunkts.
    """

    id: str
    advisory_id: str
    matched_component: str
    matched_version: str = ""
    confidence: float = 0.0
    action_required: str = "monitor"
    matched_at: str = ""
