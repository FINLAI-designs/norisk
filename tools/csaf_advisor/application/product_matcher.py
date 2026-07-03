"""
product_matcher — Gleicht CSAF Advisories gegen das Software-Inventar ab.

Matching-Strategie (in dieser Reihenfolge):
  1. Exakter Name (case-insensitive)
  2. Teilstring-Match: Advisory-Produkt enthält Inventar-Namen oder umgekehrt
  3. Token-Match: Mindestens 2 Tokens übereinstimmend

Confidence-Berechnung:
  - Exakt: 1.0
  - Teilstring: 0.75
  - Token: 0.5
  - Kein Treffer: 0.0 (wird nicht zurückgegeben)

Schichtzugehörigkeit: application/ — kein GUI-Import, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from core.logger import get_logger
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch

log = get_logger(__name__)

# Mindest-Confidence für einen akzeptierten Treffer
_MIN_CONFIDENCE = 0.5

# Confidence-Werte
_CONFIDENCE_EXACT = 1.0
_CONFIDENCE_SUBSTRING = 0.75
_CONFIDENCE_TOKEN = 0.5


class SoftwareComponent:
    """Minimale Software-Komponente für das Matching.

    Kann mit TechStackEintrag oder beliebiger Inventar-Struktur befüllt werden.

    Attributes:
        name: Produktname (z. B. "OpenSSL", "Microsoft Office").
        version: Optionale Versionsnummer.
        category: Optionale Kategorie (OS, App, Runtime, …).
    """

    def __init__(self, name: str, version: str = "", category: str = "") -> None:
        """Initialisiert eine Software-Komponente.

        Args:
            name: Produktname.
            version: Optionale Versionsnummer.
            category: Optionale Kategorie.
        """
        self.name = name
        self.version = version
        self.category = category


class ProductMatcher:
    """Gleicht CSAF Advisories gegen eine Liste von Softwarekomponenten ab.

    Erkennt wenn ein Advisory eine erfasste Softwarekomponente betrifft
    und gibt strukturierte AdvisoryMatch-Objekte zurück.
    """

    def match(
        self,
        advisories: list[CsafAdvisory],
        inventory: list[SoftwareComponent],
    ) -> list[AdvisoryMatch]:
        """Führt den vollständigen Advisory-Inventory-Abgleich durch.

        Args:
            advisories: Liste der zu prüfenden Advisories.
            inventory: Liste der erfassten Softwarekomponenten.

        Returns:
            Liste aller Treffer (confidence >= 0.5), sortiert nach Confidence.
        """
        if not inventory:
            log.info("Kein Software-Inventar vorhanden — Match übersprungen.")
            return []

        matches: list[AdvisoryMatch] = []
        now = datetime.now(tz=UTC).isoformat()

        for advisory in advisories:
            for component in inventory:
                confidence = self._compute_confidence(advisory, component)
                if confidence < _MIN_CONFIDENCE:
                    continue

                action = self._determine_action(advisory, confidence)
                match_id = str(uuid.uuid4())

                matches.append(
                    AdvisoryMatch(
                        id=match_id,
                        advisory_id=advisory.id,
                        matched_component=component.name,
                        matched_version=component.version,
                        confidence=confidence,
                        action_required=action,
                        matched_at=now,
                    )
                )
                log.debug(
                    "Match: %s ↔ %s (confidence=%.2f)",
                    advisory.tracking_id,
                    component.name,
                    confidence,
                )

        matches.sort(key=lambda m: m.confidence, reverse=True)
        log.info(
            "%d Matches gefunden für %d Advisories.", len(matches), len(advisories)
        )
        return matches

    # ------------------------------------------------------------------
    # Matching-Logik
    # ------------------------------------------------------------------

    def _compute_confidence(
        self,
        advisory: CsafAdvisory,
        component: SoftwareComponent,
    ) -> float:
        """Berechnet die Treffsicherheit zwischen Advisory und Komponente.

        Args:
            advisory: Das zu prüfende Advisory.
            component: Die Softwarekomponente aus dem Inventar.

        Returns:
            Confidence-Wert (0.0–1.0).
        """
        comp_name_lower = component.name.lower().strip()
        if not comp_name_lower:
            return 0.0

        # Alle Produktnamen des Advisory normieren
        advisory_texts = [p.lower() for p in advisory.affected_products] + [
            advisory.title.lower()
        ]

        best = 0.0
        for adv_text in advisory_texts:
            c = self._text_confidence(adv_text, comp_name_lower)
            if c > best:
                best = c
            if best >= _CONFIDENCE_EXACT:
                break

        return best

    @staticmethod
    def _text_confidence(adv_text: str, comp_name: str) -> float:
        """Berechnet die Treffsicherheit zwischen zwei normalisierten Texten.

        Args:
            adv_text: Normierter Advisory-Produktname.
            comp_name: Normierter Komponentenname.

        Returns:
            Confidence-Wert (0.0–1.0).
        """
        # Exakter Match
        if comp_name == adv_text:
            return _CONFIDENCE_EXACT

        # Teilstring-Match (bidirektional)
        if comp_name in adv_text or adv_text in comp_name:
            return _CONFIDENCE_SUBSTRING

        # Token-Match: mindestens 2 gemeinsame Tokens (>= 3 Zeichen)
        adv_tokens = set(re.split(r"[\s\-_/]", adv_text))
        comp_tokens = set(re.split(r"[\s\-_/]", comp_name))
        meaningful_adv = {t for t in adv_tokens if len(t) >= 3}
        meaningful_comp = {t for t in comp_tokens if len(t) >= 3}

        common = meaningful_adv & meaningful_comp
        if len(common) >= 2:
            return _CONFIDENCE_TOKEN
        if len(common) == 1 and len(meaningful_comp) == 1:
            # Einzel-Token-Match wenn Komponente nur einen bedeutenden Token hat
            return _CONFIDENCE_TOKEN

        return 0.0

    @staticmethod
    def _determine_action(advisory: CsafAdvisory, confidence: float) -> str:
        """Leitet die empfohlene Maßnahme ab.

        Args:
            advisory: Das gematchte Advisory.
            confidence: Treffsicherheit des Matchings.

        Returns:
            "update", "workaround" oder "monitor".
        """
        if (
            advisory.severity in ("critical", "high")
            and confidence >= _CONFIDENCE_SUBSTRING
        ):
            return "update"
        if advisory.severity in ("critical", "high"):
            return "workaround"
        return "monitor"
