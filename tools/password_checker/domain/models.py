"""models — Domänenmodelle für den Passwort-Policy-Checker.

Alle Datenklassen für Passwort-Analyse und Policy-Compliance.
Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Security-Hinweis:
    Passwörter werden NIEMALS in diesen Modellen persistiert.
    PasswordCheckResult enthält nur abgeleitete Metriken, nie das
    ursprüngliche Passwort.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PasswordStaerke(Enum):
    """Bewertungsstufen der Passwort-Stärke."""

    SEHR_SCHWACH = "sehr_schwach"
    SCHWACH = "schwach"
    MITTEL = "mittel"
    STARK = "stark"
    SEHR_STARK = "sehr_stark"


class PolicyVorlage(Enum):
    """Vordefinierte Policy-Vorlagen."""

    BSI = "bsi"
    NIST = "nist"
    ISO27001 = "iso27001"
    BENUTZERDEFINIERT = "benutzerdefiniert"


@dataclass
class PasswordPolicy:
    """Definition einer Passwort-Policy.

    Attributes:
        name: Anzeigename der Policy.
        vorlage: Zugrunde liegende Vorlage.
        min_laenge: Mindestlänge in Zeichen.
        gross_buchstaben: Großbuchstaben erforderlich.
        klein_buchstaben: Kleinbuchstaben erforderlich.
        ziffern: Ziffern erforderlich.
        sonderzeichen: Sonderzeichen erforderlich.
        max_alter_tage: Maximales Passwort-Alter (0 = kein Ablauf).
        breach_check: HIBP-Prüfung aktivieren.
        keine_wiederverwendung: Anzahl der Passwörter die nicht wiederverwendet werden dürfen.
    """

    name: str
    vorlage: PolicyVorlage = PolicyVorlage.BENUTZERDEFINIERT
    min_laenge: int = 12
    gross_buchstaben: bool = True
    klein_buchstaben: bool = True
    ziffern: bool = True
    sonderzeichen: bool = True
    max_alter_tage: int = 365
    breach_check: bool = True
    keine_wiederverwendung: int = 5


@dataclass
class PolicyCheck:
    """Ergebnis einer einzelnen Policy-Prüfung.

    Attributes:
        bezeichnung: Bezeichnung der geprüften Anforderung.
        erfuellt: True wenn die Anforderung erfüllt ist.
        hinweis: Optionaler Hinweis bei Nicht-Erfüllung.
    """

    bezeichnung: str
    erfuellt: bool
    hinweis: str = ""


@dataclass
class PasswordCheckResult:
    """Vollständiges Prüfergebnis für ein Passwort.

    Security: Dieses Objekt enthält NIEMALS das ursprüngliche Passwort.

    Attributes:
        staerke: Bewertungsstufe der Passwort-Stärke.
        score: Numerischer Score 0–100.
        entropie_bits: Berechnete Informations-Entropie in Bits.
        laenge: Länge des Passworts.
        policy_checks: Liste der Einzel-Policy-Prüfungen.
        muster_gefunden: Erkannte schwache Muster.
        empfehlungen: Verbesserungsvorschläge.
        breach_vorkommnisse: Anzahl HIBP-Vorkommen (0 = sicher, -1 = nicht geprüft).
        policy_erfuellt: True wenn alle Policy-Anforderungen erfüllt.
    """

    staerke: PasswordStaerke
    score: int
    entropie_bits: float
    laenge: int
    policy_checks: list[PolicyCheck] = field(default_factory=list)
    muster_gefunden: list[str] = field(default_factory=list)
    empfehlungen: list[str] = field(default_factory=list)
    breach_vorkommnisse: int = -1

    @property
    def policy_erfuellt(self) -> bool:
        """True wenn alle Policy-Checks erfüllt sind.

        Returns:
            True wenn keine Policy-Verletzungen vorliegen.
        """
        return all(c.erfuellt for c in self.policy_checks)

    @property
    def breach_geprueft(self) -> bool:
        """True wenn ein HIBP-Check durchgeführt wurde.

        Returns:
            True wenn breach_vorkommnisse >= 0.
        """
        return self.breach_vorkommnisse >= 0

    @property
    def ist_kompromittiert(self) -> bool:
        """True wenn das Passwort in bekannten Breaches gefunden wurde.

        Returns:
            True wenn breach_vorkommnisse > 0.
        """
        return self.breach_vorkommnisse > 0
