"""password_analyzer — Passwort-Stärke-Analyse und Policy-Prüfung.

Berechnet Entropie, erkennt schwache Muster und prüft Policy-Compliance.

Security:
    - Das Passwort wird NIEMALS geloggt oder persistiert.
    - Alle Funktionen sind pure (keine Seiteneffekte).
    - Keine Netzwerk-I/O (HIBP ist in data/hibp_client.py).

Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import math
import re

from tools.password_checker.domain.models import (
    PasswordCheckResult,
    PasswordPolicy,
    PasswordStaerke,
    PolicyCheck,
)

# ---------------------------------------------------------------------------
# Bekannte schwache Passwörter (Top-25, OWASP)
# ---------------------------------------------------------------------------

_SCHWACHE_PASSWOERTER: frozenset[str] = frozenset(
    [
        "password",
        "123456",
        "123456789",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
        "master",
        "admin",
        "welcome",
        "login",
        "hello",
        "passwort",
        "hallo",
        "geheim",
        "test123",
        "sommer",
        "winter",
        "qwertz",
        "111111",
        "sunshine",
        "princess",
    ]
)

# Tastatur-Zeilen-Muster (QWERTZ-Tastatur)
_KEYBOARD_PATTERNS: tuple[str, ...] = (
    "qwertz",
    "qwerty",
    "asdfgh",
    "yxcvbn",
    "zxcvbn",
    "123456",
    "234567",
    "345678",
    "456789",
    "567890",
    "abcdef",
    "fedcba",
)


# ---------------------------------------------------------------------------
# Entropie
# ---------------------------------------------------------------------------


def berechne_entropie(passwort: str) -> float:
    """Berechnet die Informations-Entropie des Passworts in Bits.

    Berücksichtigt den genutzten Zeichenraum (Groß/Klein/Ziffern/Sonderzeichen).

    Args:
        passwort: Das zu analysierende Passwort.

    Returns:
        Entropie in Bits. 0.0 bei leerem Passwort.
    """
    if not passwort:
        return 0.0

    zeichenraum = 0
    if re.search(r"[a-z]", passwort):
        zeichenraum += 26
    if re.search(r"[A-Z]", passwort):
        zeichenraum += 26
    if re.search(r"[0-9]", passwort):
        zeichenraum += 10
    if re.search(r"[^a-zA-Z0-9]", passwort):
        zeichenraum += 33

    if zeichenraum == 0:
        return 0.0

    return len(passwort) * math.log2(zeichenraum)


# ---------------------------------------------------------------------------
# Muster-Erkennung
# ---------------------------------------------------------------------------


def erkenne_muster(passwort: str) -> list[str]:
    """Erkennt schwache Muster im Passwort.

    Args:
        passwort: Das zu analysierende Passwort.

    Returns:
        Liste der gefundenen schwachen Muster (leer = keine gefunden).
    """
    gefunden: list[str] = []
    pw_lower = passwort.lower()

    # In Top-25-Liste
    if pw_lower in _SCHWACHE_PASSWOERTER:
        gefunden.append("Passwort ist in der Liste bekannter schwacher Passwörter")

    # Tastatur-Muster
    for muster in _KEYBOARD_PATTERNS:
        if muster in pw_lower:
            gefunden.append(f"Tastaturmuster erkannt: '{muster}'")
            break

    # Zeichen-Wiederholungen (aaa, 111)
    if re.search(r"(.)\1{2,}", passwort):
        gefunden.append("Zeichenwiederholung erkannt (z.B. 'aaa', '111')")

    # Nur Ziffern
    if passwort.isdigit():
        gefunden.append("Passwort besteht ausschließlich aus Ziffern")

    # Nur Buchstaben
    if passwort.isalpha():
        gefunden.append("Passwort besteht ausschließlich aus Buchstaben")

    # Aufsteigende/absteigende Sequenzen (1234, dcba)
    if re.search(r"(012|123|234|345|456|567|678|789|890)", passwort):
        gefunden.append("Aufsteigende Ziffernsequenz erkannt")

    return gefunden


# ---------------------------------------------------------------------------
# Score-Berechnung
# ---------------------------------------------------------------------------


def berechne_score(passwort: str) -> int:
    """Berechnet den Stärke-Score 0–100.

    Scoring-Kriterien:
    - Länge: bis zu 40 Punkte (4 Punkte × Zeichen, max. bei 10+)
    - Zeichenklassen: bis zu 40 Punkte (je 10 pro Klasse)
    - Muster-Abzug: -10 pro gefundenem schwachen Muster (max. -30)
    - Entropie-Bonus: bis zu 20 Punkte (ab 60 Bits)

    Args:
        passwort: Das zu analysierende Passwort.

    Returns:
        Score von 0 bis 100.
    """
    if not passwort:
        return 0

    score = 0

    # Länge (max. 40 Punkte)
    laenge_punkte = min(40, len(passwort) * 4)
    score += laenge_punkte

    # Zeichenklassen (je 10 Punkte, max. 40)
    if re.search(r"[a-z]", passwort):
        score += 10
    if re.search(r"[A-Z]", passwort):
        score += 10
    if re.search(r"[0-9]", passwort):
        score += 10
    if re.search(r"[^a-zA-Z0-9]", passwort):
        score += 10

    # Entropie-Bonus (max. 20 Punkte ab 60 Bits)
    entropie = berechne_entropie(passwort)
    if entropie >= 80:
        score += 20
    elif entropie >= 60:
        score += 10

    # Muster-Abzug
    muster = erkenne_muster(passwort)
    score -= min(30, len(muster) * 10)

    return max(0, min(100, score))


def score_zu_staerke(score: int) -> PasswordStaerke:
    """Konvertiert einen numerischen Score in eine Bewertungsstufe.

    Args:
        score: Numerischer Score 0–100.

    Returns:
        Entsprechende PasswordStaerke-Stufe.
    """
    if score < 20:
        return PasswordStaerke.SEHR_SCHWACH
    if score < 40:
        return PasswordStaerke.SCHWACH
    if score < 60:
        return PasswordStaerke.MITTEL
    if score < 80:
        return PasswordStaerke.STARK
    return PasswordStaerke.SEHR_STARK


def staerke_bei_breach(
    staerke: PasswordStaerke, score: int, breach_vorkommnisse: int
) -> tuple[PasswordStaerke, int]:
    """Kappt die Stärke-Bewertung, wenn das Passwort in einer Datenpanne auftaucht.

    Ein in einem bekannten Breach gefundenes Passwort ist unabhängig von Entropie,
    Länge und Zeichenklassen kompromittiert (NIST SP 800-63B §5.1.1.2; zxcvbn):
    der reine Score würde es sonst fälschlich als „stark" ausweisen. Ein
    HIBP-Treffer (``breach_vorkommnisse > 0``) überschreibt das score-basierte
    Verdikt daher hart auf:attr:`PasswordStaerke.SEHR_SCHWACH` (Score 0). Ohne
    Treffer (``0``) oder ohne Prüfung (``-1``) bleibt die Bewertung unverändert.

    Args:
        staerke: Die score-basierte Stärke-Stufe.
        score: Der numerische Score 0–100.
        breach_vorkommnisse: HIBP-Vorkommen (``>0`` = kompromittiert).

    Returns:
        ``(staerke, score)`` — auf ``(SEHR_SCHWACH, 0)`` gekappt bei Breach-Treffer,
        sonst unverändert.
    """
    if breach_vorkommnisse > 0:
        return PasswordStaerke.SEHR_SCHWACH, 0
    return staerke, score


# ---------------------------------------------------------------------------
# Policy-Compliance
# ---------------------------------------------------------------------------


def pruefe_policy(passwort: str, policy: PasswordPolicy) -> list[PolicyCheck]:
    """Prüft die Compliance des Passworts gegen eine Policy.

    Args:
        passwort: Das zu prüfende Passwort.
        policy: Die Policy gegen die geprüft wird.

    Returns:
        Liste der PolicyCheck-Ergebnisse für jede Anforderung.
    """
    checks: list[PolicyCheck] = []

    # Mindestlänge
    checks.append(
        PolicyCheck(
            bezeichnung=f"Mindestlänge {policy.min_laenge} Zeichen",
            erfuellt=len(passwort) >= policy.min_laenge,
            hinweis=f"Aktuell: {len(passwort)} Zeichen"
            if len(passwort) < policy.min_laenge
            else "",
        )
    )

    # Großbuchstaben
    if policy.gross_buchstaben:
        hat_gross = bool(re.search(r"[A-Z]", passwort))
        checks.append(
            PolicyCheck(
                bezeichnung="Großbuchstaben enthalten",
                erfuellt=hat_gross,
                hinweis="Mindestens ein Großbuchstabe erforderlich"
                if not hat_gross
                else "",
            )
        )

    # Kleinbuchstaben
    if policy.klein_buchstaben:
        hat_klein = bool(re.search(r"[a-z]", passwort))
        checks.append(
            PolicyCheck(
                bezeichnung="Kleinbuchstaben enthalten",
                erfuellt=hat_klein,
                hinweis="Mindestens ein Kleinbuchstabe erforderlich"
                if not hat_klein
                else "",
            )
        )

    # Ziffern
    if policy.ziffern:
        hat_ziffer = bool(re.search(r"[0-9]", passwort))
        checks.append(
            PolicyCheck(
                bezeichnung="Ziffern enthalten",
                erfuellt=hat_ziffer,
                hinweis="Mindestens eine Ziffer (0–9) erforderlich"
                if not hat_ziffer
                else "",
            )
        )

    # Sonderzeichen
    if policy.sonderzeichen:
        hat_sonder = bool(re.search(r"[^a-zA-Z0-9]", passwort))
        checks.append(
            PolicyCheck(
                bezeichnung="Sonderzeichen enthalten",
                erfuellt=hat_sonder,
                hinweis="Mindestens ein Sonderzeichen (!@#$% …) erforderlich"
                if not hat_sonder
                else "",
            )
        )

    return checks


def erstelle_empfehlungen(
    passwort: str,
    policy: PasswordPolicy,
    policy_checks: list[PolicyCheck],
    muster: list[str],
) -> list[str]:
    """Erstellt kontextspezifische Verbesserungsempfehlungen.

    Args:
        passwort: Das analysierte Passwort.
        policy: Die verwendete Policy.
        policy_checks: Ergebnisse der Policy-Prüfung.
        muster: Gefundene schwache Muster.

    Returns:
        Liste der Empfehlungen (leer wenn alles in Ordnung).
    """
    empfehlungen: list[str] = []

    for check in policy_checks:
        if not check.erfuellt:
            empfehlungen.append(check.hinweis)

    if muster:
        empfehlungen.append("Tastaturmuster und einfache Sequenzen vermeiden")

    if len(passwort) < 16 and len(passwort) >= policy.min_laenge:
        empfehlungen.append(
            "Längeres Passwort (16+ Zeichen) erhöht die Sicherheit deutlich"
        )

    entropie = berechne_entropie(passwort)
    if entropie < 50:
        empfehlungen.append(
            "Passwort-Manager verwenden um zufällige, starke Passwörter zu generieren"
        )

    return empfehlungen


# ---------------------------------------------------------------------------
# Haupt-Analyse-Funktion
# ---------------------------------------------------------------------------


def analysiere_passwort(
    passwort: str,
    policy: PasswordPolicy,
) -> PasswordCheckResult:
    """Führt die vollständige Passwort-Analyse durch.

    Security: Das Passwort wird nicht ins Result-Objekt übernommen.

    Args:
        passwort: Das zu analysierende Passwort (bleibt im RAM).
        policy: Die anzuwendende Policy.

    Returns:
        PasswordCheckResult mit allen Analyseergebnissen.
    """
    entropie = berechne_entropie(passwort)
    score = berechne_score(passwort)
    staerke = score_zu_staerke(score)
    muster = erkenne_muster(passwort)
    policy_checks = pruefe_policy(passwort, policy)
    empfehlungen = erstelle_empfehlungen(passwort, policy, policy_checks, muster)

    return PasswordCheckResult(
        staerke=staerke,
        score=score,
        entropie_bits=round(entropie, 1),
        laenge=len(passwort),
        policy_checks=policy_checks,
        muster_gefunden=muster,
        empfehlungen=empfehlungen,
        breach_vorkommnisse=-1,  # HIBP wird separat in application/ aufgerufen
    )
