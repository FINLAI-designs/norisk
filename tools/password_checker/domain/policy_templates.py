"""policy_templates — Vordefinierte Passwort-Policy-Vorlagen.

Enthält BSI Grundschutz, NIST 800-63B und ISO 27001 Vorlagen.
Alle Vorlagen basieren auf dem jeweiligen Stand 2024.

Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.password_checker.domain.models import PasswordPolicy, PolicyVorlage

# ---------------------------------------------------------------------------
# BSI Grundschutz (M 2.11, ORP.4)
# ---------------------------------------------------------------------------

POLICY_BSI = PasswordPolicy(
    name="BSI Grundschutz",
    vorlage=PolicyVorlage.BSI,
    min_laenge=12,
    gross_buchstaben=True,
    klein_buchstaben=True,
    ziffern=True,
    sonderzeichen=True,
    max_alter_tage=365,
    breach_check=True,
    keine_wiederverwendung=10,
)

# ---------------------------------------------------------------------------
# NIST Special Publication 800-63B (2024)
# ---------------------------------------------------------------------------
# NIST empfiehlt: Länge > Komplexität, kein erzwungener Ablauf,
# aber Breach-Prüfung und keine Keyboard-Patterns.

POLICY_NIST = PasswordPolicy(
    name="NIST 800-63B (2024)",
    vorlage=PolicyVorlage.NIST,
    min_laenge=15,
    gross_buchstaben=False,  # NIST: keine Komplexitätsregeln erzwingen
    klein_buchstaben=False,
    ziffern=False,
    sonderzeichen=False,
    max_alter_tage=0,  # NIST: kein erzwungener Ablauf
    breach_check=True,  # NIST: Pflicht-Prüfung gegen Breach-Listen
    keine_wiederverwendung=0,
)

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 + 27002 (Annex A.5.17)
# ---------------------------------------------------------------------------

POLICY_ISO27001 = PasswordPolicy(
    name="ISO 27001:2022",
    vorlage=PolicyVorlage.ISO27001,
    min_laenge=10,
    gross_buchstaben=True,
    klein_buchstaben=True,
    ziffern=True,
    sonderzeichen=True,
    max_alter_tage=90,
    breach_check=True,
    keine_wiederverwendung=12,
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALLE_VORLAGEN: dict[PolicyVorlage, PasswordPolicy] = {
    PolicyVorlage.BSI: POLICY_BSI,
    PolicyVorlage.NIST: POLICY_NIST,
    PolicyVorlage.ISO27001: POLICY_ISO27001,
}

VORLAGE_NAMEN: list[str] = [p.name for p in ALLE_VORLAGEN.values()]
