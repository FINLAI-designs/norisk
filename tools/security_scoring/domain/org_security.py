"""
org_security — Domain-Modelle und Fragenkataloge für Organisatorische Sicherheit.

Vier Metriken: DSGVO-Compliance, Phishing-Schutz, MFA, Passwort-Manager.
Enthält reine Daten-Klassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from core.security_subject.models import NutzungsSignale


class OrgAntwort(StrEnum):
    """Antwortzustand einer Self-Assessment-Frage.

    JA/NEIN/UNBEKANNT zählen im Score-Nenner — UNBEKANNT (unverifiziert) gibt
    keinen Kredit (Microsoft-Secure-Score-Stil). NICHT_ANWENDBAR fällt
    aus dem Nenner: eine Frage, die fürs Subjekt nicht zutrifft, senkt den
    Score nicht.
    """

    JA = "ja"
    NEIN = "nein"
    UNBEKANNT = "unbekannt"
    NICHT_ANWENDBAR = "nicht_anwendbar"


@dataclass(frozen=True)
class OrgFrage:
    """Eine Self-Assessment-Frage.

    Attributes:
        key: Stabiler Schlüssel für Persistenz.
        text: Neutral formulierter Fragetext für die UI.
    """

    key: str
    text: str


METRIK_DSGVO = "dsgvo"
METRIK_PHISHING = "phishing"
METRIK_MFA = "mfa"
METRIK_PASSWORT_MANAGER = "passwort_manager"

METRIK_ANZEIGENAME: dict[str, str] = {
    METRIK_DSGVO: "DSGVO-Compliance",
    METRIK_PHISHING: "Phishing-Schutz",
    METRIK_MFA: "Multi-Factor Authentication",
    METRIK_PASSWORT_MANAGER: "Passwort-Manager",
}


FRAGEN_DSGVO: tuple[OrgFrage, ...] = (
    OrgFrage(
        "datenschutzerklaerung_aktuell",
        "Datenschutzerklärung auf der Website vorhanden und aktuell",
    ),
    OrgFrage(
        "vvt_gefuehrt",
        "Verzeichnis von Verarbeitungstätigkeiten (VVT) geführt",
    ),
    OrgFrage(
        "avv_abgeschlossen",
        "Auftragsverarbeitungsverträge (AVV) mit Dienstleistern abgeschlossen",
    ),
    OrgFrage(
        "dsb_benannt",
        "Datenschutzbeauftragter benannt (falls gemäß Kriterien erforderlich)",
    ),
    OrgFrage(
        "mitarbeiter_geschult",
        "Mitarbeiter auf Datenschutz geschult (letzte 12 Monate)",
    ),
    OrgFrage(
        "betroffenenrechte_prozess",
        "Prozess für Betroffenenrechte (Auskunft/Löschung) dokumentiert",
    ),
)

FRAGEN_PHISHING: tuple[OrgFrage, ...] = (
    OrgFrage(
        "schulung_letzte_12m",
        "Phishing-Schulung für Mitarbeiter (letzte 12 Monate)",
    ),
    OrgFrage(
        "simulation_letzte_12m",
        "Phishing-Simulation durchgeführt (letzte 12 Monate)",
    ),
    OrgFrage(
        "spam_filter_aktiv",
        "Spam- und Phishing-Filter im E-Mail-System aktiv",
    ),
    OrgFrage(
        "meldekette_etabliert",
        "Meldekette für verdächtige Mails etabliert",
    ),
    OrgFrage(
        "link_pruefung_mail_gateway",
        "Links in E-Mails werden automatisch geprüft (Mail-Gateway)",
    ),
)

# MFA: 1 Auto-Detection ("windows_hello") + 6 Self-Assessment-Fragen.
MFA_AUTO_KEY = "windows_hello"
FRAGEN_MFA: tuple[OrgFrage, ...] = (
    OrgFrage("mfa_m365_azure", "MFA aktiv für Microsoft 365 / Azure"),
    OrgFrage(
        "mfa_steuerberater_software",
        "MFA aktiv für Steuerberater-Software (BMD, DATEV o.ä.)",
    ),
    OrgFrage("mfa_online_banking", "MFA aktiv für Online-Banking"),
    OrgFrage(
        "mfa_cloud_speicher",
        "MFA aktiv für Cloud-Speicher (Dropbox, OneDrive, Google Drive)",
    ),
    OrgFrage("mfa_passwort_manager", "MFA aktiv für den Passwort-Manager selbst"),
    OrgFrage(
        "mfa_email_accounts",
        "MFA aktiv für E-Mail-Accounts (privat und geschäftlich)",
    ),
)

# Passwort-Manager: 1 Auto-Detection ("passwort_manager_installiert")
# + 3 Self-Assessment-Fragen.
PM_AUTO_KEY = "passwort_manager_installiert"
FRAGEN_PASSWORT_MANAGER: tuple[OrgFrage, ...] = (
    OrgFrage("pm_aktiv_genutzt", "Passwort-Manager wird aktiv für alle Logins genutzt"),
    OrgFrage(
        "pm_master_stark",
        "Master-Passwort ist stark (mindestens 16 Zeichen, einmalig verwendet)",
    ),
    OrgFrage(
        "pm_regelmaessig_gesichert",
        "Passwort-Manager-Datenbank wird regelmäßig gesichert",
    ),
)


# Whitelist bekannter Passwort-Manager — genutzt für Auto-Detection.
BEKANNTE_PASSWORT_MANAGER: tuple[str, ...] = (
    "1Password",
    "Bitwarden",
    "KeePass",
    "KeePassXC",
    "LastPass",
    "Dashlane",
    "NordPass",
    "RoboForm",
    "Enpass",
)


# ---------------------------------------------------------------------------
# Default-Gewichtung
# ---------------------------------------------------------------------------
# Block "Organisatorische Sicherheit" macht ~25% des Gesamtscores aus.
# Innerhalb des Blocks: DSGVO und MFA je 30%, Phishing und PW-Manager je 20%.
#
# Absolute Gewichte (werden in ScoreComponent.weight eingetragen):
# DSGVO 0.10 (MFA + DSGVO zusammen = 0.20, ~60% des Blocks)
# MFA 0.10
# Phishing 0.07 (~20% des Blocks)
# Passwort-Mgr 0.07
# ──────
# Summe Org-Block 0.34
#
# Technischer Block (scoring_engine.DEFAULT_WEIGHTS) summiert zu 1.00 —
# damit hat Org-Block 0.34 / 1.34 ≈ 25,4% des Gesamtscores.
# calculate_overall_score normalisiert via total_weight.
DEFAULT_ORG_WEIGHTS: dict[str, float] = {
    METRIK_DSGVO: 0.10,
    METRIK_MFA: 0.10,
    METRIK_PHISHING: 0.07,
    METRIK_PASSWORT_MANAGER: 0.07,
}


@dataclass(frozen=True)
class OrgMetrikErgebnis:
    """Ergebnis einer einzelnen Metrik.

    Attributes:
        metrik: Metrik-Key (siehe METRIK_*-Konstanten).
        antworten: Zuordnung Frage-Key → OrgAntwort.
        auto_status: Auto-Detection-Rohstatus (``"aktiv"``, ``"inaktiv"``,
                         ``"unbekannt"``) oder leer wenn keine Auto-Detection.
        auto_details: Freie Details zur Auto-Detection (z.B. erkannter
                         Programmname). Leer wenn keine Details vorliegen.
        custom_pm_name: Vom User manuell ergänzter Passwort-Manager.
    """

    metrik: str
    antworten: dict[str, OrgAntwort] = field(default_factory=dict)
    auto_status: str = ""
    auto_details: str = ""
    custom_pm_name: str = ""


@dataclass(frozen=True)
class OrgAssessment:
    """Vollständiges Organisations-Sicherheits-Assessment.

    Attributes:
        audit_id: UUID.
        timestamp: ISO-Datetime der Speicherung.
        dsgvo: OrgMetrikErgebnis für DSGVO.
        phishing: OrgMetrikErgebnis für Phishing-Schutz.
        mfa: OrgMetrikErgebnis für MFA.
        passwort_manager: OrgMetrikErgebnis für Passwort-Manager.
    """

    audit_id: str
    timestamp: str
    dsgvo: OrgMetrikErgebnis
    phishing: OrgMetrikErgebnis
    mfa: OrgMetrikErgebnis
    passwort_manager: OrgMetrikErgebnis

    def metriken(self) -> list[OrgMetrikErgebnis]:
        """Gibt alle Metriken in definierter Reihenfolge zurück."""
        return [self.dsgvo, self.phishing, self.mfa, self.passwort_manager]


# ---------------------------------------------------------------------------
# Ebene 2 — profil-bedingte „nicht anwendbar"-Vorbelegung
# ---------------------------------------------------------------------------
# Heuristische DSB-Schwelle: ein Datenschutzbeauftragter ist erst ab einer
# gewissen Mitarbeiterzahl regelmäßig Pflicht (DE §38 BDSG: 20 Personen ständig
# mit automatisierter Verarbeitung; AT folgt den GDPR-Art-37-Kriterien ohne
# starre Zahl). Bewusst konservativ + zentral anpassbar.
DSB_FTE_SCHWELLE = 20

# Mitarbeiter-abhängige Fragen: ohne Mitarbeiter (Solo) nicht anwendbar.
_MITARBEITER_FRAGEN: frozenset[str] = frozenset(
    {
        "mitarbeiter_geschult",   # DSGVO
        "schulung_letzte_12m",    # Phishing
        "simulation_letzte_12m",  # Phishing
        "meldekette_etabliert",   # Phishing
    }
)


def profil_na_keys(fte: int | None) -> frozenset[str]:
    """Frage-Keys, die laut Firmenprofil „nicht anwendbar" sind Ebene 2).

    Konservativ: nur bei BEKANNTEM ``fte`` wird etwas auf N/A vorbelegt.
    ``fte is None`` (unbekannt) → leere Menge, alle Fragen bleiben aktiv
    („nicht erfasst" ≠ „trifft nicht zu").

    Args:
        fte: Vollzeitäquivalente des eigenen Subjekts oder ``None``.

    Returns:
        Menge der Frage-Keys, die als ``NICHT_ANWENDBAR`` vorzubelegen sind.
    """
    if fte is None:
        return frozenset()
    keys: set[str] = set()
    if fte <= 1:
        # Solo / keine Mitarbeiter → mitarbeiter-abhängige Fragen entfallen.
        keys |= _MITARBEITER_FRAGEN
    if fte < DSB_FTE_SCHWELLE:
        # Unter der DSB-Schwelle i.d.R. kein Datenschutzbeauftragter Pflicht.
        keys.add("dsb_benannt")
    return frozenset(keys)


# ---------------------------------------------------------------------------
# Ebene 3 — nutzungs-bedingte „nicht anwendbar"-Vorbelegung
# ---------------------------------------------------------------------------
# Zuordnung tri-state-Nutzungssignal (NutzungsSignale-Feld) → Org-Frage-Key.
# Nur diese vier Fragen sind nutzungs-bedingt sicher ableitbar; der Rest der
# 20 Fragen ist quasi-universal und bleibt außerhalb der Auto-Detection.
_NUTZUNG_ZU_FRAGE: tuple[tuple[str, str], ...] = (
    ("nutzt_m365", "mfa_m365_azure"),
    ("nutzt_kanzlei_software", "mfa_steuerberater_software"),
    ("nutzt_cloud_speicher", "mfa_cloud_speicher"),
    ("hat_auftragsverarbeiter", "avv_abgeschlossen"),
)

# Confirm-only-Fragen: bestätigte Nutzung (True) hält die Frage aktiv, ein
# Nicht-Befund (False) löst aber KEIN Auto-N/A aus. ``avv_abgeschlossen``: der
# Sovereignty-Katalog erfasst nur Cloud-/Software-Dienste — Art-28-Auftrags-
# verarbeiter umfassen weit mehr (Steuerberater, Lohnverrechnung, IT-Dienstleister,
# Hoster), daher ist „Katalog leer" ein zu schwacher Beleg für „keine AV"
# (Patrick-Entscheidung 2026-06-05; 3-Sub-Agent-Review P3).
_CONFIRM_ONLY_FRAGEN: frozenset[str] = frozenset({"avv_abgeschlossen"})


@dataclass(frozen=True)
class NaVorbelegung:
    """„Nicht anwendbar"-Vorbelegung mit Begründungs-Herkunft Ebene 2 + 3).

    Attributes:
        keys: Alle Frage-Keys, die als ``NICHT_ANWENDBAR`` vorzubelegen sind
            (Firmengröße ∪ Nutzung), abzüglich konkret beantworteter und
            bestätigt genutzter Keys.
        nutzungs_keys: Teilmenge von ``keys``, die aus einem Nutzungssignal
            (Ebene 3) stammt — für den differenzierten Wizard-Tooltip
            („Nutzung" vs. „Firmengröße").
        audit_datum: ISO-Datum des zugrunde liegenden SELF-Audits (``""`` wenn
            keins) — für den erklärenden Tooltip Mechanismus 3).
    """

    keys: frozenset[str] = frozenset()
    nutzungs_keys: frozenset[str] = frozenset()
    audit_datum: str = ""


def konkret_beantwortete_keys(assessment: OrgAssessment) -> frozenset[str]:
    """Frage-Keys, die im Assessment konkret mit JA/NEIN beantwortet wurden.

    Grundlage der Konflikt-Regel: eine bereits konkret beantwortete
    Frage darf **nicht** erneut auto-N/A-vorbelegt werden — die jüngere,
    explizite Nutzerantwort ist stärkeres Signal als ein älterer Snapshot.
    UNBEKANNT und NICHT_ANWENDBAR zählen NICHT als konkret beantwortet.

    Args:
        assessment: Das (jüngste) gespeicherte Assessment.

    Returns:
        Menge der mit JA oder NEIN beantworteten Frage-Keys.
    """
    konkret: set[str] = set()
    for metrik in assessment.metriken():
        for key, antwort in metrik.antworten.items():
            if antwort in (OrgAntwort.JA, OrgAntwort.NEIN):
                konkret.add(key)
    return frozenset(konkret)


def nutzungs_na_keys(
    fte_na: frozenset[str],
    signale: NutzungsSignale,
    konkret_beantwortet: frozenset[str],
) -> NaVorbelegung:
    """Kombiniert FTE-Profil- und Nutzungs-Vorbelegung Ebene 3).

    Konservative Regeln (rein, deterministisch):
      * Signal ``True`` (Nutzung bestätigt) → Frage **aktiv** halten; hebt eine
        etwaige Auto-N/A-Vorbelegung auf (Bestätigung schlägt Suppression).
      * Signal ``False`` (Nicht-Nutzung bestätigt) → Frage zur N/A-Vorbelegung,
        **außer** der Key ist confirm-only (``_CONFIRM_ONLY_FRAGEN``) → No-op.
      * Signal ``None`` (unbekannt) → No-op.
      * **Confirm-only** (z. B. ``avv_abgeschlossen``): nur ``True`` hält aktiv,
        ``False`` löst nie Auto-N/A aus (Katalog zu schmaler Proxy).
      * **Konflikt-Regel:** ein konkret (JA/NEIN) beantworteter Key wird **nie**
        auto-N/A-vorbelegt — gilt für FTE- *und* Nutzungs-Quelle.

    Args:
        fte_na: FTE-bedingte N/A-Keys (Ebene 2, aus:func:`profil_na_keys`).
        signale: Tri-state-Nutzungssignale des eigenen Subjekts.
        konkret_beantwortet: Bereits mit JA/NEIN beantwortete Frage-Keys
            (aus dem jüngsten Assessment;:func:`konkret_beantwortete_keys`).

    Returns:
:class:`NaVorbelegung` mit der finalen N/A-Menge, der Nutzungs-Teilmenge
        (für den Tooltip) und dem Audit-Datum.
    """
    nutzungs_na: set[str] = set()
    aktiv_bestaetigt: set[str] = set()
    for attr, frage_key in _NUTZUNG_ZU_FRAGE:
        wert = getattr(signale, attr)
        if wert is True:
            aktiv_bestaetigt.add(frage_key)
        elif wert is False and frage_key not in _CONFIRM_ONLY_FRAGEN:
            nutzungs_na.add(frage_key)
        # wert is None (oder confirm-only + False) → No-op

    # Bestätigte Nutzung UND konkrete Antworten heben jede Auto-N/A-Vorbelegung
    # auf (Override-Vorrang: Bestätigung/explizite Antwort > Suppression).
    unterdrueckt = konkret_beantwortet | aktiv_bestaetigt
    nutzungs_na -= unterdrueckt
    alle = (set(fte_na) | nutzungs_na) - unterdrueckt
    return NaVorbelegung(
        keys=frozenset(alle),
        nutzungs_keys=frozenset(nutzungs_na),
        audit_datum=signale.audit_datum,
    )
