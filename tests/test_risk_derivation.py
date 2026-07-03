"""Tests für ``tools.customer_audit.domain.risk_derivation``.

Deckt ab:
  - Backup-Score → Backup-Ausfall-Risiko (stark = GERING, schwach = SEHR_HOCH).
  - Organisatorische Antworten → abgeleitete Wahrscheinlichkeiten.
  - Phishing-Antworten → Phishing-Risiko.
  - "Nicht möglich"/"Unbekannt" wirken neutral (kein Override / ignoriert).
  - Risiken ohne Signal (hardware_defekt, stromausfall) erscheinen NIE.
  - Fehlende Eingabe-Blöcke (None) erzeugen keine Overrides.
"""

from __future__ import annotations

from tools.customer_audit.domain.entities import OrganizationalData, PhishingData
from tools.customer_audit.domain.risk_derivation import derive_risk_seeds
from tools.customer_audit.domain.risk_entities import (
    RiskImpact,
    RiskLevel,
    RiskProbability,
)

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def test_starkes_backup_macht_backup_ausfall_gering():
    """Bestes Backup (Score 15) → SELTEN × BETRAECHTLICH = GERING (statt statisch HOCH)."""
    seeds = derive_risk_seeds(backup_score=15)
    prob, impact = seeds["backup_ausfall"]
    assert prob == RiskProbability.SELTEN
    assert impact == RiskImpact.BETRAECHTLICH
    assert RiskLevel.from_score(prob, impact) == RiskLevel.GERING


def test_fehlendes_backup_macht_backup_ausfall_sehr_hoch():
    """Score 0 → SEHR_HAEUFIG × EXISTENZBEDROHEND = SEHR_HOCH."""
    seeds = derive_risk_seeds(backup_score=0)
    prob, impact = seeds["backup_ausfall"]
    assert prob == RiskProbability.SEHR_HAEUFIG
    assert impact == RiskImpact.EXISTENZBEDROHEND
    assert RiskLevel.from_score(prob, impact) == RiskLevel.SEHR_HOCH


def test_backup_score_none_kein_override():
    """Ohne Backup-Audit kein Backup-Ausfall-Override."""
    seeds = derive_risk_seeds(backup_score=None)
    assert "backup_ausfall" not in seeds


# ---------------------------------------------------------------------------
# Organisatorisch
# ---------------------------------------------------------------------------


def test_alle_kontrollen_ja_macht_risiken_selten():
    """Durchgehend 'Ja' → SELTEN für die abgeleiteten organisatorischen Risiken."""
    org = OrganizationalData(
        zugangskontrollen="Ja",
        update_management="Ja",
        mitarbeitersensibilisierung="Ja",
        dsgvo_konformitaet="Ja",
        avv_key_separate_storage="Ja",
    )
    seeds = derive_risk_seeds(organizational=org)
    for key in (
        "patch_luecke",
        "insider_bedrohung",
        "mitarbeiter_fehler",
        "mandantendaten_leak",
        "compliance_verstoss",
    ):
        prob, _ = seeds[key]
        assert prob == RiskProbability.SELTEN, key


def test_alle_kontrollen_nein_macht_risiken_sehr_haeufig():
    """Durchgehend 'Nein' → SEHR_HAEUFIG (volle Exposition)."""
    org = OrganizationalData(
        zugangskontrollen="Nein",
        update_management="Nein",
        mitarbeitersensibilisierung="Nein",
        dsgvo_konformitaet="Nein",
        avv_key_separate_storage="Nein",
    )
    seeds = derive_risk_seeds(organizational=org)
    assert seeds["patch_luecke"][0] == RiskProbability.SEHR_HAEUFIG
    assert seeds["insider_bedrohung"][0] == RiskProbability.SEHR_HAEUFIG


def test_zugangskontrolle_nicht_moeglich_wirkt_neutral():
    """'Nicht möglich' wird ignoriert — nur die anderen Signale zählen."""
    org = OrganizationalData(
        zugangskontrollen="Nicht möglich",
        mitarbeitersensibilisierung="Ja",
    )
    seeds = derive_risk_seeds(organizational=org)
    # insider = avg(neutral, Ja) = 1.0 → SELTEN (nicht durch 'nicht möglich' verschlechtert)
    assert seeds["insider_bedrohung"][0] == RiskProbability.SELTEN


def test_komplett_neutrale_org_keine_overrides():
    """Nur neutrale Antworten → kein einziger organisatorischer Override."""
    org = OrganizationalData(
        zugangskontrollen="Unbekannt",
        update_management="Unbekannt",
        mitarbeitersensibilisierung="Unbekannt",
        dsgvo_konformitaet="Unbekannt",
        avv_key_separate_storage="Unbekannt",
    )
    seeds = derive_risk_seeds(organizational=org)
    for key in (
        "patch_luecke",
        "insider_bedrohung",
        "mitarbeiter_fehler",
        "mandantendaten_leak",
        "compliance_verstoss",
    ):
        assert key not in seeds


# ---------------------------------------------------------------------------
# Phishing
# ---------------------------------------------------------------------------


def test_starke_mail_sicherheit_macht_phishing_selten():
    """MFA+Schulung+SPF/DKIM/DMARC+Filter alle 'Ja' → Phishing SELTEN."""
    ph = PhishingData(
        mfa_aktiv="Ja",
        phishing_schulung_aktuell="Ja",
        mail_spoofing_schutz="Ja",
        mail_filter_aktiv="Ja",
    )
    seeds = derive_risk_seeds(phishing=ph)
    assert seeds["phishing"][0] == RiskProbability.SELTEN


def test_keine_mail_sicherheit_macht_phishing_sehr_haeufig():
    """Alles 'Nein' → Phishing SEHR_HAEUFIG."""
    ph = PhishingData()  # Defaults: alle "Nein"
    seeds = derive_risk_seeds(phishing=ph)
    assert seeds["phishing"][0] == RiskProbability.SEHR_HAEUFIG


def test_phishing_none_kein_override():
    seeds = derive_risk_seeds(phishing=None)
    assert "phishing" not in seeds


# ---------------------------------------------------------------------------
# Risiken ohne Signal
# ---------------------------------------------------------------------------


def test_risiken_ohne_signal_nie_abgeleitet():
    """Hardware-Defekt + Stromausfall haben kein Audit-Signal → nie im Ergebnis."""
    org = OrganizationalData(zugangskontrollen="Ja", update_management="Ja")
    seeds = derive_risk_seeds(organizational=org, backup_score=10, phishing=PhishingData())
    assert "hardware_defekt" not in seeds
    assert "stromausfall" not in seeds


def test_leere_eingabe_leere_seeds():
    """Ohne jede Eingabe gibt es keine Overrides."""
    assert derive_risk_seeds() == {}


def test_backup_ableitung_ungedeckelt_macht_backup_ausfall_gering():
    """Voll deklariertes Backup (Detection AUS) → Backup-Ausfall GERING.

    Regression: der 50%-Detection-Cap von compute_backup_score gilt nur fuer den
    Gesamt-Score, NICHT fuer die Ableitung — sonst erreicht ein perfekt
    angehaktes Selbst-Auskunft-Backup nie 'stark' und das Risiko bliebe hoch
    (Patrick-Live-Test 2026-06-27: 'alles angehakt -> trotzdem Maengel').
    """
    from tools.customer_audit.domain.entities import (  # noqa: PLC0415
        BackupAuditResult,
        compute_backup_score,
    )

    audit = BackupAuditResult(
        rule_3_2_1_1_0={
            "3_copies": True,
            "2_media": True,
            "1_offsite": True,
            "1_immutable": True,
            "0_restore_tested": True,
        },
        rpo_hours=4,
        rto_hours=8,
        encryption_enabled=True,
        key_separately_stored=True,
        konzept_pdf_uploaded=True,
        detection_enabled=False,  # reine Selbst-Auskunft
    )
    gedeckelt = compute_backup_score(audit)
    ungedeckelt = compute_backup_score(audit, apply_detection_cap=False)
    assert ungedeckelt > gedeckelt  # Cap greift im Default, nicht ungedeckelt
    assert ungedeckelt >= 12

    prob, impact = derive_risk_seeds(backup_score=ungedeckelt)["backup_ausfall"]
    assert RiskLevel.from_score(prob, impact) == RiskLevel.GERING
