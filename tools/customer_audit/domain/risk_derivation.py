"""
risk_derivation — leitet BSI-200-3-Risiko-Startwerte aus den Audit-Antworten ab.

Statt die 10 Default-Risiken mit FIXEN P/S-Werten zu seeden (alt: rein statischer
:data:`DEFAULT_RISK_CATALOG`), berechnet diese reine Domain-Funktion aus den
bereits ausgefüllten Audit-Schritten (Backup-Audit, organisatorische Sicherheit,
Phishing-/E-Mail-Sicherheit) sinnvolle **Startwerte** pro Risiko. Der Auditor
kann sie danach weiterhin manuell anpassen — die Ableitung setzt nur die
Ausgangslage, damit z. B. ein starkes 3-2-1-1-0-Backup das Risiko
"Backup-Ausfall" nicht weiter auf "hoch" stehen lässt.

Designprinzip (Patrick-Entscheid 2026-06-27): "Aus Audit ableiten". Nur Risiken
mit klarem Audit-Signal werden überschrieben; Risiken ohne Signal (Hardware-
Defekt, Stromausfall) behalten ihren Katalog-Default. Antworten "Nicht
zutreffend" / "Nicht möglich" / "Unbekannt" wirken NEUTRAL (kein Auf-/Abschlag),
nicht wie ein "Nein".

Schichtzugehörigkeit: domain/ — keine Importe aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.customer_audit.domain.entities import OrganizationalData, PhishingData
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskImpact,
    RiskProbability,
)

#: Maximaler Backup-Score aus:func:`entities.compute_backup_score` (0..15).
_BACKUP_SCORE_MAX = 15

#: "Ja/Teilweise/Nein" → Kontroll-Stärke in [0,1]. Alles andere (Nicht
#: zutreffend / Nicht möglich / Unbekannt / leer) → ``None`` = neutral.
_STRENGTH_BY_ANSWER: dict[str, float] = {
    "ja": 1.0,
    "teilweise": 0.5,
    "nein": 0.0,
}


def _control_strength(answer: str) -> float | None:
    """Übersetzt eine Ja/Nein/Teilweise-Antwort in eine Kontroll-Stärke [0,1].

    Args:
        answer: Antworttext ("Ja"/"Nein"/"Teilweise"/"Nicht möglich"/...).

    Returns:
        ``1.0`` (Ja), ``0.5`` (Teilweise), ``0.0`` (Nein) oder ``None`` für
        neutrale Antworten (Nicht zutreffend/möglich, Unbekannt, leer).
    """
    return _STRENGTH_BY_ANSWER.get(answer.strip().lower())


def _avg_strength(*answers: str) -> float | None:
    """Mittelt die Kontroll-Stärken; neutrale Antworten werden ignoriert.

    Returns:
        Durchschnittliche Stärke in [0,1] oder ``None``, wenn KEINE der
        Antworten ein verwertbares Signal liefert (dann kein Override).
    """
    values = [s for a in answers if (s := _control_strength(a)) is not None]
    if not values:
        return None
    return sum(values) / len(values)


def _prob_from_exposure(exposure: float) -> RiskProbability:
    """Bildet die Risiko-Exposition [0,1] auf eine 4-stufige Wahrscheinlichkeit ab.

    Höhere Exposition (= schwächere Kontrollen) → höhere Eintrittswahrscheinlichkeit.
    Schwellen folgen den Vierteln der BSI-200-3-Skala (25/50/75 %).
    """
    if exposure < 0.25:
        return RiskProbability.SELTEN
    if exposure < 0.50:
        return RiskProbability.MITTEL
    if exposure < 0.75:
        return RiskProbability.HAEUFIG
    return RiskProbability.SEHR_HAEUFIG


def _default_impact(catalog_key: str) -> RiskImpact:
    """Katalog-Default-Schadenshöhe für ein Risiko (Fallback BETRAECHTLICH)."""
    entry = DEFAULT_RISK_CATALOG_BY_KEY.get(catalog_key)
    return entry.default_impact if entry is not None else RiskImpact.BETRAECHTLICH


def derive_risk_seeds(
    *,
    organizational: OrganizationalData | None = None,
    backup_score: int | None = None,
    phishing: PhishingData | None = None,
) -> dict[str, tuple[RiskProbability, RiskImpact]]:
    """Leitet Risiko-Startwerte (P, S) aus den Audit-Antworten ab.

    Liefert NUR Overrides für Risiken mit klarem Audit-Signal. Risiken ohne
    Signal (``hardware_defekt``, ``stromausfall``) fehlen im Ergebnis und
    behalten beim Seeding ihren Katalog-Default. Fehlt ein ganzer Eingabe-Block
    (z. B. ``phishing is None`` oder nur neutrale Antworten), wird das jeweilige
    Risiko nicht überschrieben.

    Args:
        organizational: Organisatorische Sicherheits-Antworten (Zugangskontrolle,
            Update-Management, Sensibilisierung, DSGVO, AVV-Schlüsseltrennung).
        backup_score: Ergebnis von:func:`entities.compute_backup_score` (0..15)
            oder ``None``, wenn der Backup-Audit nicht ausgefüllt ist.
        phishing: E-Mail-/Phishing-Sicherheits-Antworten (MFA, Schulung,
            SPF/DKIM/DMARC, Mailfilter).

    Returns:
        ``{catalog_key: (RiskProbability, RiskImpact)}`` für die abgeleiteten
        Risiken.
    """
    seeds: dict[str, tuple[RiskProbability, RiskImpact]] = {}

    # ── Backup-Ausfall ────────────────────────────────────────────────
    # Starkes 3-2-1-1-0-Backup (hoher Score) → seltener UND weniger
    # existenzbedrohend (recoverbar). Schwaches Backup → häufig + existenzbedr.
    backup_strength: float | None = None
    if backup_score is not None:
        backup_strength = max(0.0, min(1.0, backup_score / _BACKUP_SCORE_MAX))
        prob = _prob_from_exposure(1.0 - backup_strength)
        impact = (
            RiskImpact.BETRAECHTLICH
            if backup_strength >= 0.85
            else RiskImpact.EXISTENZBEDROHEND
        )
        seeds["backup_ausfall"] = (prob, impact)

    org = organizational

    # ── Patch-Lücke ───────────────────────────────────────────────────
    if org is not None:
        patch_strength = _avg_strength(org.update_management)
        if patch_strength is not None:
            seeds["patch_luecke"] = (
                _prob_from_exposure(1.0 - patch_strength),
                _default_impact("patch_luecke"),
            )

    # ── Phishing / Spear-Phishing ─────────────────────────────────────
    if phishing is not None:
        phish_strength = _avg_strength(
            phishing.mfa_aktiv,
            phishing.phishing_schulung_aktuell,
            phishing.mail_spoofing_schutz,
            phishing.mail_filter_aktiv,
        )
        if phish_strength is not None:
            seeds["phishing"] = (
                _prob_from_exposure(1.0 - phish_strength),
                _default_impact("phishing"),
            )

    # ── Ransomware ────────────────────────────────────────────────────
    # Wahrscheinlichkeit aus Patch- + Phishing-Lage; Schadenshöhe sinkt bei
    # starkem Backup (wiederherstellbar → weniger existenzbedrohend).
    if org is not None or phishing is not None:
        exposure_signals: list[float] = []
        if org is not None and (s := _control_strength(org.update_management)) is not None:
            exposure_signals.append(s)
        if phishing is not None:
            ph = _avg_strength(
                phishing.mfa_aktiv,
                phishing.phishing_schulung_aktuell,
                phishing.mail_spoofing_schutz,
                phishing.mail_filter_aktiv,
            )
            if ph is not None:
                exposure_signals.append(ph)
        if exposure_signals:
            avg = sum(exposure_signals) / len(exposure_signals)
            prob = _prob_from_exposure(1.0 - avg)
            if backup_strength is not None and backup_strength >= 0.6:
                impact = RiskImpact.BETRAECHTLICH
            else:
                impact = RiskImpact.EXISTENZBEDROHEND
            seeds["ransomware"] = (prob, impact)

    if org is not None:
        # ── Insider-Bedrohung ─────────────────────────────────────────
        insider = _avg_strength(
            org.zugangskontrollen, org.mitarbeitersensibilisierung
        )
        if insider is not None:
            seeds["insider_bedrohung"] = (
                _prob_from_exposure(1.0 - insider),
                _default_impact("insider_bedrohung"),
            )

        # ── Mitarbeiter-Fehler ────────────────────────────────────────
        mitarbeiter = _avg_strength(
            org.mitarbeitersensibilisierung, org.zugangskontrollen
        )
        if mitarbeiter is not None:
            seeds["mitarbeiter_fehler"] = (
                _prob_from_exposure(1.0 - mitarbeiter),
                _default_impact("mitarbeiter_fehler"),
            )

        # ── Mandantendaten-Leck ───────────────────────────────────────
        leak = _avg_strength(org.zugangskontrollen, org.dsgvo_konformitaet)
        if leak is not None:
            seeds["mandantendaten_leak"] = (
                _prob_from_exposure(1.0 - leak),
                _default_impact("mandantendaten_leak"),
            )

        # ── DSGVO-/Berufsrechts-Verstoß ──────────────────────────────
        compliance = _avg_strength(
            org.dsgvo_konformitaet, org.avv_key_separate_storage
        )
        if compliance is not None:
            seeds["compliance_verstoss"] = (
                _prob_from_exposure(1.0 - compliance),
                _default_impact("compliance_verstoss"),
            )

    return seeds
