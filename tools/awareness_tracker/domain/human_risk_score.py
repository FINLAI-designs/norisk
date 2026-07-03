"""
human_risk_score — gewichteter Human-Risk-Score fuer die Awareness-Lage.

Aggregiert das Melde-/Klick-Verhalten aus Phishing-Simulationen und die
Schulungs-Aktualitaet zu EINER Kennzahl 0..100 (hoeher = besser, d. h.
geringeres Human-Risk). Kern-KPI ist die Phishing-MELDErate, nicht die
Klickrate: wer eine Phishing-Mail aktiv meldet, schuetzt die ganze
Organisation — das ist branchenueblich der wertvollste Awareness-Indikator.

Formel (mit >=1 Phishing-Kampagne):
    score = 0.40 * Melderate
          + 0.35 * (100 - Klickrate) # Klick-Vermeidung
          + 0.25 * Schulungs-Aktualitaet

Ohne Phishing-Daten faellt der Score auf die Schulungs-Aktualitaet zurueck
(die GUI blendet dann einen "noch keine Simulationsdaten"-Hinweis ein,
statt einen Score aus Luft zu zeigen).

Schichtzugehoerigkeit: domain/ — keine Imports aus application/data/gui,
kein Qt, keine DB. Rein rechnerisch und vollstaendig headless testbar.

Author: Patrick Riederich
Version: 1.0 (IA-Welle 2)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Gewichte (Summe = 1.0). Melde-Verhalten ist der staerkste Hebel.
WEIGHT_REPORT = 0.40
WEIGHT_CLICK_AVOIDANCE = 0.35
WEIGHT_TRAINING = 0.25

# Banding analog Hardening-Score (hoeher = besser):
# Secure >=85 / Moderate 65-84 / At Risk 40-64 / Critical <40.
BAND_SECURE_MIN = 85.0
BAND_MODERATE_MIN = 65.0
BAND_AT_RISK_MIN = 40.0


class RiskBand(Enum):
    """Ampel-Stufe des Human-Risk-Scores (hoeher = besser)."""

    SECURE = "secure"
    MODERATE = "moderate"
    AT_RISK = "at_risk"
    CRITICAL = "critical"
    #: Ohne Phishing-Simulationsdaten ist die Awareness-Lage NICHT als
    #: Sicherheits-Score bewertbar — Schulungen allein machen nicht "stark"
    #: (1 Mitarbeiter + 1 Schulung != 100 % Sicherheit). Dieses Band signalisiert
    #: "Phishing-Resilienz ungetestet" statt einer falschen Ampel-Stufe.
    UNGETESTET = "ungetestet"

    @property
    def label(self) -> str:
        """Deutsches Anzeige-Label der Stufe."""
        return {
            RiskBand.SECURE: "Stark",
            RiskBand.MODERATE: "Solide",
            RiskBand.AT_RISK: "Ausbaufaehig",
            RiskBand.CRITICAL: "Kritisch",
            RiskBand.UNGETESTET: "Ungetestet",
        }[self]


def band_for_score(score: float) -> RiskBand:
    """Leitet die:class:`RiskBand` aus einem Score 0..100 ab."""
    if score >= BAND_SECURE_MIN:
        return RiskBand.SECURE
    if score >= BAND_MODERATE_MIN:
        return RiskBand.MODERATE
    if score >= BAND_AT_RISK_MIN:
        return RiskBand.AT_RISK
    return RiskBand.CRITICAL


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Begrenzt ``value`` auf das Intervall ``[low, high]``."""
    return max(low, min(high, value))


@dataclass(frozen=True)
class HumanRiskScore:
    """Ergebnis der Human-Risk-Berechnung.

    Attributes:
        score: Gesamt-Score 0..100 (hoeher = besser).
        band: Ampel-Stufe zum Score.
        report_rate: Melderate in % (``None`` ohne Phishing-Daten).
        click_rate: Klickrate in % (``None`` ohne Phishing-Daten).
        training_completion: Anteil aktiver MA mit gueltiger Schulung in %.
        report_component: Gewichteter Teilbeitrag Melderate (oder ``None``).
        click_avoidance_component: Gewichteter Teilbeitrag Klick-Vermeidung.
        training_component: Gewichteter Teilbeitrag Schulung.
        trend_delta: Klickraten-Delta neueste vs. vorherige Kampagnen
                                   (negativ = besser); ``None`` bei < 2 Kampagnen.
        has_phishing_data: True, wenn der Score Phishing-Daten enthaelt.
        campaign_count: Anzahl erfasster Kampagnen.
        active_employee_count: Anzahl aktiver Mitarbeiter.
    """

    score: float
    band: RiskBand
    report_rate: float | None
    click_rate: float | None
    training_completion: float
    report_component: float | None
    click_avoidance_component: float | None
    training_component: float
    trend_delta: float | None
    has_phishing_data: bool
    campaign_count: int
    active_employee_count: int

    @property
    def has_any_data(self) -> bool:
        """True, sobald mindestens Mitarbeiter ODER Kampagnen erfasst sind."""
        return self.campaign_count > 0 or self.active_employee_count > 0

    @property
    def trend_label(self) -> str:
        """Pfeil-Label fuer die Trend-Anzeige (Klickraten-Delta)."""
        if self.trend_delta is None:
            return "—"
        if self.trend_delta <= -1.0:
            return f"↓ {abs(self.trend_delta):.1f} %P besser"
        if self.trend_delta >= 1.0:
            return f"↑ {self.trend_delta:.1f} %P schlechter"
        return "≈ stabil"


def compute_human_risk_score(
    *,
    avg_report_rate: float | None,
    avg_click_rate: float | None,
    campaign_count: int,
    training_completion: float,
    active_employee_count: int,
    trend_delta: float | None = None,
) -> HumanRiskScore:
    """Berechnet den Human-Risk-Score 0..100 (hoeher = besser).

    Args:
        avg_report_rate: Gewichtete Melderate in % (``None`` ohne Daten).
        avg_click_rate: Gewichtete Klickrate in % (``None`` ohne Daten).
        campaign_count: Anzahl Phishing-Kampagnen.
        training_completion: Anteil aktiver MA mit gueltiger Schulung in %.
        active_employee_count: Anzahl aktiver Mitarbeiter.
        trend_delta: Klickraten-Delta (negativ = besser), optional.

    Returns:
        Ein:class:`HumanRiskScore`. Ohne Phishing-Daten basiert der Score
        allein auf ``training_completion``.
    """
    training_completion = _clamp(training_completion)
    has_phishing = (
        campaign_count >= 1
        and avg_report_rate is not None
        and avg_click_rate is not None
    )

    if has_phishing:
        report = _clamp(avg_report_rate)
        click = _clamp(avg_click_rate)
        report_component = WEIGHT_REPORT * report
        click_avoidance_component = WEIGHT_CLICK_AVOIDANCE * (100.0 - click)
        training_component = WEIGHT_TRAINING * training_completion
        score = _clamp(
            report_component + click_avoidance_component + training_component
        )
        return HumanRiskScore(
            score=score,
            band=band_for_score(score),
            report_rate=report,
            click_rate=click,
            training_completion=training_completion,
            report_component=report_component,
            click_avoidance_component=click_avoidance_component,
            training_component=training_component,
            trend_delta=trend_delta,
            has_phishing_data=True,
            campaign_count=campaign_count,
            active_employee_count=active_employee_count,
        )

    # Ohne Phishing-Daten ist die Lage NICHT als Sicherheits-Ampel bewertbar:
    # die Melde-/Klick-Dimensionen (75 % des Scores) sind ungemessen. Der Score
    # bleibt als Schulungs-Abdeckung sichtbar, das Band ist aber UNGETESTET
    # (statt faelschlich SECURE bei hoher Schulungsquote — "100 % Sicherheit").
    return HumanRiskScore(
        score=training_completion,
        band=RiskBand.UNGETESTET,
        report_rate=None,
        click_rate=None,
        training_completion=training_completion,
        report_component=None,
        click_avoidance_component=None,
        training_component=training_completion,
        trend_delta=trend_delta,
        has_phishing_data=False,
        campaign_count=campaign_count,
        active_employee_count=active_employee_count,
    )
