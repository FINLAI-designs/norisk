"""
anomaly_models — Domain-Modelle fuer die Light-SIEM-Anomalie-Heuristik.

Iter 3e: Detection von ungewoehnlichen Mustern im
Event-Pool aus 3d. Ein Finding ist ein Tag (oder Tage-Block), an dem der
severity-gewichtete Score signifikant ueber dem Median liegt.

Statistik-Wahl: **Median + MAD** (Median Absolute Deviation), nicht
Mittelwert + Standardabweichung. Begruendung: in einem KMU-Stream sind
Single-Day-Spikes haeufig (z. B. Inventur-Tag mit allen System-Scanner-
Events). Mittelwert + STDDEV wuerde die Baseline durch den Ausreisser
selbst nach oben ziehen ("masking effect"). Median + MAD ist robust —
ein Tages-Spike beeinflusst weder Median noch MAD signifikant.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum

from tools.norisk_dashboard.domain.light_siem_models import EventSource

# Default-Sensitivitaet fuer den MAD-Faktor (2.5 ≈ robustes 3-Sigma-Aequivalent).
# Niedriger → mehr false positives, hoeher → weniger Findings.
DEFAULT_MAD_SENSITIVITY: float = 2.5

# Mindestanzahl an Tagen mit Events, bevor wir ueberhaupt rechnen — bei
# weniger Daten ist jede Statistik Spielzeug.
MIN_BASELINE_DAYS: int = 7

# Default-Lookback fuer die Anomaly-Berechnung.
DEFAULT_ANOMALY_LOOKBACK_DAYS: int = 30


class AnomalySeverity(Enum):
    """Schweregrad eines Anomaly-Findings.

    Schwelle ergibt sich aus dem Verhaeltnis ``observed/threshold``:
    - LOW: 1.0..1.5x → leichter Ausschlag.
    - MEDIUM: 1.5..2.5x → klarer Spike.
    - HIGH: 2.5..4.0x → starker Spike.
    - CRITICAL: > 4x → Plateau ueberschritten.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_ratio(cls, ratio: float) -> AnomalySeverity:
        """Mappt ``observed/threshold`` auf eine Stufe.

        Args:
            ratio: ``observed_value / threshold``. ``>= 1`` heisst der
                   Tages-Score liegt ueber dem Anomaly-Threshold.

        Returns:
            Eine der vier:class:`AnomalySeverity`-Stufen.
        """
        if ratio < 1.5:
            return cls.LOW
        if ratio < 2.5:
            return cls.MEDIUM
        if ratio < 4.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def display_label(self) -> str:
        return self.value.upper()


@dataclass(frozen=True)
class AnomalyFinding:
    """Ein erkanntes Anomaly-Event.

    Eine Anomaly ist immer einem Tag zugeordnet — Stunden-Granularitaet
    wuerde in einem KMU-Stream zu viel Rauschen erzeugen.

    Attributes:
        observed_at: Der Tag, an dem die Anomaly registriert wurde.
        source::class:`EventSource` oder ``None`` (= ueber alle
                         Quellen aggregiert).
        observed_score: Severity-gewichteter Tages-Score am ``observed_at``.
        threshold: Berechneter Threshold (Median + sensitivity * MAD).
        baseline_median: Tagesmedian der Baseline (Lookback-Tage exkl. Tag).
        severity::class:`AnomalySeverity` aus dem Verhaeltnis.
        reason: Klartext-Begruendung fuer den Dashboard-Anzeige.

    Raises:
        ValueError: Bei nicht-positivem Threshold oder leerer Reason.
    """

    observed_at: date
    source: EventSource | None
    observed_score: float
    threshold: float
    baseline_median: float
    severity: AnomalySeverity
    reason: str

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError(
                "AnomalyFinding.threshold muss > 0 sein "
                f"(aktuell {self.threshold})."
            )
        if not self.reason.strip():
            raise ValueError("AnomalyFinding.reason darf nicht leer sein.")

    @property
    def ratio(self) -> float:
        """``observed / threshold``. >1 heisst es ist eine Anomaly."""
        return self.observed_score / self.threshold

    @property
    def source_label(self) -> str:
        """Anzeige-Label fuer die Quelle ('Alle Quellen' bei Aggregat)."""
        if self.source is None:
            return "Alle Quellen"
        return self.source.value


@dataclass(frozen=True)
class AnomalyReport:
    """Aggregierter Anomaly-Befund fuer die Dashboard-Card.

    Attributes:
        findings: Liste der gefundenen:class:`AnomalyFinding`s,
                            sortiert nach Severity desc + observed_at desc.
        lookback_days: Wie viele Tage zurueck wurde gerechnet.
        baseline_day_count: Anzahl Tage in der Baseline-Stichprobe (alle Tage
                            mit Events AUSSER dem juengsten). Wenn
                            ``< MIN_BASELINE_DAYS``, sind ``findings`` leer und
                            ``has_enough_data`` False. NICHT mit
                            ``total_events`` verwechseln: ein frisches System
                            hat Events nur am heutigen Tag -> baseline_day_count
                            0, obwohl der Pool gefuellt ist.
        total_events: Gesamtzahl der Events im Lookback-Pool. Trennt
                            "Pool leer" (0) von "Pool gefuellt, aber noch keine
                            Mehrtages-Baseline" (>0, baseline_day_count < N) —
                            die Anzeige war sonst irrefuehrend.
        latest_score: Severity-gewichteter Score des juengsten Tages.
        generated_at: Wann der Report berechnet wurde (UTC).
    """

    findings: list[AnomalyFinding] = field(default_factory=list)
    lookback_days: int = DEFAULT_ANOMALY_LOOKBACK_DAYS
    baseline_day_count: int = 0
    total_events: int = 0
    latest_score: float = 0.0
    generated_at: datetime | None = None

    @property
    def has_enough_data(self) -> bool:
        """``True`` wenn die Baseline gross genug fuer Statistik ist."""
        return self.baseline_day_count >= MIN_BASELINE_DAYS

    @property
    def is_alarmed(self) -> bool:
        """``True`` wenn mindestens ein MEDIUM-/HIGH-/CRITICAL-Finding existiert."""
        return any(
            f.severity is not AnomalySeverity.LOW for f in self.findings
        )

    @property
    def top_finding(self) -> AnomalyFinding | None:
        """Liefert das (sortierungs-erste) Finding oder None."""
        return self.findings[0] if self.findings else None

    def aggregate_score(self) -> int:
        """Liefert einen 0-100-Score fuer die Dashboard-Anzeige.

        - **0** wenn keine Findings ODER nicht genug Baseline-Daten.
        - Pro Finding: ``LOW=10, MEDIUM=25, HIGH=50, CRITICAL=100``,
          ueberlagert mit ``max`` (nicht aufsummiert — sonst wuerde ein
          ruhiger Stream mit fuenf LOWs schlimmer aussehen als ein
          stiller mit einem CRITICAL).
        """
        if not self.has_enough_data or not self.findings:
            return 0
        weight = {
            AnomalySeverity.LOW: 10,
            AnomalySeverity.MEDIUM: 25,
            AnomalySeverity.HIGH: 50,
            AnomalySeverity.CRITICAL: 100,
        }
        return max(weight[f.severity] for f in self.findings)
