"""
hardening_score — Finale Public-API fuer den Hardening Score (Phase 1.4).

Verbindet die Bausteine aus Phase 1.1-1.3 zu einer aufrufbaren Funktion
:func:`compute_hardening_score`. Diese ist die einzige Public-API, die
spaeter von der GUI (Phase 4 — Gauge-Widget) und dem Hard-Cap-Layer
(Phase 2) konsumiert wird.

Berechnungs-Pipeline (Pure-Funktion ohne Side-Effects):

    1. Bundle: ScoreComponents → 5 Kategorien-Buckets
       (:func:`bundle_components_to_categories`).
    2. Per-Category-Score: gewichteter Mittel der `data_available=True`
       Components in jeder Kategorie. Kategorien ohne aktive Components
       werden als "fehlend" markiert.
    3. Redistribute: fehlende Kategorien geben ihr Basisgewicht an die
       Anwesenden ab (:func:`redistribute_unavailable_weights`).
    4. Overall-Score: gewichtete Summe der per-category-Scores.
    5. Stage::func:`score_to_stage` auf den Overall-Score.

Architektur-Prinzip wie Phase 1.1-1.3: **additiv** und **pure**.

Backwards-Compat-Hinweis: bestehende
:func:`tools.security_scoring.domain.scoring_engine.calculate_overall_score`
+:func:`score_to_grade` bleiben unveraendert produktiv. Diese neue
API ist ein zweiter Pfad fuer das Hardening-Score-Feature, nicht ein
Replace.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.herkunft import Herkunft
from tools.security_scoring.domain.hardening_aggregation import (
    bundle_components_to_categories,
    redistribute_unavailable_weights,
)
from tools.security_scoring.domain.hardening_caps import (
    HardCapEvent,
    apply_hard_caps,
)
from tools.security_scoring.domain.hardening_categories import HardeningCategory
from tools.security_scoring.domain.hardening_stages import (
    STAGE_AT_RISK,
    ScoreStage,
    cap_stage,
    score_to_stage,
)

if TYPE_CHECKING:
    from tools.security_scoring.domain.models import ScoreComponent
    from tools.system_scanner.domain.entities import (
        HardeningCoverage,
        MeasurementDisposition,
        ScanResult,
    )


# ---------------------------------------------------------------------------
# Ergebnis-Datenklassen
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """Per-Kategorie-Score-Breakdown — Input fuer das GUI-Breakdown-Panel.

    Attributes:
        category: Eine der 5:class:`HardeningCategory`-Werte.
        score: Gewichteter Mittel der Components in dieser Kategorie
            (0-100). Berechnung pro Kategorie:
            ``sum(c.score * c.weight) / sum(c.weight)``.
        weight: Final-Gewicht der Kategorie nach
:func:`redistribute_unavailable_weights` (0-1).
        components_count: Anzahl der ``data_available=True`` Components,
            die in diese Kategorie geflossen sind. Hauptsaechlich fuer
            Debug + UI-Tooltips relevant.
    """

    category: HardeningCategory
    score: float
    weight: float
    components_count: int


@dataclass(frozen=True, slots=True)
class HardeningScoreResult:
    """Vollstaendiges Ergebnis einer Hardening-Score-Berechnung.

    Frozen + slots: unveraenderbar + speicherarm. Wird vom
    GUI-Dashboard-Widget + PDF-Report konsumiert (Phase 4).

    Attributes:
        overall_score: Gesamt-Score 0-100 (auf 1 Nachkommastelle
            gerundet). **Bereits durch aktive Hard-Caps eingeschraenkt.**
            Zugriff auf den un-gecappten Wert ueber
:attr:`raw_weighted_score`.
        stage: Eine der 4:class:`ScoreStage` (Secure / Moderate /
            At Risk / Critical) — auf Basis von
            ``overall_score`` (gecappt).
        category_scores: Tuple aller anwesenden Kategorien in der
            Kanon-Reihenfolge aus:class:`HardeningCategory` (CVE_PATCH,
            NETWORK, PASSWORD, API_SECURITY, SYSTEM_HARDENING). Fehlende
            Kategorien sind NICHT enthalten — Caller pruefe Liste-Laenge
            falls relevant.
        missing_categories: Tuple der Kategorien ohne anwesende
            Components (typisch: SYSTEM_HARDENING vor Phase 3 fertig).
            UI kann das fuer "—"-Placeholder + Tooltip nutzen.
        hard_cap_events: Tuple aller getriggerten Hard-Cap-Events
            (Phase 2 v2 §3). Leer wenn kein Cap aktiv.
            GUI zeigt die als Hinweis-Liste; PDF-Report
            dokumentiert sie pro Audit.
        raw_weighted_score: Gewichteter Mittelwert vor Cap-Anwendung
            (0-100). Wenn keine Caps aktiv sind, gleich
            ``overall_score``. Damit kann die GUI optional anzeigen:
            "Score gedeckelt von 87 auf 25 wegen ≥ 3 kritischen
            Findings".
        coverage: Mess-Abdeckung der Hardening-Checks, oder ``None``
            wenn kein ``scan_result`` mit Checks vorlag. Treibt den
            Stage-Guard + die Report-Sektion "nicht gemessen".
        stage_capped_by_coverage: ``True`` wenn ``stage`` wegen zu geringer
            Coverage (< Schwelle) auf At Risk begrenzt wurde — die GUI/der
            Report MUSS das erklaeren (Owner-Prinzip: nicht Gemessenes wird
            im Rating sichtbar). Der ``overall_score`` bleibt unveraendert
            (Transparenz des gemessenen Teils).
        disposition: Mess-zuerst-Gate-Status P4), oder ``None`` ohne
            ``scan_result``. ``disposition.gate_open`` treibt das Soft-"N offen"-
            Banner (D4); ``open_remeasurable`` ist die Zahl im Banner.
        herkunft: Provenance des Ergebnisses E5). ``GEMESSEN`` für eine
            Live-Messung des eigenen Systems (Default), ``ERFASST`` für manuell
            für einen Kunden eingetragene Fakten. NIE mischen — der Beweiswert
            (gemessen ≠ erfasst) bleibt durchgängig sichtbar.
    """

    overall_score: float
    stage: ScoreStage
    category_scores: tuple[CategoryScore, ...]
    missing_categories: tuple[HardeningCategory, ...]
    hard_cap_events: tuple[HardCapEvent, ...] = ()
    raw_weighted_score: float = 0.0
    coverage: HardeningCoverage | None = None
    stage_capped_by_coverage: bool = False
    disposition: MeasurementDisposition | None = None
    herkunft: Herkunft = Herkunft.GEMESSEN


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

#: Mindest-Mess-Abdeckung (gemessen/anwendbar), ab der die Ampel die volle
#: Bandbreite erreichen darf. Darunter begrenzt der Stage-Guard die Stage auf
#: At Risk: ein hoher Score auf zu wenig gemessener Flaeche ist nicht
#: vertrauenswuerdig Owner-Prinzip; Default 70 %).
_COVERAGE_STAGE_FLOOR: float = 0.70


def _coverage_capped_stage(
    stage: ScoreStage,
    coverage: HardeningCoverage | None,
) -> tuple[ScoreStage, bool]:
    """Begrenzt die Stage bei zu geringer Mess-Abdeckung auf At Risk.

    Args:
        stage: Die aus dem (gecappten) Score abgeleitete Stage.
        coverage: Mess-Abdeckung oder ``None`` (dann kein Guard).

    Returns:
        ``(effektive_stage, wurde_begrenzt)``.
    """
    if (
        coverage is None
        or coverage.applicable <= 0
        or coverage.ratio >= _COVERAGE_STAGE_FLOOR
    ):
        return stage, False
    capped = cap_stage(stage, STAGE_AT_RISK)
    return capped, capped is not stage


def _compute_coverage(scan_result: ScanResult | None) -> HardeningCoverage | None:
    """Berechnet die Mess-Abdeckung aus ``scan_result`` (oder ``None``)."""
    if scan_result is None or not scan_result.hardening_checks:
        return None
    # Cross-Tool-Domain-Import lazy: domain->domain ist import-linter-konform
    # (nur domain->aeussere Schichten ist verboten); lazy = kein Lade-Coupling.
    from tools.system_scanner.domain.entities import (  # noqa: PLC0415
        compute_hardening_coverage,
    )

    return compute_hardening_coverage(scan_result.hardening_checks)


def _compute_disposition(
    scan_result: ScanResult | None,
) -> MeasurementDisposition | None:
    """Leitet den Mess-zuerst-Gate-Status aus ``scan_result`` ab (oder ``None``)."""
    if scan_result is None or not scan_result.hardening_checks:
        return None
    from tools.system_scanner.domain.entities import (  # noqa: PLC0415
        evaluate_measurement_disposition,
    )

    return evaluate_measurement_disposition(scan_result.hardening_checks)


def compute_hardening_score(
    components: list[ScoreComponent],
    *,
    scan_result: ScanResult | None = None,
    herkunft: Herkunft = Herkunft.GEMESSEN,
) -> HardeningScoreResult:
    """Berechnet den Hardening-Score aus einer ScoreComponent-Liste.

    Verbindet die Phase-1.1-1.4-Bausteine + Phase-2-Hard-Caps zur finalen
    Score-Pipeline.

    Pipeline:
        1. Bundle ScoreComponents in 5 Kategorien-Buckets.
        2. Per-Category gewichteter Mittel (nur data_available=True).
        3. Fehlende Kategorien geben Gewicht an Anwesende ab.
        4. Overall = Σ(cat_score × adjusted_weight).
        5. **Phase 2:** Hard-Caps anwenden — niedrigster aktiver Cap
           clampt den Score.
        6. Stage = score_to_stage(geclampter Overall).

    Edge-Cases:

    * Leere ``components`` oder alle ``data_available=False`` →
      ``overall_score=0.0``, ``stage=Critical``, leere
      ``category_scores``. Alle 5 Kategorien sind dann ``missing``.
      Hard-Caps werden trotzdem evaluiert (z. B. Cap-5
      "≥ 3 kritische Findings" — bei 0 active Components nicht aktiv).
    * ``weight=0``-Components werden im Per-Category-Avg ignoriert
      (sonst Division durch Null).

    Args:
        components: Liste der Per-Tool-ScoreComponents aus z.B.
:meth:`ScoringService.berechne_score`. ``data_available=False``-
            Components werden in der Per-Category-Aggregation
            ignoriert, koennen aber Hard-Cap-Detectors (Cap 1+2)
            ueber ``findings_critical`` triggern.
        scan_result: Optionales:class:`ScanResult` aus
:mod:`tools.system_scanner`. Aktiviert Caps 3+4 (RDP,
            Firewall). ``None`` = Caps 3+4 inaktiv (Phase 3 noch
            nicht produktiv).

    Returns:
:class:`HardeningScoreResult` mit gecapptem Overall-Score,
        Stage, Per-Category-Breakdown, Hard-Cap-Events und un-gecapptem
        Raw-Score (fuer GUI-Hinweise).

    Raises:
        KeyError: Wenn eine Komponente einen ``source_tool``-Wert hat,
            der weder in
:data:`tools.security_scoring.domain.hardening_categories.SOURCE_TOOL_TO_CATEGORY`
            noch ``"org_security"`` ist.
        ValueError: Wenn eine ``org_security``-Komponente einen
            unbekannten ``name`` hat (keine bekannte Org-Metrik).
    """
    # 0. Mess-Abdeckung + Gate-Status — treiben Stage-Guard, Soft-
    # Banner und Report-Sektion "nicht gemessen".
    coverage = _compute_coverage(scan_result)
    disposition = _compute_disposition(scan_result)

    # 1. Bundle in 5 Kategorien-Buckets
    buckets = bundle_components_to_categories(components)

    # 2. Per-Category gewichteter Mittel (nur data_available=True Components)
    per_category_data: dict[HardeningCategory, tuple[float, int]] = {}
    for cat, bucket in buckets.items():
        active = [c for c in bucket if c.data_available and c.weight > 0]
        if not active:
            continue
        total_weight = sum(c.weight for c in active)
        # total_weight > 0 garantiert weil alle active c.weight > 0 haben
        avg_score = sum(c.score * c.weight for c in active) / total_weight
        per_category_data[cat] = (avg_score, len(active))

    if not per_category_data:
        # Keine aktive Daten — kein Score moeglich. Hard-Caps werden
        # trotzdem auf 0 evaluiert (kann z. B. Cap-5 bei
        # data_available=False Comps mit findings_critical triggern).
        raw = 0.0
        capped, events = apply_hard_caps(raw, components, scan_result)
        guarded_stage, stage_capped = _coverage_capped_stage(
            score_to_stage(capped), coverage
        )
        return HardeningScoreResult(
            overall_score=round(capped, 1),
            stage=guarded_stage,
            category_scores=(),
            missing_categories=tuple(HardeningCategory),
            hard_cap_events=tuple(events),
            raw_weighted_score=raw,
            coverage=coverage,
            stage_capped_by_coverage=stage_capped,
            disposition=disposition,
            herkunft=herkunft,
        )

    # 3. Gewichte umverteilen
    present = set(per_category_data.keys())
    adjusted_weights = redistribute_unavailable_weights(present)

    # 4. Overall-Score (gewichteter Mittel der Kategorien-Scores)
    raw_overall = sum(
        per_category_data[cat][0] * adjusted_weights[cat] for cat in present
    )
    raw_overall = round(raw_overall, 1)

    # 5. Hard-Caps anwenden (Phase 2)
    capped_overall, cap_events = apply_hard_caps(
        raw_overall, components, scan_result
    )
    capped_overall = round(capped_overall, 1)

    # 6. Stage auf Basis des gecappten Scores + Coverage-Stage-Guard:
    # bei zu geringer Mess-Abdeckung wird die Ampel auf At Risk begrenzt.
    stage, stage_capped = _coverage_capped_stage(
        score_to_stage(capped_overall), coverage
    )

    # 7. Breakdown in Kanon-Reihenfolge (Per-Category-Scores bleiben
    # un-gecappt — Caps wirken nur auf den Overall-Score)
    category_scores = tuple(
        CategoryScore(
            category=cat,
            score=round(per_category_data[cat][0], 1),
            weight=adjusted_weights[cat],
            components_count=per_category_data[cat][1],
        )
        for cat in HardeningCategory
        if cat in present
    )

    missing = tuple(cat for cat in HardeningCategory if cat not in present)

    return HardeningScoreResult(
        overall_score=capped_overall,
        stage=stage,
        category_scores=category_scores,
        missing_categories=missing,
        hard_cap_events=tuple(cap_events),
        raw_weighted_score=raw_overall,
        coverage=coverage,
        stage_capped_by_coverage=stage_capped,
        disposition=disposition,
        herkunft=herkunft,
    )


# ---------------------------------------------------------------------------
# Anzeige-Hilfen (pure — Single Source of Truth fuer Subtitle + PDF)
# ---------------------------------------------------------------------------

#: Mindest-Differenz (Rohscore - gecappter Score), ab der im Summary-Text
#: ein Hard-Cap-Hinweis erscheint. Beide Werte sind auf 1 Nachkommastelle
#: gerundet — die Schwelle puffert Rundungsrauschen.
_CAP_HINT_MIN_DELTA: float = 0.1


def build_hardening_summary(result: HardeningScoreResult) -> str:
    """Baut den anzeige-fertigen Zusammenfassungstext zum Hardening-Score.

    Single Source of Truth fuer den Subtitle im Security-Scoring-Tab und die
    Executive-Summary im PDF-Report. Pure Funktion ohne Seiteneffekte —
    leitet den Text ausschliesslich aus dem:class:`HardeningScoreResult` ab,
    damit Tab und PDF garantiert denselben Wortlaut zeigen.

    Args:
        result: Das berechnete Hardening-Ergebnis.

    Returns:
        Ein laienverstaendlicher Du-Form-Satz: Stufe + Score, plus optionale
        Hinweise auf einen aktiven Hard-Cap (Score gedeckelt) und auf fehlende
        Datenbereiche (Coverage-Transparenz, loest die 85/69/96-Verwirrung).
    """
    teile = [
        f"Dein Sicherheitsniveau: {result.stage.label} — "
        f"{result.overall_score:.0f}/100"
    ]

    # Hard-Cap aktiv? Der gecappte Score liegt dann unter dem Rohwert.
    if result.raw_weighted_score - result.overall_score >= _CAP_HINT_MIN_DELTA:
        teile.append(
            f"gedeckelt von {result.raw_weighted_score:.0f} "
            "wegen kritischer Befunde"
        )

    # Coverage-Transparenz: wie viele der Bereiche haben noch keine Daten?
    fehlend = len(result.missing_categories)
    if fehlend:
        gesamt = len(HardeningCategory)
        teile.append(f"{fehlend} von {gesamt} Bereichen noch ohne Daten")

    # Stage durch niedrige Mess-Abdeckung begrenzt? Erklaert die Stufe/Score-
    # Divergenz (z.B. "At Risk — 92/100"): der gemessene Teil ist gut, aber zu
    # wenig Flaeche wurde gemessen Owner-Prinzip: sichtbar machen).
    if result.stage_capped_by_coverage and result.coverage is not None:
        teile.append(
            f"Stufe begrenzt — erst {result.coverage.ratio:.0%} der pruefbaren "
            "Haertung gemessen"
        )

    return " · ".join(teile)
