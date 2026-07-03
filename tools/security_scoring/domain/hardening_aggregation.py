"""
hardening_aggregation — Aggregations-Logik fuer den Hardening-Score (Phase 1.2).

Operiert auf den bestehenden:class:`ScoreComponent`-Streams und buendelt
sie auf die 5:class:`HardeningCategory`-Kategorien aus
:mod:`tools.security_scoring.domain.hardening_categories`.

Modul-Verantwortlichkeit:

* **bundle_components_to_categories** — verteilt eine ScoreComponent-Liste
  auf die 5 Kategorien-Buckets. Sub-Metrik-Aufloesung fuer
  ``source_tool="org_security"`` ueber den Anzeigenamen.
* **redistribute_unavailable_weights** — Stub-Strategie: wenn eine
  Kategorie keine Daten hat (z. B. System-Hardening vor Phase 3 fertig),
  wird ihr Gewicht proportional auf die anderen aktiven Kategorien
  umverteilt. So bleibt der Score in der korrekten 0-100-Bandbreite.

Architektur-Prinzip wie Phase 1.1: **additiv**. Bestehende
`scoring_engine.calculate_overall_score`-Pipeline bleibt unveraendert
— diese Funktionen sind ein zweiter Layer obendrauf fuer den
Hardening-Score-Pfad (Phase 4 UI).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from tools.security_scoring.domain.hardening_categories import (
    CATEGORY_WEIGHTS,
    HardeningCategory,
    map_source_tool_to_category,
)
from tools.security_scoring.domain.models import ScoreComponent
from tools.security_scoring.domain.org_security import METRIK_ANZEIGENAME

if TYPE_CHECKING:
    from collections.abc import Mapping

    from tools.system_scanner.domain.entities import HardeningCheck


# ---------------------------------------------------------------------------
# Org-Security-Reverse-Mapping
# ---------------------------------------------------------------------------

#: Reverse-Mapping: ``ScoreComponent.name`` → ``METRIK_*``-Metrik-ID.
#:
#: ``org_security_service._komponente_fuer`` setzt ``name`` aus
#::data:`METRIK_ANZEIGENAME` (z. B. ``"DSGVO-Compliance"`` →
#: ``METRIK_DSGVO="dsgvo"``). Wir invertieren diese Map einmalig hier,
#: damit ``bundle_components_to_categories`` die Sub-Metrik
#: rekonstruieren kann ohne das ScoreComponent-Modell zu erweitern.
_NAME_TO_ORG_METRIC: Final[dict[str, str]] = {
    display_name: metric_id for metric_id, display_name in METRIK_ANZEIGENAME.items()
}


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------


def bundle_components_to_categories(
    components: list[ScoreComponent],
) -> dict[HardeningCategory, list[ScoreComponent]]:
    """Buendelt ScoreComponents auf die 5 Hardening-Kategorien.

    Verwendet:func:`map_source_tool_to_category` mit Sub-Metrik-
    Aufloesung fuer ``source_tool="org_security"``. Komponenten, die
    auf ``None`` mappen (z. B. DSGVO-Compliance — Report-Layer ohne
    Score-Einfluss), werden **weggelassen**.

    Unbekannte ``source_tool``-Werte fuehren zu einem
:class:`KeyError` aus:func:`map_source_tool_to_category` — der
    Caller soll das bewusst fangen (neue Tools muessen in
:data:`SOURCE_TOOL_TO_CATEGORY` nachgepflegt werden, kein silent
    drop).

    Args:
        components: Vorhandene ScoreComponent-Liste aus
:meth:`ScoringService.berechne_score` oder direkter
            Tool-Aggregation.

    Returns:
        Dict mit allen 5:class:`HardeningCategory`-Keys, jeweils eine
        (ggf. leere) Liste der zugehoerigen Komponenten.

    Raises:
        KeyError: Wenn ein ``source_tool`` weder im
:data:`SOURCE_TOOL_TO_CATEGORY`-Mapping noch ``"org_security"``
            ist.
        ValueError: Wenn ``source_tool="org_security"`` aber der
            ``name``-Anzeigename nicht in:data:`METRIK_ANZEIGENAME`
            existiert.
    """
    buckets: dict[HardeningCategory, list[ScoreComponent]] = {
        cat: [] for cat in HardeningCategory
    }

    for comp in components:
        category = _resolve_category(comp)
        if category is None:
            # DSGVO o.ae. — kein technischer Score-Beitrag
            continue
        buckets[category].append(comp)

    return buckets


def _resolve_category(component: ScoreComponent) -> HardeningCategory | None:
    """Rueckmappt eine einzelne ScoreComponent auf ihre Kategorie.

    Helper fuer:func:`bundle_components_to_categories`. Handhabt
    den ``org_security``-Sonderfall via Name-Reverse-Lookup.
    """
    source_tool = component.source_tool
    if source_tool == "org_security":
        metric_id = _NAME_TO_ORG_METRIC.get(component.name)
        if metric_id is None:
            msg = (
                f"Org-Security-ScoreComponent mit unbekanntem Anzeigenamen: "
                f"{component.name!r}. Erwartet wurden Eintraege aus "
                f"METRIK_ANZEIGENAME ({sorted(METRIK_ANZEIGENAME.values())})."
            )
            raise ValueError(msg)
        return map_source_tool_to_category(source_tool, org_metric=metric_id)
    return map_source_tool_to_category(source_tool)


# ---------------------------------------------------------------------------
# Redistribute (Stub-Strategie fuer fehlende Kategorien)
# ---------------------------------------------------------------------------


def redistribute_unavailable_weights(
    present_categories: set[HardeningCategory],
    *,
    base_weights: Mapping[HardeningCategory, float] = CATEGORY_WEIGHTS,
) -> dict[HardeningCategory, float]:
    """Verteilt das Gewicht fehlender Kategorien proportional um.

    Ziel: solange z. B. die System-Hardening-Kategorie (E) noch nicht
    produktiv ist (Phase 3 noch nicht fertig), bleibt der Score in der
    korrekten 0-100-Bandbreite. Ihr Gewicht (0.20) wird proportional
    auf die 4 anderen aktiven Kategorien umverteilt.

    Verteilungs-Logik (proportional zum Verhaeltnis der Basis-Gewichte):

.. code-block:: text

        adjusted[i] = base[i] * (1.0 / sum(base[j] for j in present))

    Damit summieren die ``adjusted``-Werte stets auf 1.0 (innerhalb
    Float-Toleranz).

    Args:
        present_categories: Set der Kategorien mit verfuegbaren
            ScoreComponents (typisch: nicht-leere Buckets aus
:func:`bundle_components_to_categories`).
        base_weights: Basis-Gewichtsverteilung. Default
:data:`CATEGORY_WEIGHTS` aus v2; Tests koennen
            eigene Defaults injizieren.

    Returns:
        Dict mit nur den ``present_categories``, deren Gewichte auf
        1.0 normiert sind. Fehlende Kategorien sind NICHT im Result.

    Raises:
        ValueError: Wenn ``present_categories`` leer ist oder das
            Gesamtgewicht der Anwesenden 0.0 ist (dann waere keine
            Normalisierung moeglich).
    """
    if not present_categories:
        msg = (
            "redistribute_unavailable_weights: present_categories ist leer. "
            "Mindestens eine Kategorie mit Daten ist Pflicht — sonst gibt es "
            "keinen Score."
        )
        raise ValueError(msg)

    present_base_sum = sum(
        base_weights[cat] for cat in present_categories if cat in base_weights
    )
    if present_base_sum <= 0.0:
        msg = (
            f"redistribute_unavailable_weights: Summe der Basis-Gewichte fuer "
            f"present_categories ist {present_base_sum!r}. Mindestens eine "
            "Kategorie mit positivem Gewicht ist Pflicht."
        )
        raise ValueError(msg)

    factor = 1.0 / present_base_sum
    return {
        cat: base_weights[cat] * factor
        for cat in present_categories
        if cat in base_weights
    }


# ---------------------------------------------------------------------------
# System-Scanner → ScoreComponent (Phase 3.4)
# ---------------------------------------------------------------------------


#: Default-Gewicht der system_scanner-Komponente im Hardening-Score.
#: Wird in CATEGORY_WEIGHTS auf 0.20 fuer Kategorie E gemappt;
#: hier ist der Per-Tool-Gewicht (innerhalb der Kategorie hat nur diese
#: eine Komponente Beitrag, also irrelevant fuer den Mittelwert — aber
#: sie muss > 0 sein, damit ``compute_hardening_score`` die Komponente
#: nicht als ``weight=0`` ueberspringt).
_SYSTEM_SCANNER_COMPONENT_WEIGHT: float = 1.0


def build_system_scanner_component(
    checks: list[HardeningCheck],
) -> ScoreComponent | None:
    """Aggregiert:class:`HardeningCheck`-Ergebnisse zu einer ScoreComponent.

    Score-Berechnung: ``(passed_count / measurable_count) * 100``.
    Nicht messbare Checks (``measurable=False`` — z.B. BitLocker auf einer
    Home-Edition ohne Tool, Probe ohne Adminrechte) zaehlen WEDER im Nenner
    noch als Verstoss. Findings-Counts je Severity (CRITICAL/HIGH/MEDIUM)
    zaehlen nur **messbare, fehlgeschlagene** Checks — die Hard-Cap-Detectors
    (``apply_hard_caps``) lesen die Counts ggf. fuer Cap 5 (≥3 Critical).

    Args:
        checks: Liste der:class:`HardeningCheck`-Ergebnisse aus dem
:class:`WindowsHardeningScanner` (Phase 3.3) oder analog.

    Returns:
:class:`ScoreComponent` mit ``source_tool="system_scanner"``,
        ``name="System-Hardening"``. ``None`` wenn ``checks`` leer ist ODER
        kein Check messbar war — Caller soll dann auf die Komponente
        verzichten, sodass die Kategorie als ``missing`` gilt und
:func:`redistribute_unavailable_weights` greift.
    """
    if not checks:
        return None
    measurable_checks = [c for c in checks if c.measurable]
    measurable_total = len(measurable_checks)
    if measurable_total == 0:
        # Kein Check war messbar -> Kategorie gilt als 'nicht verfuegbar',
        # NICHT als 0/100. redistribute_unavailable_weights uebernimmt.
        return None
    passed = sum(1 for c in measurable_checks if c.passed)
    score = (passed / measurable_total) * 100.0

    # Severity-Imports lazy, damit das Modul keine zusaetzliche
    # Domain-Coupling im Top hat.
    from core.security.severity import Severity  # noqa: PLC0415

    def _failed(sev: Severity) -> int:
        return sum(1 for c in measurable_checks if not c.passed and c.severity == sev)

    crit = _failed(Severity.CRITICAL)
    high = _failed(Severity.HIGH)
    med = _failed(Severity.MEDIUM)

    failed = measurable_total - passed
    not_measurable = len(checks) - measurable_total
    details = f"{passed}/{measurable_total} Checks erfuellt, {failed} fehlgeschlagen"
    if not_measurable:
        details += f" ({not_measurable} nicht messbar)"
    return ScoreComponent(
        name="System-Hardening",
        score=round(score, 1),
        weight=_SYSTEM_SCANNER_COMPONENT_WEIGHT,
        findings_critical=crit,
        findings_high=high,
        findings_medium=med,
        source_tool="system_scanner",
        data_available=True,
        details=details,
    )
