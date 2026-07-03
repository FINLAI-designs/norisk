"""
assistant_findings — Composition-Root-Adapter: App-Ergebnisse → Assistenten-Kontext.

Liest SELF-only die aktuellen Sicherheitsergebnisse des EIGENEN Systems und
bildet sie auf die tool-freien core-DTOs (:mod:`core.assistant.security_findings`)
ab. Liegt in ``apps/``, weil nur der Composition-Root aus ``tools/`` importieren
darf (Layering R5) und dieser Adapter die beiden Ergebnis-Owner
(``security_scoring``, ``customer_audit``) zusammenführt — genau die
Orchestrierungs-Rolle von ``apps/`` (wie ``norisk_dashboard`` für das Cockpit).

Leitplanken:

* **SELF-only** — Hardening via ``herkunft = GEMESSEN`` (eigenes System), Audit via
  ``lade_self_audit_result`` (``audit_mode == SELF`` fail-closed). NIE Kunden-Daten.
* **PII-frei** — kein Firmenname/Kontakt; nur Kennzahlen und Klartext-Labels.
* **Zwei Dimensionen, nie gemischt** — kein Misch-Score; die Abweichung ist nur ein
  Hinweis (``bewerte_score_abweichung`` wiederverwendet, nicht neu berechnet).
* **fail-soft** — fehlt/scheitert eine Dimension, bleibt sie ``None`` (der Assistent
  läuft ohne diesen Teil weiter, statt zu crashen).

Schwellen-Texte (Skala) werden aus den Domänen-Konstanten abgeleitet (DRY, R1) —
keine hartkodierten Grenzwerte in diesem Adapter.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.assistant.security_findings import (
    AuditSummary,
    CveExposureSummary,
    HardeningSummary,
    SecurityFindingsBundle,
)
from core.logger import get_logger

_log = get_logger(__name__)

#: Anzahl der schwächsten Härtungs-Kategorien, die dem Chatbot genannt werden.
_WEAKEST_N = 2

#: Maximale Länge eines eingebetteten Freitext-Titels (Risiko-Titel), damit ein
#: Custom-Titel aus dem Wizard keinen mehrzeiligen Pseudo-Dialog in den Block bringt.
_FREETEXT_MAX_LEN = 120

#: Klartext-Labels der Hardening-Kategorien für den Datenblock (Anzeige, kein
#: Score-Identifier). Composition-Root-Mapping tool-Domäne → Anzeige.
_HARDENING_CATEGORY_LABELS: dict[str, str] = {
    "cve_patch": "CVE/Patch",
    "network": "Netzwerk",
    "password": "Passwort",  # nosec B105 — Kategorie-Anzeigelabel, kein Secret
    "api_security": "API",
    "system_hardening": "System-Härtung",
}


def build_self_findings_bundle() -> SecurityFindingsBundle | None:
    """Baut das SELF-Ergebnis-Bündel für den Assistenten (oder ``None``).

    Instanziiert die Services einmalig pro Aufruf (kein N+1 über mehrere
    Fragen — der Aufruf selbst passiert je Anfrage genau einmal). Läuft im
    Worker-Thread des Assistenten (kein UI-Block).

    Returns:
        Ein nicht-leeres:class:`SecurityFindingsBundle` oder ``None``, wenn
        keine einzige Ergebnis-Dimension vorliegt.
    """
    hardening = _load_hardening()
    audit = _load_audit()
    cve = _load_cve()
    hinweis = _abweichung_hinweis(audit, hardening)
    bundle = SecurityFindingsBundle(
        hardening=hardening, audit=audit, cve=cve, abweichung_hinweis=hinweis
    )
    return None if bundle.is_empty else bundle


def _load_hardening() -> HardeningSummary | None:
    """Lädt den jüngsten GEMESSENEN Hardening-Score des eigenen Systems (fail-soft)."""
    try:
        from tools.security_scoring.application.scoring_service import (  # noqa: PLC0415
            ScoringService,
        )

        result = ScoringService().lade_letztes_gemessenes_hardening_result()
    except Exception as exc:  # noqa: BLE001 — Cross-Tool-Grenze, fail-soft
        _log.warning("Hardening-App-State nicht ladbar: %s", type(exc).__name__)
        return None
    if result is None:
        return None
    coverage_ratio = result.coverage.ratio if result.coverage is not None else None
    return HardeningSummary(
        overall_score=result.overall_score,
        stage_label=result.stage.label,
        scale_hint=_hardening_scale_hint(),
        coverage_ratio=coverage_ratio,
        stage_capped_by_coverage=result.stage_capped_by_coverage,
        weakest_categories=_weakest_categories(result),
        missing_categories=tuple(
            _category_label(cat) for cat in result.missing_categories
        ),
    )


def _load_audit() -> AuditSummary | None:
    """Lädt das jüngste SELF-Audit des eigenen Systems (SELF-gegated, fail-soft)."""
    try:
        from core.security_subject.resolver import create_subject_store  # noqa: PLC0415
        from tools.customer_audit.application.self_audit_query import (  # noqa: PLC0415
            lade_self_audit_result,
            lade_top_risiken,
        )

        store = create_subject_store()
        if store is None:
            return None
        self_subject = store.get_self()
        if self_subject is None:
            return None
        audit = lade_self_audit_result(self_subject.subject_id)
        if audit is None:
            return None
        top_risks = lade_top_risiken(audit.audit_id)
    except Exception as exc:  # noqa: BLE001 — Cross-Tool-Grenze, fail-soft
        _log.warning("Audit-App-State nicht ladbar: %s", type(exc).__name__)
        return None
    return AuditSummary(
        overall_score=audit.overall_score,
        risk_level=audit.risk_level,
        scale_hint=_audit_scale_hint(),
        top_risks=tuple(
            f"{_sanitize_freetext(titel)} ({_sanitize_freetext(level, max_len=30)})"
            for titel, level in top_risks
        ),
    )


def _load_cve() -> CveExposureSummary | None:
    """Lädt die aktuelle CVE-Exposition des eigenen Systems (fail-soft)."""
    try:
        from tools.security_scoring.application.cve_exposure_service import (  # noqa: PLC0415
            CveExposureService,
        )

        data = CveExposureService().get_current_exposure()
    except Exception as exc:  # noqa: BLE001 — Cross-Tool-Grenze, fail-soft
        _log.warning("CVE-App-State nicht ladbar: %s", type(exc).__name__)
        return None
    # Nur berichten, wenn tatsächlich Exposure-Daten vorliegen (sonst nur Rauschen).
    if data.total_cves == 0 and data.affected_advisories == 0:
        return None
    return CveExposureSummary(
        critical_count=data.critical_count,
        high_count=data.high_count,
        kev_count=data.kev_count,
    )


def _abweichung_hinweis(
    audit: AuditSummary | None, hardening: HardeningSummary | None
) -> str | None:
    """Deutet die Abweichung der beiden Dimensionen (wiederverwendet, kein Mitteln)."""
    if audit is None or hardening is None:
        return None
    try:
        from tools.norisk_dashboard.domain.score_abweichung import (  # noqa: PLC0415
            bewerte_score_abweichung,
        )

        abweichung = bewerte_score_abweichung(
            audit.overall_score, hardening.overall_score
        )
    except Exception as exc:  # noqa: BLE001 — Cross-Tool-Grenze, fail-soft
        _log.warning("Score-Abweichung nicht ableitbar: %s", type(exc).__name__)
        return None
    return abweichung.hinweis if abweichung is not None else None


def _weakest_categories(result: object) -> tuple[str, ...]:
    """Labels der ``_WEAKEST_N`` schwächsten anwesenden Hardening-Kategorien."""
    scored = sorted(result.category_scores, key=lambda c: c.score)  # type: ignore[attr-defined]
    return tuple(_category_label(c.category) for c in scored[:_WEAKEST_N])


def _sanitize_freetext(text: str, *, max_len: int = _FREETEXT_MAX_LEN) -> str:
    """Neutralisiert eingebetteten Freitext (Risiko-Titel) für den Datenblock.

    Freitext aus dem SELF-Audit-Wizard (``custom_title``) könnte strukturierten
    Instruktions-/Injection-Text tragen. Er wird bereits als DATEN gespottet;
    zusätzlich kollabieren wir Zeilenumbrüche/Whitespace zu EINER Zeile und kappen
    die Länge, damit kein mehrzeiliger Pseudo-Dialog entsteht (Defense-in-Depth,
 / Security-Review P3).

    Args:
        text: Der (potenziell freitextige) Eingabestring.
        max_len: Maximale Zeichenlänge nach dem Kappen.

    Returns:
        Einzeiliger, längenbegrenzter String.
    """
    return " ".join(str(text).split())[:max_len]


def _category_label(category: object) -> str:
    """Klartext-Label einer:class:`HardeningCategory` (fällt auf den Wert zurück)."""
    key = getattr(category, "value", str(category))
    return _HARDENING_CATEGORY_LABELS.get(key, str(key))


def _hardening_scale_hint() -> str:
    """Skala-Hinweis der Hardening-Stufen, aus den Domänen-Grenzen abgeleitet (DRY)."""
    from tools.security_scoring.domain.hardening_stages import (  # noqa: PLC0415
        SCORE_STAGES,
    )

    return ", ".join(
        f"{stage.label} {stage.min_score}–{stage.max_score}" for stage in SCORE_STAGES
    )


def _audit_scale_hint() -> str:
    """Skala-Hinweis der Audit-Risikostufen, aus den Domänen-Schwellen abgeleitet (DRY)."""
    # Import der Schwellen-Konstanten (Single Source of Truth) statt harter Zahlen
    # im Adapter — R1/DRY: die Grenzwerte leben nur in der Audit-Domäne.
    from tools.customer_audit.domain.scoring_service import (  # noqa: PLC0415
        _RISK_KRITISCH,
        _RISK_THRESHOLDS,
    )

    parts = [f"{label} ab {int(threshold)}" for threshold, label in _RISK_THRESHOLDS]
    parts.append(f"sonst {_RISK_KRITISCH}")
    return ", ".join(parts)
