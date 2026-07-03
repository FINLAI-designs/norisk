"""
storytelling_adapter — system_tuner Scan-Findings -> FindingInput.

Wandelt noch nicht angewandte (``NOT_APPLIED``) Datenschutz-Empfehlungen in
:class:`core.storytelling.schemas.FindingInput`, die der
:class:`KiTodoEmitter` an die Regel-/Storytelling-Engine reicht ("Was tun?"-
Karten, 3. Schicht der Progressive Disclosure). Der KI-Chat erklaert/deeplinkt
nur — er fuehrt nie eine Aenderung aus.

Schichtzugehoerigkeit: application/ (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.security.severity import Severity
from core.storytelling.schemas import FindingInput
from tools.system_tuner.domain.entities import Tweak, TweakState
from tools.system_tuner.domain.enums import TweakCategory, TweakStatus

log = get_logger(__name__)

#: Tool-Bezeichner (Match in der Storytelling-/Regel-Registry).
TOOL_NAME = "system_tuner"

#: Generischer finding_type — ein Template rendert alle (Phase 1c registriert es).
FINDING_TYPE = "privacy_default_risky"

#: Kategorie -> Severity. Datenschutz-Empfehlungen sind KEINE Sicherheitsluecken;
#: bewusst niedrig/mittel, damit sie nicht mit kritischen Findings konkurrieren.
_CATEGORY_SEVERITY: dict[TweakCategory, Severity] = {
    TweakCategory.TELEMETRY: Severity.MEDIUM,
    TweakCategory.PRIVACY: Severity.MEDIUM,
    TweakCategory.SERVICES: Severity.LOW,
    TweakCategory.APPX: Severity.INFO,
}


def tweak_findings(
    tweaks: Iterable[Tweak],
    states: Iterable[TweakState],
) -> list[FindingInput]:
    """Konvertiert NOT_APPLIED-Empfehlungen in FindingInputs.

    Nur ``NOT_APPLIED`` wird zu einer Karte — bereits Angewandtes oder
    Unbekanntes erzeugt keine "Was tun?"-Empfehlung.

    Args:
        tweaks: der geladene Katalog.
        states: die Scan-Zustaende (ein:class:`TweakState` pro Tweak).

    Returns:
        Liste von:class:`FindingInput`; leere Liste wenn nichts offen ist.
    """
    by_id = {tweak.id: tweak for tweak in tweaks}
    findings: list[FindingInput] = []
    for state in states:
        if state.status is not TweakStatus.NOT_APPLIED:
            continue
        tweak = by_id.get(state.tweak_id)
        if tweak is None:
            continue
        try:
            finding = FindingInput(
                tool=TOOL_NAME,
                finding_type=FINDING_TYPE,
                severity=_CATEGORY_SEVERITY.get(tweak.category, Severity.LOW),
                subject=tweak.title_de,
                evidence_id=tweak.id,
                details={
                    "risk_tier": tweak.risk_tier.value,
                    "category": tweak.category.value,
                    "rationale": tweak.rationale_de,
                    "docs_url": tweak.docs_url,
                    "current_value": state.current_value or "",
                    "desired_value": state.desired_value or "",
                },
            )
        except Exception as exc:  # noqa: BLE001 — Adapter darf nie crashen
            log.warning(
                "system_tuner-Adapter: Tweak %s nicht konvertierbar (%s)",
                state.tweak_id,
                type(exc).__name__,
            )
            continue
        findings.append(finding)
    return findings


def emit_to_ki_emitter(
    emitter,
    tweaks: Iterable[Tweak],
    states: Iterable[TweakState],
) -> list[FindingInput]:
    """Convenience: konvertiert NOT_APPLIED-Tweaks + ruft ``emitter.emit`` auf.

    Fail-safe: Konvertierungs-Fehler werden geloggt und geschluckt — der Hook
    darf den read-only Scan nicht brechen. ``tweak_findings`` liefert die
    VOLLSTAENDIGE offene Menge (ein Finding je NOT_APPLIED-Tweak), daher
    schliesst ``reconcile_tool`` erledigte "Was tun?"-Karten beim naechsten
    Scan automatisch (Voll-Sync, Muster cert_monitor/patch_monitor).

    Args:
        emitter::class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`.
        tweaks: der geladene Katalog.
        states: die Scan-Zustaende (ein:class:`TweakState` pro Tweak).

    Returns:
        Konvertierte:class:`FindingInput`-Liste (Side-effect: emitter.emit).
    """
    try:
        findings = tweak_findings(tweaks, states)
    except Exception as exc:  # noqa: BLE001 — Hook darf Scan nicht brechen
        log.warning(
            "system_tuner → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    emitter.emit(findings, reconcile_tool=TOOL_NAME)
    return findings


__all__ = ["FINDING_TYPE", "TOOL_NAME", "emit_to_ki_emitter", "tweak_findings"]
