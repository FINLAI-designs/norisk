"""storytelling_adapter — csaf_advisor → FindingInput a/b).

Konvertiert:class:`AdvisoryMatch` plus zugehoeriges:class:`CsafAdvisory`
in ``FindingInput`` fuer das ``active_advisory_match``-Storytelling-Template.
Nur Matches mit ``action_required="update"`` werden gemeldet — Workaround/
Monitor-Empfehlungen sind nicht akut genug.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.security.severity import Severity, from_csaf
from core.storytelling.schemas import FindingInput
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch

log = get_logger(__name__)


def matches_to_ki_inputs(
    matches: Iterable[AdvisoryMatch],
    advisories_by_id: dict[str, CsafAdvisory],
) -> list[FindingInput]:
    """Wandelt Advisory-Matches in:class:`FindingInput`.

    Args:
        matches: Treffer aus:func:`AdvisoryService.run_matching`.
        advisories_by_id: Lookup-Dict ``advisory_id -> CsafAdvisory``.
            Matches ohne entsprechendes Advisory im Lookup werden uebersprungen.

    Returns:
        Liste der:class:`FindingInput`. Nur Matches mit
        ``action_required="update"`` werden uebernommen.
    """
    inputs: list[FindingInput] = []
    for match in matches:
        if match.action_required != "update":
            continue
        advisory = advisories_by_id.get(match.advisory_id)
        if advisory is None:
            continue
        # Pydantic FindingInput verlangt min_length=1 fuer subject + evidence_id.
        # Defekte Inputs (leerer Component+Title oder leere Match-ID) werden
        # uebersprungen statt eine ValidationError zu werfen — Hook darf den
        # Scan nicht brechen.
        subject = match.matched_component or advisory.title
        if not subject or not match.id:
            continue
        inputs.append(
            FindingInput(
                tool="csaf_advisor",
                finding_type="active_advisory_match",
                severity=_to_canonical_severity(advisory.severity),
                subject=subject,
                evidence_id=match.id,
                details={
                    "vendor": advisory.publisher or "Hersteller",
                    "product": match.matched_component,
                    "version": match.matched_version or "?",
                    "advisory_id": (
                        advisory.cve_ids[0] if advisory.cve_ids else advisory.tracking_id
                    ),
                    "summary": advisory.summary or advisory.title,
                    "fixed_version": "?",  # CSAF liefert nur affected, nicht fixed
                    "url": advisory.source_url,
                },
            )
        )
    return inputs


def _to_canonical_severity(value: str) -> Severity:
    """``advisory.severity`` (CSAF-String) → kanonisches ``Severity``."""
    return from_csaf(value)


def emit_to_ki_emitter(
    emitter,
    matches: Iterable[AdvisoryMatch],
    advisories: Iterable[CsafAdvisory],
) -> list[FindingInput]:
    """Convenience: konvertiert + ruft ``emitter.emit`` auf.

    Fail-safe: Konvertierungs-Fehler (z. B. unerwartete leere Felder, die
    den Empty-Guard umgehen) werden geloggt und schlucken. Der KiTodoEmitter
    selbst faengt nur Engine-Exceptions — diese Schutzlinie deckt die
    Adapter-Konvertierung ab. Hook darf den Scan nicht brechen.
    """
    try:
        by_id = {a.id: a for a in advisories}
        inputs = matches_to_ki_inputs(matches, by_id)
    except Exception as exc:  # noqa: BLE001 -- Hook darf Scan nicht brechen
        log.warning(
            "csaf_advisor → FindingInput-Konvertierung fehlgeschlagen: %s: %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        return []
    emitter.emit(inputs)
    return inputs
