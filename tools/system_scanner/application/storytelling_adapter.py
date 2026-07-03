"""
storytelling_adapter — system_scanner Findings → FindingInput.

Konvertiert fehlgeschlagene:class:`HardeningCheck`-Eintraege (SH-001..
SH-010 aus dem Windows-Hardening-Scanner) in:class:`FindingInput`-
Objekte, die der:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`
an die Regel-Engine + Storytelling-Engine weiterreicht.

Bezug-Diagnose: vor diesem Adapter speist der Hardening-Score-Pfad
keine Findings in den KI-Todo-Layer — selbst bei "Defender aus" oder
"BitLocker aus" zeigte die "Was tun?"-Section dauerhaft Evergreens
statt der echten Befunde.

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable

from core.logger import get_logger
from core.storytelling.schemas import FindingInput
from tools.system_scanner.domain.entities import HardeningCheck

log = get_logger(__name__)

#: Tool-Bezeichner — passend zu:data:`core.registry.last_scan_registry`
#: und zum ``tool``-Match in ``configs/rules/hardening.yaml``.
TOOL_NAME = "system_scanner"

#: Generischer ``finding_type`` fuer alle 10 SH-Checks. Ein einziges
#: Template (``_render_hardening_check_failed`` in
#: ``core/storytelling/finding_templates.py``) rendert sie alle —
#: die check-spezifische Headline kommt aus ``input.subject`` (= label)
#: und ``input.details["check_id"]``. Eine generische Regel matcht
#: alle SH-Checks; Urgency wird aus der Severity abgeleitet.
FINDING_TYPE = "hardening_check_failed"


def hardening_checks_to_findings(
    checks: Iterable[HardeningCheck],
) -> list[FindingInput]:
    """Konvertiert fehlgeschlagene Hardening-Checks zu FindingInputs.

    Nur ``passed=False`` UND ``measurable=True``-Checks werden konvertiert —
    erfuellte Konfigurationen brauchen keine "Was tun?"-Karte, und nicht
    messbare Checks sind kein Verstoss.

    Args:
        checks: Ergebnis von:meth:`WindowsHardeningScanner.scan_all`
            (oder einer kuratierten Teilmenge).

    Returns:
        Liste von:class:`FindingInput`-Objekten. Reihenfolge bleibt
        erhalten — der Caller (KiTodoEmitter) entscheidet ueber Dedup.
        Leere Liste bei keinen Fehlschlaegen.
    """
    findings: list[FindingInput] = []
    for check in checks:
        # erfuellte UND nicht-messbare Checks erzeugen kein Finding.
        # Ein nicht messbarer Check ('grau', z.B. BitLocker auf Home ohne
        # Tool) darf weder eine 'Was-tun?'-Karte noch eine Zeile in der
        # Regulatorik-Tabelle ausloesen (beide speisen sich hieraus).
        if check.passed or not check.measurable:
            continue
        try:
            finding = FindingInput(
                tool=TOOL_NAME,
                finding_type=FINDING_TYPE,
                severity=check.severity,
                subject=check.label or check.check_id,
                evidence_id=check.check_id,
                details={
                    "check_id": check.check_id,
                    "label": check.label,
                    "detail": check.detail,
                },
            )
        except Exception as exc:  # noqa: BLE001 — Adapter darf nie crashen
            log.warning(
                "Hardening-Adapter: konnte Check %s nicht konvertieren (%s)",
                check.check_id,
                type(exc).__name__,
            )
            continue
        findings.append(finding)
    return findings


__all__ = ["FINDING_TYPE", "TOOL_NAME", "hardening_checks_to_findings"]
