"""
storytelling_adapter — patch_monitor Findings → FindingInput.

Konvertiert:class:`PatchScanResult`-Eintraege in:class:`FindingInput`-
Objekte fuer den:class:`core.storytelling.ki_todo_emitter.KiTodoEmitter`.

Bezug-Diagnose: vor diesem Adapter speiste der Patch-Monitor keine
Findings in die KI-Todo-Engine — die "Was tun?"-Section auf der Mainpage
sah keine "Firefox jetzt updaten"-Tasks, selbst bei 5 Update-Urgent-
Faellen im Patch-Monitor-Dashboard.

**Recommendation → Finding-Type-Mapping:**

============================== ==================================== ==========
PatchScanResult.recommendation finding_type severity
============================== ==================================== ==========
update_urgent patch_update_urgent HIGH
eol_no_patch patch_eol_no_patch HIGH
workaround_available patch_workaround_available MEDIUM
patch_available_with_csaf_ctx patch_with_csaf_context MEDIUM
update / update_available patch_update_available MEDIUM
up_to_date / pinned/notify_only (SKIP — keine User-Aktion noetig) n/a
============================== ==================================== ==========

**Dedup-Strategie:** ``evidence_id = winget_id`` (oder ``normalized_name``
als Fallback). Dadurch bekommt die KI-Todo-Engine eine stabile ID pro
Software-Paket — wenn dasselbe Paket im naechsten Scan dieselbe
Recommendation hat, wird die Task nicht doppelt angelegt
(``KiTodoService.create_auto_task`` deduptet via
``compute_dedup_key(tool, finding_type, evidence_id)``).

Schichtzugehoerigkeit: ``application/`` (kein GUI, kein direktes data/).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from core.logger import get_logger
from core.patch_result import PatchScanResult
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity

log = get_logger(__name__)

#: Tool-Bezeichner — passend zum ``tool``-Match in
#: ``configs/rules/patch_monitor.yaml`` und konsistent mit
#: ``core.registry.last_scan_registry``.
TOOL_NAME: Final[str] = "patch_monitor"

#: Mapping ``recommendation → (finding_type, severity)``. ``None`` heisst
#: SKIP (keine User-Aktion noetig).
_RECOMMENDATION_MAP: Final[dict[str, tuple[str, Severity] | None]] = {
    "update_urgent": ("patch_update_urgent", Severity.HIGH),
    "eol_no_patch": ("patch_eol_no_patch", Severity.HIGH),
    "workaround_available": ("patch_workaround_available", Severity.MEDIUM),
    "patch_available_with_csaf_context": (
        "patch_with_csaf_context",
        Severity.MEDIUM,
    ),
    "update": ("patch_update_available", Severity.MEDIUM),
    "update_available": ("patch_update_available", Severity.MEDIUM),
    "up_to_date": None,
    "pinned": None,
    "notify_only": None,
}


def patch_results_to_findings(
    results: Iterable[PatchScanResult],
) -> list[FindingInput]:
    """Konvertiert Patch-Scan-Results zu:class:`FindingInput`-Objekten.

    Pipeline:
        1. Pro ``PatchScanResult`` das ``recommendation``-Feld auf
           ``_RECOMMENDATION_MAP`` schlagen — None → SKIP.
        2. ``evidence_id`` aus ``winget_id`` oder ``normalized_name``
           (Fallback fuer Registry-/MSIX-Apps).
        3. ``FindingInput`` bauen mit allen Patch-Daten in
           ``details`` damit das Template (``_render_patch_recommendation``)
           individuelle Action-Texte rendern kann.

    Args:
        results: Iterable von:class:`PatchScanResult` — typisch
            das Ergebnis von ``PatchService.scan`` oder
            ``PatchInventoryService.load_from_db``.

    Returns:
        Liste von:class:`FindingInput`. Reihenfolge bleibt erhalten.
        Items ohne actionable Recommendation werden uebersprungen.
    """
    findings: list[FindingInput] = []
    for result in results:
        mapping = _RECOMMENDATION_MAP.get(result.recommendation)
        if mapping is None:
            continue
        finding_type, severity = mapping
        evidence_id = result.winget_id or result.normalized_name
        if not evidence_id:
            log.debug(
                "patch-adapter: kein evidence_id fuer %r (winget_id=%r, "
                "normalized=%r) — skip",
                result.name, result.winget_id, result.normalized_name,
            )
            continue
        details = {
            "recommendation": result.recommendation,
            "name": result.name,
            "vendor": result.vendor or "",
            "installed_version": result.installed_version,
            "available_version": result.available_version or "",
            "cve_ids": list(result.cve_ids) if result.cve_ids else [],
            "cvss_max": result.cvss_max if result.cvss_max is not None else 0.0,
            "exploit_available": bool(result.exploit_available),
            "eol": bool(result.eol),
            "channel": result.channel or "",
        }
        try:
            finding = FindingInput(
                tool=TOOL_NAME,
                finding_type=finding_type,
                severity=severity,
                subject=result.name or evidence_id,
                evidence_id=evidence_id,
                details=details,
            )
        except Exception as exc:  # noqa: BLE001 — Adapter darf nie crashen
            log.warning(
                "patch-adapter: konnte %r (rec=%s) nicht konvertieren (%s)",
                result.name, result.recommendation, type(exc).__name__,
            )
            continue
        findings.append(finding)
    return findings


__all__ = ["TOOL_NAME", "patch_results_to_findings"]
