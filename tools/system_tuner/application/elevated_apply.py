"""
elevated_apply — Trust-Boundary-Orchestrator fuer den elevated Apply (R5/R6/R7).

Diese Funktion laeuft im **elevated** Prozess. Sie vertraut der GUI NICHT:
1. (R7) Sign-off-Gate ``APPLY_ENABLED`` — bis zu den benannten Security/Legal/
   Produkt-Sign-offs ``False`` → alles ``BLOCKED``.
2. (R3) Katalog-Signatur muss gueltig sein (``signature_ok``), sonst Abbruch.
3. (R5) Plan-Binding verifizieren (HMAC + Single-Use-Token + erwartete
   Katalog-Signatur) → sonst Reject.
4. (R5) Jede Tweak-ID muss im **signierten** Katalog existieren — sonst Reject
   (kein nicht-katalogisiertes Ziel).
5. (R6) System-Restore-Point fail-closed: schlaegt er fehl und kein Override →
   Abbruch.
6. Anwenden via:class:`TweakEngine` (allow_apply=True NUR hier, im gegateten
   Pfad) — die Engine prueft NEVER_DISABLE erneut pro Op + snapshottet.

Reine Orchestrierungs-Logik; Probe/Catalog/Snapshots/Restore-Point werden
injiziert (mock-testbar). Der echte elevated Entry + relaunch + Checkpoint-
Computer (Windows-only) sind duenne Adapter und brauchen einen Windows-Admin-
Smoke + ``/security-review`` BEVOR ``APPLY_ENABLED`` auf True geht.

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from core.logger import get_logger
from tools.system_tuner.application.apply_plan import verify_plan
from tools.system_tuner.application.tweak_engine import TweakEngine
from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
from tools.system_tuner.domain.entities import Tweak
from tools.system_tuner.domain.enums import TweakStatus
from tools.system_tuner.domain.interfaces import ISnapshotRepo, ITweakProbe

log = get_logger(__name__)

#: R7 Sign-off-Gate. Bleibt False bis zu den benannten Security/Legal/Produkt-
#: Sign-offs + Windows-Admin-Smoke + /security-review. EINE Zeile zum Scharfschalten.
APPLY_ENABLED = False


def _reject(detail: str, audit: Any | None) -> BatchResult:
    if audit is not None:
        try:
            audit.log_action("TUNER_ELEVATED_REJECTED", {"reason": detail}, tool="system_tuner")
        except Exception as exc:  # noqa: BLE001
            log.warning("Audit fehlgeschlagen: %s", exc)
    log.warning("elevated Apply abgelehnt: %s", detail)
    return BatchResult(())


def run_elevated_apply(
    payload: dict[str, object],
    catalog_tweaks: list[Tweak],
    probe: ITweakProbe,
    snapshots: ISnapshotRepo,
    *,
    secret: bytes,
    expected_catalog_sig: str,
    signature_ok: bool,
    used_tokens: frozenset[str] = frozenset(),
    restore_point: Callable[[], bool] | None = None,
    audit: Any | None = None,
    apply_enabled: bool = APPLY_ENABLED,
) -> BatchResult:
    """Fuehrt den fail-closed elevated Apply-Round-Trip aus (s. Modul-Docstring)."""
    # A1: die MODUL-Konstante APPLY_ENABLED ist der autoritative Sign-off-Gate
    # (von argv/GUI nicht beeinflussbar) UND der injizierte Parameter muss True
    # sein. Ein --allow-apply-Flag allein (untrusted argv) genuegt NICHT.
    if not (APPLY_ENABLED and apply_enabled):
        return _reject("sign_off_pending (APPLY_ENABLED/apply_enabled)", audit)
    if not signature_ok:
        return _reject("catalog_signature_invalid", audit)

    ids = verify_plan(
        payload,
        secret=secret,
        expected_catalog_sig=expected_catalog_sig,
        used_tokens=used_tokens,
    )
    if ids is None:
        return _reject("plan_binding_invalid", audit)

    by_id = {tweak.id: tweak for tweak in catalog_tweaks}
    selected = [by_id[i] for i in ids if i in by_id]
    if len(selected) != len(ids):
        return _reject("plan_contains_uncatalogued_target", audit)

    if restore_point is not None and not restore_point():
        if audit is not None:
            audit.log_action(
                "TUNER_RESTORE_POINT_FAILED", {"count": len(selected)}, tool="system_tuner"
            )
        return BatchResult(
            tuple(
                TweakResult(t.id, TweakStatus.BLOCKED, "Restore-Point fehlgeschlagen")
                for t in selected
            )
        )

    engine = TweakEngine(probe, snapshots, allow_apply=True, audit=audit)
    return engine.apply(selected)
