"""
tweak_engine — Fail-closed Apply/Revert-Engine (Phase 2).

Strukturierte, typisierte Ausfuehrung der Tweaks (keine Skript-Strings):
``dry_run`` (kein Write) / ``apply`` (Snapshot -> Write -> Verify -> Auto-
Revert bei Mismatch) / ``revert`` / ``revert_all``. Gibt immer
:class:`TweakResult`/:class:`BatchResult` zurueck — wirft nie ueber die
Grenze.

**Sicherheits-Gates (verdrahtet):**
- ``allow_apply`` (Default ``False``): das **echte Schreiben ist bis zum
  benannten Security-/Legal-Sign-off gesperrt** (Plan-Gate R7). Ohne Freigabe
  liefert ``apply`` ``BLOCKED`` — Scan/Dry-Run/Revert-Logik bleibt nutzbar.
- NEVER_DISABLE wird **pro Op unmittelbar vor jedem Write erneut** geprueft
  (R5 Defense-in-Depth — nicht nur beim Katalog-Laden).
- Snapshot vor jedem Write; Verify-Readback; bei Mismatch sofortiger
  Auto-Revert aus dem Snapshot.
- Fehlt der Snapshot, wird ``restore_prior`` verweigert (nie raten).

NOCH NICHT enthalten (reviewter Phase-2-Sprint, Plan-Gates): elevated
Round-Trip (R5), System-Restore-Point (R6), persistente SQLCipher-Snapshots,
EULA-/Consent-Gate (R7).

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any

from core.logger import get_logger
from tools.system_tuner.domain.apply_entities import (
    BatchResult,
    Snapshot,
    TweakResult,
)
from tools.system_tuner.domain.entities import Tweak
from tools.system_tuner.domain.enums import ChangeOp, RevertKind, TweakStatus
from tools.system_tuner.domain.interfaces import ISnapshotRepo, ITweakProbe
from tools.system_tuner.domain.never_disable import (
    is_never_disable_service,
    is_never_touch_registry,
)

log = get_logger(__name__)

_BLOCK_DETAIL = (
    "Anwenden ist noch nicht freigegeben (Security-/Legal-Sign-off ausstehend "
    "— Plan-Gates R5/R6/R7)."
)


class TweakEngine:
    """Fuehrt Tweaks fail-closed aus (Apply/Revert) oder simuliert sie (Dry-Run)."""

    def __init__(
        self,
        probe: ITweakProbe,
        snapshots: ISnapshotRepo,
        *,
        allow_apply: bool = False,
        audit: Any | None = None,
    ) -> None:
        self._probe = probe
        self._snapshots = snapshots
        self._allow_apply = allow_apply
        self._audit = audit

    # ==================================================================
    # Dry-Run (kein Write) — simuliert nur die Aenderungen
    # ==================================================================
    def dry_run(self, tweaks: list[Tweak]) -> list[TweakResult]:
        """Simuliert ohne Writes: zeigt pro Tweak die Ist->Soll-Absicht."""
        results: list[TweakResult] = []
        for tweak in tweaks:
            current = self._read_current(tweak)
            desired = _desired_str(tweak)
            results.append(
                TweakResult(
                    tweak_id=tweak.id,
                    status=TweakStatus.DRY_RUN,
                    detail=f"{current or '(nicht gesetzt)'} → {desired}",
                )
            )
        return results

    # ==================================================================
    # Apply
    # ==================================================================
    def apply(self, tweaks: list[Tweak]) -> BatchResult:
        """Wendet Tweaks fail-closed an (Snapshot/Write/Verify/Auto-Revert)."""
        if not self._allow_apply:
            self._log("TUNER_APPLY_BLOCKED", {"reason": "sign_off_pending"})
            return BatchResult(
                tuple(
                    TweakResult(t.id, TweakStatus.BLOCKED, _BLOCK_DETAIL)
                    for t in tweaks
                )
            )
        if not self._probe.is_available():
            return BatchResult(
                tuple(
                    TweakResult(t.id, TweakStatus.FAILED, "Nur unter Windows moeglich")
                    for t in tweaks
                )
            )
        return BatchResult(tuple(self._apply_one(t) for t in tweaks))

    def _apply_one(self, tweak: Tweak) -> TweakResult:
        if self._violates_never_disable(tweak):
            self._log("TUNER_NEVER_DISABLE_BLOCKED", {"tweak_id": tweak.id})
            return TweakResult(
                tweak.id, TweakStatus.BLOCKED, "NEVER_DISABLE-Ziel — abgelehnt"
            )
        if tweak.change.op is ChangeOp.APPX_REMOVE:
            return TweakResult(
                tweak.id, TweakStatus.SKIPPED, "AppX-Entfernung folgt (Phase 3)"
            )
        snapshot = self._capture(tweak)
        self._snapshots.save(snapshot)
        write = self._write(tweak)
        if not write.success:
            return TweakResult(tweak.id, TweakStatus.FAILED, write.error)
        if not self._verify(tweak):
            self._restore(tweak, snapshot)
            return TweakResult(
                tweak.id,
                TweakStatus.FAILED_ROLLED_BACK,
                "Verify fehlgeschlagen — automatisch zurueckgenommen",
            )
        self._log(
            "TUNER_APPLY",
            {"tweak_id": tweak.id, "op": tweak.change.op.value, "verify_ok": True},
        )
        return TweakResult(tweak.id, TweakStatus.SUCCESS, "Angewandt + verifiziert")

    # ==================================================================
    # Revert
    # ==================================================================
    def revert(self, tweak: Tweak) -> TweakResult:
        """Macht einen Tweak rueckgaengig (restore_prior/set_value/irreversible)."""
        if not self._allow_apply:
            return TweakResult(tweak.id, TweakStatus.BLOCKED, _BLOCK_DETAIL)
        kind = tweak.revert.kind
        if kind is RevertKind.IRREVERSIBLE:
            return TweakResult(
                tweak.id, TweakStatus.IRREVERSIBLE, "Nicht automatisch umkehrbar"
            )
        if kind is RevertKind.RESTORE_PRIOR:
            snapshot = self._snapshots.get(tweak.id)
            if snapshot is None:
                return TweakResult(
                    tweak.id, TweakStatus.FAILED, "Kein Snapshot — Revert verweigert"
                )
            return self._restore(tweak, snapshot)
        return self._revert_set_value(tweak)

    def revert_all(self, tweaks: list[Tweak]) -> BatchResult:
        """Nimmt alle Tweaks zurueck, fuer die ein Snapshot vorliegt."""
        by_id = {t.id: t for t in tweaks}
        results: list[TweakResult] = []
        for snapshot in self._snapshots.list_all():
            tweak = by_id.get(snapshot.tweak_id)
            if tweak is not None:
                results.append(self.revert(tweak))
        return BatchResult(tuple(results))

    # ==================================================================
    # Internals
    # ==================================================================
    @staticmethod
    def _violates_never_disable(tweak: Tweak) -> bool:
        change = tweak.change
        if change.op is ChangeOp.SERVICE_STARTMODE:
            return is_never_disable_service(change.service_name or "")
        if change.op is ChangeOp.REGISTRY_SET:
            return is_never_touch_registry(
                change.hive or "", change.key or "", change.value_name or ""
            )
        return False

    def _read_current(self, tweak: Tweak) -> str | None:
        change = tweak.change
        if change.op is ChangeOp.REGISTRY_SET:
            return self._probe.read_registry_value(
                change.hive or "", change.key or "", change.value_name or ""
            )
        if change.op is ChangeOp.SERVICE_STARTMODE:
            mode = self._probe.read_service_start_mode(change.service_name or "")
            return mode.value if mode else None
        return None

    def _capture(self, tweak: Tweak) -> Snapshot:
        change = tweak.change
        if change.op is ChangeOp.SERVICE_STARTMODE:
            mode = self._probe.read_service_start_mode(change.service_name or "")
            return Snapshot(
                tweak_id=tweak.id,
                target_key=change.target_key,
                existed=mode is not None,
                prior_start_mode=mode,
            )
        current = self._probe.read_registry_value(
            change.hive or "", change.key or "", change.value_name or ""
        )
        return Snapshot(
            tweak_id=tweak.id,
            target_key=change.target_key,
            existed=current is not None,
            prior_registry_value=current,
        )

    def _write(self, tweak: Tweak) -> Any:
        change = tweak.change
        if change.op is ChangeOp.SERVICE_STARTMODE:
            return self._probe.set_service_start_mode(
                change.service_name or "", change.desired_start_mode  # type: ignore[arg-type]
            )
        return self._probe.write_registry_value(
            change.hive or "",
            change.key or "",
            change.value_name or "",
            change.value_type,  # type: ignore[arg-type]
            change.desired,  # type: ignore[arg-type]
        )

    def _verify(self, tweak: Tweak) -> bool:
        change = tweak.change
        if change.op is ChangeOp.SERVICE_STARTMODE:
            return (
                self._probe.read_service_start_mode(change.service_name or "")
                is change.desired_start_mode
            )
        current = self._probe.read_registry_value(
            change.hive or "", change.key or "", change.value_name or ""
        )
        return current == _desired_str(tweak)

    def _restore(self, tweak: Tweak, snapshot: Snapshot) -> TweakResult:
        change = tweak.change
        if change.op is ChangeOp.SERVICE_STARTMODE:
            if not snapshot.existed or snapshot.prior_start_mode is None:
                return TweakResult(tweak.id, TweakStatus.SUCCESS, "Kein Vorzustand")
            res = self._probe.set_service_start_mode(
                change.service_name or "", snapshot.prior_start_mode
            )
        elif snapshot.existed and snapshot.prior_registry_value is not None:
            res = self._probe.write_registry_value(
                change.hive or "",
                change.key or "",
                change.value_name or "",
                change.value_type,  # type: ignore[arg-type]
                snapshot.prior_registry_value,
            )
        else:
            res = self._probe.delete_registry_value(
                change.hive or "", change.key or "", change.value_name or ""
            )
        status = TweakStatus.SUCCESS if res.success else TweakStatus.FAILED
        self._log("TUNER_REVERT", {"tweak_id": tweak.id, "ok": res.success})
        return TweakResult(tweak.id, status, res.error or "Zurueckgenommen")

    def _revert_set_value(self, tweak: Tweak) -> TweakResult:
        change = tweak.change
        revert = tweak.revert
        if change.op is ChangeOp.SERVICE_STARTMODE and revert.set_start_mode:
            res = self._probe.set_service_start_mode(
                change.service_name or "", revert.set_start_mode
            )
        elif revert.set_value is not None:
            res = self._probe.write_registry_value(
                change.hive or "",
                change.key or "",
                change.value_name or "",
                change.value_type,  # type: ignore[arg-type]
                revert.set_value,
            )
        else:
            return TweakResult(tweak.id, TweakStatus.FAILED, "set_value ohne Wert")
        status = TweakStatus.SUCCESS if res.success else TweakStatus.FAILED
        return TweakResult(tweak.id, status, res.error or "Zurueckgenommen")

    def _log(self, action: str, details: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit.log_action(action, details, tool="system_tuner")
        except Exception as exc:  # noqa: BLE001 — Audit darf den Apply nicht killen
            log.warning("Audit-Log fehlgeschlagen: %s", exc)


def _desired_str(tweak: Tweak) -> str:
    """Soll-Wert als String fuer Anzeige/Verify-Vergleich."""
    change = tweak.change
    if change.op is ChangeOp.SERVICE_STARTMODE and change.desired_start_mode:
        return change.desired_start_mode.value
    return str(change.desired)
