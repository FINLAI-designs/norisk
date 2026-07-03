"""
tuner_scan_use_case — Read-only Bestandsaufnahme (Phase 1b).

Liest den Ist-Zustand jedes Katalog-Tweaks ueber den read-only Probe-Port
(Registry/Service-Start), bildet pro Tweak einen:class:`TweakState`, ergaenzt
Edition-Gate + Verwaltungsstatus und berechnet den Privacy-Score.

**Keine Writes, keine UAC** — Free/Beginner bekommen die volle Bewertung +
Vorschau ohne Elevation. Das Anwenden (Phase 2) ist davon getrennt.

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.probes.hardening_probe import HIVE_HKLM, IHardeningProbe
from tools.system_tuner.application.edition_gate import EditionGate
from tools.system_tuner.application.managed_mode import ManagedModeDetector
from tools.system_tuner.domain.entities import Tweak, TweakState
from tools.system_tuner.domain.enums import ChangeOp, ServiceStartMode, TweakStatus
from tools.system_tuner.domain.interfaces import ITweakCatalog
from tools.system_tuner.domain.privacy_score import compute_privacy_score
from tools.system_tuner.domain.scan_entities import ScanReport

log = get_logger(__name__)

_SERVICES_KEY = "SYSTEM\\CurrentControlSet\\Services"

#: Mapping des Registry-``Start``-Werts auf den Starttyp.
_START_VALUE_TO_MODE: dict[str, ServiceStartMode] = {
    "0": ServiceStartMode.AUTOMATIC,  # Boot
    "1": ServiceStartMode.AUTOMATIC,  # System
    "2": ServiceStartMode.AUTOMATIC,
    "3": ServiceStartMode.MANUAL,
    "4": ServiceStartMode.DISABLED,
}


class TunerScanUseCase:
    """Fuehrt den read-only Scan aus und liefert einen:class:`ScanReport`."""

    def __init__(
        self,
        probe: IHardeningProbe,
        catalog: ITweakCatalog,
        edition_gate: EditionGate | None = None,
        managed_detector: ManagedModeDetector | None = None,
        ki_todo_emitter=None,
    ) -> None:
        self._probe = probe
        self._catalog = catalog
        self._edition_gate = edition_gate or EditionGate(probe)
        self._managed = managed_detector or ManagedModeDetector(probe)
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import (  # noqa: PLC0415
                KiTodoEmitter,
            )

            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    def scan(self) -> ScanReport:
        """Laedt den Katalog, liest jeden Ist-Zustand, berechnet den Score."""
        tweaks = self._catalog.load()
        edition = self._edition_gate.detect()
        managed = self._managed.detect()
        states = tuple(self._read_state(tweak) for tweak in tweaks)
        score = compute_privacy_score(states)
        log.info(
            "system_tuner-Scan: %d Tweaks, Score %d (%s), Edition=%s, verwaltet=%s",
            len(states),
            score.value,
            score.label_de,
            edition.edition_id,
            managed.is_managed,
        )
        report = ScanReport(
            edition=edition,
            managed=managed,
            score=score,
            states=states,
            tweaks=tuple(tweaks),
        )
        # offene Datenschutz-Empfehlungen als "Was tun?"-Karten (mainpage)
        # emittieren — fail-safe (No-op bei Fehler), mutiert das System NICHT.
        from tools.system_tuner.application.storytelling_adapter import (  # noqa: PLC0415
            emit_to_ki_emitter,
        )

        emit_to_ki_emitter(self._ki_todo_emitter, report.tweaks, report.states)
        return report

    # ------------------------------------------------------------------
    # Ist-Zustand pro Tweak
    # ------------------------------------------------------------------

    def _read_state(self, tweak: Tweak) -> TweakState:
        """Liest den Ist-Zustand eines Tweaks (read-only, fail-safe)."""
        if not self._probe.is_available():
            return TweakState(
                tweak_id=tweak.id,
                status=TweakStatus.UNKNOWN,
                detail="Nur unter Windows ermittelbar",
            )
        op = tweak.change.op
        if op is ChangeOp.REGISTRY_SET:
            return self._read_registry_state(tweak)
        if op is ChangeOp.SERVICE_STARTMODE:
            return self._read_service_state(tweak)
        return TweakState(
            tweak_id=tweak.id,
            status=TweakStatus.UNKNOWN,
            detail="AppX-Bestandsaufnahme folgt (Phase 3)",
        )

    def _read_registry_state(self, tweak: Tweak) -> TweakState:
        """Vergleicht den aktuellen Registry-Wert mit dem Soll."""
        change = tweak.change
        current = self._probe.read_registry_value(
            change.hive or "", change.key or "", change.value_name or ""
        )
        desired = str(change.desired)
        if current is None:
            return TweakState(
                tweak_id=tweak.id,
                status=TweakStatus.NOT_APPLIED,
                current_value="(nicht gesetzt)",
                desired_value=desired,
                detail="Wert fehlt — Windows-Default",
            )
        status = (
            TweakStatus.APPLIED if current == desired else TweakStatus.NOT_APPLIED
        )
        return TweakState(
            tweak_id=tweak.id,
            status=status,
            current_value=current,
            desired_value=desired,
        )

    def _read_service_state(self, tweak: Tweak) -> TweakState:
        """Vergleicht den aktuellen Dienst-Starttyp mit dem Soll."""
        change = tweak.change
        name = change.service_name or ""
        raw = self._probe.read_registry_value(
            HIVE_HKLM, f"{_SERVICES_KEY}\\{name}", "Start"
        )
        desired = (
            change.desired_start_mode.value if change.desired_start_mode else ""
        )
        if raw is None:
            return TweakState(
                tweak_id=tweak.id,
                status=TweakStatus.UNKNOWN,
                desired_value=desired,
                detail=f"Dienst '{name}' nicht gefunden",
            )
        current_mode = _START_VALUE_TO_MODE.get(raw.strip())
        current_value = current_mode.value if current_mode else f"Start={raw}"
        status = (
            TweakStatus.APPLIED
            if current_mode is change.desired_start_mode
            else TweakStatus.NOT_APPLIED
        )
        return TweakState(
            tweak_id=tweak.id,
            status=status,
            current_value=current_value,
            desired_value=desired,
        )
