"""
apply_entities — Domain-Entities fuer den Apply/Revert-Pfad (Phase 2).

Snapshot (Vorzustand vor jedem Write), Einzel- und Batch-Ergebnis. Reine
Datenklassen, kein I/O.

Schichtzugehoerigkeit: domain/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.system_tuner.domain.enums import ServiceStartMode, TweakStatus


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Vor dem Write gesicherter Ist-Zustand eines Tweak-Ziels.

    Genau eines der ``prior_*``-Felder ist je nach Op relevant.
    ``existed=False`` markiert, dass das Ziel vorher nicht gesetzt war
    (Revert = loeschen statt zurueckschreiben).
    """

    tweak_id: str
    target_key: str
    existed: bool
    prior_registry_value: str | None = None
    prior_registry_type: str | None = None
    prior_start_mode: ServiceStartMode | None = None


@dataclass(frozen=True, slots=True)
class TweakResult:
    """Ergebnis von Apply oder Revert eines einzelnen Tweaks."""

    tweak_id: str
    status: TweakStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        """``True`` bei erfolgreichem Apply/Revert."""
        return self.status in (TweakStatus.SUCCESS, TweakStatus.DRY_RUN)


@dataclass(frozen=True, slots=True)
class BatchResult:
    """Gebuendeltes Ergebnis eines Apply-/Revert-Laufs."""

    results: tuple[TweakResult, ...]

    @property
    def applied(self) -> int:
        return sum(1 for r in self.results if r.status is TweakStatus.SUCCESS)

    @property
    def failed(self) -> int:
        return sum(
            1
            for r in self.results
            if r.status in (TweakStatus.FAILED, TweakStatus.FAILED_ROLLED_BACK)
        )

    @property
    def blocked(self) -> int:
        return sum(1 for r in self.results if r.status is TweakStatus.BLOCKED)
