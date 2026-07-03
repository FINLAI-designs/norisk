"""
snapshot_repository — Snapshot-Persistenz fuer den Revert (Phase 2).

Diese Iteration liefert eine In-Memory-Implementation (genug fuer den
Engine-Vertrag + Tests). Die persistente SQLCipher-Variante (Muster
``tools/patch_monitor/data/upgrade_history_repository.py``) ist fuer den
elevated Round-Trip (R5) noetig und folgt im reviewten Phase-2-Sprint.

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.system_tuner.domain.apply_entities import Snapshot
from tools.system_tuner.domain.interfaces import ISnapshotRepo


class InMemorySnapshotRepo(ISnapshotRepo):
    """Fluechtige Snapshot-Ablage (ein Snapshot je tweak_id)."""

    def __init__(self) -> None:
        self._store: dict[str, Snapshot] = {}

    def save(self, snapshot: Snapshot) -> None:
        self._store[snapshot.tweak_id] = snapshot

    def get(self, tweak_id: str) -> Snapshot | None:
        return self._store.get(tweak_id)

    def list_all(self) -> list[Snapshot]:
        return list(self._store.values())
