"""patch_strategy — Patch-Strategie pro App.

Definiert, wie der Patch-Monitor mit Updates einer einzelnen App umgeht.
Die Strategie ist **user-eigene** Metadaten: der User waehlt sie pro App im
Patch-Console-Widget (Stop-Step C), sie wird in
``inventory_snapshot.patch_strategy`` persistiert (Schema-V2) und ueberlebt
Vollscans (siehe ``PatchInventoryRepository.upsert_inventory`` /
``update_strategy`` in
:mod:`tools.patch_monitor.data.patch_inventory_repository`).

Schichtzugehoerigkeit: ``core/`` (Shared Domain — wird von
``tools/patch_monitor`` und ``tools/einstellungen`` genutzt, analog
:mod:`core.patch_result` /:mod:`core.patch_upgrade`).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class PatchStrategy(StrEnum):
    """Wie der Patch-Monitor Updates einer einzelnen App behandelt.

    Als:class:`enum.StrEnum` ist jedes Mitglied gleichzeitig sein
    DB-/UI-String — ``PatchStrategy.STABLE == "stable"`` und
    ``PatchStrategy("stable") is PatchStrategy.STABLE``. Damit ist die
    Persistenz (TEXT-Spalte) ohne separates Mapping moeglich.

    Attributes:
        LATEST: Neueste verfuegbare Version inkl. Pre-Releases.
        STABLE: Nur als stabil markierte Releases (Default).
        NONE: App wird im Inventar gefuehrt, aber nie gepatcht —
            CVE-Matching und Hardening-Score bleiben aktiv, nur der
            Upgrade-Button greift nicht.
    """

    LATEST = "latest"
    STABLE = "stable"
    NONE = "none"


#: Standard-Strategie fuer neue und migrierte Inventar-Eintraege. Bestands-
#: inventare bekommen diesen Wert beim Schema-V1→V2-Upgrade, neue Eintraege
#: per Spalten-DEFAULT. Spiegelt den ``DEFAULT 'stable'`` im DB-Schema.
DEFAULT_PATCH_STRATEGY: Final[PatchStrategy] = PatchStrategy.STABLE
