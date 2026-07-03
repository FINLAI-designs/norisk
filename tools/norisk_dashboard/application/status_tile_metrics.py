"""
status_tile_metrics — Lazy, fail-soft Daten-Accessoren für die Cockpit-Status-
Kacheln (Cockpit Increment-2).

Jede Funktion liest cross-tool (lazy Import) und fällt bei JEDEM Fehler
auf einen neutralen Default zurück — eine fehlende/kaputte Tool-DB darf die
Landing-Seite nie blockieren oder leeren. Vorbild: ``light_siem_aggregator``.

Schichtzugehörigkeit: application/ — orchestriert cross-tool Reads, kein GUI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime

from core.logger import get_logger
from core.registry.last_scan_registry import get_last_scan

_log = get_logger(__name__)


def patch_offene_und_eol() -> tuple[int, int]:
    """``(N offene Updates, M EOL)`` für die Patch-Kachel; ``(0, 0)`` bei Fehler."""
    try:
        from tools.patch_monitor.application.patch_inventory_service import (  # noqa: PLC0415
            PatchInventoryService,
        )

        return PatchInventoryService().offene_und_eol_counts()
    except Exception:  # noqa: BLE001 -- Kachel-Metrik nie blockierend
        _log.debug("Cockpit-Kachel patch_offene_und_eol fehlgeschlagen")
        return (0, 0)


def netzwerk_letzter_scan() -> datetime | None:
    """Zeitpunkt des letzten Netzwerk-Scans (``network_scanner``) oder ``None``."""
    return get_last_scan("network_scanner")


def supply_offene_punkte() -> int:
    """Offene Supply-Chain-Punkte: überfällige/bald ablaufende AVVs + offene
    Vendor-Detection-Vorschläge. ``0`` bei Fehler (jeder Summand fail-soft)."""
    n = 0
    try:
        from tools.supply_chain_monitor.application.avv_service import (  # noqa: PLC0415
            AvvService,
        )

        n += len(AvvService().list_expiring())
    except Exception:  # noqa: BLE001
        _log.debug("Cockpit-Kachel supply AVV-Count fehlgeschlagen")
    try:
        from tools.supply_chain_monitor.application.detection_service import (  # noqa: PLC0415
            DetectionService,
        )

        n += len(DetectionService().list_suggestions())
    except Exception:  # noqa: BLE001
        _log.debug("Cockpit-Kachel supply Detection-Count fehlgeschlagen")
    return n


def passwort_letzter_check() -> datetime | None:
    """Zeitpunkt der letzten Passwort-Prüfung oder ``None`` (fail-soft)."""
    try:
        from tools.password_checker.data.last_check_repository import (  # noqa: PLC0415
            LastCheckRepository,
        )

        return LastCheckRepository().letzter_check()
    except Exception:  # noqa: BLE001
        _log.debug("Cockpit-Kachel passwort_letzter_check fehlgeschlagen")
        return None
