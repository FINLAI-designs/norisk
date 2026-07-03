"""
restore_point — System-Restore-Point vor einem Apply-Batch (R6).

Ruft ``Checkpoint-Computer`` via PowerShell (elevated). **Fail-closed**: ohne
Admin-Rechte, bei deaktiviertem Systemschutz, Drosselung (Standard: max. 1
Checkpoint/24 h) oder jedem Fehler → ``False``. Der Orchestrator bricht den
Batch dann ab (oder verlangt einen expliziten Override).

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.probes.hardening_probe import IHardeningProbe

log = get_logger(__name__)

#: Beschreibung des Wiederherstellungspunkts (konstant — keine User-Eingabe).
_DESCRIPTION = "NoRisk system_tuner — vor Datenschutz-Aenderung"

#: Restore-Point kann je nach System ein paar Sekunden brauchen.
_TIMEOUT_S = 120


def create_restore_point(probe: IHardeningProbe) -> bool:
    """Erstellt einen System-Restore-Point (fail-closed).

    Returns:
        ``True`` nur bei erfolgreichem ``Checkpoint-Computer``; sonst ``False``
        (kein Admin / Systemschutz aus / gedrosselt / Fehler).
    """
    if not probe.is_available():
        return False
    script = (
        f"Checkpoint-Computer -Description '{_DESCRIPTION}' "
        "-RestorePointType 'MODIFY_SETTINGS'"
    )
    result = probe.run_powershell(script, timeout=_TIMEOUT_S)
    if not result.success:
        log.warning(
            "Restore-Point fehlgeschlagen (fail-closed): %s",
            result.error or result.stderr[:200],
        )
        return False
    log.info("System-Restore-Point erstellt.")
    return True
