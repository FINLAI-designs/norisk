"""
managed_mode — Verwaltungsstatus erkennen (R4 Managed-Fleet-Ehrlichkeit).

Erkennt read-only ueber ``dsregcmd /status``, ob das Geraet domain-/Entra-
gejoined oder MDM-enrolled ist. Auf verwalteten Geraeten koennen GPO/MDM
lokale Aenderungen ueberschreiben — die GUI muss das ehrlich anzeigen und
darf keinen unqualifizierten Erfolg auf einem umkaempften Key behaupten.

Schichtzugehoerigkeit: application/ (nutzt den read-only core-Probe-Port).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from core.probes.hardening_probe import IHardeningProbe
from tools.system_tuner.domain.scan_entities import ManagedModeInfo

log = get_logger(__name__)


def _parse_dsregcmd(stdout: str) -> tuple[bool, bool, bool]:
    """Parst ``dsregcmd /status`` zu (domain_joined, azure_ad_joined, mdm).

    Robust gegen Locale/Whitespace: vergleicht je Zeile den lowercase-Key
    (vor ':') gegen bekannte Marker.
    """
    domain = aad = mdm = False
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip().lower()
        if key == "domainjoined":
            domain = value == "yes"
        elif key == "azureadjoined":
            aad = value == "yes"
        elif key == "mdmurl":
            mdm = value.startswith("http")
    return domain, aad, mdm


def _detail(domain: bool, aad: bool, mdm: bool) -> str:
    """Baut den Laien-taugliche Status-Hinweis."""
    if domain or aad or mdm:
        return (
            "Dieses Geraet wird zentral verwaltet (AD/Entra/Intune). "
            "Gruppenrichtlinien oder MDM koennen lokale Aenderungen "
            "ueberschreiben — Empfehlungen am besten ueber die IT/den "
            "Administrator umsetzen lassen."
        )
    return "Dieses Geraet wird nicht zentral verwaltet (kein AD/Entra/MDM erkannt)."


class ManagedModeDetector:
    """Erkennt den Verwaltungsstatus (read-only)."""

    def __init__(self, probe: IHardeningProbe) -> None:
        self._probe = probe

    def detect(self) -> ManagedModeInfo:
        """Fuehrt ``dsregcmd /status`` aus und wertet es aus (fail-safe)."""
        unknown = ManagedModeInfo(
            domain_joined=False,
            azure_ad_joined=False,
            mdm_enrolled=False,
            detail_de="Verwaltungsstatus unbekannt (nicht ermittelbar).",
        )
        if not self._probe.is_available():
            return unknown
        result = self._probe.run_command("dsregcmd", ["/status"])
        if not result.success:
            log.debug("dsregcmd nicht verfuegbar: %s", result.error)
            return unknown
        domain, aad, mdm = _parse_dsregcmd(result.stdout)
        return ManagedModeInfo(
            domain_joined=domain,
            azure_ad_joined=aad,
            mdm_enrolled=mdm,
            detail_de=_detail(domain, aad, mdm),
        )
