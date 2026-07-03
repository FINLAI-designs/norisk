"""
scan_entities — Domain-Entities fuer den read-only Scan (Phase 1b).

Ergebnis-Typen der Bestandsaufnahme: Windows-Edition (Edition-Gate-Ehrlichkeit),
Verwaltungsstatus (Managed-Fleet), Privacy-Score und der gebuendelte
:class:`ScanReport`. Reine Datenklassen, kein I/O.

Schichtzugehoerigkeit: domain/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.system_tuner.domain.entities import Tweak, TweakState


@dataclass(frozen=True, slots=True)
class EditionInfo:
    """Windows-Edition + Edition-Gate-Ehrlichkeit (R4/Compliance-Korrektheit).

    ``telemetry_zero_supported`` ist nur auf Enterprise/Education/IoT/Server
    True — auf Pro/Home behandelt Windows ``AllowTelemetry=0`` als ``1``.
    ``banner_de`` ist die Klartext-Aussage fuer die GUI (Laien-tauglich).
    """

    edition_id: str | None
    product_name: str | None
    telemetry_zero_supported: bool
    banner_de: str


@dataclass(frozen=True, slots=True)
class ManagedModeInfo:
    """Verwaltungsstatus (AD/Entra/Intune) — R4 Managed-Fleet-Ehrlichkeit.

    Auf verwalteten Geraeten koennen GPO/MDM lokale Aenderungen ueberschreiben;
    die GUI muss das ehrlich sagen und darf keinen unqualifizierten Erfolg
    auf einem umkaempften Key behaupten.
    """

    domain_joined: bool
    azure_ad_joined: bool
    mdm_enrolled: bool
    detail_de: str

    @property
    def is_managed(self) -> bool:
        """``True`` wenn das Geraet zentral verwaltet wird."""
        return self.domain_joined or self.azure_ad_joined or self.mdm_enrolled


@dataclass(frozen=True, slots=True)
class PrivacyScore:
    """Konfigurations-Haertungs-Score (0-100) — KEIN Compliance-Nachweis.

    Eigene Gauge; beeinflusst NICHT den kalibrierten Hardening-Score. Der
    ``disclaimer_de`` ist Pflichttext fuer die GUI (R2: Score != Compliance).
    """

    value: int
    applied: int
    applicable: int
    label_de: str
    disclaimer_de: str = "Konfigurations-Haertung — kein Compliance-Nachweis."


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Gebuendeltes Ergebnis eines read-only Scans."""

    edition: EditionInfo
    managed: ManagedModeInfo
    score: PrivacyScore
    states: tuple[TweakState, ...]
    tweaks: tuple[Tweak, ...] = ()
