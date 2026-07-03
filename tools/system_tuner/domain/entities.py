"""
entities — Domain-Entities fuer system_tuner.

Reine, unveraenderbare Datenklassen (``frozen=True, slots=True``) — kein
I/O, keine Imports aus aeusseren Schichten. Spiegeln das datengetriebene
Katalog-Modell (privacy.sexy-inspiriert, aber AGPL-frei + strukturiert
statt Skript-String).

Schichtzugehoerigkeit: domain/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.system_tuner.domain.enums import (
    ChangeOp,
    Recommendation,
    RegistryValueType,
    RevertKind,
    RiskTier,
    ServiceStartMode,
    TweakCategory,
    TweakStatus,
)


@dataclass(frozen=True, slots=True)
class ChangeSpec:
    """Strukturierte, typisierte Beschreibung EINER System-Aenderung.

    Bewusst strukturiert (kein Skript-String) — damit (a) kein monolithisches
    ``.bat`` Defender-False-Positives ausloest, (b) jede Aenderung maschinell
    introspektierbar fuer Audit ist, (c) die NEVER_DISABLE-Pruefung ein
    Ladezeit-Check statt Laufzeit-Parsing ist.

    Je nach ``op`` sind unterschiedliche Felder gesetzt:
        * ``REGISTRY_SET`` — hive/key/value_name/value_type/desired
        * ``SERVICE_STARTMODE`` — service_name/desired_start_mode
        * ``APPX_REMOVE`` — package_family
    """

    op: ChangeOp
    hive: str | None = None
    key: str | None = None
    value_name: str | None = None
    value_type: RegistryValueType | None = None
    desired: str | int | None = None
    service_name: str | None = None
    desired_start_mode: ServiceStartMode | None = None
    package_family: str | None = None

    @property
    def target_key(self) -> str:
        """Stabiler Ziel-Identifier (fuer NEVER_DISABLE-Check + Audit)."""
        if self.op is ChangeOp.REGISTRY_SET:
            return f"registry:{self.hive}\\{self.key}!{self.value_name}"
        if self.op is ChangeOp.SERVICE_STARTMODE:
            return f"service:{self.service_name}"
        return f"appx:{self.package_family}"


@dataclass(frozen=True, slots=True)
class VerifySpec:
    """Erwartung fuer den Post-Apply-Readback (Verify-Schritt, Phase 2)."""

    expect_value: str | int | None = None
    expect_start_mode: ServiceStartMode | None = None
    expect_absent: bool | None = None


@dataclass(frozen=True, slots=True)
class RevertSpec:
    """Wie ein Tweak rueckabgewickelt wird.

    ``RESTORE_PRIOR`` braucht keinen Wert (der Snapshot liefert ihn);
    ``SET_VALUE`` traegt das deterministische Inverse; ``IRREVERSIBLE``
    nur fuer T3 erlaubt (vom Loader erzwungen).
    """

    kind: RevertKind
    set_value: str | int | None = None
    set_start_mode: ServiceStartMode | None = None


@dataclass(frozen=True, slots=True)
class Provenance:
    """Herkunfts-/Lizenz-Nachweis eines Katalog-Eintrags (Clean-Room-Gate).

    Pflichtfeld ``source`` (Primaerquelle, z. B. Microsoft-Learn-URL).
    ``derived_from`` nennt eine ggf. inspirierende Technik-Quelle; ``license``
    deren Lizenz — (A)GPL fuehrt zur Ablehnung beim Laden (:class:`ProvenanceError`).
    """

    source: str
    derived_from: str | None = None
    license: str | None = None


@dataclass(frozen=True, slots=True)
class Tweak:
    """Ein einzelner, datengetriebener Datenschutz-/Debloat-Tweak.

    Identitaet ueber ``id`` (stabil, audit- und chat-referenziert). Alle
    Felder stammen 1:1 aus dem Katalog-YAML; Invarianten erzwingt der
    ``catalog_loader`` beim Laden.
    """

    id: str
    title_de: str
    category: TweakCategory
    risk_tier: RiskTier
    recommend: Recommendation
    rationale_de: str
    docs_url: str
    change: ChangeSpec
    verify: VerifySpec
    revert: RevertSpec
    provenance: Provenance
    requires_admin: bool = True
    requires_reboot: bool = False
    edition_caveat: str = ""
    compliance_relevance: tuple[str, ...] = ()
    source_attribution: str | None = None


@dataclass(frozen=True, slots=True)
class TweakState:
    """Ergebnis des read-only ``read_current`` (Scan, Phase 1b).

    ``status`` ist hier einer von ``APPLIED`` / ``NOT_APPLIED`` /
    ``UNKNOWN``. ``current_value``/``desired_value`` als Strings fuer
    die Anzeige (SophiApp-UX "aktuellen Wert zeigen").
    """

    tweak_id: str
    status: TweakStatus
    current_value: str | None = None
    desired_value: str | None = None
    detail: str = ""
