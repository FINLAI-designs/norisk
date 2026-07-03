"""
catalog_loader — Parsen + Validieren des Tweak-Katalogs (Ladezeit-Gate).

Wandelt das Katalog-YAML in:class:`Tweak`-Entities und erzwingt ALLE
Invarianten beim Laden (fail-closed). Der Katalog ist DATEN, nicht Code
(privacy.sexy-inspiriert, aber AGPL-frei + strukturiert).

Erzwungene Invarianten:
    * Pflichtfelder + gueltige Enum-Werte
    * ``risk_tier=T0_blocked`` ist NICHT katalogfaehig
    * NEVER_DISABLE-Kollision (Dienst/Registry) ->:class:`NeverDisableViolation`
    * Revert-Pflicht: T1/T2 brauchen restore_prior/set_value, nur T3 darf
      irreversible sein ->:class:`RevertMissingError`
    * Clean-Room: provenance Pflicht; (A)GPL-Lizenz ->:class:`ProvenanceError`
    * R1/R2: pro-Tweak ``compliance_relevance`` ohne Ueber-Claims
      (kein Art. 30 / NIS2 / "konform"/"compliant"/"erfuellt" auf Tweak-Ebene)
    * eindeutige IDs

Schichtzugehoerigkeit: application/ — liest die gebuendelte read-only
Katalog-Datei (kein DB-Adapter noetig) und importiert nur domain + core.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from core.logger import get_logger
from tools.system_tuner.domain.entities import (
    ChangeSpec,
    Provenance,
    RevertSpec,
    Tweak,
    VerifySpec,
)
from tools.system_tuner.domain.enums import (
    ChangeOp,
    Recommendation,
    RegistryValueType,
    RevertKind,
    RiskTier,
    ServiceStartMode,
    TweakCategory,
)
from tools.system_tuner.domain.exceptions import (
    CatalogError,
    NeverDisableViolation,
    ProvenanceError,
    RevertMissingError,
)
from tools.system_tuner.domain.interfaces import ITweakCatalog
from tools.system_tuner.domain.never_disable import (
    is_never_disable_service,
    is_never_touch_registry,
)

log = get_logger(__name__)

#: Verbotene Tokens in pro-Tweak ``compliance_relevance`` (R1/R2). Art. 30 /
#: NIS2-Framing + Konformitaets-Claims gehoeren auf das Evidence-Export-Feature,
#: nicht auf einen Einzeltweak.
_FORBIDDEN_COMPLIANCE_TOKENS: tuple[str, ...] = (
    "art. 30",
    "art.30",
    "nis2",
    "konform",
    "compliant",
    "erfüllt",
    "erfuellt",
)

#: Reversible Tiers, die einen echten Revert verlangen.
_REVERSIBLE_TIERS = (RiskTier.T1_SAFE, RiskTier.T2_CAUTION)


# ---------------------------------------------------------------------------
# Parse-Helfer
# ---------------------------------------------------------------------------


def _require(raw: dict[str, Any], key: str, ctx: str) -> Any:
    """Holt ein Pflichtfeld oder wirft:class:`CatalogError`."""
    if key not in raw or raw[key] is None or raw[key] == "":
        raise CatalogError(f"{ctx}: Pflichtfeld '{key}' fehlt oder ist leer")
    return raw[key]


def _as_enum[E: StrEnum](enum_cls: type[E], value: Any, key: str, ctx: str) -> E:
    """Mappt einen String auf ein Enum oder wirft:class:`CatalogError`."""
    try:
        return enum_cls(value)
    except ValueError as exc:
        valid = ", ".join(e.value for e in enum_cls)
        raise CatalogError(
            f"{ctx}: '{key}'='{value}' ungueltig (erlaubt: {valid})"
        ) from exc


#: A6 — Operanden-Whitelists (Defense-in-Depth zusaetzlich zu Subprocess-Quoting
#: + Katalog-Signatur). Greift bereits zur Ladezeit (fail-closed).
_ALLOWED_HIVES = frozenset({"HKLM", "HKCU"})
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,256}$")


def _validate_registry_target(hive: str, key: str, value_name: str, ctx: str) -> None:
    """A6: Registry-Operanden gegen Whitelist pruefen (fail-closed)."""
    if hive not in _ALLOWED_HIVES:
        raise CatalogError(f"{ctx}: hive '{hive}' ungueltig (nur HKLM/HKCU)")
    if not key or key[0] in "\\/" or any(ord(c) < 32 for c in key):
        raise CatalogError(
            f"{ctx}: key ungueltig (kein fuehrender Slash/Backslash, keine Steuerzeichen)"
        )
    if any(ord(c) < 32 for c in value_name):
        raise CatalogError(f"{ctx}: value_name enthaelt Steuerzeichen")


def _validate_service_name(name: str, ctx: str) -> None:
    """A6: Dienst-Namen gegen Whitelist pruefen (fail-closed)."""
    if not _SERVICE_NAME_RE.match(name):
        raise CatalogError(
            f"{ctx}: service_name '{name}' ungueltig (erlaubt: A-Za-z0-9_.- , max 256)"
        )


def _parse_change(raw: dict[str, Any], ctx: str) -> ChangeSpec:
    """Baut die:class:`ChangeSpec` op-spezifisch (mit Operanden-Whitelist, A6)."""
    op = _as_enum(ChangeOp, _require(raw, "op", ctx), "op", ctx)
    if op is ChangeOp.REGISTRY_SET:
        hive = str(_require(raw, "hive", ctx))
        key = str(_require(raw, "key", ctx))
        value_name = str(_require(raw, "value_name", ctx))
        _validate_registry_target(hive, key, value_name, ctx)
        return ChangeSpec(
            op=op,
            hive=hive,
            key=key,
            value_name=value_name,
            value_type=_as_enum(
                RegistryValueType, _require(raw, "value_type", ctx), "value_type", ctx
            ),
            desired=_require(raw, "desired", ctx),
        )
    if op is ChangeOp.SERVICE_STARTMODE:
        service_name = str(_require(raw, "service_name", ctx))
        _validate_service_name(service_name, ctx)
        return ChangeSpec(
            op=op,
            service_name=service_name,
            desired_start_mode=_as_enum(
                ServiceStartMode,
                _require(raw, "desired_start_mode", ctx),
                "desired_start_mode",
                ctx,
            ),
        )
    return ChangeSpec(op=op, package_family=str(_require(raw, "package_family", ctx)))


def _parse_verify(raw: dict[str, Any] | None, ctx: str) -> VerifySpec:
    """Baut die:class:`VerifySpec` (optional)."""
    if not raw:
        return VerifySpec()
    start_mode = raw.get("expect_start_mode")
    return VerifySpec(
        expect_value=raw.get("expect_value"),
        expect_start_mode=(
            _as_enum(ServiceStartMode, start_mode, "expect_start_mode", ctx)
            if start_mode
            else None
        ),
        expect_absent=raw.get("expect_absent"),
    )


def _parse_revert(raw: dict[str, Any], ctx: str) -> RevertSpec:
    """Baut die:class:`RevertSpec`."""
    kind = _as_enum(RevertKind, _require(raw, "kind", ctx), "kind", ctx)
    start_mode = raw.get("set_start_mode")
    return RevertSpec(
        kind=kind,
        set_value=raw.get("set_value"),
        set_start_mode=(
            _as_enum(ServiceStartMode, start_mode, "set_start_mode", ctx)
            if start_mode
            else None
        ),
    )


def _parse_provenance(raw: dict[str, Any], ctx: str) -> Provenance:
    """Baut die:class:`Provenance` + Clean-Room-Gate (keine (A)GPL-Quelle)."""
    prov = Provenance(
        source=str(_require(raw, "source", ctx)),
        derived_from=raw.get("derived_from"),
        license=raw.get("license"),
    )
    if "gpl" in (prov.license or "").lower():
        raise ProvenanceError(
            f"{ctx}: provenance.license '{prov.license}' ist (A)GPL — "
            "Katalog muss AGPL-frei sein"
        )
    return prov


# ---------------------------------------------------------------------------
# Invarianten-Checks (pro Tweak)
# ---------------------------------------------------------------------------


def _check_never_disable(tw: Tweak, ctx: str) -> None:
    """Wirft, wenn das Tweak-Ziel auf der NEVER_DISABLE-Sperrliste steht."""
    ch = tw.change
    if ch.op is ChangeOp.SERVICE_STARTMODE and is_never_disable_service(
        ch.service_name or ""
    ):
        raise NeverDisableViolation(
            f"{ctx}: Dienst '{ch.service_name}' steht auf NEVER_DISABLE"
        )
    if ch.op is ChangeOp.REGISTRY_SET and is_never_touch_registry(
        ch.hive or "", ch.key or "", ch.value_name or ""
    ):
        raise NeverDisableViolation(
            f"{ctx}: Registry-Ziel {ch.target_key} steht auf NEVER_DISABLE"
        )


def _check_revert(tw: Tweak, ctx: str) -> None:
    """Erzwingt die Revert-Pflicht (T1/T2 reversibel; set_value mit Wert)."""
    if tw.risk_tier in _REVERSIBLE_TIERS and tw.revert.kind is RevertKind.IRREVERSIBLE:
        raise RevertMissingError(
            f"{ctx}: {tw.risk_tier} verlangt reversiblen Revert "
            "(restore_prior oder set_value)"
        )
    if (
        tw.revert.kind is RevertKind.SET_VALUE
        and tw.revert.set_value is None
        and tw.revert.set_start_mode is None
    ):
        raise RevertMissingError(
            f"{ctx}: revert.kind=set_value ohne set_value/set_start_mode"
        )


def _check_compliance_wording(tw: Tweak, ctx: str) -> None:
    """R1/R2: keine Ueber-Claims in pro-Tweak compliance_relevance."""
    if not tw.compliance_relevance:
        raise CatalogError(f"{ctx}: compliance_relevance fehlt")
    for entry in tw.compliance_relevance:
        low = entry.lower()
        for token in _FORBIDDEN_COMPLIANCE_TOKENS:
            if token in low:
                raise CatalogError(
                    f"{ctx}: compliance_relevance '{entry}' enthaelt verbotenes "
                    f"Token '{token}' (R1/R2: Art.30/NIS2 + Konformitaets-Claims "
                    "gehoeren auf das Evidence-Feature, nicht auf einen Tweak)"
                )


def _check_invariants(tw: Tweak, ctx: str) -> None:
    """Buendelt alle pro-Tweak-Invarianten."""
    if tw.risk_tier is RiskTier.T0_BLOCKED:
        raise CatalogError(f"{ctx}: risk_tier T0_blocked ist nicht katalogfaehig")
    if not tw.docs_url:
        raise CatalogError(f"{ctx}: docs_url fehlt")
    _check_never_disable(tw, ctx)
    _check_revert(tw, ctx)
    _check_compliance_wording(tw, ctx)


# ---------------------------------------------------------------------------
# Tweak-Bau + Top-Level-Loader
# ---------------------------------------------------------------------------


def _build_tweak(raw: Any, index: int) -> Tweak:
    """Baut + validiert einen einzelnen Tweak aus einem YAML-Mapping."""
    if not isinstance(raw, dict):
        raise CatalogError(f"Tweak #{index}: Eintrag ist kein Mapping")
    ctx = f"Tweak {raw.get('id', f'#{index}')}"
    compliance = raw.get("compliance_relevance") or []
    if isinstance(compliance, str):
        compliance = [compliance]
    tweak = Tweak(
        id=str(_require(raw, "id", ctx)),
        title_de=str(_require(raw, "title_de", ctx)),
        category=_as_enum(TweakCategory, _require(raw, "category", ctx), "category", ctx),
        risk_tier=_as_enum(RiskTier, _require(raw, "risk_tier", ctx), "risk_tier", ctx),
        recommend=_as_enum(
            Recommendation, raw.get("recommend", "standard"), "recommend", ctx
        ),
        rationale_de=str(_require(raw, "rationale_de", ctx)),
        docs_url=str(_require(raw, "docs_url", ctx)),
        change=_parse_change(_require(raw, "change", ctx), ctx),
        verify=_parse_verify(raw.get("verify"), ctx),
        revert=_parse_revert(_require(raw, "revert", ctx), ctx),
        provenance=_parse_provenance(_require(raw, "provenance", ctx), ctx),
        requires_admin=bool(raw.get("requires_admin", True)),
        requires_reboot=bool(raw.get("requires_reboot", False)),
        edition_caveat=str(raw.get("edition_caveat", "")),
        compliance_relevance=tuple(str(x) for x in compliance),
        source_attribution=raw.get("source_attribution"),
    )
    _check_invariants(tweak, ctx)
    return tweak


def load_catalog_from_mapping(data: Any, *, source: str = "<mapping>") -> list[Tweak]:
    """Validiert ein bereits geparstes Katalog-Mapping zu:class:`Tweak`-Liste.

    Args:
        data: Geparstes YAML (Top-Level-Mapping mit catalog_version + tweaks).
        source: Quell-Bezeichner fuer Fehlermeldungen/Logs.

    Returns:
        Liste valider Tweaks (alle Invarianten erfuellt).

    Raises:
        CatalogError (+ Subklassen): bei jeder Invarianten-Verletzung.
    """
    if not isinstance(data, dict):
        raise CatalogError(f"{source}: Top-Level ist kein Mapping")
    if "catalog_version" not in data:
        raise CatalogError(f"{source}: 'catalog_version' fehlt")
    tweaks_raw = data.get("tweaks")
    if not isinstance(tweaks_raw, list) or not tweaks_raw:
        raise CatalogError(f"{source}: 'tweaks' fehlt oder ist leer")

    tweaks = [_build_tweak(raw, i) for i, raw in enumerate(tweaks_raw)]

    ids = [t.id for t in tweaks]
    duplicates = sorted({tid for tid in ids if ids.count(tid) > 1})
    if duplicates:
        raise CatalogError(f"{source}: doppelte Tweak-IDs: {duplicates}")

    log.info(
        "system_tuner-Katalog geladen: %d Tweaks (Version %s, %s)",
        len(tweaks),
        data.get("catalog_version"),
        source,
    )
    return tweaks


def load_catalog(path: Path) -> list[Tweak]:
    """Liest + validiert eine Katalog-YAML-Datei.

    Raises:
        CatalogError: Datei nicht lesbar, YAML ungueltig oder Invariante verletzt.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"Katalog nicht lesbar: {path} ({exc})") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CatalogError(f"Katalog-YAML ungueltig: {path} ({exc})") from exc
    return load_catalog_from_mapping(data, source=str(path))


def default_catalog_path() -> Path:
    """Pfad zur gebuendelten Katalog-Datei (PyInstaller-aware)."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "resources" / "system_tuner" / "catalog_v1.yaml"
    return (
        Path(__file__).resolve().parents[3]
        / "resources"
        / "system_tuner"
        / "catalog_v1.yaml"
    )


def default_signature_path() -> Path:
    """Pfad zur Katalog-Signatur (``catalog_v1.yaml.sig``)."""
    return Path(str(default_catalog_path()) + ".sig")


def verify_bundled_catalog() -> bool:
    """Fail-closed Ed25519-Pruefung des gebuendelten Katalogs (R3).

    Apply-Vorbedingung: ohne gueltige Signatur bleibt das Tool im Scan-Modus.
    Lazy data-Import (application→data erlaubt; haelt das Modul Qt-/Crypto-frei
    bis es gebraucht wird).
    """
    from tools.system_tuner.data.catalog_signature import (  # noqa: PLC0415
        verify_catalog,
    )

    return verify_catalog(default_catalog_path(), default_signature_path())


class YamlTweakCatalog(ITweakCatalog):
    """:class:`ITweakCatalog`-Adapter: laedt die gebuendelte Katalog-YAML."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or default_catalog_path()

    def load(self) -> list[Tweak]:
        """Laedt + validiert den Katalog von der Datei."""
        return load_catalog(self._path)
