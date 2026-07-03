"""
test_system_tuner_catalog — Katalog-Loader-Invarianten (system_tuner Phase 1a).

Pure Tests (kein Windows, keine I/O ausser Lesen der gebuendelten YAML).
Verifizieren das fail-closed Ladezeit-Gate: NEVER_DISABLE, Revert-Pflicht,
Clean-Room-Provenienz, R1/R2-Wording, Schema/Enum-Validierung.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.system_tuner.application.catalog_loader import (
    YamlTweakCatalog,
    default_catalog_path,
    load_catalog,
    load_catalog_from_mapping,
)
from tools.system_tuner.domain.enums import ChangeOp, RiskTier
from tools.system_tuner.domain.exceptions import (
    CatalogError,
    NeverDisableViolation,
    ProvenanceError,
    RevertMissingError,
)
from tools.system_tuner.domain.never_disable import (
    is_never_disable_service,
    is_never_touch_registry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_tweak(**overrides: Any) -> dict[str, Any]:
    """Minimaler, gueltiger Tweak als Mapping; Felder per kwargs ueberschreibbar."""
    base: dict[str, Any] = {
        "id": "TW-T-001",
        "title_de": "Test-Tweak",
        "category": "telemetry",
        "risk_tier": "T1_safe",
        "recommend": "standard",
        "rationale_de": "Begruendung.",
        "docs_url": "https://learn.microsoft.com/x",
        "compliance_relevance": ["Unterstuetzt DSGVO Art. 32 (TOM)"],
        "provenance": {"source": "Microsoft Learn", "derived_from": None, "license": None},
        "change": {
            "op": "registry_set",
            "hive": "HKLM",
            "key": "SOFTWARE\\Test\\Key",
            "value_name": "Value",
            "value_type": "REG_DWORD",
            "desired": 1,
        },
        "verify": {"expect_value": 1},
        "revert": {"kind": "restore_prior"},
    }
    base.update(overrides)
    return base


def _catalog(*tweaks: dict[str, Any]) -> dict[str, Any]:
    return {"catalog_version": "1.0", "tweaks": list(tweaks)}


def _load_one(**overrides: Any) -> Any:
    """Laedt genau einen (ueberschriebenen) Tweak; gibt ihn zurueck."""
    return load_catalog_from_mapping(_catalog(_valid_tweak(**overrides)))[0]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestValidLoad:
    def test_minimal_valid_tweak_loads(self):
        tweak = _load_one()
        assert tweak.id == "TW-T-001"
        assert tweak.risk_tier is RiskTier.T1_SAFE
        assert tweak.change.op is ChangeOp.REGISTRY_SET
        assert tweak.change.desired == 1

    def test_service_tweak_loads(self):
        tweak = _load_one(
            id="TW-S-1",
            risk_tier="T2_caution",
            category="services",
            change={
                "op": "service_startmode",
                "service_name": "DiagTrack",
                "desired_start_mode": "manual",
            },
            verify={"expect_start_mode": "manual"},
        )
        assert tweak.change.service_name == "DiagTrack"
        assert tweak.change.target_key == "service:DiagTrack"


# ---------------------------------------------------------------------------
# Schema / Enum
# ---------------------------------------------------------------------------


class TestSchema:
    def test_missing_required_field(self):
        bad = _valid_tweak()
        del bad["title_de"]
        with pytest.raises(CatalogError, match="title_de"):
            load_catalog_from_mapping(_catalog(bad))

    def test_invalid_risk_tier(self):
        with pytest.raises(CatalogError, match="risk_tier"):
            _load_one(risk_tier="T9_nope")

    def test_invalid_op(self):
        with pytest.raises(CatalogError, match="op"):
            _load_one(change={"op": "format_c_drive"})

    def test_missing_catalog_version(self):
        with pytest.raises(CatalogError, match="catalog_version"):
            load_catalog_from_mapping({"tweaks": [_valid_tweak()]})

    def test_empty_tweaks(self):
        with pytest.raises(CatalogError, match="tweaks"):
            load_catalog_from_mapping({"catalog_version": "1.0", "tweaks": []})

    def test_duplicate_ids(self):
        with pytest.raises(CatalogError, match="doppelte"):
            load_catalog_from_mapping(_catalog(_valid_tweak(), _valid_tweak()))


# ---------------------------------------------------------------------------
# T0 ist nicht katalogfaehig
# ---------------------------------------------------------------------------


class TestT0Blocked:
    def test_t0_blocked_rejected(self):
        with pytest.raises(CatalogError, match="T0_blocked"):
            _load_one(risk_tier="T0_blocked")


# ---------------------------------------------------------------------------
# NEVER_DISABLE
# ---------------------------------------------------------------------------


class TestNeverDisable:
    @pytest.mark.parametrize("svc", ["wuauserv", "WinDefend", "CryptSvc", "BITS"])
    def test_never_disable_service_rejected(self, svc):
        with pytest.raises(NeverDisableViolation, match="NEVER_DISABLE"):
            _load_one(
                risk_tier="T2_caution",
                category="services",
                change={
                    "op": "service_startmode",
                    "service_name": svc,
                    "desired_start_mode": "disabled",
                },
                verify={"expect_start_mode": "disabled"},
            )

    def test_never_touch_registry_defender_rejected(self):
        with pytest.raises(NeverDisableViolation, match="NEVER_DISABLE"):
            _load_one(
                change={
                    "op": "registry_set",
                    "hive": "HKLM",
                    "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    "value_name": "DisableAntiSpyware",
                    "value_type": "REG_DWORD",
                    "desired": 1,
                },
                verify={"expect_value": 1},
            )

    def test_allowed_service_passes(self):
        # DiagTrack ist NICHT auf der Sperrliste
        assert not is_never_disable_service("DiagTrack")
        assert is_never_disable_service("wuauserv")
        assert is_never_touch_registry(
            "HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware"
        )


# ---------------------------------------------------------------------------
# Revert-Pflicht
# ---------------------------------------------------------------------------


class TestRevert:
    def test_t1_irreversible_rejected(self):
        with pytest.raises(RevertMissingError):
            _load_one(revert={"kind": "irreversible"})

    def test_t2_irreversible_rejected(self):
        with pytest.raises(RevertMissingError):
            _load_one(risk_tier="T2_caution", revert={"kind": "irreversible"})

    def test_set_value_without_value_rejected(self):
        with pytest.raises(RevertMissingError):
            _load_one(revert={"kind": "set_value"})

    def test_t3_irreversible_allowed(self):
        tweak = _load_one(
            risk_tier="T3_advanced",
            category="appx",
            change={"op": "appx_remove", "package_family": "Microsoft.XboxApp_8wekyb3d8bbwe"},
            verify={"expect_absent": True},
            revert={"kind": "irreversible"},
        )
        assert tweak.change.op is ChangeOp.APPX_REMOVE


# ---------------------------------------------------------------------------
# Clean-Room / Provenienz (R3)
# ---------------------------------------------------------------------------


class TestProvenance:
    @pytest.mark.parametrize("lic", ["GPL-3.0", "AGPL-3.0", "gpl", "LGPL-2.1"])
    def test_gpl_license_rejected(self, lic):
        with pytest.raises(ProvenanceError, match="AGPL-frei"):
            _load_one(provenance={"source": "x", "license": lic})

    def test_mit_license_allowed(self):
        tweak = _load_one(
            provenance={
                "source": "MS Learn",
                "derived_from": "WindowsSpyBlocker (Technik)",
                "license": "MIT",
            }
        )
        assert tweak.provenance.license == "MIT"

    def test_missing_provenance_rejected(self):
        bad = _valid_tweak()
        del bad["provenance"]
        with pytest.raises(CatalogError, match="provenance"):
            load_catalog_from_mapping(_catalog(bad))


# ---------------------------------------------------------------------------
# R1/R2 Wording-Gate
# ---------------------------------------------------------------------------


class TestComplianceWording:
    @pytest.mark.parametrize(
        "claim",
        [
            "Erfuellt NIS2 Art. 21",
            "DSGVO Art. 30 Dokumentationspflicht",
            "Macht das System DSGVO-konform",
            "Fully compliant",
        ],
    )
    def test_overclaim_rejected(self, claim):
        with pytest.raises(CatalogError, match="verbotenes"):
            _load_one(compliance_relevance=[claim])

    def test_missing_compliance_rejected(self):
        with pytest.raises(CatalogError, match="compliance_relevance"):
            _load_one(compliance_relevance=[])


# ---------------------------------------------------------------------------
# Gebuendelter Real-Katalog
# ---------------------------------------------------------------------------


class TestOperandWhitelist:
    """A6 — Operanden-Whitelist (Defense-in-Depth, fail-closed zur Ladezeit)."""

    def test_invalid_hive_rejected(self):
        with pytest.raises(CatalogError, match="hive"):
            _load_one(
                change={
                    "op": "registry_set",
                    "hive": "HKEY_BOGUS",
                    "key": "Software\\X",
                    "value_name": "V",
                    "value_type": "REG_DWORD",
                    "desired": 1,
                }
            )

    def test_leading_backslash_key_rejected(self):
        with pytest.raises(CatalogError, match="key"):
            _load_one(
                change={
                    "op": "registry_set",
                    "hive": "HKLM",
                    "key": "\\Software\\X",
                    "value_name": "V",
                    "value_type": "REG_DWORD",
                    "desired": 1,
                }
            )

    def test_invalid_service_name_rejected(self):
        with pytest.raises(CatalogError, match="service_name"):
            _load_one(
                risk_tier="T2_caution",
                category="services",
                change={
                    "op": "service_startmode",
                    "service_name": "bad name & del",
                    "desired_start_mode": "manual",
                },
                verify={"expect_start_mode": "manual"},
            )


class TestBundledCatalog:
    def test_bundled_catalog_loads(self):
        tweaks = YamlTweakCatalog().load()
        assert len(tweaks) >= 6
        ids = {t.id for t in tweaks}
        assert "TW-TEL-001" in ids

    def test_default_path_exists(self):
        assert default_catalog_path().exists()

    def test_bundled_catalog_no_blocklisted_targets(self):
        # Kein einziger Tweak im Real-Katalog darf NEVER_DISABLE verletzen
        tweaks = load_catalog(default_catalog_path())
        for tweak in tweaks:
            change = tweak.change
            if change.op is ChangeOp.SERVICE_STARTMODE:
                assert not is_never_disable_service(change.service_name or "")
            if change.op is ChangeOp.REGISTRY_SET:
                assert not is_never_touch_registry(
                    change.hive or "", change.key or "", change.value_name or ""
                )

    def test_bundled_catalog_all_reversible_or_t3(self):
        tweaks = load_catalog(default_catalog_path())
        for tweak in tweaks:
            if tweak.risk_tier in (RiskTier.T1_SAFE, RiskTier.T2_CAUTION):
                assert tweak.revert.kind.value in {"restore_prior", "set_value"}
