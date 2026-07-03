"""
test_system_tuner_engine — Fail-closed Apply/Revert-Engine (Phase 2).

Alle gegen MockTweakProbe + InMemorySnapshotRepo (kein Windows):
Sign-off-Gate, Apply-Erfolg, Verify-Mismatch -> Auto-Revert, NEVER_DISABLE-
Recheck, Revert (restore_prior/irreversible), Revert ohne Snapshot, Dry-Run,
Audit-Aufrufe.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Any

from core.probes.hardening_probe import ProbeResult
from tools.system_tuner.application.catalog_loader import load_catalog_from_mapping
from tools.system_tuner.application.tweak_engine import TweakEngine
from tools.system_tuner.data.mock_tweak_probe import MockTweakProbe
from tools.system_tuner.data.snapshot_repository import InMemorySnapshotRepo
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
    RevertKind,
    RiskTier,
    ServiceStartMode,
    TweakCategory,
    TweakStatus,
)

_REG_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reg_tweak() -> Tweak:
    return load_catalog_from_mapping(
        {
            "catalog_version": "1.0",
            "tweaks": [
                {
                    "id": "TW-R",
                    "title_de": "Telemetrie",
                    "category": "telemetry",
                    "risk_tier": "T1_safe",
                    "recommend": "standard",
                    "rationale_de": "x",
                    "docs_url": "https://learn.microsoft.com/x",
                    "compliance_relevance": ["Unterstuetzt DSGVO Art. 32 (TOM)"],
                    "provenance": {"source": "MS"},
                    "change": {
                        "op": "registry_set",
                        "hive": "HKLM",
                        "key": _REG_KEY,
                        "value_name": "AllowTelemetry",
                        "value_type": "REG_DWORD",
                        "desired": 1,
                    },
                    "verify": {"expect_value": 1},
                    "revert": {"kind": "restore_prior"},
                }
            ],
        }
    )[0]


def _svc_tweak() -> Tweak:
    return load_catalog_from_mapping(
        {
            "catalog_version": "1.0",
            "tweaks": [
                {
                    "id": "TW-S",
                    "title_de": "Dienst",
                    "category": "services",
                    "risk_tier": "T2_caution",
                    "recommend": "standard",
                    "rationale_de": "x",
                    "docs_url": "https://learn.microsoft.com/x",
                    "compliance_relevance": ["Unterstuetzt DSGVO Art. 5 Abs. 1 lit. c"],
                    "provenance": {"source": "MS"},
                    "change": {
                        "op": "service_startmode",
                        "service_name": "DiagTrack",
                        "desired_start_mode": "manual",
                    },
                    "verify": {"expect_start_mode": "manual"},
                    "revert": {"kind": "restore_prior"},
                }
            ],
        }
    )[0]


def _never_disable_tweak() -> Tweak:
    """Hand-konstruiert (am Loader vorbei) — testet die Engine-Defense-in-Depth."""
    return Tweak(
        id="TW-ND",
        title_de="boese",
        category=TweakCategory.SERVICES,
        risk_tier=RiskTier.T2_CAUTION,
        recommend=Recommendation.STANDARD,
        rationale_de="x",
        docs_url="x",
        change=ChangeSpec(
            op=ChangeOp.SERVICE_STARTMODE,
            service_name="wuauserv",
            desired_start_mode=ServiceStartMode.DISABLED,
        ),
        verify=VerifySpec(expect_start_mode=ServiceStartMode.DISABLED),
        revert=RevertSpec(kind=RevertKind.RESTORE_PRIOR),
        provenance=Provenance(source="x"),
    )


class _Audit:
    def __init__(self) -> None:
        self.actions: list[tuple[str, Any, Any]] = []

    def log_action(self, action: str, details: Any = None, tool: Any = None) -> None:
        self.actions.append((action, details, tool))


class _NoStoreProbe(MockTweakProbe):
    """Write meldet success, speichert aber nicht -> Verify-Mismatch."""

    def write_registry_value(self, *args: Any, **kwargs: Any) -> ProbeResult:
        return ProbeResult(success=True)


def _engine(probe: MockTweakProbe, *, allow: bool = True, audit: Any = None) -> TweakEngine:
    return TweakEngine(probe, InMemorySnapshotRepo(), allow_apply=allow, audit=audit)


# ---------------------------------------------------------------------------
# Sign-off-Gate
# ---------------------------------------------------------------------------


class TestSignOffGate:
    def test_apply_blocked_without_signoff(self):
        audit = _Audit()
        engine = _engine(MockTweakProbe(), allow=False, audit=audit)
        result = engine.apply([_reg_tweak()])
        assert result.results[0].status is TweakStatus.BLOCKED
        assert any(a[0] == "TUNER_APPLY_BLOCKED" for a in audit.actions)

    def test_revert_blocked_without_signoff(self):
        engine = _engine(MockTweakProbe(), allow=False)
        assert engine.revert(_reg_tweak()).status is TweakStatus.BLOCKED


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


class TestApply:
    def test_registry_apply_success(self):
        probe = MockTweakProbe()
        engine = _engine(probe)
        result = engine.apply([_reg_tweak()])
        assert result.results[0].status is TweakStatus.SUCCESS
        assert result.applied == 1
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "1"

    def test_service_apply_success(self):
        probe = MockTweakProbe()
        probe.set_service("DiagTrack", ServiceStartMode.AUTOMATIC)
        engine = _engine(probe)
        result = engine.apply([_svc_tweak()])
        assert result.results[0].status is TweakStatus.SUCCESS
        assert probe.read_service_start_mode("DiagTrack") is ServiceStartMode.MANUAL

    def test_verify_mismatch_triggers_auto_revert(self):
        probe = _NoStoreProbe()
        engine = _engine(probe)
        result = engine.apply([_reg_tweak()])
        assert result.results[0].status is TweakStatus.FAILED_ROLLED_BACK
        # Wert wurde nie gesetzt -> Auto-Revert (delete) laesst ihn weiterhin fehlen
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") is None

    def test_write_failure_reported(self):
        probe = MockTweakProbe(fail_writes=True)
        engine = _engine(probe)
        assert engine.apply([_reg_tweak()]).results[0].status is TweakStatus.FAILED

    def test_non_windows_fails(self):
        engine = _engine(MockTweakProbe(available=False))
        assert engine.apply([_reg_tweak()]).results[0].status is TweakStatus.FAILED

    def test_audit_on_success(self):
        audit = _Audit()
        engine = _engine(MockTweakProbe(), audit=audit)
        engine.apply([_reg_tweak()])
        assert any(a[0] == "TUNER_APPLY" for a in audit.actions)


# ---------------------------------------------------------------------------
# NEVER_DISABLE Recheck (Defense-in-Depth)
# ---------------------------------------------------------------------------


class TestNeverDisableRecheck:
    def test_never_disable_blocked_in_engine(self):
        audit = _Audit()
        probe = MockTweakProbe()
        probe.set_service("wuauserv", ServiceStartMode.AUTOMATIC)
        engine = _engine(probe, audit=audit)
        result = engine.apply([_never_disable_tweak()])
        assert result.results[0].status is TweakStatus.BLOCKED
        assert result.blocked == 1
        # Dienst blieb unveraendert
        assert probe.read_service_start_mode("wuauserv") is ServiceStartMode.AUTOMATIC
        assert any(a[0] == "TUNER_NEVER_DISABLE_BLOCKED" for a in audit.actions)


# ---------------------------------------------------------------------------
# Revert
# ---------------------------------------------------------------------------


class TestRevert:
    def test_restore_prior_deletes_when_absent_before(self):
        probe = MockTweakProbe()
        engine = _engine(probe)
        tweak = _reg_tweak()
        engine.apply([tweak])
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "1"
        res = engine.revert(tweak)
        assert res.status is TweakStatus.SUCCESS
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") is None

    def test_restore_prior_restores_old_value(self):
        probe = MockTweakProbe()
        probe.set_registry_value("HKLM", _REG_KEY, "AllowTelemetry", "3")
        engine = _engine(probe)
        tweak = _reg_tweak()
        engine.apply([tweak])
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "1"
        engine.revert(tweak)
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "3"

    def test_revert_without_snapshot_refused(self):
        engine = _engine(MockTweakProbe())
        # Kein vorheriges apply -> kein Snapshot
        assert engine.revert(_reg_tweak()).status is TweakStatus.FAILED

    def test_service_revert_restores_mode(self):
        probe = MockTweakProbe()
        probe.set_service("DiagTrack", ServiceStartMode.AUTOMATIC)
        engine = _engine(probe)
        tweak = _svc_tweak()
        engine.apply([tweak])
        engine.revert(tweak)
        assert probe.read_service_start_mode("DiagTrack") is ServiceStartMode.AUTOMATIC

    def test_revert_all(self):
        probe = MockTweakProbe()
        probe.set_registry_value("HKLM", _REG_KEY, "AllowTelemetry", "3")
        engine = _engine(probe)
        tweak = _reg_tweak()
        engine.apply([tweak])
        result = engine.revert_all([tweak])
        assert result.results[0].status is TweakStatus.SUCCESS
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") == "3"


# ---------------------------------------------------------------------------
# Dry-Run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run_no_writes(self):
        probe = MockTweakProbe()
        engine = _engine(probe)
        results = engine.dry_run([_reg_tweak()])
        assert results[0].status is TweakStatus.DRY_RUN
        assert "→ 1" in results[0].detail
        # kein Write passiert
        assert probe.read_registry_value("HKLM", _REG_KEY, "AllowTelemetry") is None


# ---------------------------------------------------------------------------
# Irreversible
# ---------------------------------------------------------------------------


class TestIrreversible:
    def test_irreversible_revert(self):
        appx = Tweak(
            id="TW-APPX",
            title_de="x",
            category=TweakCategory.APPX,
            risk_tier=RiskTier.T3_ADVANCED,
            recommend=Recommendation.STRICT,
            rationale_de="x",
            docs_url="x",
            change=ChangeSpec(op=ChangeOp.APPX_REMOVE, package_family="X_8wekyb"),
            verify=VerifySpec(expect_absent=True),
            revert=RevertSpec(kind=RevertKind.IRREVERSIBLE),
            provenance=Provenance(source="x"),
        )
        engine = _engine(MockTweakProbe())
        assert engine.revert(appx).status is TweakStatus.IRREVERSIBLE

    def test_appx_apply_skipped(self):
        appx = Tweak(
            id="TW-APPX",
            title_de="x",
            category=TweakCategory.APPX,
            risk_tier=RiskTier.T3_ADVANCED,
            recommend=Recommendation.STRICT,
            rationale_de="x",
            docs_url="x",
            change=ChangeSpec(op=ChangeOp.APPX_REMOVE, package_family="X_8wekyb"),
            verify=VerifySpec(expect_absent=True),
            revert=RevertSpec(kind=RevertKind.IRREVERSIBLE),
            provenance=Provenance(source="x"),
        )
        assert _engine(MockTweakProbe()).apply([appx]).results[0].status is TweakStatus.SKIPPED
