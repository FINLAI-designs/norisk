"""Tests für die gemessene Audit-Vorbefüllung (core.scan_prefill).

Deckt ab:
* DTO-Immutability + ``has_measurements`` (core.scan_prefill.models).
* Port-Konformität des security_scoring-Adapters (ScanDataPort-Protocol).
* Adapter-Mapping SH-001/SH-003/SH-004/SH-010 + OS + Netzwerk inkl. Herkunft.
* Leitplanken: nicht-messbare Checks → kein Prefill; Non-Windows → leer;
  read-only Netzwerk-Zugriff (no-persist); strukturelle PII-Freiheit des DTO.
* Headless ``detect_os_info`` + lazy core-Resolver.
"""

from __future__ import annotations

import dataclasses
import platform
from datetime import UTC, datetime

import pytest

from core.scan_prefill import AuditPrefill, MeasuredField, ScanDataPort
from core.scan_prefill.resolver import create_scan_data_provider
from core.security.severity import Severity
from tools.security_scoring.application.scan_prefill_provider import (
    ScanPrefillProvider,
    create_default_scan_prefill_provider,
)
from tools.system_scanner.application.os_info_use_case import detect_os_info
from tools.system_scanner.domain.entities import HardeningCheck, OSInfo, ScanResult
from tools.system_scanner.domain.enums import OSPlatform, UnmeasuredReason

# Stabile Test-Zeit (DTO-Felder tragen ISO-Strings).
_TS = datetime(2026, 6, 27, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Test-Bausteine
# ---------------------------------------------------------------------------


def _check(
    check_id: str,
    *,
    passed: bool,
    measurable: bool = True,
    detail: str = "",
) -> HardeningCheck:
    """Baut einen HardeningCheck-Invariante beachtet)."""
    return HardeningCheck(
        check_id=check_id,
        label=check_id,
        passed=passed,
        severity=Severity.HIGH,
        detail=detail,
        measurable=measurable,
        unmeasured_reason=None if measurable else UnmeasuredReason.NEEDS_ADMIN,
    )


def _scan(*checks: HardeningCheck) -> ScanResult:
    """Baut ein ScanResult mit den gegebenen Hardening-Checks."""
    return ScanResult(
        scan_id="test-scan",
        timestamp=_TS,
        os_info=OSInfo(platform=OSPlatform.WINDOWS),
        hardening_checks=list(checks),
    )


def _full_scan() -> ScanResult:
    """ScanResult mit allen vier vom Adapter genutzten Checks (alle messbar)."""
    return _scan(
        _check("SH-001", passed=True, detail="Firewall in allen Profilen aktiv"),
        _check("SH-003", passed=False, detail="RDP erreichbar (3389 Listen)"),
        _check("SH-004", passed=True, detail="Update vor 2 Tagen"),
        _check("SH-010", passed=True, detail="BitLocker auf C: aktiv"),
    )


class _FakeNet:
    """Duck-typed NetworkService: zeichnet Aufrufe auf (Beweis: read-only)."""

    def __init__(self, scans: list[object]) -> None:
        self._scans = scans
        self.calls: list[tuple[str, int]] = []

    def lade_letzte_scans(self, limit: int = 10) -> list[object]:
        self.calls.append(("lade_letzte_scans", limit))
        return self._scans


def _fake_network_scan(offene: int = 3):
    """Minimaler NetworkScanResult-Stand-in (gestartet_am + anzahl_offene_ports)."""
    import types

    return types.SimpleNamespace(
        gestartet_am=_TS,
        anzahl_offene_ports=offene,
        hosts=[],
    )


def _provider_with_full_data() -> tuple[ScanPrefillProvider, _FakeNet]:
    """Adapter, der alle Quellen über injizierte Fakes bedient (Windows-Pfad)."""
    net = _FakeNet([_fake_network_scan(3)])
    provider = ScanPrefillProvider(
        scan_runner=_full_scan,
        network_service=net,
        os_info_fn=lambda: OSInfo(
            platform=OSPlatform.WINDOWS, name="Windows 11", version="10.0.26200"
        ),
    )
    return provider, net


# ---------------------------------------------------------------------------
# DTO-Modelle
# ---------------------------------------------------------------------------


class TestAuditPrefillModels:
    def test_measured_field_is_frozen(self) -> None:
        field = MeasuredField(
            value=True, check_id="SH-001", source_tool="system_scanner", measured_at=""
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            field.value = False  # type: ignore[misc]

    def test_audit_prefill_is_frozen(self) -> None:
        prefill = AuditPrefill()
        with pytest.raises(dataclasses.FrozenInstanceError):
            prefill.generated_at = "x"  # type: ignore[misc]

    def test_empty_prefill_has_no_measurements(self) -> None:
        assert AuditPrefill().has_measurements is False

    def test_one_field_sets_has_measurements(self) -> None:
        prefill = AuditPrefill(
            firewall_active=MeasuredField(
                value=True,
                check_id="SH-001",
                source_tool="system_scanner",
                measured_at="",
            )
        )
        assert prefill.has_measurements is True

    def test_dto_carries_no_pii_fields(self) -> None:
        """Strukturelle Garantie: keine Kunden-/PII-Felder im Vertrag."""
        prefill_fields = {f.name for f in dataclasses.fields(AuditPrefill)}
        assert prefill_fields == {
            "firewall_active",
            "remote_access_rdp",
            "disk_encryption_active",
            "patch_ok",
            "os_name",
            "open_ports_scanned",
            "generated_at",
        }
        measured_fields = {f.name for f in dataclasses.fields(MeasuredField)}
        assert measured_fields == {
            "value",
            "check_id",
            "source_tool",
            "measured_at",
            "detail",
        }


# ---------------------------------------------------------------------------
# Port-Konformität
# ---------------------------------------------------------------------------


class TestScanDataPortConformance:
    def test_provider_satisfies_scan_data_port(self) -> None:
        provider, _ = _provider_with_full_data()
        assert isinstance(provider, ScanDataPort)

    def test_default_factory_satisfies_port(self) -> None:
        provider = create_default_scan_prefill_provider()
        assert isinstance(provider, ScanDataPort)

    def test_resolver_returns_port(self) -> None:
        provider = create_scan_data_provider()
        # Factory ist lazy/trivial → in der Testumgebung immer eine Instanz.
        assert isinstance(provider, ScanDataPort)


# ---------------------------------------------------------------------------
# Adapter-Mapping + Herkunft
# ---------------------------------------------------------------------------


class TestScanPrefillProviderMapping:
    def test_all_fields_measured_with_provenance(self) -> None:
        provider, _net = _provider_with_full_data()
        prefill = provider.build_audit_prefill()

        assert prefill.has_measurements is True
        assert prefill.generated_at  # nicht leer

        # SH-001 Firewall: passed=True → aktiv
        assert prefill.firewall_active is not None
        assert prefill.firewall_active.value is True
        assert prefill.firewall_active.check_id == "SH-001"
        assert prefill.firewall_active.source_tool == "system_scanner"
        assert prefill.firewall_active.measured_at == _TS.isoformat()

        # SH-003 RDP: passed=False → exposed=True
        assert prefill.remote_access_rdp is not None
        assert prefill.remote_access_rdp.value is True
        assert prefill.remote_access_rdp.check_id == "SH-003"

        # SH-010 BitLocker: passed=True → encryption aktiv
        assert prefill.disk_encryption_active is not None
        assert prefill.disk_encryption_active.value is True
        assert prefill.disk_encryption_active.check_id == "SH-010"

        # SH-004 Patch: passed=True
        assert prefill.patch_ok is not None
        assert prefill.patch_ok.value is True
        assert prefill.patch_ok.check_id == "SH-004"

        # OS-Name (str-Wert)
        assert prefill.os_name is not None
        assert prefill.os_name.value == "Windows 11"
        assert prefill.os_name.check_id == "os_info"

        # Netzwerk-Präsenz
        assert prefill.open_ports_scanned is not None
        assert prefill.open_ports_scanned.value is True
        assert prefill.open_ports_scanned.check_id == "network_scanner"
        assert prefill.open_ports_scanned.measured_at == _TS.isoformat()

    def test_rdp_disabled_maps_to_not_exposed(self) -> None:
        provider = ScanPrefillProvider(
            scan_runner=lambda: _scan(_check("SH-003", passed=True)),
            network_service=_FakeNet([]),
            os_info_fn=lambda: OSInfo(platform=OSPlatform.UNKNOWN),
        )
        prefill = provider.build_audit_prefill()
        assert prefill.remote_access_rdp is not None
        assert prefill.remote_access_rdp.value is False  # RDP aus → nicht exponiert

    def test_unmeasurable_check_yields_no_prefill(self) -> None:
        provider = ScanPrefillProvider(
            scan_runner=lambda: _scan(
                _check("SH-001", passed=False, measurable=False)
            ),
            network_service=_FakeNet([]),
            os_info_fn=lambda: OSInfo(platform=OSPlatform.UNKNOWN),
        )
        prefill = provider.build_audit_prefill()
        # measurable=False → KEIN Prefill: nicht messbar ≠ Verstoß)
        assert prefill.firewall_active is None

    def test_missing_check_yields_no_prefill(self) -> None:
        provider = ScanPrefillProvider(
            scan_runner=lambda: _scan(),  # keine Checks
            network_service=_FakeNet([]),
            os_info_fn=lambda: OSInfo(platform=OSPlatform.UNKNOWN),
        )
        prefill = provider.build_audit_prefill()
        assert prefill.firewall_active is None
        assert prefill.patch_ok is None

    def test_non_windows_yields_empty_prefill(self) -> None:
        """Non-Windows: kein Scan, kein OS-Name, kein Netzwerk-Scan → leer."""
        provider = ScanPrefillProvider(
            scan_runner=lambda: None,  # run_hardening_baseline_scan → None
            network_service=_FakeNet([]),
            os_info_fn=lambda: OSInfo(platform=OSPlatform.UNKNOWN),  # name=""
        )
        prefill = provider.build_audit_prefill()
        assert prefill.has_measurements is False
        assert prefill.firewall_active is None
        assert prefill.os_name is None
        assert prefill.open_ports_scanned is None

    def test_no_network_scan_yields_no_prefill(self) -> None:
        provider = ScanPrefillProvider(
            scan_runner=lambda: None,
            network_service=_FakeNet([]),  # kein Scan vorhanden
            os_info_fn=lambda: OSInfo(platform=OSPlatform.UNKNOWN),
        )
        assert provider.build_audit_prefill().open_ports_scanned is None

    def test_network_access_is_read_only(self) -> None:
        """no-persist: der Adapter ruft NUR den lesenden lade_letzte_scans."""
        provider, net = _provider_with_full_data()
        provider.build_audit_prefill()
        assert net.calls == [("lade_letzte_scans", 1)]

    def test_scan_runner_failure_is_fail_soft(self) -> None:
        """Eine werfende Hardening-Quelle darf den Prefill nicht crashen."""

        def _boom() -> ScanResult:
            raise RuntimeError("Probe-Fehler")

        net = _FakeNet([_fake_network_scan(1)])
        provider = ScanPrefillProvider(
            scan_runner=_boom,
            network_service=net,
            os_info_fn=lambda: OSInfo(platform=OSPlatform.WINDOWS, name="Windows 11"),
        )
        prefill = provider.build_audit_prefill()
        # Hardening-Felder fehlen (fail-soft), OS + Netzwerk bleiben gesetzt.
        assert prefill.firewall_active is None
        assert prefill.os_name is not None
        assert prefill.open_ports_scanned is not None

    def test_os_info_failure_is_fail_soft(self) -> None:
        """Ein werfendes os_info_fn darf nur os_name auf None setzen."""

        def _boom_os() -> OSInfo:
            raise RuntimeError("OS-Fehler")

        provider = ScanPrefillProvider(
            scan_runner=_full_scan,
            network_service=_FakeNet([_fake_network_scan(1)]),
            os_info_fn=_boom_os,
        )
        prefill = provider.build_audit_prefill()
        assert prefill.os_name is None
        assert prefill.firewall_active is not None  # Rest bleibt gesetzt
        assert prefill.open_ports_scanned is not None

    def test_network_read_failure_is_fail_soft(self) -> None:
        """Ein werfendes lade_letzte_scans darf nur open_ports_scanned None lassen."""

        class _BoomNet:
            def lade_letzte_scans(self, limit: int = 10) -> list[object]:
                raise RuntimeError("DB-Fehler")

        provider = ScanPrefillProvider(
            scan_runner=_full_scan,
            network_service=_BoomNet(),
            os_info_fn=lambda: OSInfo(platform=OSPlatform.WINDOWS, name="Windows 11"),
        )
        prefill = provider.build_audit_prefill()
        assert prefill.open_ports_scanned is None
        assert prefill.firewall_active is not None  # Rest bleibt gesetzt
        assert prefill.os_name is not None


# ---------------------------------------------------------------------------
# Headless OS-Detection
# ---------------------------------------------------------------------------


class TestDetectOsInfo:
    def test_returns_os_info_for_current_platform(self) -> None:
        info = detect_os_info()
        assert isinstance(info, OSInfo)
        system = platform.system().lower()
        if system in {"windows", "darwin", "linux"}:
            # Auf einer unterstützten Plattform muss ein Name ermittelt werden.
            assert info.platform is not OSPlatform.UNKNOWN
            assert info.name
        else:
            assert info.platform is OSPlatform.UNKNOWN
