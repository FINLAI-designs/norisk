"""
test_bitlocker_compliance.

Tests fuer die BitLocker-Compliance-Bewertung. Pure Bewertung pro Volume +
Aggregat-Status fuer den Banner.
"""

from __future__ import annotations

from tools.system_scanner.application.bitlocker_compliance import (
    BitLockerComplianceLevel,
    BitLockerComplianceService,
    _assess_volume,
)
from tools.system_scanner.data.bitlocker_inspector import (
    BitLockerOverallStatus,
    BitLockerReport,
    BitLockerVolumeProbe,
    BitLockerVolumeStatus,
    RecoveryKeyLocation,
)


def _probe(
    *,
    mount: str = "C:",
    on: bool = True,
    location: RecoveryKeyLocation = RecoveryKeyLocation.ACTIVE_DIRECTORY,
) -> BitLockerVolumeProbe:
    return BitLockerVolumeProbe(
        mount_point=mount,
        protection_on=on,
        volume_status=BitLockerVolumeStatus.FULLY_ENCRYPTED
        if on
        else BitLockerVolumeStatus.FULLY_DECRYPTED,
        protector_types=frozenset(),
        key_location=location,
    )


# ---------------------------------------------------------------------------
# _assess_volume — pure Bewertungs-Funktion
# ---------------------------------------------------------------------------


class TestAssessVolume:
    def test_off_ist_critical(self) -> None:
        assessment = _assess_volume(_probe(on=False))
        assert assessment.level is BitLockerComplianceLevel.CRITICAL
        assert "NICHT" in assessment.message

    def test_ad_ist_ok(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.ACTIVE_DIRECTORY)
        )
        assert assessment.level is BitLockerComplianceLevel.OK
        assert "Active Directory" in assessment.message

    def test_ms_account_ist_info(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.MICROSOFT_ACCOUNT)
        )
        assert assessment.level is BitLockerComplianceLevel.INFO
        assert "Microsoft" in assessment.message

    def test_local_numerical_ist_warning(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.LOCAL_NUMERICAL_ONLY)
        )
        assert assessment.level is BitLockerComplianceLevel.WARNING

    def test_tpm_only_ist_warning(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.TPM_ONLY)
        )
        assert assessment.level is BitLockerComplianceLevel.WARNING
        assert "TPM" in assessment.message

    def test_none_ist_critical(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.NONE)
        )
        assert assessment.level is BitLockerComplianceLevel.CRITICAL

    def test_unknown_ist_unknown(self) -> None:
        assessment = _assess_volume(
            _probe(location=RecoveryKeyLocation.UNKNOWN)
        )
        assert assessment.level is BitLockerComplianceLevel.UNKNOWN


# ---------------------------------------------------------------------------
# Compliance-Level-severity_order
# ---------------------------------------------------------------------------


class TestSeverityOrder:
    def test_critical_ist_schwerer_als_warning(self) -> None:
        assert (
            BitLockerComplianceLevel.CRITICAL.severity_order
            > BitLockerComplianceLevel.WARNING.severity_order
        )

    def test_warning_ist_schwerer_als_info(self) -> None:
        assert (
            BitLockerComplianceLevel.WARNING.severity_order
            > BitLockerComplianceLevel.INFO.severity_order
        )

    def test_max_funktioniert_via_severity_order(self) -> None:
        # Wir benutzen max im Service — pruefen dass die Severity-Reihenfolge passt.
        levels = [
            BitLockerComplianceLevel.OK,
            BitLockerComplianceLevel.WARNING,
            BitLockerComplianceLevel.INFO,
        ]
        worst = max(levels, key=lambda lv: lv.severity_order)
        assert worst is BitLockerComplianceLevel.WARNING


# ---------------------------------------------------------------------------
# Service — Gather mit injizierter Probe
# ---------------------------------------------------------------------------


class TestServiceGather:
    def test_non_windows_liefert_not_applicable(self) -> None:
        def fake_prober() -> BitLockerReport:
            return BitLockerReport(
                status=BitLockerOverallStatus.NOT_APPLICABLE,
                volumes=[],
                source="none",
                message="Nicht-Windows.",
            )

        info = BitLockerComplianceService(prober=fake_prober).gather()
        assert info.overall_level is BitLockerComplianceLevel.NOT_APPLICABLE
        assert info.needs_attention is False

    def test_unknown_status_liefert_unknown(self) -> None:
        def fake_prober() -> BitLockerReport:
            return BitLockerReport(
                status=BitLockerOverallStatus.UNKNOWN,
                volumes=[],
                source="none",
                message="Probe defekt.",
            )

        info = BitLockerComplianceService(prober=fake_prober).gather()
        assert info.overall_level is BitLockerComplianceLevel.UNKNOWN

    def test_alle_protected_mit_ad_ist_ok(self) -> None:
        report = BitLockerReport(
            status=BitLockerOverallStatus.FULLY_PROTECTED,
            volumes=[
                _probe(),
                _probe(mount="D:"),
            ],
            source="powershell",
            message="alle 2 ok",
        )
        info = BitLockerComplianceService(prober=lambda: report).gather()
        assert info.overall_level is BitLockerComplianceLevel.OK
        assert info.needs_attention is False

    def test_eine_volume_off_macht_overall_critical(self) -> None:
        report = BitLockerReport(
            status=BitLockerOverallStatus.PARTIALLY_PROTECTED,
            volumes=[
                _probe(),  # AD-OK
                _probe(mount="D:", on=False),
            ],
            source="powershell",
            message="1/2",
        )
        info = BitLockerComplianceService(prober=lambda: report).gather()
        assert info.overall_level is BitLockerComplianceLevel.CRITICAL
        assert info.needs_attention is True

    def test_tpm_only_macht_overall_warning(self) -> None:
        report = BitLockerReport(
            status=BitLockerOverallStatus.FULLY_PROTECTED,
            volumes=[
                _probe(location=RecoveryKeyLocation.TPM_ONLY),
            ],
            source="powershell",
            message="1/1",
        )
        info = BitLockerComplianceService(prober=lambda: report).gather()
        assert info.overall_level is BitLockerComplianceLevel.WARNING
        assert info.needs_attention is True

    def test_banner_text_nicht_leer(self) -> None:
        report = BitLockerReport(
            status=BitLockerOverallStatus.FULLY_PROTECTED,
            volumes=[_probe()],
            source="powershell",
            message="ok",
        )
        info = BitLockerComplianceService(prober=lambda: report).gather()
        assert info.banner_text  # nicht-leer

    def test_assessments_pro_volume(self) -> None:
        report = BitLockerReport(
            status=BitLockerOverallStatus.FULLY_PROTECTED,
            volumes=[
                _probe(),
                _probe(
                    mount="D:",
                    location=RecoveryKeyLocation.MICROSOFT_ACCOUNT,
                ),
            ],
            source="powershell",
            message="ok",
        )
        info = BitLockerComplianceService(prober=lambda: report).gather()
        assert len(info.assessments) == 2
        levels = {a.level for a in info.assessments}
        assert BitLockerComplianceLevel.OK in levels
        assert BitLockerComplianceLevel.INFO in levels
