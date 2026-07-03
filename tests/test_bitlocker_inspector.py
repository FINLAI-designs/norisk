"""
test_bitlocker_inspector.

Tests fuer den BitLocker-Inspector. Parser-Tests fuer beide Pfade
(PowerShell-JSON + manage-bde-Plaintext), Klassifikation der Recovery-
Key-Lokation, Overall-Status-Berechnung.
"""

from __future__ import annotations

from tools.system_scanner.data.bitlocker_inspector import (
    BitLockerOverallStatus,
    BitLockerVolumeProbe,
    BitLockerVolumeStatus,
    RecoveryKeyLocation,
    _classify_key_location,
    _compute_overall_status,
    _normalize_protector,
    _parse_manage_bde,
    _parse_powershell_json,
)

# ---------------------------------------------------------------------------
# _normalize_protector
# ---------------------------------------------------------------------------


class TestNormalizeProtector:
    def test_tpm(self) -> None:
        assert _normalize_protector("Tpm") == "tpm"
        assert _normalize_protector("TPM") == "tpm"

    def test_recovery_password(self) -> None:
        assert (
            _normalize_protector("RecoveryPassword") == "numerical_password"
        )
        assert (
            _normalize_protector("Recovery Password") == "numerical_password"
        )
        assert (
            _normalize_protector("NumericalPassword") == "numerical_password"
        )

    def test_ad_account(self) -> None:
        assert _normalize_protector("AdAccountOrGroup") == "ad_account"
        assert _normalize_protector("AD Account or Group") == "ad_account"

    def test_unknown_faellt_auf_unverfaelschten_lower(self) -> None:
        assert _normalize_protector("FooBar") == "foobar"

    def test_leer(self) -> None:
        assert _normalize_protector("") == "unknown"


# ---------------------------------------------------------------------------
# _classify_key_location
# ---------------------------------------------------------------------------


class TestClassifyKeyLocation:
    def test_leer_ist_none(self) -> None:
        assert _classify_key_location(frozenset()) is RecoveryKeyLocation.NONE

    def test_ad_hat_vorrang_vor_anderen(self) -> None:
        protectors = frozenset({"tpm", "numerical_password", "ad_account"})
        assert (
            _classify_key_location(protectors)
            is RecoveryKeyLocation.ACTIVE_DIRECTORY
        )

    def test_ms_account_vor_local(self) -> None:
        protectors = frozenset({"microsoft_account", "numerical_password"})
        assert (
            _classify_key_location(protectors)
            is RecoveryKeyLocation.MICROSOFT_ACCOUNT
        )

    def test_nur_local_numerical(self) -> None:
        assert (
            _classify_key_location(frozenset({"numerical_password"}))
            is RecoveryKeyLocation.LOCAL_NUMERICAL_ONLY
        )

    def test_nur_tpm(self) -> None:
        assert (
            _classify_key_location(frozenset({"tpm"}))
            is RecoveryKeyLocation.TPM_ONLY
        )

    def test_tpm_and_pin(self) -> None:
        assert (
            _classify_key_location(frozenset({"tpm_and_pin"}))
            is RecoveryKeyLocation.TPM_ONLY
        )

    def test_unbekannte_protectors(self) -> None:
        assert (
            _classify_key_location(frozenset({"weird_stuff"}))
            is RecoveryKeyLocation.UNKNOWN
        )


# ---------------------------------------------------------------------------
# BitLockerVolumeStatus.from_label
# ---------------------------------------------------------------------------


class TestVolumeStatusFromLabel:
    def test_full_encrypted(self) -> None:
        assert (
            BitLockerVolumeStatus.from_label("FullyEncrypted")
            is BitLockerVolumeStatus.FULLY_ENCRYPTED
        )

    def test_with_space(self) -> None:
        assert (
            BitLockerVolumeStatus.from_label("Fully Encrypted")
            is BitLockerVolumeStatus.FULLY_ENCRYPTED
        )

    def test_decrypted(self) -> None:
        assert (
            BitLockerVolumeStatus.from_label("FullyDecrypted")
            is BitLockerVolumeStatus.FULLY_DECRYPTED
        )

    def test_unbekannt(self) -> None:
        assert (
            BitLockerVolumeStatus.from_label("Zustand-Mars")
            is BitLockerVolumeStatus.UNKNOWN
        )


# ---------------------------------------------------------------------------
# _parse_powershell_json
# ---------------------------------------------------------------------------


_PS_OUTPUT_ARRAY = """
[
  {
    "MountPoint": "C:",
    "ProtectionStatus": "On",
    "VolumeStatus": "FullyEncrypted",
    "EncryptionMethod": "XtsAes256",
    "Protectors": ["Tpm", "RecoveryPassword"]
  },
  {
    "MountPoint": "D:",
    "ProtectionStatus": "Off",
    "VolumeStatus": "FullyDecrypted",
    "EncryptionMethod": "None",
    "Protectors": []
  }
]
"""

_PS_OUTPUT_SINGLE = """
{
  "MountPoint": "C:",
  "ProtectionStatus": "On",
  "VolumeStatus": "FullyEncrypted",
  "EncryptionMethod": "XtsAes256",
  "Protectors": "Tpm"
}
"""

_PS_OUTPUT_AD_BACKUP = """
[{
  "MountPoint": "C:",
  "ProtectionStatus": "On",
  "VolumeStatus": "FullyEncrypted",
  "EncryptionMethod": "XtsAes256",
  "Protectors": ["Tpm", "AdAccountOrGroup", "RecoveryPassword"]
}]
"""


class TestParsePowershellJson:
    def test_array_parsed(self) -> None:
        volumes = _parse_powershell_json(_PS_OUTPUT_ARRAY)
        assert len(volumes) == 2
        c_vol = next(v for v in volumes if v.mount_point == "C:")
        d_vol = next(v for v in volumes if v.mount_point == "D:")
        assert c_vol.protection_on is True
        assert d_vol.protection_on is False
        assert "tpm" in c_vol.protector_types
        assert "numerical_password" in c_vol.protector_types
        assert d_vol.key_location is RecoveryKeyLocation.NONE

    def test_single_dict_normalisiert_zu_array(self) -> None:
        volumes = _parse_powershell_json(_PS_OUTPUT_SINGLE)
        assert len(volumes) == 1
        assert volumes[0].protector_types == frozenset({"tpm"})
        assert volumes[0].key_location is RecoveryKeyLocation.TPM_ONLY

    def test_ad_backup_klassifiziert_active_directory(self) -> None:
        volumes = _parse_powershell_json(_PS_OUTPUT_AD_BACKUP)
        assert len(volumes) == 1
        assert volumes[0].key_location is RecoveryKeyLocation.ACTIVE_DIRECTORY

    def test_leerer_input(self) -> None:
        assert _parse_powershell_json("") == []
        assert _parse_powershell_json("   ") == []

    def test_invalid_json(self) -> None:
        assert _parse_powershell_json("{not-json") == []


# ---------------------------------------------------------------------------
# _parse_manage_bde
# ---------------------------------------------------------------------------


_MANAGE_BDE_OUTPUT = """
BitLocker Drive Encryption: Configuration Tool

Volume C: [OS]
[OS Volume]

    Size:                 500.00 GB
    BitLocker Version:    2.0
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 256
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Identification Field: None
    Key Protectors:
        TPM
        Numerical Password

Volume D: [Data]

    Size:                 1.00 TB
    Conversion Status:    Fully Decrypted
    Encryption Method:    None
    Protection Status:    Protection Off
    Key Protectors:
        None Found
"""


class TestParseManageBde:
    def test_zwei_volumes(self) -> None:
        volumes = _parse_manage_bde(_MANAGE_BDE_OUTPUT)
        mounts = sorted(v.mount_point for v in volumes)
        assert mounts == ["C:", "D:"]

    def test_protection_on_off(self) -> None:
        volumes = _parse_manage_bde(_MANAGE_BDE_OUTPUT)
        by_mount = {v.mount_point: v for v in volumes}
        assert by_mount["C:"].protection_on is True
        assert by_mount["D:"].protection_on is False

    def test_protectors_klassifiziert(self) -> None:
        volumes = _parse_manage_bde(_MANAGE_BDE_OUTPUT)
        c = next(v for v in volumes if v.mount_point == "C:")
        # C: hat TPM + Numerical Password → local-numerical-only.
        assert c.key_location is RecoveryKeyLocation.LOCAL_NUMERICAL_ONLY
        assert c.volume_status is BitLockerVolumeStatus.FULLY_ENCRYPTED

    def test_leere_eingabe(self) -> None:
        assert _parse_manage_bde("") == []


# ---------------------------------------------------------------------------
# _compute_overall_status
# ---------------------------------------------------------------------------


def _probe(
    mount: str,
    *,
    on: bool = True,
    location: RecoveryKeyLocation = RecoveryKeyLocation.ACTIVE_DIRECTORY,
) -> BitLockerVolumeProbe:
    return BitLockerVolumeProbe(
        mount_point=mount,
        protection_on=on,
        volume_status=BitLockerVolumeStatus.FULLY_ENCRYPTED
        if on
        else BitLockerVolumeStatus.FULLY_DECRYPTED,
        protector_types=frozenset({"tpm"} | ({"ad_account"} if on else set())),
        key_location=location,
    )


class TestOverallStatus:
    def test_leere_volumes_ist_unknown(self) -> None:
        status, msg = _compute_overall_status([])
        assert status is BitLockerOverallStatus.UNKNOWN
        assert msg

    def test_alle_protected_ist_fully(self) -> None:
        status, msg = _compute_overall_status([_probe("C:"), _probe("D:")])
        assert status is BitLockerOverallStatus.FULLY_PROTECTED
        assert "2" in msg

    def test_keine_protected_ist_no_volumes_protected(self) -> None:
        status, _ = _compute_overall_status(
            [_probe("C:", on=False), _probe("D:", on=False)]
        )
        assert status is BitLockerOverallStatus.NO_VOLUMES_PROTECTED

    def test_partial(self) -> None:
        status, msg = _compute_overall_status(
            [_probe("C:"), _probe("D:", on=False)]
        )
        assert status is BitLockerOverallStatus.PARTIALLY_PROTECTED
        assert "1/2" in msg
