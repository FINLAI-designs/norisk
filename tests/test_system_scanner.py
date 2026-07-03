"""
test_system_scanner — Unit-Tests für das system_scanner-Modul.

Testet:
  - Entities (Serialisierung/Deserialisierung)
  - Enums
  - Use Cases (mit gemockten Dependencies)
  - Platform-Scanner (mit gemockten Scannern)
  - Repository (mit In-Memory-Mock)
  - Windows/macOS/Linux-Scanner-Logik (mit Mocking — kein echter Systemzugriff)

Alle Tests laufen ohne echten DB- oder Systemzugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from tools.system_scanner.domain.entities import (
    InstalledSoftware,
    OSInfo,
    ScanResult,
    SecurityComponent,
)
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType, OSPlatform

#: Skip-Marker fuer Tests, die ``tools.system_scanner.data.windows_scanner``
#: importieren oder patchen — der Modul-Import zieht ``winreg`` (Windows-only
#: Stdlib), das auf Linux/macOS ``ModuleNotFoundError`` wirft. Linux-Smoke-CI
#: §7) braucht den Skip statt Errors.
_WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-only — winreg / windows_scanner-Modul",
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen / Fixtures
# ---------------------------------------------------------------------------


def _make_scan_result(
    platform: OSPlatform = OSPlatform.WINDOWS,
    n_software: int = 3,
    n_components: int = 2,
) -> ScanResult:
    """Erstellt ein Test-ScanResult.

    Args:
        platform: Zu verwendende Plattform.
        n_software: Anzahl Software-Einträge.
        n_components: Anzahl Sicherheitskomponenten.

    Returns:
        ScanResult für Tests.
    """
    os_info = OSInfo(
        platform=platform,
        name="Test OS",
        version="1.0",
        build="12345",
        architecture="AMD64",
    )
    software = [
        InstalledSoftware(
            name=f"App {i}",
            version=f"1.{i}.0",
            vendor="Vendor",
            is_security_relevant=(i == 0),
        )
        for i in range(n_software)
    ]
    components = [
        SecurityComponent(
            name=f"Component {i}",
            type=ComponentType.ANTIVIRUS,
            status=ComponentStatus.ACTIVE,
            version="1.0",
        )
        for i in range(n_components)
    ]
    return ScanResult(
        scan_id="test-uuid-1234",
        timestamp=datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC),
        os_info=os_info,
        software_list=software,
        security_components=components,
        scan_duration_s=1.5,
        warnings=["Test-Warnung"],
    )


# ---------------------------------------------------------------------------
# Enum-Tests
# ---------------------------------------------------------------------------


class TestEnums:
    """Tests für ComponentType, ComponentStatus, OSPlatform."""

    def test_component_type_values(self) -> None:
        """Alle ComponentType-Werte sind strings."""
        assert ComponentType.ANTIVIRUS.value == "antivirus"
        assert ComponentType.FIREWALL.value == "firewall"
        assert ComponentType.ENCRYPTION.value == "encryption"
        assert ComponentType.BROWSER.value == "browser"
        assert ComponentType.OS_UPDATE.value == "os_update"

    def test_component_status_values(self) -> None:
        """Alle ComponentStatus-Werte sind strings."""
        assert ComponentStatus.ACTIVE.value == "active"
        assert ComponentStatus.INACTIVE.value == "inactive"
        assert ComponentStatus.OUTDATED.value == "outdated"
        assert ComponentStatus.UNKNOWN.value == "unknown"
        assert ComponentStatus.RISK.value == "risk"

    def test_os_platform_values(self) -> None:
        """Alle OSPlatform-Werte sind strings."""
        assert OSPlatform.WINDOWS.value == "windows"
        assert OSPlatform.MACOS.value == "macos"
        assert OSPlatform.LINUX.value == "linux"
        assert OSPlatform.UNKNOWN.value == "unknown"

    def test_enum_from_string(self) -> None:
        """Enums können aus String-Werten erstellt werden."""
        assert ComponentType("antivirus") == ComponentType.ANTIVIRUS
        assert ComponentStatus("active") == ComponentStatus.ACTIVE
        assert OSPlatform("windows") == OSPlatform.WINDOWS


# ---------------------------------------------------------------------------
# Entity-Tests
# ---------------------------------------------------------------------------


class TestInstalledSoftware:
    """Tests für InstalledSoftware."""

    def test_to_dict_round_trip(self) -> None:
        """Serialisierung und Deserialisierung sind konsistent."""
        sw = InstalledSoftware(
            name="Test App",
            version="2.0.1",
            vendor="Vendor GmbH",
            install_date="2026-01-01",
            is_security_relevant=True,
        )
        d = sw.to_dict()
        sw2 = InstalledSoftware.from_dict(d)
        assert sw2.name == sw.name
        assert sw2.version == sw.version
        assert sw2.vendor == sw.vendor
        assert sw2.install_date == sw.install_date
        assert sw2.is_security_relevant == sw.is_security_relevant

    def test_from_dict_defaults(self) -> None:
        """from_dict mit minimalem Dict setzt Defaults."""
        sw = InstalledSoftware.from_dict({"name": "Minimal"})
        assert sw.name == "Minimal"
        assert sw.version == ""
        assert sw.is_security_relevant is False


class TestSecurityComponent:
    """Tests für SecurityComponent."""

    def test_to_dict_round_trip(self) -> None:
        """Serialisierung und Deserialisierung sind konsistent."""
        comp = SecurityComponent(
            name="Windows Defender",
            type=ComponentType.ANTIVIRUS,
            status=ComponentStatus.ACTIVE,
            version="1.2.3",
            last_updated="2026-04-01",
            detail="Aktiv und aktuell",
        )
        d = comp.to_dict()
        comp2 = SecurityComponent.from_dict(d)
        assert comp2.name == comp.name
        assert comp2.type == comp.type
        assert comp2.status == comp.status
        assert comp2.version == comp.version
        assert comp2.detail == comp.detail

    def test_from_dict_defaults(self) -> None:
        """from_dict mit Minimal-Dict setzt Defaults."""
        comp = SecurityComponent.from_dict(
            {"name": "Test", "type": "firewall", "status": "unknown"}
        )
        assert comp.type == ComponentType.FIREWALL
        assert comp.status == ComponentStatus.UNKNOWN


class TestOSInfo:
    """Tests für OSInfo."""

    def test_to_dict_round_trip(self) -> None:
        """Serialisierung und Deserialisierung sind konsistent."""
        from tools.system_scanner.domain.entities import OSInfo

        info = OSInfo(
            platform=OSPlatform.WINDOWS,
            name="Windows 11",
            version="23H2",
            build="22631",
            architecture="AMD64",
            last_update="2026-04-01",
            update_status=ComponentStatus.ACTIVE,
        )
        d = info.to_dict()
        info2 = OSInfo.from_dict(d)
        assert info2.platform == info.platform
        assert info2.name == info.name
        assert info2.update_status == info.update_status


class TestScanResult:
    """Tests für ScanResult."""

    def test_to_dict_round_trip(self) -> None:
        """Serialisierung und Deserialisierung sind konsistent."""
        result = _make_scan_result()
        d = result.to_dict()
        result2 = ScanResult.from_dict(d)
        assert result2.scan_id == result.scan_id
        assert result2.timestamp == result.timestamp
        assert len(result2.software_list) == len(result.software_list)
        assert len(result2.security_components) == len(result.security_components)
        assert result2.warnings == result.warnings

    def test_security_software_filter(self) -> None:
        """security_software gibt nur sicherheitsrelevante Software zurück."""
        result = _make_scan_result(n_software=3)
        sec_sw = result.security_software
        assert all(sw.is_security_relevant for sw in sec_sw)

    def test_to_dict_contains_required_keys(self) -> None:
        """to_dict enthält alle Pflichtfelder."""
        result = _make_scan_result()
        d = result.to_dict()
        required_keys = {
            "scan_id",
            "timestamp",
            "os_info",
            "software_list",
            "security_components",
            "scan_duration_s",
            "warnings",
        }
        assert required_keys.issubset(d.keys())


# ---------------------------------------------------------------------------
# Use-Case-Tests (mit Mock-Dependencies)
# ---------------------------------------------------------------------------


class TestScanUseCase:
    """Tests für ScanUseCase."""

    def test_execute_calls_scanner_and_saves(self) -> None:
        """execute ruft Scanner auf und speichert das Ergebnis."""
        from tools.system_scanner.application.scan_use_case import ScanUseCase

        expected_result = _make_scan_result()
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = expected_result
        mock_repo = MagicMock()

        use_case = ScanUseCase(scanner=mock_scanner, repository=mock_repo)
        result = use_case.execute()

        mock_scanner.scan.assert_called_once()
        mock_repo.save.assert_called_once_with(expected_result)
        assert result is expected_result

    def test_execute_continues_if_save_fails(self) -> None:
        """execute gibt Ergebnis zurück auch wenn Speichern fehlschlägt."""
        from tools.system_scanner.application.scan_use_case import ScanUseCase

        expected_result = _make_scan_result()
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = expected_result
        mock_repo = MagicMock()
        mock_repo.save.side_effect = OSError("DB nicht erreichbar")

        use_case = ScanUseCase(scanner=mock_scanner, repository=mock_repo)
        result = use_case.execute()

        assert result is expected_result

    def test_execute_raises_on_scanner_error(self) -> None:
        """execute propagiert RuntimeError vom Scanner."""
        from tools.system_scanner.application.scan_use_case import ScanUseCase

        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("Scanner-Fehler")
        mock_repo = MagicMock()

        use_case = ScanUseCase(scanner=mock_scanner, repository=mock_repo)
        with pytest.raises(RuntimeError, match="Scanner-Fehler"):
            use_case.execute()


class TestScanHistoryUseCase:
    """Tests für ScanHistoryUseCase."""

    def test_get_latest_returns_latest(self) -> None:
        """get_latest gibt das neueste Ergebnis zurück."""
        from tools.system_scanner.application.scan_history_use_case import (
            ScanHistoryUseCase,
        )

        expected = _make_scan_result()
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = expected

        use_case = ScanHistoryUseCase(repository=mock_repo)
        result = use_case.get_latest()

        mock_repo.load_latest.assert_called_once()
        assert result is expected

    def test_get_latest_returns_none_if_empty(self) -> None:
        """get_latest gibt None zurück wenn kein Scan vorhanden."""
        from tools.system_scanner.application.scan_history_use_case import (
            ScanHistoryUseCase,
        )

        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = None

        use_case = ScanHistoryUseCase(repository=mock_repo)
        assert use_case.get_latest() is None

    def test_get_history_delegates_to_repo(self) -> None:
        """get_history delegiert an das Repository."""
        from tools.system_scanner.application.scan_history_use_case import (
            ScanHistoryUseCase,
        )

        results = [_make_scan_result(), _make_scan_result()]
        mock_repo = MagicMock()
        mock_repo.load_history.return_value = results

        use_case = ScanHistoryUseCase(repository=mock_repo)
        history = use_case.get_history(limit=5)

        mock_repo.load_history.assert_called_once_with(limit=5)
        assert history == results


# ---------------------------------------------------------------------------
# Platform-Scanner-Tests
# ---------------------------------------------------------------------------


class TestPlatformScanner:
    """Tests für PlatformScanner (Plattform-Erkennung und Delegation)."""

    def test_detect_windows(self) -> None:
        """Erkennt Windows korrekt."""
        from tools.system_scanner.data.platform_scanner import _detect_platform

        with patch("platform.system", return_value="Windows"):
            platform_result = _detect_platform()
        assert platform_result == OSPlatform.WINDOWS

    def test_detect_macos(self) -> None:
        """Erkennt macOS korrekt."""
        from tools.system_scanner.data.platform_scanner import _detect_platform

        with patch("platform.system", return_value="Darwin"):
            platform_result = _detect_platform()
        assert platform_result == OSPlatform.MACOS

    def test_detect_linux(self) -> None:
        """Erkennt Linux korrekt."""
        from tools.system_scanner.data.platform_scanner import _detect_platform

        with patch("platform.system", return_value="Linux"):
            platform_result = _detect_platform()
        assert platform_result == OSPlatform.LINUX

    def test_detect_unknown(self) -> None:
        """Unbekanntes OS wird als UNKNOWN erkannt."""
        from tools.system_scanner.data.platform_scanner import _detect_platform

        with patch("platform.system", return_value="FreeBSD"):
            platform_result = _detect_platform()
        assert platform_result == OSPlatform.UNKNOWN

    @_WINDOWS_ONLY
    def test_platform_scanner_delegates_to_windows(self) -> None:
        """PlatformScanner delegiert an WindowsScanner auf Windows."""
        from tools.system_scanner.data.platform_scanner import PlatformScanner

        expected = _make_scan_result()
        mock_win_scanner = MagicMock()
        mock_win_scanner.scan.return_value = expected

        with (
            patch("platform.system", return_value="Windows"),
            patch(
                "tools.system_scanner.data.windows_scanner.WindowsScanner",
                return_value=mock_win_scanner,
            ),
        ):
            scanner = PlatformScanner()
            result = scanner.scan()

        assert result is expected

    def test_unsupported_platform_raises(self) -> None:
        """Nicht unterstützte Plattform wirft RuntimeError."""
        from tools.system_scanner.data.platform_scanner import _create_scanner

        with pytest.raises(RuntimeError, match="Nicht unterstützte Plattform"):
            _create_scanner(OSPlatform.UNKNOWN)


# ---------------------------------------------------------------------------
# Windows-Scanner-Hilfsfunktionen
# ---------------------------------------------------------------------------


@_WINDOWS_ONLY
class TestWindowsScannerHelpers:
    """Tests für Windows-Scanner-Hilfsfunktionen."""

    def test_parse_product_state_active(self) -> None:
        """ProductState 266240 = 0x41000 → aktiv (nibble 4 = 1)."""
        from tools.system_scanner.data.windows_scanner import _parse_product_state

        # 0x41000 = 266240 → nibble an Position 3: (266240 >> 12) & 0xF = 1 → ACTIVE
        result = _parse_product_state("266240")
        assert result == ComponentStatus.ACTIVE

    def test_parse_product_state_invalid(self) -> None:
        """Ungültiger ProductState → UNKNOWN."""
        from tools.system_scanner.data.windows_scanner import _parse_product_state

        result = _parse_product_state("INVALID")
        assert result == ComponentStatus.UNKNOWN

    def test_bitlocker_status_not_found(self) -> None:
        """manage-bde nicht gefunden → UNKNOWN."""
        from tools.system_scanner.data.windows_scanner import _get_bitlocker_status

        with patch("subprocess.run", side_effect=FileNotFoundError):
            status = _get_bitlocker_status()
        assert status == ComponentStatus.UNKNOWN

    def test_query_security_center_parses_multiple_products(self) -> None:
        """/S-1-Regression: mehrere AV-Produkte werden geparst (nicht leer)."""
        from tools.system_scanner.data import windows_scanner as ws

        fake = [
            {
                "displayName": "Windows Defender",
                "productState": 393472,
                "pathToSignedProductExe": "windowsdefender://",
            },
            {
                "displayName": "Bitdefender",
                "productState": 266240,
                "pathToSignedProductExe": "C:\\bd.exe",
            },
        ]
        with patch.object(ws, "_run_powershell_json", return_value=fake):
            result = ws._query_wmi_security_center("AntiVirusProduct")
        assert [r["displayName"] for r in result] == ["Windows Defender", "Bitdefender"]
        assert result[0]["productState"] == "393472"

    def test_query_security_center_parses_single_object(self) -> None:
        """ConvertTo-Json liefert bei genau 1 Treffer ein Objekt statt einer Liste."""
        from tools.system_scanner.data import windows_scanner as ws

        single = {
            "displayName": "Bitdefender",
            "productState": 266240,
            "pathToSignedProductExe": "",
        }
        with patch.object(ws, "_run_powershell_json", return_value=single):
            result = ws._query_wmi_security_center("AntiVirusProduct")
        assert len(result) == 1
        assert result[0]["displayName"] == "Bitdefender"

    def test_query_security_center_empty_on_failure(self) -> None:
        """Scheitert die Abfrage (None) → leere Liste, kein Crash."""
        from tools.system_scanner.data import windows_scanner as ws

        with patch.object(ws, "_run_powershell_json", return_value=None):
            assert ws._query_wmi_security_center("AntiVirusProduct") == []

    def test_firewall_fallback_active(self) -> None:
        """/S-2: mindestens ein aktives Profil → Windows-Firewall ACTIVE."""
        from tools.system_scanner.data import windows_scanner as ws

        profiles = [
            {"Name": "Domain", "Enabled": 1},
            {"Name": "Public", "Enabled": 0},
        ]
        with patch.object(ws, "_run_powershell_json", return_value=profiles):
            status, detail = ws._get_windows_firewall_fallback()
        assert status == ComponentStatus.ACTIVE
        assert "Domain" in detail

    def test_firewall_fallback_inactive(self) -> None:
        """Alle Profile deaktiviert → INACTIVE."""
        from tools.system_scanner.data import windows_scanner as ws

        profiles = [
            {"Name": "Domain", "Enabled": 0},
            {"Name": "Public", "Enabled": 0},
        ]
        with patch.object(ws, "_run_powershell_json", return_value=profiles):
            status, _ = ws._get_windows_firewall_fallback()
        assert status == ComponentStatus.INACTIVE

    def test_firewall_fallback_unknown_on_failure(self) -> None:
        """Abfrage scheitert (None) → UNKNOWN, kein Crash."""
        from tools.system_scanner.data import windows_scanner as ws

        with patch.object(ws, "_run_powershell_json", return_value=None):
            status, _ = ws._get_windows_firewall_fallback()
        assert status == ComponentStatus.UNKNOWN

    def test_firewall_fallback_single_object(self) -> None:
        """ConvertTo-Json-Einzelobjekt (genau 1 Profil) → korrekt behandelt."""
        from tools.system_scanner.data import windows_scanner as ws

        single = {"Name": "Domain", "Enabled": 1}
        with patch.object(ws, "_run_powershell_json", return_value=single):
            status, detail = ws._get_windows_firewall_fallback()
        assert status == ComponentStatus.ACTIVE
        assert "Domain" in detail

    def test_run_powershell_json_parses_valid(self) -> None:
        """Gültiges JSON aus stdout wird geparst."""
        from tools.system_scanner.data import windows_scanner as ws

        fake = MagicMock(stdout='[{"a": 1}, {"a": 2}]')
        with patch("subprocess.run", return_value=fake):
            assert ws._run_powershell_json("X") == [{"a": 1}, {"a": 2}]

    def test_run_powershell_json_empty_stdout(self) -> None:
        """Leeres stdout → None (kein Crash)."""
        from tools.system_scanner.data import windows_scanner as ws

        with patch("subprocess.run", return_value=MagicMock(stdout="")):
            assert ws._run_powershell_json("X") is None

    def test_run_powershell_json_invalid_json(self) -> None:
        """Nicht-JSON-stdout → None (ValueError gefangen, kein Crash)."""
        from tools.system_scanner.data import windows_scanner as ws

        with patch("subprocess.run", return_value=MagicMock(stdout="kein json{")):
            assert ws._run_powershell_json("X") is None

    def test_run_powershell_json_subprocess_error(self) -> None:
        """subprocess-Fehler (Timeout) → None, kein Crash."""
        from tools.system_scanner.data import windows_scanner as ws

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("powershell", 12),
        ):
            assert ws._run_powershell_json("X") is None


# ---------------------------------------------------------------------------
# Linux-Scanner-Hilfsfunktionen
# ---------------------------------------------------------------------------


class TestLinuxScannerHelpers:
    """Tests für Linux-Scanner-Hilfsfunktionen."""

    def test_read_os_release_parses_correctly(self) -> None:
        """_read_os_release parst /etc/os-release korrekt."""
        from tools.system_scanner.data.linux_scanner import _read_os_release

        fake_content = 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n'
        with patch("pathlib.Path.read_text", return_value=fake_content):
            result = _read_os_release()
        assert result["ID"] == "ubuntu"
        assert result["VERSION_ID"] == "22.04"
        assert result["PRETTY_NAME"] == "Ubuntu 22.04 LTS"

    def test_get_ufw_status_active(self) -> None:
        """ufw active → ACTIVE."""
        from tools.system_scanner.data.linux_scanner import _get_ufw_status

        with patch(
            "tools.system_scanner.data.linux_scanner._run",
            return_value="Status: active\n",
        ):
            status = _get_ufw_status()
        assert status == ComponentStatus.ACTIVE

    def test_get_ufw_status_inactive(self) -> None:
        """ufw inactive → INACTIVE."""
        from tools.system_scanner.data.linux_scanner import _get_ufw_status

        with patch(
            "tools.system_scanner.data.linux_scanner._run",
            return_value="Status: inactive\n",
        ):
            status = _get_ufw_status()
        assert status == ComponentStatus.INACTIVE

    def test_packages_dpkg_parse(self) -> None:
        """_get_packages_dpkg parst dpkg -l Ausgabe korrekt."""
        from tools.system_scanner.data.linux_scanner import _get_packages_dpkg

        fake_dpkg = (
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
            "||/ Name           Version        Architecture\n"
            "+++-==============-==============-============\n"
            "ii  firefox        124.0          amd64\n"
            "ii  vim            9.0            amd64\n"
        )
        with patch(
            "tools.system_scanner.data.linux_scanner._run", return_value=fake_dpkg
        ):
            packages = _get_packages_dpkg()
        assert len(packages) == 2
        firefox = next((p for p in packages if p.name == "firefox"), None)
        assert firefox is not None
        assert firefox.version == "124.0"
        assert (
            firefox.is_security_relevant is True
        )  # "firefox" ist in _SECURITY_KEYWORDS


# ---------------------------------------------------------------------------
# macOS-Scanner-Hilfsfunktionen
# ---------------------------------------------------------------------------


class TestMacOSScannerHelpers:
    """Tests für macOS-Scanner-Hilfsfunktionen."""

    def test_get_filevault_active(self) -> None:
        """FileVault on → ACTIVE."""
        from tools.system_scanner.data.macos_scanner import _get_filevault_status

        with patch(
            "tools.system_scanner.data.macos_scanner._run_subprocess",
            return_value="FileVault is On.\n",
        ):
            status = _get_filevault_status()
        assert status == ComponentStatus.ACTIVE

    def test_get_filevault_inactive(self) -> None:
        """FileVault off → INACTIVE."""
        from tools.system_scanner.data.macos_scanner import _get_filevault_status

        with patch(
            "tools.system_scanner.data.macos_scanner._run_subprocess",
            return_value="FileVault is Off.\n",
        ):
            status = _get_filevault_status()
        assert status == ComponentStatus.INACTIVE

    def test_get_firewall_enabled(self) -> None:
        """Firewall enabled → ACTIVE."""
        from tools.system_scanner.data.macos_scanner import _get_firewall_status

        with patch(
            "tools.system_scanner.data.macos_scanner._run_subprocess",
            return_value="Firewall is enabled.\n",
        ):
            status = _get_firewall_status()
        assert status == ComponentStatus.ACTIVE

    def test_get_gatekeeper_enabled(self) -> None:
        """Gatekeeper enabled → ACTIVE."""
        from tools.system_scanner.data.macos_scanner import _get_gatekeeper_status

        with patch(
            "tools.system_scanner.data.macos_scanner._run_subprocess",
            return_value="assessments enabled\n",
        ):
            status = _get_gatekeeper_status()
        assert status == ComponentStatus.ACTIVE


# ---------------------------------------------------------------------------
# Repository-Tests (mit Mock-EncryptedDatabase)
# ---------------------------------------------------------------------------


class TestScanRepository:
    """Tests für ScanRepository (mit gemockter EncryptedDatabase)."""

    def _make_mock_db(self) -> MagicMock:
        """Erstellt eine Mock-EncryptedDatabase mit Context-Manager-Support.

        Returns:
            Mock-Objekt.
        """
        mock_conn = MagicMock()
        mock_db = MagicMock()
        mock_db.connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_db.connection.return_value.__exit__ = MagicMock(return_value=False)
        return mock_db, mock_conn

    def test_save_calls_db(self) -> None:
        """save führt INSERT auf der DB aus."""
        from tools.system_scanner.data.scanner_repository import ScanRepository

        result = _make_scan_result()
        mock_db, mock_conn = self._make_mock_db()

        with patch(
            "tools.system_scanner.data.scanner_repository.EncryptedDatabase",
            return_value=mock_db,
        ):
            repo = ScanRepository()
            repo.save(result)

        assert mock_conn.execute.called

    def test_load_latest_returns_none_when_empty(self) -> None:
        """load_latest gibt None zurück wenn keine Scans vorhanden."""
        from tools.system_scanner.data.scanner_repository import ScanRepository

        mock_db, mock_conn = self._make_mock_db()
        mock_conn.execute.return_value.fetchall.return_value = []

        with patch(
            "tools.system_scanner.data.scanner_repository.EncryptedDatabase",
            return_value=mock_db,
        ):
            repo = ScanRepository()
            result = repo.load_latest()

        assert result is None

    def test_load_history_deserializes_json(self) -> None:
        """load_history deserialisiert gespeicherte JSON-Daten korrekt."""
        import json as _json

        from tools.system_scanner.data.scanner_repository import ScanRepository

        stored_result = _make_scan_result()
        json_blob = _json.dumps(stored_result.to_dict())
        mock_db, mock_conn = self._make_mock_db()
        mock_conn.execute.return_value.fetchall.return_value = [(json_blob,)]

        with patch(
            "tools.system_scanner.data.scanner_repository.EncryptedDatabase",
            return_value=mock_db,
        ):
            repo = ScanRepository()
            history = repo.load_history(limit=1)

        assert len(history) == 1
        assert history[0].scan_id == stored_result.scan_id


class TestDetectBrowsers:
    """Edge-Dedup in der Browser-Erkennung (Patrick-Live-Test 2026-06-25)."""

    @staticmethod
    def _sw(name: str, version: str = "1.0"):
        from tools.system_scanner.domain.entities import InstalledSoftware

        return InstalledSoftware(
            name=name,
            version=version,
            vendor="x",
            install_date="",
            is_security_relevant=False,
        )

    @_WINDOWS_ONLY
    def test_edge_nur_einmal_trotz_begleitkomponenten(self) -> None:
        from tools.system_scanner.data.windows_scanner import _detect_browsers

        software = [
            self._sw("Microsoft Edge", "120.0.1"),
            self._sw("Microsoft Edge Update", "1.3"),
            self._sw("Microsoft Edge WebView2 Runtime", "120.0.2"),
            self._sw("Google Chrome", "119.0"),
        ]
        browsers = _detect_browsers(software)
        names = [b.name for b in browsers]

        assert names.count("Microsoft Edge") == 1  # nicht 3x
        assert "Google Chrome" in names
        assert len(browsers) == 2
        # Edge-Version stammt vom Browser selbst, nicht Updater/WebView2.
        edge = next(b for b in browsers if b.name == "Microsoft Edge")
        assert edge.version == "120.0.1"
