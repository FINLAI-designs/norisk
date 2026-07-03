"""
tests/test_network_scanner.py — Unit-Tests für den Netzwerk-Scanner.

Prüft:
  - Domain-Modelle (PortState, PortRisk, HostInfo, NetworkScanResult)
  - Risiko-Analyzer (analysiere_port, analysiere_ports)
  - SocketScanner (gemockte Sockets)
  - NetworkService (Validierung, Backend-Auswahl)

Kein echtes Netzwerk-I/O — alles gemockt oder pure-function Tests.

Author: Patrick Riederich
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from tools.network_scanner.domain.analyzer import analysiere_port, analysiere_ports
from tools.network_scanner.domain.models import (
    HostInfo,
    NetworkScanResult,
    PortInfo,
    PortRisk,
    PortState,
)

# ===========================================================================
# Domain-Modelle
# ===========================================================================


class TestPortInfo:
    def test_default_risk_ist_info(self):
        p = PortInfo(port=12345, state=PortState.OPEN)
        assert p.risk == PortRisk.INFO

    def test_banner_und_hinweis_optional(self):
        p = PortInfo(port=80, state=PortState.OPEN)
        assert p.banner == ""
        assert p.hinweis == ""


class TestHostInfo:
    def test_max_risiko_ohne_ports_ist_info(self):
        host = HostInfo(host="127.0.0.1", erreichbar=True)
        assert host.max_risiko == PortRisk.INFO

    def test_max_risiko_kritisch_dominiert(self):
        host = HostInfo(
            host="10.0.0.1",
            erreichbar=True,
            offene_ports=[
                PortInfo(port=80, state=PortState.OPEN, risk=PortRisk.MITTEL),
                PortInfo(port=445, state=PortState.OPEN, risk=PortRisk.KRITISCH),
                PortInfo(port=443, state=PortState.OPEN, risk=PortRisk.NIEDRIG),
            ],
        )
        assert host.max_risiko == PortRisk.KRITISCH

    def test_max_risiko_hoch_ohne_kritisch(self):
        host = HostInfo(
            host="10.0.0.2",
            erreichbar=True,
            offene_ports=[
                PortInfo(port=22, state=PortState.OPEN, risk=PortRisk.HOCH),
                PortInfo(port=443, state=PortState.OPEN, risk=PortRisk.NIEDRIG),
            ],
        )
        assert host.max_risiko == PortRisk.HOCH


class TestNetworkScanResult:
    def _make_result(self, hosts: list[HostInfo]) -> NetworkScanResult:
        now = datetime.now(UTC)
        return NetworkScanResult(
            ziel="192.168.1.1",
            hosts=hosts,
            gestartet_am=now,
            beendet_am=now,
            scanner_typ="socket",
        )

    def test_anzahl_offene_ports_summiert(self):
        hosts = [
            HostInfo(
                host="192.168.1.1",
                erreichbar=True,
                offene_ports=[
                    PortInfo(port=80, state=PortState.OPEN),
                    PortInfo(port=443, state=PortState.OPEN),
                ],
            ),
            HostInfo(
                host="192.168.1.2",
                erreichbar=True,
                offene_ports=[PortInfo(port=22, state=PortState.OPEN)],
            ),
        ]
        result = self._make_result(hosts)
        assert result.anzahl_offene_ports == 3

    def test_erreichbare_hosts_filtert_korrekt(self):
        hosts = [
            HostInfo(host="192.168.1.1", erreichbar=True),
            HostInfo(host="192.168.1.2", erreichbar=False),
        ]
        result = self._make_result(hosts)
        assert len(result.erreichbare_hosts) == 1
        assert result.erreichbare_hosts[0].host == "192.168.1.1"


# ===========================================================================
# Analyzer
# ===========================================================================


class TestAnalysierePort:
    def test_bekannter_kritischer_port_445(self):
        p = PortInfo(port=445, state=PortState.OPEN)
        p = analysiere_port(p)
        assert p.risk == PortRisk.KRITISCH
        assert "SMB" in p.service or "SMB" in p.hinweis

    def test_bekannter_kritischer_port_3306(self):
        p = PortInfo(port=3306, state=PortState.OPEN)
        p = analysiere_port(p)
        assert p.risk == PortRisk.KRITISCH

    def test_bekannter_hoher_port_22(self):
        p = PortInfo(port=22, state=PortState.OPEN)
        p = analysiere_port(p)
        assert p.risk == PortRisk.HOCH

    def test_https_ist_niedrig(self):
        p = PortInfo(port=443, state=PortState.OPEN)
        p = analysiere_port(p)
        assert p.risk == PortRisk.NIEDRIG

    def test_geschlossener_port_unveraendert(self):
        p = PortInfo(port=445, state=PortState.CLOSED)
        p = analysiere_port(p)
        assert p.risk == PortRisk.INFO  # Kein Risiko wenn geschlossen

    def test_unbekannter_offener_port_ist_mittel(self):
        p = PortInfo(port=54321, state=PortState.OPEN)
        p = analysiere_port(p)
        assert p.risk == PortRisk.MITTEL
        assert "Unbekannter" in p.hinweis

    def test_vorhandener_service_bleibt_erhalten(self):
        p = PortInfo(port=22, state=PortState.OPEN, service="openssh 8.9")
        p = analysiere_port(p)
        # Vorhandener Service-Name darf nicht überschrieben werden
        assert p.service == "openssh 8.9"

    def test_service_wird_gesetzt_wenn_leer(self):
        p = PortInfo(port=22, state=PortState.OPEN, service="")
        p = analysiere_port(p)
        assert p.service == "SSH"


class TestAnalysierePorts:
    def test_mehrere_ports_werden_analysiert(self):
        ports = [
            PortInfo(port=80, state=PortState.OPEN),
            PortInfo(port=445, state=PortState.OPEN),
            PortInfo(port=443, state=PortState.OPEN),
        ]
        result = analysiere_ports(ports)
        assert len(result) == 3
        risiken = {p.port: p.risk for p in result}
        assert risiken[445] == PortRisk.KRITISCH
        assert risiken[443] == PortRisk.NIEDRIG
        assert risiken[80] == PortRisk.MITTEL

    def test_leere_liste(self):
        assert analysiere_ports([]) == []


# ===========================================================================
# NetworkService — Validierung
# ===========================================================================


class TestNetworkServiceValidierung:
    def _make_service(self):
        from tools.network_scanner.application.network_service import NetworkService
        from tools.network_scanner.domain.interfaces import (
            IScannerBackend,
            IScanRepository,
        )

        mock_backend = MagicMock(spec=IScannerBackend)
        mock_backend.ist_verfuegbar.return_value = True
        mock_backend.scan_host.return_value = HostInfo(
            host="127.0.0.1",
            erreichbar=True,
            offene_ports=[],
        )

        mock_repo = MagicMock(spec=IScanRepository)
        return NetworkService(scanner=mock_backend, repo=mock_repo)

    def test_leeres_ziel_wirft_valueerror(self):
        service = self._make_service()
        with pytest.raises(ValueError, match="Kein Scan-Ziel"):
            service.starte_scan(ziel="")

    def test_zu_langes_ziel_wirft_valueerror(self):
        service = self._make_service()
        with pytest.raises(ValueError, match="zu lang"):
            service.starte_scan(ziel="a" * 300)

    def test_sonderzeichen_im_ziel_wirft_valueerror(self):
        service = self._make_service()
        with pytest.raises(ValueError, match="unerlaubte Zeichen"):
            service.starte_scan(ziel="host; rm -rf /")

    def test_gueltige_ipv4_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(ziel="192.168.1.1", ports=[80])
        assert result.ziel == "192.168.1.1"

    def test_gueltige_ipv6_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(ziel="::1", ports=[80])
        assert result.ziel == "::1"

    def test_externer_hostname_blockt_default(self):
        service = self._make_service()
        # Hostnames werden ohne extern_erlaubt blockiert (DNS-Auflösung
        # vor User-Consent wäre selbst Netzwerk-Aufruf).
        with pytest.raises(ValueError, match="kein internes Ziel"):
            service.starte_scan(ziel="example.com", ports=[80])

    def test_externer_hostname_mit_extern_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(
            ziel="example.com", ports=[80], extern_erlaubt=True
        )
        assert result.ziel == "example.com"

    def test_externe_ip_blockt_default(self):
        service = self._make_service()
        # 8.8.8.8 ist Public-DNS, klare externe IP — §202c-Schranke
        with pytest.raises(ValueError, match="kein internes Ziel"):
            service.starte_scan(ziel="8.8.8.8", ports=[80])

    def test_externe_ip_mit_extern_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(
            ziel="8.8.8.8", ports=[80], extern_erlaubt=True
        )
        assert result.ziel == "8.8.8.8"

    def test_loopback_ipv6_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(ziel="::1", ports=[80])
        assert result.ziel == "::1"

    def test_link_local_erlaubt(self):
        service = self._make_service()
        result = service.starte_scan(ziel="169.254.1.1", ports=[80])
        assert result.ziel == "169.254.1.1"

    def test_nmap_nicht_verwendet_wenn_nicht_verfuegbar(self):
        from tools.network_scanner.application.network_service import NetworkService
        from tools.network_scanner.domain.interfaces import (
            IScannerBackend,
            IScanRepository,
        )

        socket_mock = MagicMock(spec=IScannerBackend)
        socket_mock.ist_verfuegbar.return_value = True
        socket_mock.scan_host.return_value = HostInfo(
            host="192.168.1.1", erreichbar=True
        )

        nmap_mock = MagicMock(spec=IScannerBackend)
        nmap_mock.ist_verfuegbar.return_value = False  # nmap nicht da

        repo_mock = MagicMock(spec=IScanRepository)

        service = NetworkService(
            scanner=socket_mock, repo=repo_mock, nmap_scanner=nmap_mock
        )
        service.starte_scan(ziel="192.168.1.1", ports=[80], nmap_bevorzugt=True)
        # Trotz nmap_bevorzugt=True muss socket_mock verwendet werden
        socket_mock.scan_host.assert_called_once()
        nmap_mock.scan_host.assert_not_called()


# ===========================================================================
# SocketScanner — Unit Tests (ohne echtes Netzwerk)
# ===========================================================================


class TestSocketScanner:
    def test_ist_verfuegbar_true(self):
        from tools.network_scanner.data.socket_scanner import SocketScanner

        scanner = SocketScanner()
        assert scanner.ist_verfuegbar() is True

    def test_offener_port_wird_erkannt(self):
        from tools.network_scanner.data.socket_scanner import SocketScanner

        scanner = SocketScanner(timeout=0.5)
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
            mock_conn.return_value = mock_sock

            result = scanner.scan_host("127.0.0.1", [22])
            offene = [p for p in result.offene_ports if p.state == PortState.OPEN]
            assert any(p.port == 22 for p in offene)

    def test_geschlossener_port_wird_gefiltert(self):
        from tools.network_scanner.data.socket_scanner import SocketScanner

        scanner = SocketScanner(timeout=0.1)
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            result = scanner.scan_host("127.0.0.1", [9999])
            assert len(result.offene_ports) == 0


class TestNmapPathResolution:
    """D1 (Patrick-Live-Test): nmap wird auch ausserhalb des PATH gefunden
    (Windows-Installation in Program Files ohne PATH-Eintrag)."""

    def test_path_lookup_gewinnt(self) -> None:
        from tools.network_scanner.data.nmap_scanner import NmapScanner

        with patch(
            "tools.network_scanner.data.nmap_scanner.shutil.which",
            return_value="/usr/bin/nmap",
        ):
            assert NmapScanner._resolve_nmap_path("nmap") == "/usr/bin/nmap"

    def test_windows_fallback_wenn_nicht_im_path(self) -> None:
        from pathlib import Path

        from tools.network_scanner.data.nmap_scanner import (
            _WINDOWS_NMAP_PATHS,
            NmapScanner,
        )

        with (
            patch(
                "tools.network_scanner.data.nmap_scanner.shutil.which",
                return_value=None,
            ),
            patch.object(
                Path,
                "is_file",
                autospec=True,
                side_effect=lambda self: str(self) == _WINDOWS_NMAP_PATHS[0],
            ),
        ):
            assert (
                NmapScanner._resolve_nmap_path("nmap") == _WINDOWS_NMAP_PATHS[0]
            )

    def test_none_wenn_nirgends_gefunden(self) -> None:
        from pathlib import Path

        from tools.network_scanner.data.nmap_scanner import NmapScanner

        with (
            patch(
                "tools.network_scanner.data.nmap_scanner.shutil.which",
                return_value=None,
            ),
            patch.object(Path, "is_file", autospec=True, return_value=False),
        ):
            assert NmapScanner._resolve_nmap_path("nmap") is None
            assert NmapScanner("nmap").ist_verfuegbar() is False
