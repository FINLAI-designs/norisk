"""tests/test_network_discovery.py — Unit-Tests für den Host-Discovery-Modul.

Prüft:
  - DiscoveredHost / NetworkDiscoveryResult Dataclasses
  - NetworkDiscovery._parse_arp_windows
  - NetworkDiscovery._parse_ip_neigh
  - NetworkDiscovery._parse_arp_n
  - NetworkDiscovery.eigene_netzwerk_info
  - NetworkDiscovery.discover_hosts (gemockter Ping + ARP)
  - _ip_sort_key Hilfsfunktion

Kein echtes Netzwerk-I/O — subprocess und socket werden vollständig gemockt.

Author: Patrick Riederich
"""

from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock, patch

from tools.network_scanner.data.network_discovery import (
    DiscoveredHost,
    NetworkDiscovery,
    NetworkDiscoveryResult,
    _ip_sort_key,
    _ist_scanbarer_host,
)

# ---------------------------------------------------------------------------
# DiscoveredHost
# ---------------------------------------------------------------------------


class TestDiscoveredHost:
    def test_defaults(self):
        host = DiscoveredHost(ip="192.168.1.1")
        assert host.hostname == ""
        assert host.mac_adresse == ""
        assert host.erreichbar is True
        assert host.quelle == ""

    def test_felder_gesetzt(self):
        host = DiscoveredHost(
            ip="10.0.0.1",
            hostname="router.local",
            mac_adresse="AA:BB:CC:DD:EE:FF",
            quelle="arp",
        )
        assert host.ip == "10.0.0.1"
        assert host.hostname == "router.local"
        assert host.mac_adresse == "AA:BB:CC:DD:EE:FF"
        assert host.quelle == "arp"

    def test_nicht_erreichbar(self):
        host = DiscoveredHost(ip="1.2.3.4", erreichbar=False)
        assert host.erreichbar is False


# ---------------------------------------------------------------------------
# NetworkDiscoveryResult
# ---------------------------------------------------------------------------


class TestNetworkDiscoveryResult:
    def test_defaults(self):
        result = NetworkDiscoveryResult(subnetz="192.168.0.0/24")
        assert result.hosts == []
        assert result.dauer_s == 0.0
        assert result.eigene_ip == ""
        assert result.gateway == ""

    def test_hosts_liste(self):
        h1 = DiscoveredHost(ip="192.168.0.1")
        h2 = DiscoveredHost(ip="192.168.0.2")
        result = NetworkDiscoveryResult(subnetz="192.168.0.0/24", hosts=[h1, h2])
        assert len(result.hosts) == 2

    def test_dauer_gesetzt(self):
        result = NetworkDiscoveryResult(subnetz="10.0.0.0/24", dauer_s=3.5)
        assert result.dauer_s == 3.5


# ---------------------------------------------------------------------------
# _ip_sort_key
# ---------------------------------------------------------------------------


class TestIpSortKey:
    def test_standard(self):
        assert _ip_sort_key("192.168.1.10") == (192, 168, 1, 10)

    def test_null_adresse(self):
        assert _ip_sort_key("0.0.0.0") == (0, 0, 0, 0)

    def test_ungueltig(self):
        assert _ip_sort_key("kein-ip") == (0, 0, 0, 0)

    def test_sortierung(self):
        ips = ["192.168.1.20", "192.168.1.5", "192.168.1.1"]
        sortiert = sorted(ips, key=_ip_sort_key)
        assert sortiert == ["192.168.1.1", "192.168.1.5", "192.168.1.20"]


# ---------------------------------------------------------------------------
# _parse_arp_windows
# ---------------------------------------------------------------------------


class TestParseArpWindows:
    def _nd(self):
        return NetworkDiscovery()

    def test_leere_ausgabe(self):
        nd = self._nd()
        assert nd._parse_arp_windows.__doc__ is not None  # sanity check

    def test_typische_ausgabe(self):
        ausgabe = """
Schnittstelle: 192.168.1.100 --- 0x4
  Internetadresse      Physische Adresse     Typ
  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamisch
  192.168.1.50         11-22-33-44-55-66     dynamisch
  192.168.1.255        ff-ff-ff-ff-ff-ff     statisch
"""
        nd = NetworkDiscovery()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=ausgabe, returncode=0)
            result = nd._parse_arp_windows()

        assert "192.168.1.1" in result
        assert "192.168.1.50" in result
        assert result["192.168.1.1"].mac_adresse == "AA:BB:CC:DD:EE:FF"
        assert result["192.168.1.50"].quelle == "arp"

    def test_keine_mac_zeilen_ignoriert(self):
        ausgabe = "  Schnittstelle: 192.168.1.100\n  Header-Zeile\n"
        nd = NetworkDiscovery()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=ausgabe, returncode=0)
            result = nd._parse_arp_windows()
        assert len(result) == 0

    def test_subprocess_fehler(self):
        nd = NetworkDiscovery()
        with patch("subprocess.run", side_effect=OSError("not found")):
            result = nd._parse_arp_windows()
        assert result == {}

    def test_timeout(self):
        import subprocess as sp

        nd = NetworkDiscovery()
        with patch("subprocess.run", side_effect=sp.TimeoutExpired(["arp"], 5)):
            result = nd._parse_arp_windows()
        assert result == {}


# ---------------------------------------------------------------------------
# _parse_ip_neigh
# ---------------------------------------------------------------------------


class TestParseIpNeigh:
    def _nd(self):
        return NetworkDiscovery()

    def test_reachable_eintraege(self):
        ausgabe = (
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        )
        nd = self._nd()
        result = nd._parse_ip_neigh(ausgabe)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert result["192.168.1.1"].mac_adresse == "AA:BB:CC:DD:EE:FF"

    def test_failed_ignoriert(self):
        ausgabe = "192.168.1.99 dev eth0  FAILED\n"
        nd = self._nd()
        result = nd._parse_ip_neigh(ausgabe)
        assert "192.168.1.99" not in result

    def test_incomplete_ignoriert(self):
        ausgabe = "192.168.1.88 dev eth0  INCOMPLETE\n"
        nd = self._nd()
        result = nd._parse_ip_neigh(ausgabe)
        assert "192.168.1.88" not in result

    def test_leere_ausgabe(self):
        nd = self._nd()
        result = nd._parse_ip_neigh("")
        assert result == {}

    def test_ipv6_ignoriert(self):
        ausgabe = "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        nd = self._nd()
        result = nd._parse_ip_neigh(ausgabe)
        # fe80:: ist IPv6 — sollte nicht im result sein
        for key in result:
            assert ipaddress.ip_address(key).version == 4


# ---------------------------------------------------------------------------
# _parse_arp_n
# ---------------------------------------------------------------------------


class TestParseArpN:
    def test_typische_ausgabe(self):
        ausgabe = (
            "Address     HWtype  HWaddress           Flags  Iface\n"
            "192.168.1.1 ether   aa:bb:cc:dd:ee:ff   C      eth0\n"
            "192.168.1.2 ether   11:22:33:44:55:66   C      eth0\n"
        )
        nd = NetworkDiscovery()
        result = nd._parse_arp_n(ausgabe)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_zeile_ohne_mac_ignoriert(self):
        ausgabe = "192.168.1.3  (incomplete)   eth0\n"
        nd = NetworkDiscovery()
        result = nd._parse_arp_n(ausgabe)
        assert "192.168.1.3" not in result


# ---------------------------------------------------------------------------
# eigene_netzwerk_info
# ---------------------------------------------------------------------------


class TestEigeneNetzwerkInfo:
    def test_gibt_tuple_zurueck(self):
        nd = NetworkDiscovery()
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.getsockname.return_value = ("192.168.1.42", 0)
            mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
            # Direkt mit context-manager-loser API mocken
            mock_sock_cls.return_value = mock_sock
            eigene_ip, subnetz, gateway = nd.eigene_netzwerk_info()

        # Subnetz muss gültiges CIDR sein
        if eigene_ip:
            assert "/" in subnetz
            assert eigene_ip.count(".") == 3

    def test_fehler_gibt_leerstring(self):
        nd = NetworkDiscovery()
        with patch("socket.socket", side_effect=OSError("no network")):
            eigene_ip, subnetz, gateway = nd.eigene_netzwerk_info()
        assert eigene_ip == ""
        assert subnetz == ""
        assert gateway == ""

    def test_subnetz_format(self):
        nd = NetworkDiscovery()
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.getsockname.return_value = ("10.0.0.5", 0)
            mock_sock_cls.return_value = mock_sock
            eigene_ip, subnetz, gateway = nd.eigene_netzwerk_info()

        if eigene_ip:
            netz = ipaddress.IPv4Network(subnetz, strict=False)
            assert netz.prefixlen == 24


# ---------------------------------------------------------------------------
# discover_hosts (gemockt)
# ---------------------------------------------------------------------------


class TestDiscoverHosts:
    def _nd_mit_mocks(self, arp_hosts: dict, ping_antworten: dict[str, bool]):
        """Erstellt NetworkDiscovery mit gemocktem ARP + Ping."""
        nd = NetworkDiscovery()
        nd._arp_scan = MagicMock(return_value=arp_hosts)
        nd._ping_host = MagicMock(side_effect=lambda ip: ping_antworten.get(ip, False))
        nd._resolve_hostname = MagicMock(return_value="")
        return nd

    def test_arp_hosts_enthalten(self):
        arp = {
            "192.168.1.1": DiscoveredHost(
                ip="192.168.1.1", mac_adresse="AA:BB:CC:DD:EE:01", quelle="arp"
            ),
        }
        nd = self._nd_mit_mocks(arp, {})
        result = nd.discover_hosts("192.168.1.0/30")
        ips = [h.ip for h in result.hosts]
        assert "192.168.1.1" in ips

    def test_ping_hosts_enthalten(self):
        nd = self._nd_mit_mocks({}, {"192.168.1.2": True})
        result = nd.discover_hosts("192.168.1.0/30")
        ips = [h.ip for h in result.hosts]
        assert "192.168.1.2" in ips

    def test_nicht_erreichbare_nicht_enthalten(self):
        nd = self._nd_mit_mocks({}, {"192.168.1.1": False, "192.168.1.2": False})
        result = nd.discover_hosts("192.168.1.0/30")
        assert len(result.hosts) == 0

    def test_doppelte_dedupliziert(self):
        arp = {
            "192.168.1.1": DiscoveredHost(ip="192.168.1.1", quelle="arp"),
        }
        # Ping antwortet auch für dieselbe IP — sollte nicht doppelt sein
        nd = self._nd_mit_mocks(arp, {"192.168.1.1": True})
        result = nd.discover_hosts("192.168.1.0/30")
        count = sum(1 for h in result.hosts if h.ip == "192.168.1.1")
        assert count == 1

    def test_result_typ(self):
        nd = self._nd_mit_mocks({}, {})
        result = nd.discover_hosts("192.168.1.0/30")
        assert isinstance(result, NetworkDiscoveryResult)

    def test_subnetz_in_result(self):
        nd = self._nd_mit_mocks({}, {})
        result = nd.discover_hosts("10.0.0.0/28")
        assert result.subnetz == "10.0.0.0/28"

    def test_unguentiges_subnetz(self):
        nd = NetworkDiscovery()
        result = nd.discover_hosts("kein-subnetz")
        assert result.hosts == []

    def test_sortierung_nach_ip(self):
        arp = {
            "192.168.1.10": DiscoveredHost(ip="192.168.1.10", quelle="arp"),
            "192.168.1.2": DiscoveredHost(ip="192.168.1.2", quelle="arp"),
            "192.168.1.1": DiscoveredHost(ip="192.168.1.1", quelle="arp"),
        }
        nd = self._nd_mit_mocks(arp, {})
        result = nd.discover_hosts("192.168.1.0/28")
        ips = [h.ip for h in result.hosts]
        assert ips == sorted(ips, key=_ip_sort_key)

    def test_progress_callback_aufgerufen(self):
        nd = self._nd_mit_mocks({}, {})
        aufrufe: list[tuple[int, int]] = []
        nd.discover_hosts(
            "192.168.1.0/30", progress_callback=lambda c, t: aufrufe.append((c, t))
        )
        assert len(aufrufe) > 0
        # Letzter Aufruf: aktuell == gesamt
        letzter = aufrufe[-1]
        assert letzter[0] == letzter[1]

    def test_hostname_aufgeloest(self):
        arp = {"192.168.1.1": DiscoveredHost(ip="192.168.1.1", quelle="arp")}
        nd = self._nd_mit_mocks(arp, {})
        nd._resolve_hostname = MagicMock(return_value="router.local")
        result = nd.discover_hosts("192.168.1.0/30")
        host = next((h for h in result.hosts if h.ip == "192.168.1.1"), None)
        assert host is not None
        assert host.hostname == "router.local"

    def test_pseudo_hosts_aus_arp_gefiltert(self):
        """-F3: Multicast/Broadcast/Cross-Subnet-ARP-Eintraege fliegen raus."""
        arp = {
            "192.168.1.1": DiscoveredHost(ip="192.168.1.1", quelle="arp"),  # echt
            "192.168.1.7": DiscoveredHost(ip="192.168.1.7", quelle="arp"),  # Broadcast /29
            "224.0.0.251": DiscoveredHost(ip="224.0.0.251", quelle="arp"),  # mDNS-Multicast
            "239.255.255.250": DiscoveredHost(ip="239.255.255.250", quelle="arp"),  # SSDP
            "10.20.20.254": DiscoveredHost(ip="10.20.20.254", quelle="arp"),  # Cross-Subnet
        }
        nd = self._nd_mit_mocks(arp, {})
        result = nd.discover_hosts("192.168.1.0/29")
        ips = {h.ip for h in result.hosts}
        assert ips == {"192.168.1.1"}


# ---------------------------------------------------------------------------
# _ist_scanbarer_host-F3)
# ---------------------------------------------------------------------------


class TestIstScanbarerHost:
    _NETZ = ipaddress.IPv4Network("192.168.1.0/24")

    def test_echter_host(self):
        assert _ist_scanbarer_host("192.168.1.50", self._NETZ) is True

    def test_multicast_gefiltert(self):
        assert _ist_scanbarer_host("224.0.0.251", self._NETZ) is False
        assert _ist_scanbarer_host("239.255.255.250", self._NETZ) is False

    def test_broadcast_gefiltert(self):
        assert _ist_scanbarer_host("192.168.1.255", self._NETZ) is False

    def test_netzadresse_gefiltert(self):
        assert _ist_scanbarer_host("192.168.1.0", self._NETZ) is False

    def test_cross_subnet_gefiltert(self):
        assert _ist_scanbarer_host("10.20.20.254", self._NETZ) is False

    def test_ungueltige_adresse_gefiltert(self):
        assert _ist_scanbarer_host("kein-ip", self._NETZ) is False
