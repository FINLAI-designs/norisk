"""
network_discovery — Host-Discovery via ARP + Ping-Sweep.

Erkennt erreichbare Hosts im lokalen Netz ohne aktiven Port-Scan.
Zwei Erkennungsmethoden werden kombiniert:
  1. ARP-Cache-Auswertung (arp -a / ip neigh)
  2. ICMP-Ping-Sweep über alle Adressen des Subnetzes

Hostname-Auflösung via socket.gethostbyaddr (bestes-Effort).
Parallele Ausführung via ThreadPoolExecutor.

Sicherheitsdesign:
  - Kein Schreiben in ARP-Cache, nur Lesen
  - subprocess mit fester Argument-Liste (kein Shell=True)
  - IP-Adressen werden via ipaddress-Modul validiert

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from core.logger import get_logger
from tools.network_scanner.domain.models import (
    DiscoveredHost,
    NetworkDiscoveryResult,
)

# Re-Export fuer Backward-Compat.
__all__ = ["DiscoveredHost", "NetworkDiscovery", "NetworkDiscoveryResult"]

_log = get_logger(__name__)

# Regex für MAC-Adressen (beide gängigen Trennzeichen)
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}")

# Maximale Parallelität für Ping-Sweep
_MAX_WORKERS = 50

# Ping-Timeout in Millisekunden (Windows) / Sekunden (Unix)
_PING_TIMEOUT_MS = 500


def _ist_scanbarer_host(ip_str: str, netz: ipaddress.IPv4Network) -> bool:
    """True, wenn ``ip_str`` ein echter, scanbarer Host im Subnetz ``netz`` ist.

    Filtert Pseudo-Hosts aus dem rohen ARP-Cache, die kein einzelnes Geraet sind
-F3): Multicast (224.0.0.0/4 + 239.0.0.0/8, z.B. 224.0.0.251,
    239.255.255.250), die Subnetz-Broadcast-Adresse (x.x.x.255) und die
    Netzadresse, sowie Cross-Subnet-Eintraege (z.B. 10.20.20.254 beim Scan eines
    192.168er-Netzes), die zwar im ARP-Cache stehen, aber nicht zum gescannten
    Subnetz gehoeren. Der Ping-Sweep iteriert ohnehin nur ueber ``netz.hosts``
    und ist damit sauber; nur der rohe ARP-Cache kann Pseudo-Hosts einschleusen.

    Args:
        ip_str: IP-Adresse als String (aus dem ARP-Cache).
        netz: Das gescannte Subnetz.

    Returns:
        True, wenn die Adresse ein regulaerer Host innerhalb des Subnetzes ist.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    if ip.is_multicast:
        return False
    if ip in (netz.network_address, netz.broadcast_address):
        return False
    return ip in netz


class NetworkDiscovery:
    """Erkennt erreichbare Hosts im lokalen Netzwerk.

    Kombiniert ARP-Cache-Auswertung und ICMP-Ping-Sweep.
    Kein aktiver Port-Scan — nur Erreichbarkeits-Test.

    Beispiel:
        nd = NetworkDiscovery
        eigene_ip, subnetz, gateway = nd.eigene_netzwerk_info
        result = nd.discover_hosts(subnetz)
    """

    def eigene_netzwerk_info(self) -> tuple[str, str, str]:
        """Ermittelt IP-Adresse, Subnetz und Gateway dieses Geräts.

        Verwendet den UDP-Socket-Trick: verbindet auf eine externe IP
        (ohne Pakete zu senden) und liest die lokale Interface-Adresse.
        Subnetz wird als /24 angenommen (typisch für LAN).
        Gateway wird als erste Adresse des Subnetzes angenommen.

        Returns:
            Tupel (eigene_ip, subnetz_cidr, gateway_ip).
            Bei Fehler ("", "", "").
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("8.8.8.8", 80))
                eigene_ip: str = sock.getsockname()[0]
            finally:
                sock.close()

            netz = ipaddress.IPv4Network(f"{eigene_ip}/24", strict=False)
            gateway = str(list(netz.hosts())[0])
            return eigene_ip, str(netz), gateway
        except OSError as exc:
            _log.warning("Netzwerk-Info nicht ermittelbar: %s", exc)
            return "", "", ""

    def discover_hosts(
        self,
        subnetz: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> NetworkDiscoveryResult:
        """Erkennt erreichbare Hosts im angegebenen Subnetz.

        Kombiniert ARP-Cache (schnell, keine neuen Pakete) mit Ping-Sweep
        (findet Hosts die nicht im ARP-Cache sind). Hostnamen werden
        für alle gefundenen Hosts aufgelöst.

        Args:
            subnetz: Netzwerk in CIDR-Notation (z.B. "192.168.1.0/24").
            progress_callback: Optionale Fortschritts-Funktion (aktuell, gesamt).

        Returns:
            NetworkDiscoveryResult mit allen gefundenen Hosts.
        """
        gestartet = datetime.now(UTC)
        t0_monotonic = __import__("time").monotonic()

        try:
            netz = ipaddress.IPv4Network(subnetz, strict=False)
        except ValueError as exc:
            _log.error("Ungültiges Subnetz '%s': %s", subnetz, exc)
            return NetworkDiscoveryResult(subnetz=subnetz)

        alle_ips = [str(h) for h in netz.hosts()]
        gesamt = len(alle_ips)

        # Schritt 1: ARP-Cache lesen (sofort, keine Netzwerk-Last)
        arp_hosts: dict[str, DiscoveredHost] = {}
        try:
            arp_hosts = self._arp_scan()
        except Exception as exc:  # noqa: BLE001
            _log.warning("ARP-Scan fehlgeschlagen: %s", exc)

        # F3: Pseudo-Hosts (Multicast/Broadcast/Cross-Subnet) aus dem rohen
        # ARP-Cache aussortieren — sie sind keine einzelnen Geraete und blaehen
        # die Host-Liste auf. Der Ping-Sweep (Schritt 2) iteriert ohnehin nur
        # ueber netz.hosts und bleibt damit sauber.
        arp_hosts = {
            ip: host
            for ip, host in arp_hosts.items()
            if _ist_scanbarer_host(ip, netz)
        }

        # Schritt 2: Ping-Sweep (parallel)
        gefunden: dict[str, DiscoveredHost] = dict(arp_hosts)
        fertig = 0

        def _ping_und_merge(ip: str) -> DiscoveredHost | None:
            """Pingt einen Host und gibt DiscoveredHost zurück oder None."""
            if ip in gefunden:
                # Bereits via ARP bekannt — Quelle ergänzen
                return None
            if self._ping_host(ip):
                return DiscoveredHost(ip=ip, quelle="ping")
            return None

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(_ping_und_merge, ip): ip for ip in alle_ips}
            for future in as_completed(futures):
                fertig += 1
                if progress_callback:
                    progress_callback(fertig, gesamt)
                result_host = future.result()
                if result_host is not None:
                    gefunden[result_host.ip] = result_host

        # Schritt 3: Hostnamen auflösen (parallel, bestes-Effort)
        def _resolve(host: DiscoveredHost) -> DiscoveredHost:
            host.hostname = self._resolve_hostname(host.ip)
            return host

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            resolved = list(pool.map(_resolve, gefunden.values()))

        dauer = __import__("time").monotonic() - t0_monotonic
        hosts_sortiert = sorted(resolved, key=lambda h: _ip_sort_key(h.ip))

        _log.info(
            "Discovery abgeschlossen: %d Hosts in %.1fs (Subnetz: %s)",
            len(hosts_sortiert),
            dauer,
            subnetz,
        )

        return NetworkDiscoveryResult(
            subnetz=subnetz,
            hosts=hosts_sortiert,
            dauer_s=dauer,
            gestartet_am=gestartet,
        )

    def _arp_scan(self) -> dict[str, DiscoveredHost]:
        """Liest und parst den ARP-Cache des Betriebssystems.

        Windows: arp -a
        Linux/macOS: ip neigh (oder arp -n als Fallback)

        Returns:
            Dict von IP → DiscoveredHost (nur erreichbare Einträge).
        """
        system = platform.system()
        if system == "Windows":
            return self._parse_arp_windows()
        return self._parse_arp_unix()

    def _parse_arp_windows(self) -> dict[str, DiscoveredHost]:
        """Parst `arp -a` auf Windows.

        Format: " 192.168.1.1 aa-bb-cc-dd-ee-ff dynamisch"

        Returns:
            Dict von IP → DiscoveredHost.
        """
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            _log.warning("arp -a fehlgeschlagen: %s", exc)
            return {}

        hosts: dict[str, DiscoveredHost] = {}
        for line in output.splitlines():
            line = line.strip()
            # Nur dynamische / statische Einträge (keine Header-Zeilen)
            mac_match = _MAC_RE.search(line)
            if not mac_match:
                continue
            parts = line.split()
            if not parts:
                continue
            ip_str = parts[0]
            try:
                ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            mac = mac_match.group(0).upper().replace("-", ":")
            hosts[ip_str] = DiscoveredHost(ip=ip_str, mac_adresse=mac, quelle="arp")
        return hosts

    def _parse_arp_unix(self) -> dict[str, DiscoveredHost]:
        """Parst `ip neigh` (Linux) oder `arp -n` (macOS/Fallback).

        ip neigh Format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        arp -n Format: "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"

        Returns:
            Dict von IP → DiscoveredHost.
        """
        # ip neigh bevorzugt (Linux)
        try:
            result = subprocess.run(
                ["ip", "neigh"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return self._parse_ip_neigh(result.stdout)
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Fallback: arp -n
        try:
            result = subprocess.run(
                ["arp", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return self._parse_arp_n(result.stdout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            _log.warning("arp -n fehlgeschlagen: %s", exc)
            return {}

    def _parse_ip_neigh(self, output: str) -> dict[str, DiscoveredHost]:
        """Parst die Ausgabe von `ip neigh`.

        Args:
            output: stdout von `ip neigh`.

        Returns:
            Dict von IP → DiscoveredHost.
        """
        hosts: dict[str, DiscoveredHost] = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_str = parts[0]
            try:
                ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            # FAILED/INCOMPLETE ignorieren
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            mac = ""
            mac_match = _MAC_RE.search(line)
            if mac_match:
                mac = mac_match.group(0).upper()
            hosts[ip_str] = DiscoveredHost(ip=ip_str, mac_adresse=mac, quelle="arp")
        return hosts

    def _parse_arp_n(self, output: str) -> dict[str, DiscoveredHost]:
        """Parst die Ausgabe von `arp -n`.

        Args:
            output: stdout von `arp -n`.

        Returns:
            Dict von IP → DiscoveredHost.
        """
        hosts: dict[str, DiscoveredHost] = {}
        for line in output.splitlines():
            mac_match = _MAC_RE.search(line)
            if not mac_match:
                continue
            parts = line.split()
            if not parts:
                continue
            ip_str = parts[0]
            try:
                ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            mac = mac_match.group(0).upper()
            hosts[ip_str] = DiscoveredHost(ip=ip_str, mac_adresse=mac, quelle="arp")
        return hosts

    def _ping_host(self, ip: str) -> bool:
        """Prüft ob ein Host via ICMP-Ping erreichbar ist.

        Verwendet minimalen Timeout und einzelnes Paket.
        Kein Shell=True — kein Risiko für Befehlsinjektion.

        Args:
            ip: Zu pingende IPv4-Adresse.

        Returns:
            True wenn der Host antwortet.
        """
        system = platform.system()
        if system == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(_PING_TIMEOUT_MS), ip]
        else:
            timeout_s = str(_PING_TIMEOUT_MS // 1000) or "1"
            cmd = ["ping", "-c", "1", "-W", timeout_s, ip]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=2,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _resolve_hostname(self, ip: str) -> str:
        """Versucht den Hostnamen einer IP aufzulösen.

        Args:
            ip: IPv4-Adresse als String.

        Returns:
            Hostname oder leerer String bei Fehler.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    """Sortier-Schlüssel für IPv4-Adressen.

    Args:
        ip: IPv4-Adresse als String.

    Returns:
        Tupel von Integer-Oktetten.
    """
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)
