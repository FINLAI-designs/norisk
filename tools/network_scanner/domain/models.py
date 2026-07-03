"""
models — Domänenmodelle für den Netzwerk-Scanner.

Enthält alle Datenklassen und Enums für Port-Scans und Host-Analysen.
Keine Außen-Abhängigkeiten (nur Python-Stdlib).

 (RUN2-GUI): ``DiscoveredHost`` und ``NetworkDiscoveryResult`` von
``data/network_discovery.py`` hierher gezogen — sie sind reine Daten-
Modelle, gehoeren zur Domain und werden nun auch von der GUI ueber
den ``NetworkService`` konsumiert.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class PortState(Enum):
    """Zustand eines gescannten Ports."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class PortRisk(Enum):
    """Risikoklasse eines offenen Ports."""

    KRITISCH = "kritisch"
    HOCH = "hoch"
    MITTEL = "mittel"
    NIEDRIG = "niedrig"
    INFO = "info"


@dataclass
class PortInfo:
    """Informationen zu einem einzelnen gescannten Port.

    Attributes:
        port: Port-Nummer (1–65535).
        state: Ermittelter Port-Zustand.
        service: Erkannter Dienst-Name (z.B. "http", "ssh").
        banner: Optionales Service-Banner (max. 200 Zeichen).
        risk: Eingeschätzte Risikoklasse.
        hinweis: Optionaler Sicherheitshinweis.
    """

    port: int
    state: PortState
    service: str = ""
    banner: str = ""
    risk: PortRisk = PortRisk.INFO
    hinweis: str = ""


@dataclass
class HostInfo:
    """Scan-Ergebnis für einen einzelnen Host.

    Attributes:
        host: IP-Adresse oder Hostname.
        erreichbar: True wenn der Host auf den Scan reagiert hat.
        offene_ports: Liste der offenen Ports mit Details.
        betriebssystem: Erkanntes Betriebssystem (optional, nur mit nmap).
        scan_dauer_s: Scan-Dauer in Sekunden.
    """

    host: str
    erreichbar: bool
    offene_ports: list[PortInfo] = field(default_factory=list)
    betriebssystem: str = ""
    scan_dauer_s: float = 0.0

    @property
    def max_risiko(self) -> PortRisk:
        """Höchste Risikoklasse unter den offenen Ports.

        Returns:
            Höchste PortRisk oder INFO wenn keine offenen Ports.
        """
        reihenfolge = [
            PortRisk.KRITISCH,
            PortRisk.HOCH,
            PortRisk.MITTEL,
            PortRisk.NIEDRIG,
            PortRisk.INFO,
        ]
        for risk in reihenfolge:
            if any(p.risk == risk for p in self.offene_ports):
                return risk
        return PortRisk.INFO


@dataclass
class NetworkScanResult:
    """Gesamtergebnis eines Netzwerk-Scans.

    Attributes:
        ziel: Scan-Ziel (IP, Range oder Hostname).
        hosts: Liste der gescannten Hosts.
        gestartet_am: Startzeitpunkt des Scans (UTC).
        beendet_am: Endzeitpunkt des Scans (UTC).
        scanner_typ: Verwendeter Scanner ("socket" oder "nmap").
        scan_id: Eindeutiger Bezeichner für diesen Scan.
    """

    ziel: str
    hosts: list[HostInfo]
    gestartet_am: datetime
    beendet_am: datetime
    scanner_typ: str
    scan_id: str = ""

    @property
    def dauer_s(self) -> float:
        """Gesamtdauer des Scans in Sekunden.

        Returns:
            Dauer als float.
        """
        delta = self.beendet_am - self.gestartet_am
        return delta.total_seconds()

    @property
    def anzahl_offene_ports(self) -> int:
        """Gesamtanzahl offener Ports über alle Hosts.

        Returns:
            Summe aller offenen Ports.
        """
        return sum(len(h.offene_ports) for h in self.hosts)

    @property
    def erreichbare_hosts(self) -> list[HostInfo]:
        """Liste der erreichbaren Hosts.

        Returns:
            Gefilterte Host-Liste.
        """
        return [h for h in self.hosts if h.erreichbar]


@dataclass
class DiscoveredHost:
    """Gefundener Host im lokalen Netzwerk.

    aus ``data/network_discovery.py`` hierher gezogen — reines
    Daten-Objekt, gehoert zur Domain.

    Attributes:
        ip: IPv4-Adresse als String.
        hostname: Aufgelöster Hostname oder leerer String.
        mac_adresse: MAC-Adresse (aus ARP-Cache) oder leerer String.
        erreichbar: True wenn Host auf Ping oder ARP reagiert hat.
        quelle: "arp" | "ping" | "arp+ping"
    """

    ip: str
    hostname: str = ""
    mac_adresse: str = ""
    erreichbar: bool = True
    quelle: str = ""


@dataclass
class NetworkDiscoveryResult:
    """Ergebnis eines Host-Discovery-Durchlaufs.

    aus ``data/network_discovery.py`` hierher gezogen — reines
    Daten-Objekt, gehoert zur Domain.

    Attributes:
        subnetz: Gescanntes Subnetz (CIDR-Notation).
        hosts: Gefundene erreichbare Hosts.
        dauer_s: Scan-Dauer in Sekunden.
        gestartet_am: Startzeitpunkt (UTC).
        eigene_ip: IP-Adresse dieses Geräts.
        gateway: Standard-Gateway-IP.
    """

    subnetz: str
    hosts: list[DiscoveredHost] = field(default_factory=list)
    dauer_s: float = 0.0
    gestartet_am: datetime = field(default_factory=lambda: datetime.now(UTC))
    eigene_ip: str = ""
    gateway: str = ""
