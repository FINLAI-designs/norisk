"""
analyzer — Port-Risiko-Analyse für den Netzwerk-Scanner.

Bewertet offene Ports anhand einer bekannten Risikoliste und
erzeugt Sicherheitshinweise. Keine Außen-Abhängigkeiten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.network_scanner.domain.models import PortInfo, PortRisk

# Port → (Risikoklasse, Dienst-Name, Hinweis)
# Quellen: NIST, CIS Benchmarks, SANS Top 20
HIGH_RISK_PORTS: dict[int, tuple[PortRisk, str, str]] = {
    # Kritisch: Dienste mit direktem Remote-Exploit-Potenzial
    21: (
        PortRisk.KRITISCH,
        "FTP",
        "Unverschlüsselter Dateitransfer — deaktivieren oder durch SFTP ersetzen",
    ),
    23: (PortRisk.KRITISCH, "Telnet", "Klartext-Protokoll — sofort durch SSH ersetzen"),
    69: (PortRisk.KRITISCH, "TFTP", "Kein Auth. — nur in isolierten Netzen erlaubt"),
    135: (
        PortRisk.KRITISCH,
        "RPC/DCOM",
        "Windows-RPC — häufig ausgenutzt, extern blockieren",
    ),
    139: (PortRisk.KRITISCH, "NetBIOS", "Veraltet — extern blockieren"),
    445: (
        PortRisk.KRITISCH,
        "SMB",
        "EternalBlue-Ziel — extern blockieren, Patching prüfen",
    ),
    1433: (PortRisk.KRITISCH, "MSSQL", "Datenbank-Port — niemals extern zugänglich"),
    1521: (
        PortRisk.KRITISCH,
        "Oracle DB",
        "Datenbank-Port — niemals extern zugänglich",
    ),
    3306: (
        PortRisk.KRITISCH,
        "MySQL/MariaDB",
        "Datenbank-Port — niemals extern zugänglich",
    ),
    3389: (
        PortRisk.KRITISCH,
        "RDP",
        "BlueKeep-Ziel — Brute-Force-Risiko, VPN vorschalten",
    ),
    5432: (
        PortRisk.KRITISCH,
        "PostgreSQL",
        "Datenbank-Port — niemals extern zugänglich",
    ),
    5900: (
        PortRisk.KRITISCH,
        "VNC",
        "Schwache Auth. — VPN vorschalten oder deaktivieren",
    ),
    6379: (PortRisk.KRITISCH, "Redis", "Oft ohne Auth. — niemals extern zugänglich"),
    27017: (PortRisk.KRITISCH, "MongoDB", "Oft ohne Auth. — niemals extern zugänglich"),
    # Hoch: Dienste mit erhöhtem Risiko
    22: (
        PortRisk.HOCH,
        "SSH",
        "Nur Schlüssel-Auth., kein Root-Login, Fail2Ban empfohlen",
    ),
    25: (PortRisk.HOCH, "SMTP", "Mail-Relay — Open Relay prüfen"),
    110: (PortRisk.HOCH, "POP3", "Unverschlüsselt — durch POP3S ersetzen"),
    143: (PortRisk.HOCH, "IMAP", "Unverschlüsselt — durch IMAPS ersetzen"),
    512: (PortRisk.HOCH, "rexec", "Veraltet, unsicher — deaktivieren"),
    513: (PortRisk.HOCH, "rlogin", "Veraltet, unsicher — deaktivieren"),
    514: (
        PortRisk.HOCH,
        "rsh/syslog",
        "Veraltet — deaktivieren oder durch rsyslog/TLS ersetzen",
    ),
    2049: (PortRisk.HOCH, "NFS", "Dateisystem-Freigabe — Zugriffsrechte prüfen"),
    4444: (
        PortRisk.HOCH,
        "Backdoor/Metasploit",
        "Standard-Meterpreter-Port — sofort untersuchen",
    ),
    8080: (PortRisk.HOCH, "HTTP-Alt", "HTTP-Proxy/Dev-Server — TLS prüfen"),
    8443: (PortRisk.HOCH, "HTTPS-Alt", "Alternativer HTTPS-Port — Zertifikat prüfen"),
    # Mittel: Dienste die konfigurationsabhängig riskant sind
    53: (
        PortRisk.MITTEL,
        "DNS",
        "Offener Resolver prüfen — Zone-Transfer deaktivieren",
    ),
    80: (PortRisk.MITTEL, "HTTP", "Unverschlüsselt — Redirect zu HTTPS einrichten"),
    111: (PortRisk.MITTEL, "RPC Portmapper", "RPC-Dienste inventarisieren"),
    161: (PortRisk.MITTEL, "SNMP", "Community-String prüfen — SNMPv3 verwenden"),
    389: (PortRisk.MITTEL, "LDAP", "Unverschlüsselt — LDAPS bevorzugen"),
    2181: (
        PortRisk.MITTEL,
        "ZooKeeper",
        "Cluster-Koordination — nicht extern erreichbar",
    ),
    # Niedrig / Info: Standard-Dienste
    443: (PortRisk.NIEDRIG, "HTTPS", "TLS-Konfiguration und Zertifikat prüfen"),
    465: (PortRisk.NIEDRIG, "SMTPS", "TLS-Konfiguration prüfen"),
    587: (PortRisk.NIEDRIG, "SMTP Submission", "STARTTLS und Auth prüfen"),
    636: (PortRisk.NIEDRIG, "LDAPS", "Zertifikat prüfen"),
    993: (PortRisk.NIEDRIG, "IMAPS", "TLS-Konfiguration prüfen"),
    995: (PortRisk.NIEDRIG, "POP3S", "TLS-Konfiguration prüfen"),
}


def analysiere_port(port_info: PortInfo) -> PortInfo:
    """Bewertet einen Port und setzt Risikoklasse und Hinweis.

    Schlägt den Port in HIGH_RISK_PORTS nach. Unbekannte offene Ports
    erhalten MITTEL als Standard-Risikoklasse.

    Args:
        port_info: Port-Info mit Zustand.

    Returns:
        Aktualisiertes PortInfo-Objekt mit risk und hinweis.
    """
    from tools.network_scanner.domain.models import PortState

    if port_info.state != PortState.OPEN:
        return port_info

    eintrag = HIGH_RISK_PORTS.get(port_info.port)
    if eintrag:
        risk, service, hinweis = eintrag
        if not port_info.service:
            port_info.service = service
        port_info.risk = risk
        port_info.hinweis = hinweis
    else:
        # Unbekannter offener Port — als mittel einstufen
        port_info.risk = PortRisk.MITTEL
        port_info.hinweis = "Unbekannter Dienst — Notwendigkeit prüfen"

    return port_info


def analysiere_ports(ports: list[PortInfo]) -> list[PortInfo]:
    """Bewertet alle Ports einer Port-Liste.

    Args:
        ports: Liste der PortInfo-Objekte.

    Returns:
        Liste mit aktualisierten Risikoklassen.
    """
    return [analysiere_port(p) for p in ports]
