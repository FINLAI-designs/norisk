"""network_monitor.domain.models — Datenklassen für den Netzwerkmonitor.

Enthält ausschließlich `@dataclass`-Strukturen, keine Seiteneffekte, keine
Framework-Abhängigkeiten. Importierbar ohne PySide6 oder psutil.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum

#: Ein geparstes IP-Netz — IPv4/IPv6, plain (als ``/32``/``/128``) oder CIDR.
#: Gemeinsamer Werttyp für Blocklist/Feed/Whitelist F-D).
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class InterfaceStats:
    """Bandbreiten-Snapshot für ein einzelnes Netzwerk-Interface.

    Attributes:
        name: Interface-Name (z.B. ``"Ethernet"``, ``"WLAN"``).
        upload_kbps: Upload-Rate in KB/s (Delta zwischen zwei Samples).
        download_kbps: Download-Rate in KB/s (Delta zwischen zwei Samples).
        bytes_sent_total: Gesamtsumme gesendeter Bytes seit Boot.
        bytes_recv_total: Gesamtsumme empfangener Bytes seit Boot.
        is_up: True wenn das Interface aktuell aktiv ist.
        mac_address: MAC-Adresse (kann leer sein).
        ip_address: IPv4-Adresse (kann leer sein).
    """

    name: str
    upload_kbps: float
    download_kbps: float
    bytes_sent_total: int
    bytes_recv_total: int
    is_up: bool = True
    mac_address: str = ""
    ip_address: str = ""


@dataclass(frozen=True)
class ConnectionInfo:
    """Eine aktive Netzwerk-Verbindung zu einem bestimmten Zeitpunkt.

    Attributes:
        remote_ip: Entfernte IP-Adresse. Leer bei LISTEN-Sockets.
        remote_port: Entfernter Port. 0 bei LISTEN-Sockets.
        local_port: Lokaler Port.
        pid: Prozess-ID (0 wenn nicht ermittelbar).
        process_name: Prozessname (``"–"`` wenn nicht ermittelbar).
        status: Socket-Status (z.B. ``"ESTABLISHED"``, ``"LISTEN"``).
        suspicious: True wenn die Remote-IP gegen die Blocklist matcht.
        suspicious_reason: Freitext-Grund für Verdacht (leer wenn nicht verdächtig).
    """

    remote_ip: str
    remote_port: int
    local_port: int
    pid: int
    process_name: str
    status: str
    suspicious: bool = False
    suspicious_reason: str = ""

    @property
    def dedup_key(self) -> tuple[str, int, int, int]:
        """Stabiler Hash-Key für Diff-Logik."""
        return (self.remote_ip, self.remote_port, self.local_port, self.pid)


@dataclass(frozen=True)
class Conversation:
    """Aggregierte „Wer-mit-Wem"-Konversation Phase 5, kein Capture).

    Verdichtet die Verbindungs-Historie (``connection_history``) zu einem Eintrag je
    (Prozess, Ziel-IP) über ein Zeitfenster: wie oft, über welche Ports, in welchem
    Status, ob je verdächtig. Reine Aggregation vorhandener Socket-Snapshots — KEIN
    Byte-Volumen (das käme aus den ETW-Flow-Daten und ist ein späterer Schritt).

    Attributes:
        process_name: Prozessname (``"–"`` wenn nicht ermittelbar).
        remote_ip: Entfernte IP-Adresse der Konversation.
        connection_count: Anzahl der Historien-Snapshots für dieses (Prozess, IP)-Paar.
        ports: Distinkte Ziel-Ports, aufsteigend.
        statuses: Distinkte Socket-Status (z. B. ``"ESTABLISHED"``).
        suspicious: True, wenn die IP im Fenster je gegen die Blocklist matchte.
        suspicious_reason: Repräsentativer Verdachts-Grund (leer wenn nie verdächtig).
        first_seen: Frühester Snapshot-Zeitstempel (Unix-Sekunden).
        last_seen: Jüngster Snapshot-Zeitstempel (Unix-Sekunden).
        bytes_sent: Gesendete Bytes (aus ETW-Flow-Daten angereichert; 0 ohne
            elevated Collector).
        bytes_recv: Empfangene Bytes (analog ``bytes_sent``).
    """

    process_name: str
    remote_ip: str
    connection_count: int
    ports: tuple[int, ...] = ()
    statuses: tuple[str, ...] = ()
    suspicious: bool = False
    suspicious_reason: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass(frozen=True)
class ProcessTrafficSample:
    """Netzwerk-Byte-Verbrauch pro (Prozess, Remote-IP) in einem Intervall.

    Wird vom ETW-Subscriber (Stop-Step B) pro 60s-Intervall erzeugt und
    persistiert. Anders als:class:`ConnectionInfo` (Socket-Liste, psutil)
    traegt diese Struktur die tatsaechlich uebertragenen **Bytes** — auf Windows
    nur via ETW-Kernel-Network-Provider ermittelbar (Admin).

    Grain = ``(pid, remote_ip, remote_port, protocol)`` pro Intervall
    (Flow-artig, vgl. NetFlow/Sysmon-EID-3). Die feinere per-IP-Granularitaet
    traegt die Threshold-Alerts „High-Volume-Single-IP" und „Game-CDN" (D);
    per-Prozess-Summen entstehen via ``GROUP BY pid``.

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname (``"–"`` wenn nicht ermittelbar).
        remote_ip: Remote-IP des Flows (Schluessel-Dimension; ``daddr`` bei
            Send, ``saddr`` bei Recv).
        remote_port: Remote-Port (``dport`` bei Send, ``sport`` bei Recv;
            0 wenn unbekannt).
        protocol: ``"TCP"`` oder ``"UDP"`` (aus der Event-ID abgeleitet).
        bytes_sent: Im Intervall an diese IP gesendete Bytes.
        bytes_recv: Im Intervall von dieser IP empfangene Bytes.
        image_path: Vollstaendiger exe-Pfad des Prozesses (zur Startzeit via
            Kernel-Process-Provider eingefroren; leer wenn nicht ermittelbar) —
            Basis fuer die Unknown-Path-Regel (Regel 4).
    """

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int
    image_path: str = ""


@dataclass(frozen=True)
class ProcessTrafficAggregate:
    """Kumulierter Byte-Verbrauch eines Prozesses ueber ein Zeitfenster.

    Ergebnis der 24h-Aggregation fuer die Live-View (Stop-Step C): pro Prozess
    die Summe aller Intervall-Bytes.

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname.
        total_bytes_sent: Summe gesendeter Bytes im Fenster.
        total_bytes_recv: Summe empfangener Bytes im Fenster.
    """

    pid: int
    process_name: str
    total_bytes_sent: int
    total_bytes_recv: int


@dataclass(frozen=True)
class ProcessOutbound:
    """Outbound-Bytes eines Prozesses in einem Fenster D).

    Eingang fuer die Volume-Spike-, Off-Hours- und Unknown-Path-Regeln.

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname.
        bytes_sent: Summe gesendeter Bytes im Fenster.
        image_path: Vollstaendiger Pfad der ausfuehrbaren Datei (leer bis die
            Kernel-Process-Population — B2-Folgeschritt — ihn fuellt).
    """

    pid: int
    process_name: str
    bytes_sent: int
    image_path: str = ""


@dataclass(frozen=True)
class RemoteIpTraffic:
    """Bytes eines Prozesses zu EINER Remote-IP im Fenster D).

    Eingang fuer die Single-IP- und Game-CDN-Regeln.

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname.
        remote_ip: Remote-IP des Flows.
        bytes_sent: Summe gesendeter Bytes an diese IP.
        bytes_recv: Summe empfangener Bytes von dieser IP.
    """

    pid: int
    process_name: str
    remote_ip: str
    bytes_sent: int
    bytes_recv: int


@dataclass(frozen=True)
class DnsQuerySample:
    """DNS-Query-Statistik eines Prozesses in einem Intervall D, Regel 5).

    Vom DNS-Aggregator pro 60s-Intervall erzeugt (Quelle: ETW-Provider
    ``Microsoft-Windows-DNS-Client``, Event 3006). Traegt neben der reinen
    Query-Anzahl die DGA-/Tunneling-Signale (viele distinct Namen, lange/
    hoch-entropische Labels).

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname.
        query_count: Anzahl DNS-Queries im Intervall.
        distinct_names: Anzahl unterschiedlicher Query-Namen.
        max_label_len: Laengstes einzelnes DNS-Label (Tunneling stopft Daten
            in lange Labels).
        max_label_entropy: Hoechste Shannon-Entropie eines Labels (encodierte
            Payloads wirken zufaellig).
        sample_query: Repraesentativer Query-Name (fuer die Alert-Anzeige).
    """

    pid: int
    process_name: str
    query_count: int
    distinct_names: int
    max_label_len: int
    max_label_entropy: float
    sample_query: str = ""
    game_cdn: str = ""  # Game-/Download-CDN-Label, falls eine Query matchte (Regel 3)


@dataclass(frozen=True)
class DnsRateAggregate:
    """Peak-DNS-Rate eines Prozesses ueber ein Fenster D, Regel 5).

    Ergebnis der Repo-Aggregation: pro Prozess die hoechste in einem
    60s-Intervall gesehene Query-Anzahl + die staerksten DGA-Signale.

    Attributes:
        pid: Prozess-ID.
        process_name: Prozessname.
        peak_query_count: Maximale Query-Anzahl in einem Intervall (≈/Min).
        max_label_len: Maximales Label im Fenster.
        max_label_entropy: Maximale Label-Entropie im Fenster.
        sample_query: Repraesentativer Query-Name.
    """

    pid: int
    process_name: str
    peak_query_count: int
    max_label_len: int
    max_label_entropy: float
    sample_query: str = ""
    game_cdn: str = ""  # Game-/Download-CDN-Label, falls eine Query matchte (Regel 3)


class AnomalyType(StrEnum):
    """Die sechs Threshold-Alert-Typen Phase 2)."""

    VOLUME_SPIKE = "volume_spike"
    OFF_HOURS = "off_hours"
    GAME_CDN = "game_cdn"
    UNKNOWN_PATH = "unknown_path"
    DNS_TUNNELING = "dns_tunneling"
    SINGLE_IP = "single_ip"


class AnomalySeverity(StrEnum):
    """Schweregrad eines Alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Anomaly:
    """Eine erkannte Netzwerk-Anomalie D).

    Speist die Live-Anzeige und (Stop-Step E) die KiTodo-Findings.

    Attributes:
        anomaly_type: Welche Regel ausgeloest hat.
        severity: Schweregrad.
        pid: Betroffene Prozess-ID.
        process_name: Betroffener Prozess.
        value_bytes: Gemessener Wert (Bytes; bei DNS spaeter Query-Anzahl).
        threshold_bytes: Ueberschrittener Schwellwert.
        remote_ip: Betroffene Remote-IP (Single-IP/Game-CDN; sonst leer).
        detail: Zusatz-Klartext (z. B. CDN-Name oder Image-Pfad).
    """

    anomaly_type: AnomalyType
    severity: AnomalySeverity
    pid: int
    process_name: str
    value_bytes: int
    threshold_bytes: int
    remote_ip: str = ""
    detail: str = ""


# ── Threat-Intelligence-Feed F-D) ───────────────────────────────────


class FeedFormat(StrEnum):
    """Roh-Format eines Threat-Intel-Feeds (steuert die Parser-Toleranz).

    Beide Formate laufen durch denselben toleranten Zeilen-Parser
    (:func:`~tools.network_monitor.data.threat_feed_client.parse_feed_text`);
    der Wert dient der Doku/Status-Anzeige und kuenftiger Sonderbehandlung.
    """

    #: Eine IP/CIDR pro Zeile, ``#``-Kommentare (z. B. abuse.ch Feodo ipblocklist).
    PLAINTEXT_IP = "plaintext_ip"
    #: CSV mit ``ioc_value``-Spalte ``IP:Port`` (z. B. abuse.ch ThreatFox-Export).
    THREATFOX_CSV = "threatfox_csv"


@dataclass(frozen=True)
class ThreatFeedSource:
    """Definition einer Threat-Intel-Quelle (Referenzdaten, kein I/O).

    Attributes:
        key: Stabiler interner Schluessel (Cache-Primaerschluessel, Logging).
        name: Anzeigename der Quelle (z. B. ``"abuse.ch Feodo Tracker"``).
        url: HTTPS-Download-URL des Roh-Feeds.
        feed_format: Roh-Format (steuert die Parser-Toleranz).
        license_id: SPDX-/Lizenz-Kuerzel (Default-Feeds: ``"CC0-1.0"``).
        reason: Match-Begruendung, die geblockte IPs dieser Quelle tragen.
        enabled: Ob die Quelle standardmaessig abgerufen wird.
    """

    key: str
    name: str
    url: str
    feed_format: FeedFormat
    license_id: str
    reason: str
    enabled: bool = True


@dataclass(frozen=True)
class FeedUpdateResult:
    """Ergebnis eines Feed-Aktualisierungslaufs (Status fuer UI/Log).

    Attributes:
        updated_keys: Quell-Schluessel, die frisch heruntergeladen wurden.
        skipped_keys: Quellen, deren Cache noch frisch war (kein Download).
        total_entries: Summe der geparsten Eintraege ueber alle Cache-Quellen.
        errors: Pro fehlgeschlagener Quelle ein ``(key, kurzgrund)``-Paar
            (generischer Grund — KEIN Roh-Exception-Text, R-Log).
    """

    updated_keys: list[str] = field(default_factory=list)
    skipped_keys: list[str] = field(default_factory=list)
    total_entries: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class FeedRefreshSnapshot:
    """Ergebnis eines vollständigen Refresh-Durchlaufs (Update + Merge).

    Bündelt, was der periodische und der manuelle (One-Shot) GUI-Worker nach einem
    ``update`` an die GUI weiterreichen — die zusammengeführten Einträge, die
    Whitelist und die Quellen-Bilanz. Zentralisiert über
:meth:`ThreatFeedService.refresh_snapshot` (DRY statt dupliziert pro Worker).

    Attributes:
        entries: Zusammengeführte (Netzwerk, Grund)-Einträge (Blocklist + Feeds).
        whitelist: Aktuelle Whitelist-Netze (Override gegen Treffer).
        updated_count: Anzahl frisch heruntergeladener Quellen.
        error_count: Anzahl Quellen, die beim Update fehlschlugen.
    """

    entries: list[tuple[Network, str]] = field(default_factory=list)
    whitelist: list[Network] = field(default_factory=list)
    updated_count: int = 0
    error_count: int = 0


@dataclass(frozen=True)
class CachedFeed:
    """Ein verschluesselt gecachter Feed-Rohinhalt mit Metadaten.

    Attributes:
        key: Quell-Schluessel (:class:`ThreatFeedSource`).
        raw_payload: Roher (bereits groessen-begrenzter) Feed-Text.
        fetched_at: Unix-Zeitstempel des letzten erfolgreichen Downloads.
        entry_count: Anzahl der beim Download geparsten gueltigen Eintraege.
    """

    key: str
    raw_payload: str
    fetched_at: float
    entry_count: int
