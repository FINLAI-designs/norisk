"""network_monitor.domain.interfaces — Abstrakte Ports (Ports/Adapter).

Definiert Interfaces die von der Application-Schicht verwendet und von
der Data-Schicht implementiert werden. Die Application-Schicht kennt
nur diese Interfaces, niemals konkrete Adapter-Implementierungen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.network_monitor.domain.models import (
    ConnectionInfo,
    Conversation,
    DnsRateAggregate,
    ProcessOutbound,
    ProcessTrafficAggregate,
    RemoteIpTraffic,
)


class IBlocklistProvider(ABC):
    """Stellt eine Liste bekannter verdächtiger IPs / CIDR-Ranges bereit."""

    @abstractmethod
    def is_suspicious(self, ip: str) -> tuple[bool, str]:
        """Prüft ob eine IP-Adresse gegen die Blocklist matcht.

        Args:
            ip: Zu prüfende IP-Adresse (IPv4 oder IPv6).

        Returns:
            Tupel (matched, reason). ``matched=False`` → ``reason=""``.
        """
        ...


class IConnectionRepository(ABC):
    """Persistenz-Port für Verbindungs-Historie (Pro-Feature)."""

    @abstractmethod
    def save_snapshot(self, connections: list[ConnectionInfo]) -> None:
        """Speichert einen Verbindungs-Snapshot mit aktuellem Timestamp.

        Args:
            connections: Aktiv gesehene Verbindungen.
        """
        ...

    @abstractmethod
    def load_recent(self, hours: int = 24) -> list[tuple[float, ConnectionInfo]]:
        """Lädt alle Verbindungs-Einträge der letzten ``hours`` Stunden.

        Args:
            hours: Zeitfenster in Stunden (Default 24).

        Returns:
            Liste aus (timestamp, ConnectionInfo) — sortiert nach Timestamp absteigend.
        """
        ...

    @abstractmethod
    def purge_older_than(self, hours: int = 24) -> int:
        """Löscht Einträge älter als ``hours`` Stunden.

        Args:
            hours: Maximales Alter in Stunden.

        Returns:
            Anzahl gelöschter Zeilen.
        """
        ...

    @abstractmethod
    def aggregate_conversations(self, hours: int = 24) -> list[Conversation]:
        """Verdichtet die Historie zu (Prozess, Ziel-IP)-Konversationen (Phase 5).

        Args:
            hours: Zeitfenster in Stunden (Default 24).

        Returns:
            Liste aggregierter:class:`Conversation`-Objekte, häufigste zuerst.
        """
        ...


class IProcessTrafficRepository(ABC):
    """Lese-Port für die Per-Prozess-Traffic-History, Pro-Feature).

    Wird von der Live-View (``gui/``) genutzt, damit diese den konkreten
    SQLCipher-Adapter (``data/``) nicht direkt importieren muss
    (hexagonaler Contract: gui ↛ data).
    """

    @abstractmethod
    def aggregate_last_24h(self) -> list[ProcessTrafficAggregate]:
        """Per-Prozess kumulierte Bytes der letzten 24h, größte zuerst."""
        ...

    @abstractmethod
    def outbound_per_process_since(self, cutoff_ts: float) -> list[ProcessOutbound]:
        """Per-Prozess gesendete Bytes ab ``cutoff_ts`` (Volume-Spike/Path)."""
        ...

    @abstractmethod
    def offhours_outbound_per_process(
        self, cutoff_ts: float
    ) -> list[ProcessOutbound]:
        """Per-Prozess gesendete Bytes ab ``cutoff_ts``, nur Nacht-Stunden (22–07)."""
        ...

    @abstractmethod
    def traffic_per_remote_ip_since(
        self, cutoff_ts: float
    ) -> list[RemoteIpTraffic]:
        """Per-(Prozess, Remote-IP) Bytes ab ``cutoff_ts`` (Single-IP/Game-CDN)."""
        ...


class IDnsQueryRepository(ABC):
    """Lese-Port fuer die DNS-Query-History Regel 5)."""

    @abstractmethod
    def peak_rate_per_process(self, cutoff_ts: float) -> list[DnsRateAggregate]:
        """Pro Prozess die hoechste Query-Rate (pro Intervall) ab ``cutoff_ts``."""
        ...
