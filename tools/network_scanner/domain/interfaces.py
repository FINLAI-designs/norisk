"""
interfaces — Abstrakte Ports für den Netzwerk-Scanner.

Definiert die Schnittstellen die von den data/-Adaptern
implementiert werden müssen. Keine Außen-Abhängigkeiten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.network_scanner.domain.models import HostInfo, NetworkScanResult


class IScannerBackend(ABC):
    """Port für einen Scan-Backend-Adapter."""

    @abstractmethod
    def scan_host(
        self,
        host: str,
        ports: list[int],
    ) -> HostInfo:
        """Scannt einen einzelnen Host.

        Args:
            host: IP-Adresse oder Hostname.
            ports: Liste der zu scannenden Port-Nummern.

        Returns:
            HostInfo mit Scan-Ergebnis.
        """
        ...

    @abstractmethod
    def ist_verfuegbar(self) -> bool:
        """Prüft ob das Backend verwendbar ist.

        Returns:
            True wenn das Backend einsatzbereit ist.
        """
        ...


class IScanRepository(ABC):
    """Port für die Persistenz von Scan-Ergebnissen."""

    @abstractmethod
    def speichere_scan(self, result: NetworkScanResult) -> None:
        """Speichert ein Scan-Ergebnis.

        Args:
            result: Zu speicherndes Scan-Ergebnis.
        """
        ...

    @abstractmethod
    def lade_letzte_scans(self, limit: int = 10) -> list[NetworkScanResult]:
        """Lädt die zuletzt gespeicherten Scans.

        Args:
            limit: Maximale Anzahl zurückgegebener Scans.

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        ...

    @abstractmethod
    def lade_scan(self, scan_id: str) -> NetworkScanResult | None:
        """Lädt einen Scan anhand seiner ID.

        Args:
            scan_id: Eindeutiger Scan-Bezeichner.

        Returns:
            Scan-Ergebnis oder None wenn nicht gefunden.
        """
        ...
