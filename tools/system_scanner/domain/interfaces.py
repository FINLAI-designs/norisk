"""
interfaces — Abstrakte Ports für das System-Scanner-Modul.

Definiert die Contracts die von data/ implementiert werden.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.system_scanner.domain.entities import ScanResult


class ISystemScanner(ABC):
    """Port: System-Scanner-Implementierung (plattformspezifisch).

    Wird von data/platform_scanner.py implementiert.
    """

    @abstractmethod
    def scan(self) -> ScanResult:
        """Führt einen vollständigen System-Scan durch.

        Returns:
            Scan-Ergebnis mit OS-Info, Software-Liste und
            Sicherheitskomponenten.

        Raises:
            RuntimeError: Bei unbehebbaren Scan-Fehlern.
        """
        ...


class IScanRepository(ABC):
    """Port: Persistenz für Scan-Ergebnisse."""

    @abstractmethod
    def save(self, result: ScanResult) -> None:
        """Speichert ein Scan-Ergebnis.

        Args:
            result: Zu speicherndes Ergebnis.
        """
        ...

    @abstractmethod
    def load_latest(self) -> ScanResult | None:
        """Lädt das zuletzt gespeicherte Scan-Ergebnis.

        Returns:
            Letztes Scan-Ergebnis oder None wenn keines vorhanden.
        """
        ...

    @abstractmethod
    def load_history(self, limit: int = 10) -> list[ScanResult]:
        """Lädt die letzten N Scan-Ergebnisse.

        Args:
            limit: Maximale Anzahl.

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        ...
