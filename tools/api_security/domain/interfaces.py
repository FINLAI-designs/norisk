"""
interfaces — Abstrakte Ports für den API Security Analyzer (Hexagonal).

Definiert die Grenzen zwischen Domain und Infrastruktur.
Keine konkreten Implementierungen — nur ABC mit reinen Signaturen.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from tools.api_security.domain.models import ScanLauf, ScanResult, ScanTarget


class IScannerPort(ABC):
    """Schnittstelle für HTTP-Scanner-Implementierungen.

    Abstrahiert den konkreten HTTP-Client (requests, httpx usw.)
    sodass die Anwendungsschicht unabhängig von der Infrastruktur bleibt.
    """

    @abstractmethod
    def scan(self, target: ScanTarget) -> ScanResult:
        """Führt einen vollständigen passiven Scan durch.

        Args:
            target: Scan-Ziel mit URL und Konfiguration.

        Returns:
            ScanResult mit allen gefundenen Befunden.

        Raises:
            ValueError: Bei ungültiger Ziel-URL.
            ConnectionError: Wenn das Ziel nicht erreichbar ist.
        """


class IReportPort(ABC):
    """Schnittstelle für Report-Adapter (JSON, PDF usw.)."""

    @abstractmethod
    def export_json(self, result: ScanResult, path: Path) -> Path:
        """Exportiert ein ScanResult als JSON-Datei.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad (wird überschrieben wenn vorhanden).

        Returns:
            Absoluter Pfad der erzeugten Datei.
        """

    @abstractmethod
    def export_pdf(self, result: ScanResult, path: Path) -> Path:
        """Exportiert ein ScanResult als PDF-Bericht.

        Args:
            result: Scan-Ergebnis.
            path: Ausgabepfad (wird überschrieben wenn vorhanden).

        Returns:
            Absoluter Pfad der erzeugten Datei.
        """


class IScanRepository(ABC):
    """Schnittstelle fuer die Persistenz von Scan-Laeufen."""

    @abstractmethod
    def speichere_lauf(self, lauf: ScanLauf) -> None:
        """Persistiert einen abgeschlossenen Scan-Lauf mit allen Findings.

        Args:
            lauf: Abgeschlossener ScanLauf mit findings und severity_summary.
        """

    @abstractmethod
    def lade_verlauf(
        self,
        target_url: str | None = None,
        limit: int = 20,
    ) -> list[ScanLauf]:
        """Laedt die letzten N Scan-Laeufe, neueste zuerst.

        Laeufe werden OHNE Findings zurueckgegeben (nur Metadaten).
        Findings werden nur ueber lade_lauf geladen.

        Args:
            target_url: Optionaler URL-Filter. None = alle URLs.
            limit: Maximale Anzahl Eintraege.

        Returns:
            Liste der ScanLauf-Objekte (findings=[]), neueste zuerst.
        """

    @abstractmethod
    def lade_lauf(self, lauf_id: str) -> ScanLauf | None:
        """Laedt einen einzelnen Scan-Lauf vollstaendig (inkl. Findings).

        Args:
            lauf_id: UUID des Laufs.

        Returns:
            ScanLauf mit Findings oder None wenn nicht gefunden.
        """

    @abstractmethod
    def loesche_lauf(self, lauf_id: str) -> None:
        """Loescht einen Scan-Lauf inkl. aller Findings (CASCADE).

        Args:
            lauf_id: UUID des zu loeschenden Laufs.
        """

    @abstractmethod
    def lade_alle_urls(self) -> list[str]:
        """Gibt alle distinct gescannten URLs zurueck (alphabetisch).

        Returns:
            Sortierte Liste aller URLs ohne Duplikate.
        """
