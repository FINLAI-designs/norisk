"""
interfaces — Abstrakte Ports fuer den Dependency-Auditor (Hexagonal).

Definiert die Grenzen zwischen Domain und Infrastruktur.

Schichtzugehoerigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    VulnerabilityInfo,
)


class IAdvisorySource(ABC):
    """Schnittstelle fuer Advisory-Datenbanken (OSV, NVD usw.)."""

    @abstractmethod
    def query_vulnerabilities(
        self, package_name: str, version: str | None
    ) -> list[VulnerabilityInfo]:
        """Fragt bekannte Schwachstellen fuer ein Package ab.

        Args:
            package_name: Name des Packages (z. B. ``"requests"``).
            version: Exakt gepinnte Version oder None fuer alle.

        Returns:
            Liste der gefundenen Vulnerabilities. Leer wenn keine.
        """


class IAuditRepository(ABC):
    """Schnittstelle fuer die Persistenz von Audit-Ergebnissen."""

    @abstractmethod
    def speichere_audit(self, result: DependencyAuditResult) -> None:
        """Persistiert ein Audit-Ergebnis.

        Args:
            result: Abgeschlossenes Audit-Ergebnis.
        """

    @abstractmethod
    def lade_verlauf(self, limit: int = 10) -> list[DependencyAuditResult]:
        """Laedt die letzten N Audit-Ergebnisse ohne Vulnerabilities.

        Args:
            limit: Maximale Anzahl Eintraege.

        Returns:
            Liste der Ergebnisse (vulnerabilities=[]), neueste zuerst.
        """

    @abstractmethod
    def lade_letztes_ergebnis(self) -> DependencyAuditResult | None:
        """Laedt das juengste Audit-Ergebnis VOLLSTAENDIG (inkl. Vulnerabilities).

        Returns:
            Das zuletzt gespeicherte Ergebnis, oder ``None`` wenn keines existiert.
        """
