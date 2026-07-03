"""
models — Domain-Datenmodelle fuer den Dependency-Auditor.

Enthaelt reine Datenklassen ohne externe Abhaengigkeiten.

Schichtzugehoerigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class VulnSeverity(Enum):
    """Schweregrad-Kategorien fuer Dependency-Vulnerabilities."""

    CRITICAL = "KRITISCH"
    HIGH = "HOCH"
    MEDIUM = "MITTEL"
    LOW = "NIEDRIG"

    def sort_order(self) -> int:
        """Numerische Sortierreihenfolge (niedriger = schwerer)."""
        _order = {
            "KRITISCH": 0,
            "HOCH": 1,
            "MITTEL": 2,
            "NIEDRIG": 3,
        }
        return _order[self.value]


@dataclass
class DependencyInfo:
    """Eine einzelne Dependency aus requirements.txt.

    Attributes:
        name: Normalisierter Package-Name (Kleinbuchstaben).
        version_pinned: Exakt gepinnte Version (z. B. ``"2.32.5"``) oder
                           None wenn unpinned.
        version_spec: Vollstaendige Versions-Spezifikation aus der Datei
                           (z. B. ``"==2.32.5"``, ``">=2.30"``, ``""`` wenn
                           keine Angabe).
        line_number: Zeile in der requirements.txt (1-basiert).
        version_installed: Tatsaechlich installierte Version der laufenden
                           Umgebung, nur beim Self-Audit aufgeloest)
                           oder None wenn unbekannt/nicht aufgeloest.
    """

    name: str
    version_pinned: str | None
    version_spec: str
    line_number: int
    version_installed: str | None = None

    def effective_version(self) -> str | None:
        """Effektive Version fuer den Vulnerability-Abgleich.

        Ein expliziter ``==``-Pin gewinnt immer vor der installierten
        Version; ohne beides ist kein Abgleich moeglich.

        Returns:
            Gepinnte Version, sonst installierte Version, sonst None.
        """
        return self.version_pinned or self.version_installed


@dataclass
class VulnerabilityInfo:
    """Eine bekannte Schwachstelle in einer Dependency.

    Attributes:
        vuln_id: Advisory-ID (z. B. ``"GHSA-xxxx-xxxx-xxxx"``
                           oder ``"CVE-2024-xxxxx"``).
        package_name: Betroffenes Package.
        affected_versions: Betroffener Versionsbereich (z. B. ``">=2.0,<2.32"``).
        fixed_version: Version mit dem Fix oder None wenn kein Fix
                           bekannt.
        severity: Schweregrad.
        summary: Kurzbeschreibung der Schwachstelle.
        url: Link zur Advisory-Seite.
    """

    vuln_id: str
    package_name: str
    affected_versions: str
    fixed_version: str | None
    severity: VulnSeverity
    summary: str
    url: str


@dataclass
class DependencyAuditResult:
    """Gesamtergebnis eines Dependency-Audits.

    Attributes:
        source_file: Pfad zur geprueften requirements.txt.
        scan_timestamp: Zeitstempel des Audits (ISO-8601).
        total_dependencies: Gesamtzahl der geparsten Dependencies.
        total_vulnerabilities: Gesamtzahl versions-verifizierter Vulnerabilities.
        dependencies: Alle geparsten Dependencies.
        vulnerabilities: Versions-verifizierte Vulnerabilities (effektive
                               Version liegt nachweislich im affected-Bereich).
        unpinned_dependencies: Dependencies ohne exakte Versionsangabe.
        unverified_vulnerabilities: Advisories, die NUR wegen unbekannter
                               Version gemeldet werden (kein Pin, keine
                               installierte Version ermittelbar) — kein
                               Abgleich moeglich. Zaehlen NICHT in
                               severity_summary / critical_count usw.
        unverified_dependencies: Dependencies ohne effektive Version, fuer
                               die mindestens eine Advisory gefunden wurde.
        severity_summary: Anzahl je Schweregrad (Schluessel =
                               VulnSeverity.value) — nur verifizierte Treffer.
        error: Fehlermeldung wenn der Audit abgebrochen wurde.
    """

    source_file: str
    scan_timestamp: str
    total_dependencies: int
    total_vulnerabilities: int
    dependencies: list[DependencyInfo] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityInfo] = field(default_factory=list)
    unpinned_dependencies: list[DependencyInfo] = field(default_factory=list)
    unverified_vulnerabilities: list[VulnerabilityInfo] = field(default_factory=list)
    unverified_dependencies: list[DependencyInfo] = field(default_factory=list)
    severity_summary: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def critical_count(self) -> int:
        """Anzahl kritischer Vulnerabilities."""
        return self.severity_summary.get(VulnSeverity.CRITICAL.value, 0)

    def high_count(self) -> int:
        """Anzahl hoher Vulnerabilities."""
        return self.severity_summary.get(VulnSeverity.HIGH.value, 0)

    def medium_count(self) -> int:
        """Anzahl mittlerer Vulnerabilities."""
        return self.severity_summary.get(VulnSeverity.MEDIUM.value, 0)

    def low_count(self) -> int:
        """Anzahl niedriger Vulnerabilities."""
        return self.severity_summary.get(VulnSeverity.LOW.value, 0)

    def unverified_count(self) -> int:
        """Anzahl Advisories ohne moeglichen Versionsabgleich.

        Eigene Zaehl-Kategorie „Version unbekannt" — bewusst NICHT Teil
        von severity_summary, damit unverifizierte Findings weder den
        Severity-Score aufblaehen noch als CRITICAL/HIGH erscheinen.

        Returns:
            Laenge von unverified_vulnerabilities.
        """
        return len(self.unverified_vulnerabilities)
