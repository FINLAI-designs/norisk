"""
models — Domain-Datenmodelle für den API Security Analyzer.

Enthält reine Daten-Klassen (dataclasses) ohne externe Abhängigkeiten.
Alle Werte-Objekte folgen dem OWASP API Security Top 10 (2023).

Sicherheitsdesign (STRIDE):
    Information Disclosure: ScanTarget speichert keine Credentials,
                            nur URL und Metadaten.
    Tampering: Alle Modelle sind frozen=True — keine
                            nachträgliche Mutation nach Erstellung.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """CVSS-ähnliche Schweregradkategorien für Befunde."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def label(self) -> str:
        """Gibt das deutsche Anzeigelabel zurück."""
        _labels = {
            "critical": "Kritisch",
            "high": "Hoch",
            "medium": "Mittel",
            "low": "Niedrig",
            "info": "Info",
        }
        return _labels[self.value]

    def sort_order(self) -> int:
        """Numerische Sortierreihenfolge (niedriger = schwerer)."""
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return _order[self.value]


class OWASPCategory(StrEnum):
    """OWASP API Security Top 10 (2023) Kategorien."""

    API1 = "API1"  # Broken Object Level Authorization
    API2 = "API2"  # Broken Authentication
    API3 = "API3"  # Broken Object Property Level Authorization
    API4 = "API4"  # Unrestricted Resource Consumption
    API5 = "API5"  # Broken Function Level Authorization
    API6 = "API6"  # Unrestricted Access to Sensitive Business Flows
    API7 = "API7"  # Server Side Request Forgery
    API8 = "API8"  # Security Misconfiguration
    API9 = "API9"  # Improper Inventory Management
    API10 = "API10"  # Unsafe Consumption of APIs

    def description(self) -> str:
        """Gibt die vollständige OWASP-Kategoriebeschreibung zurück."""
        _desc = {
            "API1": "Broken Object Level Authorization",
            "API2": "Broken Authentication",
            "API3": "Broken Object Property Level Authorization",
            "API4": "Unrestricted Resource Consumption",
            "API5": "Broken Function Level Authorization",
            "API6": "Unrestricted Access to Sensitive Business Flows",
            "API7": "Server Side Request Forgery (SSRF)",
            "API8": "Security Misconfiguration",
            "API9": "Improper Inventory Management",
            "API10": "Unsafe Consumption of APIs",
        }
        return _desc[self.value]


class APIType(StrEnum):
    """API-Typ für kontextsensitive Checks."""

    REST = "REST"
    GRAPHQL = "GraphQL"
    SOAP = "SOAP"
    UNKNOWN = "Unbekannt"


class AuthType(StrEnum):
    """Erwarteter Authentifizierungstyp der API."""

    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"


@dataclass(frozen=True)
class ScanTarget:
    """Beschreibt das Scan-Ziel (URL + Metadaten).

    Attributes:
        url: Vollständige Basis-URL der API (z. B. https://api.example.com/v1).
        api_type: Erkannter oder angegebener API-Typ.
        auth_type: Erwarteter Authentifizierungstyp.
        timeout: HTTP-Timeout in Sekunden.
        headers: Zusätzliche HTTP-Header für den Scan.
        active_checks: True = Active Checks (10-14) zusaetzlich durchfuehren.
    """

    url: str
    api_type: APIType = APIType.REST
    auth_type: AuthType = AuthType.NONE
    timeout: int = 10
    headers: dict[str, str] = field(default_factory=dict)
    active_checks: bool = False


@dataclass(frozen=True)
class TLSInfo:
    """TLS/SSL-Zertifikatsinformationen aus der SSL-Verbindung.

    Alle Datumsfelder als ISO-8601-Strings (UTC). Wird von
    check_tls_certificate als reiner, netzwerkfreier Input verwendet.

    Attributes:
        subject_cn: Common Name des Zertifikat-Subjects.
        subject_org: Organisation des Zertifikat-Subjects.
        issuer_cn: Common Name des Ausstellers.
        issuer_org: Organisation des Ausstellers.
        not_before: Gültigkeitsbeginn als ISO-8601-String.
        not_after: Ablaufdatum als ISO-8601-String.
        san: Subject Alternative Names (DNS-Einträge).
        tls_version: TLS-Protokollversion (z. B. ``"TLSv1.3"``).
        cipher_name: Name der ausgehandelten Cipher-Suite.
        cipher_bits: Schlüssellänge in Bit.
        is_self_signed: True wenn Aussteller-CN == Subject-CN.
        hostname_valid: True wenn Hostname-Verifikation erfolgreich war.
    """

    subject_cn: str = ""
    subject_org: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_before: str = ""
    not_after: str = ""
    san: tuple[str, ...] = field(default_factory=tuple)
    tls_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    is_self_signed: bool = False
    hostname_valid: bool = True


@dataclass(frozen=True)
class Finding:
    """Einzelner Sicherheitsbefund aus einem Check.

    Attributes:
        code: Maschinenlesbarer Befund-Code (z. B. MISSING_HSTS).
        title: Kurztitel für die UI.
        description: Ausführliche Beschreibung des Problems.
        severity: Schweregradkategorie.
        owasp: Zugeordnete OWASP API Top 10 Kategorie.
        detail: Optionaler technischer Detail-String (z. B. Header-Wert).
        remediation: Empfohlene Gegenmaßnahme.
    """

    code: str
    title: str
    description: str
    severity: Severity
    owasp: OWASPCategory
    detail: str = ""
    remediation: str = ""


@dataclass(frozen=True)
class ScanLauf:
    """Ein persistierter Scan-Durchlauf.

    Attributes:
        id: UUID des Laufs.
        target_url: Bereinigte Ziel-URL (ohne Query-Parameter).
        api_type: API-Typ-Bezeichnung (z. B. ``"REST"``).
        scan_start: Startzeit als ISO-8601-String.
        scan_end: Endzeit als ISO-8601-String.
        total_checks: Anzahl durchgefuehrter Checks.
        findings_count: Gesamtzahl der Findings.
        severity_summary: Findings-Anzahl je Schweregrad
                          (Schlussel = Severity.value, z. B. ``"critical"``).
        findings: Liste der Finding-Objekte (leer bei Listenansicht,
                          befuellt bei Detailabfrage).
    """

    id: str
    target_url: str
    api_type: str
    scan_start: str
    scan_end: str
    total_checks: int
    findings_count: int
    severity_summary: dict[str, int]
    findings: list[Finding] = field(default_factory=list)

    def dauer_sekunden(self) -> float:
        """Berechnet die Scan-Dauer aus Start- und Endzeit.

        Returns:
            Dauer in Sekunden, 0.0 wenn nicht berechenbar.
        """
        from datetime import datetime

        try:
            start = datetime.fromisoformat(self.scan_start)
            end = datetime.fromisoformat(self.scan_end)
            return (end - start).total_seconds()
        except (ValueError, TypeError):
            return 0.0


@dataclass(frozen=True)
class ScanResult:
    """Gesamtergebnis eines API-Security-Scans.

    Attributes:
        target: Das gescannte Ziel.
        findings: Liste aller gefundenen Sicherheitsprobleme.
        scan_time: Zeitstempel des Scans (ISO 8601, UTC).
        duration_ms: Scan-Dauer in Millisekunden.
        error: Fehlermeldung wenn der Scan abgebrochen wurde.
    """

    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    scan_time: str = ""
    duration_ms: int = 0
    error: str = ""

    def findings_by_severity(self) -> list[Finding]:
        """Gibt Befunde sortiert nach Schweregrad zurück (kritisch zuerst)."""
        return sorted(self.findings, key=lambda f: f.severity.sort_order())

    def findings_by_owasp(self) -> dict[OWASPCategory, list[Finding]]:
        """Gruppiert Befunde nach OWASP-Kategorie."""
        result: dict[OWASPCategory, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.owasp, []).append(f)
        return result

    def critical_count(self) -> int:
        """Anzahl kritischer Befunde."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    def high_count(self) -> int:
        """Anzahl hoher Befunde."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def risk_score(self) -> int:
        """Einfacher Risikoscore (0-100): höher = gefährlicher."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 10,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        raw = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, raw)
