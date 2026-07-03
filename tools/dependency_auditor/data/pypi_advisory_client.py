"""
pypi_advisory_client — Abfrage der OSV API fuer Python-Vulnerabilities.

Verwendet die Open Source Vulnerabilities API (https://osv.dev).
Kein API-Key noetig. Rate-Limit: konservativ per HTTP-Client-Singleton.

API-Endpoint: POST https://api.osv.dev/v1/query
Dokumentation: https://osv.dev/docs/

Sicherheitsdesign:
    - Verwendet get_http_client mit Token-Bucket-Rate-Limiting
    - Alle Exceptions werden gefangen → leere Liste statt Crash
    - Kein Logging von Response-Inhalten (koennen PII enthalten)

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.feed_settings import external_fetches_allowed
from core.http_client import get_http_client
from core.logger import get_logger
from tools.dependency_auditor.domain.interfaces import IAdvisorySource
from tools.dependency_auditor.domain.models import VulnerabilityInfo, VulnSeverity

_log = get_logger(__name__)

_OSV_API_URL = "https://api.osv.dev/v1/query"

# OSV-Range-Typen, deren Events direkt PEP-440-Versionen tragen.
# GIT-Ranges enthalten Commit-SHAs — als Versions-Spec unbrauchbar
# (InvalidSpecifier) und werden uebersprungen Drop-Gate-Fix).
_PEP440_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})


class PyPIAdvisoryClient(IAdvisorySource):
    """Fragt die OSV-Datenbank nach bekannten Python-Schwachstellen ab.

    Implementiert IAdvisorySource aus domain/interfaces.py.
    """

    def __init__(self) -> None:
        """Initialisiert den Client mit dem zentralen HTTP-Client."""
        self._client = get_http_client()

    def query_vulnerabilities(
        self, package_name: str, version: str | None
    ) -> list[VulnerabilityInfo]:
        """Fragt OSV nach Vulnerabilities fuer ein Package.

        Args:
            package_name: Name des PyPI-Packages (z. B. ``"requests"``).
            version: Exakt gepinnte Version oder None fuer alle.

        Returns:
            Liste der gefundenen VulnerabilityInfo-Objekte.
            Leer bei Fehler oder keinen Findings.
        """
        if not external_fetches_allowed():
            # Offline-Modus: kein OSV-Abruf. Der GUI-Handler zeigt den Hinweis +
            # verhindert, dass das leere Ergebnis als "keine Funde" missdeutet wird.
            return []
        payload: dict = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI",
            }
        }
        if version:
            payload["version"] = version

        try:
            response = self._client.post(
                _OSV_API_URL,
                json=payload,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_response(data, package_name)
        except Exception:  # noqa: BLE001
            _log.warning("OSV-Abfrage fuer %r fehlgeschlagen", package_name)
            return []

    # ------------------------------------------------------------------
    # Response-Parsing
    # ------------------------------------------------------------------

    def _parse_response(self, data: dict, package_name: str) -> list[VulnerabilityInfo]:
        """Konvertiert eine OSV-Response in VulnerabilityInfo-Objekte.

        Args:
            data: Geparstes JSON aus der OSV-Response.
            package_name: Name des abgefragten Packages.

        Returns:
            Liste der VulnerabilityInfo-Objekte.
        """
        vulns = []
        for vuln in data.get("vulns", []):
            severity = self._map_severity(vuln)
            fixed = self._extract_fixed_version(vuln, package_name)
            affected = self._extract_affected_range(vuln, package_name)
            vuln_id = vuln.get("id", "UNKNOWN")

            vulns.append(
                VulnerabilityInfo(
                    vuln_id=vuln_id,
                    package_name=package_name,
                    affected_versions=affected,
                    fixed_version=fixed,
                    severity=severity,
                    summary=vuln.get("summary", "Keine Beschreibung verfuegbar"),
                    url=f"https://osv.dev/vulnerability/{vuln_id}",
                )
            )
        return vulns

    def _map_severity(self, vuln: dict) -> VulnSeverity:
        """Mappt OSV-Severity auf FINLAI VulnSeverity.

        Liest CVSS v3-Scores aus dem ``severity``-Array. Faellt auf
        MEDIUM zurueck wenn kein Score vorhanden.

        Args:
            vuln: Einzelner Vuln-Eintrag aus der OSV-Response.

        Returns:
            VulnSeverity-Enum-Wert.
        """
        for sev_entry in vuln.get("severity", []):
            score_str = sev_entry.get("score", "")
            try:
                # CVSS v3 Vector: ``CVSS:3.1/AV:N/...`` oder reiner Float
                if score_str.startswith("CVSS:"):
                    # Basis-Score steht nicht direkt im Vector-String
                    # → ueberspringe und versuche naechsten Eintrag
                    continue
                cvss = float(score_str)
                if cvss >= 9.0:
                    return VulnSeverity.CRITICAL
                if cvss >= 7.0:
                    return VulnSeverity.HIGH
                if cvss >= 4.0:
                    return VulnSeverity.MEDIUM
                return VulnSeverity.LOW
            except (ValueError, AttributeError):
                continue

        # Fallback: database_specific CVSS-Scores (GitHub Advisory)
        db_spec = vuln.get("database_specific", {})
        gh_severity = db_spec.get("severity", "").upper()
        _gh_map = {
            "CRITICAL": VulnSeverity.CRITICAL,
            "HIGH": VulnSeverity.HIGH,
            "MODERATE": VulnSeverity.MEDIUM,
            "LOW": VulnSeverity.LOW,
        }
        if gh_severity in _gh_map:
            return _gh_map[gh_severity]

        return VulnSeverity.MEDIUM

    def _extract_fixed_version(self, vuln: dict, package_name: str) -> str | None:
        """Extrahiert die erste fixe Version aus dem ``affected``-Array.

        GIT-Ranges werden uebersprungen — deren ``fixed``-Event ist ein
        Commit-SHA, keine PyPI-Version (Boy-Scout zu).

        Args:
            vuln: Einzelner Vuln-Eintrag.
            package_name: Name des Packages (Case-insensitiv verglichen).

        Returns:
            Versions-String oder None wenn kein Fix bekannt.
        """
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() != package_name.lower():
                continue
            for version_range in affected.get("ranges", []):
                if str(version_range.get("type", "")).upper() not in _PEP440_RANGE_TYPES:
                    continue
                for event in version_range.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    def _extract_affected_range(self, vuln: dict, package_name: str) -> str:
        """Extrahiert den betroffenen Versionsbereich im PEP-440-Format.

        Bevorzugt ECOSYSTEM/SEMVER-Ranges (``introduced``/``fixed``-Events),
        da diese direkt als PEP-440-Spec verwendbar sind. GIT-Ranges
        (Commit-SHAs) werden uebersprungen — vorher lieferte die ERSTE
        Range eines Eintrags den Spec, auch wenn sie eine GIT-Range war,
        und der Spec war dann unparsebar Drop-Gate-Fix).
        Faellt auf explizite Versions-Listen zurueck (OR-Semantik) —
        VOLLSTAENDIG, ohne Trunkierung: der String wird fuers Matching
        verwendet, eine gekuerzte Liste wuerde Betroffene verlieren.

        Args:
            vuln: Einzelner Vuln-Eintrag.
            package_name: Name des Packages.

        Returns:
            Versionsbereich als String (z. B. ``">=0,<2.32"``).
            ``"unbekannt"`` wenn kein Bereich ermittelbar.
        """
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() != package_name.lower():
                continue

            # Ranges zuerst (nur ECOSYSTEM/SEMVER) — direkt als PEP-440-Spec
            # nutzbar. GIT-Ranges ueberspringen statt blind zu uebernehmen.
            for version_range in affected.get("ranges", []):
                range_type = str(version_range.get("type", "")).upper()
                if range_type not in _PEP440_RANGE_TYPES:
                    continue
                events = version_range.get("events", [])
                introduced = next(
                    (e.get("introduced", "0") for e in events if "introduced" in e),
                    "0",
                )
                fixed = next(
                    (e.get("fixed", "") for e in events if "fixed" in e),
                    "",
                )
                if fixed:
                    return f">={introduced},<{fixed}"
                return f">={introduced}"

            # Fallback: explizite Versions-Liste → OR-Semantik (komma-getrennte ==)
            # is_version_affected behandelt dieses Format korrekt.
            versions = affected.get("versions", [])
            if versions:
                return ",".join(f"=={v}" for v in versions)

        return "unbekannt"
