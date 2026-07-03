"""
test_dependency_auditor — Unit-Tests fuer den Dependency-Auditor.

Testet:
1. requirements_parser: pinned, minimum, extras, Kommentare, -r, Normalisierung
2. analyzer (domain): affected/not-affected, unpinned, clean package
3. is_version_affected: verschiedene Spezifikationen
4. pypi_advisory_client (Mock): OSV-Response parsing, leere Response,
   Fehler → leere Liste
5. audit_service: audit_self findet requirements.txt,
   audit_requirements vollstaendiger Flow (gemockt)

Author: Patrick Riederich
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.dependency_auditor.application.audit_service import AuditService
from tools.dependency_auditor.data.pypi_advisory_client import PyPIAdvisoryClient
from tools.dependency_auditor.data.requirements_parser import (
    _normalize_name,
    parse_requirements,
)
from tools.dependency_auditor.domain.analyzer import (
    analyze_dependencies,
    is_version_affected,
)
from tools.dependency_auditor.domain.models import (
    DependencyInfo,
    VulnerabilityInfo,
    VulnSeverity,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_dep(
    name: str = "requests",
    version_pinned: str | None = "2.32.5",
    version_spec: str = "==2.32.5",
    line_number: int = 1,
) -> DependencyInfo:
    """Erzeugt ein minimales DependencyInfo fuer Tests."""
    return DependencyInfo(
        name=name,
        version_pinned=version_pinned,
        version_spec=version_spec,
        line_number=line_number,
    )


def _make_vuln(
    package_name: str = "requests",
    affected_versions: str = ">=2.0,<2.32.0",
    fixed_version: str | None = "2.32.0",
    severity: VulnSeverity = VulnSeverity.HIGH,
) -> VulnerabilityInfo:
    """Erzeugt ein minimales VulnerabilityInfo fuer Tests."""
    return VulnerabilityInfo(
        vuln_id="GHSA-test-xxxx-yyyy",
        package_name=package_name,
        affected_versions=affected_versions,
        fixed_version=fixed_version,
        severity=severity,
        summary="Test vulnerability",
        url="https://osv.dev/vulnerability/GHSA-test-xxxx-yyyy",
    )


def _write_requirements(tmp_path: Path, content: str) -> str:
    """Schreibt content in eine temporaere requirements.txt und gibt den Pfad zurueck."""
    f = tmp_path / "requirements.txt"
    f.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(f)


# ---------------------------------------------------------------------------
# 1. requirements_parser
# ---------------------------------------------------------------------------


class TestRequirementsParser:
    def test_pinned_version(self, tmp_path):
        """Pinned Eintrag wird korrekt geparst."""
        path = _write_requirements(tmp_path, "requests==2.32.5\n")
        deps = parse_requirements(path)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version_pinned == "2.32.5"
        assert deps[0].version_spec == "==2.32.5"

    def test_minimum_spec(self, tmp_path):
        """Minimum-Spec ohne gepinnte Version → version_pinned=None."""
        path = _write_requirements(tmp_path, "requests>=2.30\n")
        deps = parse_requirements(path)
        assert deps[0].version_pinned is None
        assert ">=2.30" in deps[0].version_spec

    def test_extras_stripped(self, tmp_path):
        """Extras-Klammern werden ignoriert, Name korrekt extrahiert."""
        path = _write_requirements(tmp_path, "requests[security]==2.32.5\n")
        deps = parse_requirements(path)
        assert deps[0].name == "requests"
        assert deps[0].version_pinned == "2.32.5"

    def test_comments_ignored(self, tmp_path):
        """Kommentarzeilen werden uebersprungen."""
        content = "# This is a comment\nrequests==2.32.5\n# another comment\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert len(deps) == 1

    def test_empty_lines_ignored(self, tmp_path):
        """Leerzeilen werden uebersprungen."""
        content = "\n\nrequests==2.32.5\n\n\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert len(deps) == 1

    def test_r_include_ignored(self, tmp_path):
        """-r Includes werden uebersprungen (kein rekursives Parsen)."""
        content = "-r base.txt\nrequests==2.32.5\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_inline_comment_stripped(self, tmp_path):
        """Inline-Kommentare nach # werden abgeschnitten."""
        content = "requests==2.32.5  # HTTP-Client\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert deps[0].version_pinned == "2.32.5"

    def test_environment_marker_stripped(self, tmp_path):
        """Environment-Marker nach; werden abgeschnitten."""
        content = 'requests==2.32.5; python_version >= "3.10"\n'
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert deps[0].version_pinned == "2.32.5"

    def test_unpinned_package(self, tmp_path):
        """Package ohne Versionsangabe → version_pinned=None."""
        path = _write_requirements(tmp_path, "requests\n")
        deps = parse_requirements(path)
        assert deps[0].name == "requests"
        assert deps[0].version_pinned is None
        assert deps[0].version_spec == ""

    def test_line_number_korrekt(self, tmp_path):
        """Zeilennummern werden korrekt gesetzt."""
        content = "# Kommentar\nrequests==2.32.5\npillow==10.4.0\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert deps[0].line_number == 2
        assert deps[1].line_number == 3

    def test_ungueltige_endung_wirft_value_error(self, tmp_path):
        """Nicht-erlaubte Dateiendung wirft ValueError."""
        bad = tmp_path / "requirements.csv"
        bad.write_text("requests==2.32.5")
        with pytest.raises(ValueError):
            parse_requirements(str(bad))

    def test_mehrere_pakete(self, tmp_path):
        """Mehrere Pakete werden alle geparst."""
        content = "requests==2.32.5\npillow==10.4.0\ncryptography>=42.0.0\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert names == {"requests", "pillow", "cryptography"}

    def test_version_installed_bleibt_none(self, tmp_path):
        """Parser setzt version_installed nie — Aufloesung passiert separat."""
        content = "requests==2.32.5\npillow>=10.0\ncryptography\n"
        path = _write_requirements(tmp_path, content)
        deps = parse_requirements(path)
        assert len(deps) == 3
        assert all(d.version_installed is None for d in deps)


class TestNormalizeName:
    def test_lowercase(self):
        assert _normalize_name("Requests") == "requests"

    def test_dots_to_dashes(self):
        assert _normalize_name("my.package") == "my-package"

    def test_underscores_to_dashes(self):
        assert _normalize_name("my_package") == "my-package"

    def test_multiple_separators(self):
        assert _normalize_name("my--package") == "my-package"


# ---------------------------------------------------------------------------
# 2. is_version_affected
# ---------------------------------------------------------------------------


class TestIsVersionAffected:
    def test_version_im_bereich(self):
        """Version liegt im affected-Bereich."""
        assert is_version_affected("2.31.0", ">=2.0,<2.32") is True

    def test_version_ausserhalb(self):
        """Version liegt ausserhalb des affected-Bereichs."""
        assert is_version_affected("2.32.0", ">=2.0,<2.32") is False

    def test_version_exakt_an_grenze_exklusiv(self):
        """Version exakt an der exclusiven oberen Grenze gilt als nicht betroffen."""
        assert is_version_affected("2.32.0", ">=2.0,<2.32.0") is False

    def test_version_exakt_an_unterer_grenze(self):
        """Version exakt an der inclusiven unteren Grenze ist betroffen."""
        assert is_version_affected("2.0", ">=2.0,<2.32") is True

    def test_leere_version(self):
        """Leere Version ist nicht auswertbar → None (Tri-State)."""
        assert is_version_affected("", ">=2.0,<2.32") is None

    def test_unbekannter_spec(self):
        """'unbekannt' als Spec ist nicht auswertbar → None (Tri-State)."""
        assert is_version_affected("2.31.0", "unbekannt") is None

    def test_ungueltige_version(self):
        """Ungueltiges Versionsformat ist nicht auswertbar → None."""
        assert is_version_affected("not-a-version", ">=2.0,<2.32") is None

    def test_ungueltige_spec(self):
        """Ungueltiger Spec ist nicht auswertbar → None (Tri-State)."""
        assert is_version_affected("2.31.0", "INVALID_SPEC") is None

    def test_git_range_spec_nicht_auswertbar(self):
        """Commit-SHA als Range-Grenze (GIT-Range) → None statt False."""
        assert is_version_affected("2.31.0", ">=6a7b8c9d0e1f") is None

    def test_lange_versions_liste_match(self):
        """OR-Liste mit >20 Eintraegen: spaete Eintraege matchen (kein Cut)."""
        spec = ",".join(f"==1.0.{i}" for i in range(30))
        assert is_version_affected("1.0.29", spec) is True
        assert is_version_affected("1.0.99", spec) is False

    def test_pinned_eq_spec(self):
        """Explizit gepinnte Version im Spec ist betroffen."""
        assert is_version_affected("2.31.0", "==2.31.0") is True

    def test_pinned_eq_spec_mismatch(self):
        """Explizit gepinnte Version passt nicht zum Spec."""
        assert is_version_affected("2.31.0", "==2.30.0") is False


# ---------------------------------------------------------------------------
# 3. analyzer — analyze_dependencies
# ---------------------------------------------------------------------------


class TestAnalyzeDependencies:
    def test_betroffenes_package_gefunden(self):
        """Package mit Vuln im affected-Bereich wird als Vulnerability erkannt."""
        dep = _make_dep("requests", "2.31.0", "==2.31.0")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.HIGH)
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1
        assert result.vulnerabilities[0].package_name == "requests"

    def test_nicht_betroffene_version_kein_finding(self):
        """Package mit Vuln aber Version ausserhalb des Bereichs → kein Finding."""
        dep = _make_dep("requests", "2.32.0", "==2.32.0")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 0

    def test_unpinned_package_erkannt(self):
        """Unpinned Packages werden in unpinned_dependencies aufgefuehrt."""
        dep = _make_dep("requests", None, ">=2.0")
        result = analyze_dependencies([dep], {})
        assert len(result.unpinned_dependencies) == 1
        assert result.unpinned_dependencies[0].name == "requests"

    def test_package_ohne_vuln_ist_ok(self):
        """Package ohne bekannte Vulns hat keine Findings."""
        dep = _make_dep("pillow", "10.4.0")
        result = analyze_dependencies([dep], {})
        assert result.total_vulnerabilities == 0
        assert result.total_dependencies == 1

    def test_severity_summary_korrekt(self):
        """severity_summary zaehlt Vulnerabilities je Schweregrad."""
        dep = _make_dep("requests", "2.31.0")
        vulns = [
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.CRITICAL),
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.HIGH),
        ]
        result = analyze_dependencies([dep], {"requests": vulns})
        assert result.severity_summary.get(VulnSeverity.CRITICAL.value, 0) == 1
        assert result.severity_summary.get(VulnSeverity.HIGH.value, 0) == 1

    def test_vulns_sortiert_nach_severity(self):
        """Vulnerabilities werden nach Severity sortiert (KRITISCH zuerst)."""
        dep = _make_dep("requests", "2.31.0")
        vulns = [
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.LOW),
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.CRITICAL),
        ]
        result = analyze_dependencies([dep], {"requests": vulns})
        assert result.vulnerabilities[0].severity == VulnSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 3a. Drop-Gate — server-bestaetigte Advisories nicht still verwerfen
# ---------------------------------------------------------------------------


class TestDropGateT356:
    """Lokales Matching darf OSV-Treffer nur mit eindeutigem False verwerfen.

    Vorbedingung des Analyzers: Die OSV-Abfrage lief MIT der effektiven
    Version — die Antwort ist serverseitig nach Betroffenheit gefiltert.
    Nicht-auswertbare Specs (None) zaehlen deshalb als betroffen.
    """

    def test_spec_unbekannt_bleibt_gemeldet(self):
        """Spec 'unbekannt' → Treffer bleibt in vulnerabilities."""
        dep = _make_dep("requests", "2.31.0", "==2.31.0")
        vuln = _make_vuln("requests", "unbekannt")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1
        assert result.unverified_vulnerabilities == []

    def test_git_range_spec_bleibt_gemeldet(self):
        """Unparsebarer GIT-Commit-Range → Treffer bleibt gemeldet."""
        dep = _make_dep("requests", "2.31.0", "==2.31.0")
        vuln = _make_vuln("requests", ">=6a7b8c9d0e1f")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1

    def test_lange_versionsliste_spaeter_treffer_gemeldet(self):
        """Treffer jenseits des frueheren versions[:20]-Cuts bleibt gemeldet."""
        dep = _make_dep("requests", "1.0.25", "==1.0.25")
        spec = ",".join(f"==1.0.{i}" for i in range(30))
        vuln = _make_vuln("requests", spec)
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1

    def test_eindeutiges_false_verwirft_weiterhin(self):
        """Nachweislich nicht betroffene Version wird weiter verworfen."""
        dep = _make_dep("requests", "2.32.0", "==2.32.0")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 0


# ---------------------------------------------------------------------------
# 3b. — Versionsabgleich: Pin > installierte Version > unbekannt
# ---------------------------------------------------------------------------


class TestVersionsabgleichT356:
    """Pin gewinnt vor installierter Version; ohne beides → „Version unbekannt"."""

    def test_effective_version_pin_gewinnt(self):
        """effective_version liefert den Pin, auch wenn installiert abweicht."""
        dep = _make_dep("requests", "2.32.0", "==2.32.0")
        dep.version_installed = "2.31.0"
        assert dep.effective_version() == "2.32.0"

    def test_effective_version_faellt_auf_installiert_zurueck(self):
        """Ohne Pin liefert effective_version die installierte Version."""
        dep = _make_dep("requests", None, ">=2.0")
        dep.version_installed = "2.31.0"
        assert dep.effective_version() == "2.31.0"

    def test_effective_version_none_ohne_beides(self):
        """Ohne Pin und ohne installierte Version → None."""
        dep = _make_dep("requests", None, ">=2.0")
        assert dep.effective_version() is None

    def test_pin_gewinnt_pin_nicht_betroffen(self):
        """Pin (sauber) gewinnt vor installierter Version (betroffen)."""
        dep = _make_dep("requests", "2.32.0", "==2.32.0")
        dep.version_installed = "2.31.0"
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 0
        assert result.unverified_vulnerabilities == []

    def test_pin_gewinnt_pin_betroffen(self):
        """Pin (betroffen) gewinnt vor installierter Version (sauber)."""
        dep = _make_dep("requests", "2.31.0", "==2.31.0")
        dep.version_installed = "2.32.0"
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1

    def test_installierte_version_greift_bei_fehlendem_pin(self):
        """Ohne Pin wird die installierte Version abgeglichen — betroffen."""
        dep = _make_dep("requests", None, ">=2.0")
        dep.version_installed = "2.31.0"
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 1
        assert result.unverified_vulnerabilities == []

    def test_installierte_version_greift_nicht_betroffen(self):
        """Ohne Pin, installierte Version ausserhalb des Bereichs → 0 Findings."""
        dep = _make_dep("requests", None, ">=2.0")
        dep.version_installed = "2.32.0"
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        result = analyze_dependencies([dep], {"requests": [vuln]})
        assert result.total_vulnerabilities == 0
        assert result.unverified_vulnerabilities == []

    def test_ohne_beides_kategorie_version_unbekannt(self):
        """Ohne Pin + ohne installierte Version → eigene Kategorie, keine Counts."""
        dep = _make_dep("requests", None, ">=2.0")
        vulns = [
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.CRITICAL),
            _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.HIGH),
        ]
        result = analyze_dependencies([dep], {"requests": vulns})
        assert result.total_vulnerabilities == 0
        assert result.critical_count() == 0
        assert result.high_count() == 0
        assert result.severity_summary == {}
        assert result.unverified_count() == 2
        assert result.unverified_dependencies == [dep]

    def test_unverified_nach_severity_sortiert(self):
        """unverified_vulnerabilities sind nach Severity sortiert."""
        dep = _make_dep("requests", None, ">=2.0")
        vulns = [
            _make_vuln("requests", severity=VulnSeverity.LOW),
            _make_vuln("requests", severity=VulnSeverity.CRITICAL),
        ]
        result = analyze_dependencies([dep], {"requests": vulns})
        assert result.unverified_vulnerabilities[0].severity == VulnSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 3c. — installed_versions-Helper (data/)
# ---------------------------------------------------------------------------


class TestResolveInstalledVersions:
    """Aufloesung installierter Versionen via importlib.metadata."""

    def test_unpinned_wird_aufgeloest(self):
        """pytest ist in der Test-Umgebung sicher installiert → Version gesetzt."""
        from importlib import metadata

        from tools.dependency_auditor.data.installed_versions import (
            resolve_installed_versions,
        )

        dep = _make_dep("pytest", None, ">=1.0")
        resolve_installed_versions([dep])
        assert dep.version_installed == metadata.version("pytest")

    def test_gepinnte_dependency_wird_uebersprungen(self):
        """Bei vorhandenem ==-Pin wird nicht aufgeloest (Pin gewinnt ohnehin)."""
        from tools.dependency_auditor.data.installed_versions import (
            resolve_installed_versions,
        )

        dep = _make_dep("pytest", "1.0.0", "==1.0.0")
        resolve_installed_versions([dep])
        assert dep.version_installed is None

    def test_nicht_installiertes_paket_bleibt_none(self):
        """Unbekanntes Package → version_installed bleibt None, kein Raten."""
        from tools.dependency_auditor.data.installed_versions import (
            resolve_installed_versions,
        )

        dep = _make_dep("finlai-paket-das-es-nicht-gibt-xyz", None, ">=1.0")
        resolve_installed_versions([dep])
        assert dep.version_installed is None


# ---------------------------------------------------------------------------
# 4. pypi_advisory_client (gemockt)
# ---------------------------------------------------------------------------


class TestPyPIAdvisoryClient:
    """Tests fuer PyPIAdvisoryClient mit gemocktem HTTP-Client."""

    _OSV_2_VULNS = {
        "vulns": [
            {
                "id": "GHSA-abcd-1234-5678",
                "summary": "Buffer overflow in PKCS12",
                "affected": [
                    {
                        "package": {"name": "cryptography", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "38.0.0"},
                                    {"fixed": "42.0.4"},
                                ],
                            }
                        ],
                    }
                ],
                "database_specific": {"severity": "CRITICAL"},
            },
            {
                "id": "GHSA-efgh-5678-9012",
                "summary": "DoS via crafted input",
                "affected": [
                    {
                        "package": {"name": "cryptography", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "41.0.0"},
                                ],
                            }
                        ],
                    }
                ],
                "database_specific": {"severity": "HIGH"},
            },
        ]
    }

    def _make_client_with_mock(self, response_data: dict) -> PyPIAdvisoryClient:
        """Erstellt PyPIAdvisoryClient mit gemocktem HTTP-Client."""
        mock_response = MagicMock()
        mock_response.json.return_value = response_data
        mock_response.raise_for_status.return_value = None

        mock_http = MagicMock()
        mock_http.post.return_value = mock_response

        client = PyPIAdvisoryClient.__new__(PyPIAdvisoryClient)
        client._client = mock_http
        return client

    def test_zwei_vulns_aus_response(self):
        """OSV-Response mit 2 Vulns → 2 VulnerabilityInfo-Objekte."""
        client = self._make_client_with_mock(self._OSV_2_VULNS)
        result = client.query_vulnerabilities("cryptography", "41.0.0")
        assert len(result) == 2
        ids = {v.vuln_id for v in result}
        assert "GHSA-abcd-1234-5678" in ids
        assert "GHSA-efgh-5678-9012" in ids

    def test_leere_response_gibt_leere_liste(self):
        """Leere OSV-Response gibt leere Liste zurueck."""
        client = self._make_client_with_mock({"vulns": []})
        result = client.query_vulnerabilities("requests", "2.32.5")
        assert result == []

    def test_fehlende_vulns_key(self):
        """Response ohne 'vulns'-Key gibt leere Liste zurueck."""
        client = self._make_client_with_mock({})
        result = client.query_vulnerabilities("requests", "2.32.5")
        assert result == []

    def test_api_fehler_kein_crash(self):
        """HTTP-Fehler fuehrt zu leerer Liste, kein Crash."""
        mock_http = MagicMock()
        mock_http.post.side_effect = ConnectionError("Netzwerkfehler")

        client = PyPIAdvisoryClient.__new__(PyPIAdvisoryClient)
        client._client = mock_http

        result = client.query_vulnerabilities("requests", "2.32.5")
        assert result == []

    def test_severity_mapping_critical(self):
        """GitHub-Advisory CRITICAL wird auf VulnSeverity.CRITICAL gemapt."""
        client = self._make_client_with_mock(self._OSV_2_VULNS)
        result = client.query_vulnerabilities("cryptography", "41.0.0")
        crit = next(v for v in result if v.vuln_id == "GHSA-abcd-1234-5678")
        assert crit.severity == VulnSeverity.CRITICAL

    def test_fixed_version_extrahiert(self):
        """Fixed-Version wird aus OSV-Events korrekt extrahiert."""
        client = self._make_client_with_mock(self._OSV_2_VULNS)
        result = client.query_vulnerabilities("cryptography", "41.0.0")
        vuln = next(v for v in result if v.vuln_id == "GHSA-abcd-1234-5678")
        assert vuln.fixed_version == "42.0.4"

    def test_affected_range_extrahiert(self):
        """Affected-Range wird als PEP-440-Spec extrahiert."""
        client = self._make_client_with_mock(self._OSV_2_VULNS)
        result = client.query_vulnerabilities("cryptography", "41.0.0")
        vuln = next(v for v in result if v.vuln_id == "GHSA-abcd-1234-5678")
        assert "38.0.0" in vuln.affected_versions
        assert "42.0.4" in vuln.affected_versions

    def test_url_korrekt_aufgebaut(self):
        """Advisory-URL wird korrekt aus der vuln_id aufgebaut."""
        client = self._make_client_with_mock(self._OSV_2_VULNS)
        result = client.query_vulnerabilities("cryptography", "41.0.0")
        assert all(v.url.startswith("https://osv.dev/vulnerability/") for v in result)

    # ------------------------------------------------------------------
    # Drop-Gate — Range-Typen + Versions-Listen
    # ------------------------------------------------------------------

    @staticmethod
    def _osv_single(affected_entry: dict) -> dict:
        """Baut eine OSV-Response mit genau einem Vuln-Eintrag."""
        return {
            "vulns": [
                {
                    "id": "GHSA-t356-0001",
                    "summary": "Range-Typ-Test",
                    "affected": [affected_entry],
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        }

    def test_git_range_wird_uebersprungen(self):
        """GIT-Range zuerst im Eintrag → ECOSYSTEM-Range gewinnt trotzdem."""
        client = self._make_client_with_mock(
            self._osv_single(
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/psf/requests",
                            "events": [
                                {"introduced": "6a7b8c9d0e1f"},
                                {"fixed": "deadbeef0123"},
                            ],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.0"}, {"fixed": "2.32.0"}],
                        },
                    ],
                }
            )
        )
        result = client.query_vulnerabilities("requests", "2.31.0")
        assert result[0].affected_versions == ">=2.0,<2.32.0"
        # Boy-Scout: Fix-Version stammt nicht aus dem GIT-Range (kein SHA).
        assert result[0].fixed_version == "2.32.0"

    def test_nur_git_range_faellt_auf_versionsliste_zurueck(self):
        """Nur GIT-Ranges vorhanden → explizite Versionsliste wird genutzt."""
        client = self._make_client_with_mock(
            self._osv_single(
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"introduced": "6a7b8c9d0e1f"}],
                        }
                    ],
                    "versions": ["2.30.0", "2.31.0"],
                }
            )
        )
        result = client.query_vulnerabilities("requests", "2.31.0")
        assert result[0].affected_versions == "==2.30.0,==2.31.0"

    def test_nur_git_range_ohne_versionsliste_unbekannt(self):
        """Nur GIT-Range, keine Versionsliste → Spec 'unbekannt'."""
        client = self._make_client_with_mock(
            self._osv_single(
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"introduced": "6a7b8c9d0e1f"}],
                        }
                    ],
                }
            )
        )
        result = client.query_vulnerabilities("requests", "2.31.0")
        assert result[0].affected_versions == "unbekannt"

    def test_versionsliste_ohne_trunkierung(self):
        """>20 explizite Versionen landen VOLLSTAENDIG im Spec-String."""
        versions = [f"1.0.{i}" for i in range(30)]
        client = self._make_client_with_mock(
            self._osv_single(
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "versions": versions,
                }
            )
        )
        result = client.query_vulnerabilities("requests", "1.0.25")
        spec = result[0].affected_versions
        assert "==1.0.29" in spec
        assert spec.count("==") == 30


# ---------------------------------------------------------------------------
# 5. audit_service
# ---------------------------------------------------------------------------


class TestAuditService:
    def _make_service(
        self, vulns_return: list | None = None
    ) -> tuple[AuditService, MagicMock]:
        """Erstellt AuditService mit gemocktem Advisory-Source."""
        mock_advisory = MagicMock()
        mock_advisory.query_vulnerabilities.return_value = vulns_return or []
        service = AuditService(advisory_source=mock_advisory)
        return service, mock_advisory

    def test_audit_requirements_vollstaendiger_flow(self, tmp_path):
        """audit_requirements durchlaeuft vollstaendigen Flow (gemockt)."""
        path = _write_requirements(tmp_path, "requests==2.32.5\npillow==10.4.0\n")
        service, mock_advisory = self._make_service()

        result = service.audit_requirements(path)

        assert result.total_dependencies == 2
        assert result.error is None
        assert mock_advisory.query_vulnerabilities.call_count == 2

    def test_audit_requirements_mit_vuln(self, tmp_path):
        """audit_requirements meldet Vulnerability wenn Advisory eines zurueckgibt."""
        path = _write_requirements(tmp_path, "requests==2.31.0\n")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0", severity=VulnSeverity.HIGH)
        service, _ = self._make_service(vulns_return=[vuln])

        result = service.audit_requirements(path)

        assert result.total_vulnerabilities == 1
        assert result.high_count() == 1

    def test_audit_requirements_fehlende_datei(self):
        """Nicht existierende Datei gibt Ergebnis mit error-Feld zurueck."""
        service, _ = self._make_service()
        result = service.audit_requirements("/nicht/vorhanden/requirements.txt")
        assert result.error is not None

    def test_audit_self_findet_requirements_txt(self):
        """audit_self findet requirements/base.txt mit echten Packages."""
        from pathlib import Path

        service, mock_advisory = self._make_service()
        base_txt = Path(__file__).resolve().parents[1] / "requirements" / "base.txt"
        result = service.audit_requirements(str(base_txt))
        # Kein Fehler → Datei wurde gefunden und geparst
        assert result.error is None or "nicht gefunden" not in (result.error or "")
        # Advisory wurde mindestens einmal aufgerufen (Packages vorhanden)
        assert mock_advisory.query_vulnerabilities.call_count >= 1

    def test_progress_callback_wird_aufgerufen(self, tmp_path):
        """progress_callback wird fuer jedes Package aufgerufen."""
        path = _write_requirements(
            tmp_path, "requests==2.32.5\npillow==10.4.0\ncryptography>=42.0\n"
        )
        service, _ = self._make_service()

        calls = []
        service.audit_requirements(
            path, progress_callback=lambda c, t, p: calls.append((c, t, p))
        )

        assert len(calls) == 3
        # Erster Aufruf: aktuell=1, gesamt=3
        assert calls[0][0] == 1
        assert calls[0][1] == 3
        # Letzter Aufruf: aktuell=3
        assert calls[-1][0] == 3

    def test_repo_fehler_bricht_nicht_ab(self, tmp_path):
        """Fehler beim Persistieren bricht audit_requirements nicht ab."""
        path = _write_requirements(tmp_path, "requests==2.32.5\n")
        mock_advisory = MagicMock()
        mock_advisory.query_vulnerabilities.return_value = []
        mock_repo = MagicMock()
        mock_repo.speichere_audit.side_effect = RuntimeError("DB kaputt")

        service = AuditService(advisory_source=mock_advisory, audit_repo=mock_repo)
        result = service.audit_requirements(path)

        assert result.error is None
        assert result.total_dependencies == 1

    # ------------------------------------------------------------------
    # resolve_installed-Fallback im Selbst-Audit
    # ------------------------------------------------------------------

    def test_resolve_installed_setzt_installierte_version(self, tmp_path):
        """resolve_installed=True loest unpinned Versionen aus der Umgebung auf."""
        from importlib import metadata

        path = _write_requirements(tmp_path, "pytest>=1.0\n")
        service, mock_advisory = self._make_service()

        result = service.audit_requirements(path, resolve_installed=True)

        installed = metadata.version("pytest")
        assert result.dependencies[0].version_installed == installed
        # Effektive Version wird an die Advisory-Quelle durchgereicht —
        # OSV filtert dann serverseitig schon nach Version.
        mock_advisory.query_vulnerabilities.assert_called_once_with(
            "pytest", installed
        )

    def test_ohne_resolve_installed_bleibt_version_unbekannt(self, tmp_path):
        """Default (fremde Datei): lokale Umgebung wird NICHT herangezogen."""
        path = _write_requirements(tmp_path, "pytest>=1.0\n")
        service, mock_advisory = self._make_service()

        result = service.audit_requirements(path)

        assert result.dependencies[0].version_installed is None
        mock_advisory.query_vulnerabilities.assert_called_once_with("pytest", None)

    def test_resolve_installed_pin_gewinnt(self, tmp_path):
        """Gepinnte Version wird unveraendert an die Advisory-Quelle gereicht."""
        path = _write_requirements(tmp_path, "pytest==1.0.0\n")
        service, mock_advisory = self._make_service()

        result = service.audit_requirements(path, resolve_installed=True)

        assert result.dependencies[0].version_pinned == "1.0.0"
        assert result.dependencies[0].version_installed is None
        mock_advisory.query_vulnerabilities.assert_called_once_with(
            "pytest", "1.0.0"
        )

    def test_audit_self_aktiviert_resolve_installed(self, monkeypatch):
        """audit_self reicht resolve_installed=True an audit_requirements durch."""
        from datetime import UTC, datetime

        from tools.dependency_auditor.domain.models import DependencyAuditResult

        service, _ = self._make_service()
        captured: dict = {}

        def _fake_audit_requirements(
            file_path, progress_callback=None, *, resolve_installed=False
        ):
            captured["resolve_installed"] = resolve_installed
            return DependencyAuditResult(
                source_file=file_path,
                scan_timestamp=datetime.now(UTC).isoformat(),
                total_dependencies=0,
                total_vulnerabilities=0,
            )

        monkeypatch.setattr(service, "audit_requirements", _fake_audit_requirements)
        service.audit_self()

        assert captured["resolve_installed"] is True

    def test_unverified_advisories_im_ergebnis(self, tmp_path):
        """Unpinned + nicht installiert + Advisory → Kategorie „Version unbekannt"."""
        path = _write_requirements(
            tmp_path, "finlai-paket-das-es-nicht-gibt-xyz>=1.0\n"
        )
        vuln = _make_vuln(
            "finlai-paket-das-es-nicht-gibt-xyz",
            ">=0,<99",
            severity=VulnSeverity.CRITICAL,
        )
        service, _ = self._make_service(vulns_return=[vuln])

        result = service.audit_requirements(path, resolve_installed=True)

        assert result.total_vulnerabilities == 0
        assert result.critical_count() == 0
        assert result.unverified_count() == 1


class _SpyEmitter:
    """Zeichnet emit-Aufrufe inkl. reconcile_tool-Kwarg auf."""

    def __init__(self) -> None:
        self.calls: list[tuple[list, str | None]] = []

    def emit(self, findings, *, reconcile_tool: str | None = None) -> None:
        self.calls.append((list(findings), reconcile_tool))


class TestAuditServiceReconcile:
    """ Review-Fix: Self-Audit emittiert mit Voll-Sync (Reconcile)."""

    def _make_service(
        self, vulns_return: list | None = None
    ) -> tuple[AuditService, _SpyEmitter]:
        mock_advisory = MagicMock()
        mock_advisory.query_vulnerabilities.return_value = vulns_return or []
        spy = _SpyEmitter()
        service = AuditService(advisory_source=mock_advisory, ki_todo_emitter=spy)
        return service, spy

    def test_self_audit_emittiert_mit_reconcile(self, tmp_path):
        """resolve_installed=True (Self-Audit) → reconcile_tool gesetzt."""
        path = _write_requirements(tmp_path, "requests==2.31.0\n")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        service, spy = self._make_service(vulns_return=[vuln])

        service.audit_requirements(path, resolve_installed=True)

        assert len(spy.calls) == 1
        findings, reconcile = spy.calls[0]
        assert reconcile == "dependency_auditor"
        assert len(findings) == 1

    def test_self_audit_ohne_findings_emittiert_trotzdem(self, tmp_path):
        """Leere Findings-Liste MIT reconcile → offene Karten werden geschlossen.

        Der ki_todo_emitter early-returnt bei emit([]) nur ohne
        reconcile_tool — der Self-Audit muss den Aufruf deshalb immer
        absetzen, sonst wird „Pakete ohne verifizierbare Version" nach
        dem Pinnen nie auto-erledigt.
        """
        path = _write_requirements(tmp_path, "requests==2.32.5\n")
        service, spy = self._make_service()

        service.audit_requirements(path, resolve_installed=True)

        assert spy.calls == [([], "dependency_auditor")]

    def test_fremddatei_emittiert_ohne_reconcile(self, tmp_path):
        """Default-Pfad (fremde Datei) → kein Voll-Sync (kein reconcile)."""
        path = _write_requirements(tmp_path, "requests==2.31.0\n")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        service, spy = self._make_service(vulns_return=[vuln])

        service.audit_requirements(path)

        assert len(spy.calls) == 1
        assert spy.calls[0][1] is None

    def test_audit_file_emittiert_ohne_reconcile(self, tmp_path):
        """audit_file (Fremddatei-Pfad) → kein Voll-Sync (kein reconcile)."""
        path = _write_requirements(tmp_path, "requests==2.31.0\n")
        vuln = _make_vuln("requests", ">=2.0,<2.32.0")
        service, spy = self._make_service(vulns_return=[vuln])

        service.audit_file(path)

        assert len(spy.calls) == 1
        assert spy.calls[0][1] is None
