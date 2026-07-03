"""
test_dependency_auditor_session3 — Tests fuer Session-3-Aenderungen.

Prueft:
1. analyzer.is_version_affected — Versionsbereich-Matching korrekt
2. analyzer.is_version_affected — Multi-==-Liste (OR-Semantik)
3. analyzer.analyze_dependencies — Unpinned-Packages erhalten Vulns
4. json_parser — Format 1 (Objekt-Liste), Format 2 (Dict), Format 3 (Strings)
5. xlsx_parser — Name + Version aus Sheet erkannt
6. file_parser — Dispatch auf korrekte Parser
7. audit_service.audit_file — Pfad-Routing (kein Netzwerk noetig)

Alle Tests ohne Netzwerk — keine OSV-API-Calls.

Author: Patrick Riederich
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def _make_vuln(
    pkg: str = "requests",
    affected: str = ">=2.0,<2.32",
    severity: VulnSeverity = VulnSeverity.HIGH,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        vuln_id="GHSA-test-0001",
        package_name=pkg,
        affected_versions=affected,
        fixed_version="2.32.0",
        severity=severity,
        summary="Test-Vulnerability",
        url="https://osv.dev/vulnerability/GHSA-test-0001",
    )


def _make_dep(
    name: str = "requests",
    version: str | None = "2.31.0",
    spec: str = "==2.31.0",
    line: int = 1,
) -> DependencyInfo:
    return DependencyInfo(
        name=name, version_pinned=version, version_spec=spec, line_number=line
    )


# ---------------------------------------------------------------------------
# 1. is_version_affected — Bereichs-Matching
# ---------------------------------------------------------------------------


def test_is_version_affected_in_range() -> None:
    """Version im Bereich >= einschliesslich fixed < faellt rein."""
    assert is_version_affected("2.31.0", ">=2.0,<2.32") is True


def test_is_version_affected_fixed_version_excluded() -> None:
    """Die Fix-Version selbst ist nicht mehr betroffen."""
    assert is_version_affected("2.32.0", ">=2.0,<2.32") is False


def test_is_version_affected_unbekannt() -> None:
    """'unbekannt' ist nicht auswertbar → None (Tri-State)."""
    assert is_version_affected("2.31.0", "unbekannt") is None


def test_is_version_affected_empty_spec() -> None:
    """Leerer Spec ist nicht auswertbar → None (Tri-State)."""
    assert is_version_affected("2.31.0", "") is None


def test_is_version_affected_empty_version() -> None:
    """Leere Version ist nicht auswertbar → None (Tri-State)."""
    assert is_version_affected("", ">=2.0,<2.32") is None


# ---------------------------------------------------------------------------
# 2. is_version_affected — Multi-==-Liste (OR-Semantik)
# ---------------------------------------------------------------------------


def test_is_version_affected_multi_eq_match() -> None:
    """Version in expliziter OR-Liste erkannt."""
    assert is_version_affected("2.31.0", "==2.30.0,==2.31.0,==2.31.1") is True


def test_is_version_affected_multi_eq_no_match() -> None:
    """Version nicht in OR-Liste."""
    assert is_version_affected("2.32.0", "==2.30.0,==2.31.0,==2.31.1") is False


def test_is_version_affected_single_eq() -> None:
    """Einzelner ==-Spec funktioniert korrekt."""
    assert is_version_affected("2.31.0", "==2.31.0") is True
    assert is_version_affected("2.32.0", "==2.31.0") is False


# ---------------------------------------------------------------------------
# 3. analyze_dependencies — Unpinned-Packages erhalten Vulns
# ---------------------------------------------------------------------------


def test_analyze_dependencies_unpinned_gets_vulns() -> None:
    """Unpinned ohne installierte Version → Kategorie „Version unbekannt".

    Vor wurden ALLE Advisories eines unpinned Packages als
    Voll-Severity-Vulnerabilities gemeldet (Score-Inflation). Jetzt landen
    sie in unverified_vulnerabilities und zaehlen nicht in severity_summary.
    """
    dep_unpinned = _make_dep("flask", version=None, spec=">=2.0")
    vuln = _make_vuln("flask", ">=0,<3.0")
    result = analyze_dependencies([dep_unpinned], {"flask": [vuln]})
    assert result.vulnerabilities == []
    assert result.total_vulnerabilities == 0
    assert result.unverified_vulnerabilities == [vuln]
    assert result.unverified_count() == 1
    assert dep_unpinned in result.unpinned_dependencies
    assert dep_unpinned in result.unverified_dependencies
    assert result.severity_summary == {}


def test_analyze_dependencies_unpinned_mit_installierter_version() -> None:
    """Unpinned MIT installierter Version wird normal abgeglichen."""
    dep = _make_dep("flask", version=None, spec=">=2.0")
    dep.version_installed = "2.5.0"
    vuln = _make_vuln("flask", ">=0,<3.0")
    result = analyze_dependencies([dep], {"flask": [vuln]})
    assert len(result.vulnerabilities) == 1
    assert result.unverified_vulnerabilities == []
    assert dep in result.unpinned_dependencies


def test_analyze_dependencies_pinned_in_range() -> None:
    """Gepinnte Version im betroffenen Bereich erscheint in vulnerabilities."""
    dep = _make_dep("requests", "2.31.0", "==2.31.0")
    vuln = _make_vuln("requests", ">=2.0,<2.32")
    result = analyze_dependencies([dep], {"requests": [vuln]})
    assert len(result.vulnerabilities) == 1


def test_analyze_dependencies_pinned_fixed_not_affected() -> None:
    """Fix-Version ist NICHT mehr in vulnerabilities."""
    dep = _make_dep("requests", "2.32.0", "==2.32.0")
    vuln = _make_vuln("requests", ">=2.0,<2.32")
    result = analyze_dependencies([dep], {"requests": [vuln]})
    assert result.total_vulnerabilities == 0


def test_analyze_dependencies_no_vulns_for_package() -> None:
    """Keine Vulns fuer Package → leeres Result."""
    dep = _make_dep("flask", "2.3.0", "==2.3.0")
    result = analyze_dependencies([dep], {})
    assert result.total_vulnerabilities == 0
    assert result.total_dependencies == 1


# ---------------------------------------------------------------------------
# 4. json_parser
# ---------------------------------------------------------------------------


def test_json_parser_object_list(tmp_path: Path) -> None:
    """Format 1: Liste von Objekten mit name + version."""
    from tools.dependency_auditor.data.json_parser import parse_json_dependencies

    data = [
        {"name": "requests", "version": "2.31.0"},
        {"name": "flask", "version": "2.3.0"},
    ]
    f = tmp_path / "packages.json"
    f.write_text(json.dumps(data), encoding="utf-8")

    deps = parse_json_dependencies(str(f))
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version_pinned == "2.31.0"
    assert deps[1].name == "flask"


def test_json_parser_dict_format(tmp_path: Path) -> None:
    """Format 2: {'dependencies': {'pkg': 'version'}}."""
    from tools.dependency_auditor.data.json_parser import parse_json_dependencies

    data = {"dependencies": {"requests": "==2.31.0", "flask": ">=2.0"}}
    f = tmp_path / "deps.json"
    f.write_text(json.dumps(data), encoding="utf-8")

    deps = parse_json_dependencies(str(f))
    assert len(deps) == 2
    names = {d.name for d in deps}
    assert "requests" in names
    assert "flask" in names


def test_json_parser_string_list(tmp_path: Path) -> None:
    """Format 3: Liste von requirements-Strings."""
    from tools.dependency_auditor.data.json_parser import parse_json_dependencies

    data = ["requests==2.31.0", "flask>=2.0", "# Kommentar"]
    f = tmp_path / "reqs.json"
    f.write_text(json.dumps(data), encoding="utf-8")

    deps = parse_json_dependencies(str(f))
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version_pinned == "2.31.0"


def test_json_parser_empty_list(tmp_path: Path) -> None:
    """Leere Liste → leeres Ergebnis."""
    from tools.dependency_auditor.data.json_parser import parse_json_dependencies

    f = tmp_path / "empty.json"
    f.write_text("[]", encoding="utf-8")
    assert parse_json_dependencies(str(f)) == []


def test_json_parser_invalid_json(tmp_path: Path) -> None:
    """Ungültiges JSON → ValueError."""
    from tools.dependency_auditor.data.json_parser import parse_json_dependencies

    f = tmp_path / "bad.json"
    f.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Ungültiges JSON"):
        parse_json_dependencies(str(f))


# ---------------------------------------------------------------------------
# 5. xlsx_parser
# ---------------------------------------------------------------------------


def test_xlsx_parser_with_header(tmp_path: Path) -> None:
    """XLSX mit Name/Version-Header wird korrekt geparst."""
    pytest.importorskip("openpyxl")
    import openpyxl  # noqa: PLC0415

    from tools.dependency_auditor.data.xlsx_parser import parse_xlsx_dependencies

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["name", "version"])  # type: ignore[union-attr]
    ws.append(["requests", "2.31.0"])  # type: ignore[union-attr]
    ws.append(["flask", "2.3.0"])  # type: ignore[union-attr]
    f = tmp_path / "packages.xlsx"
    wb.save(str(f))

    deps = parse_xlsx_dependencies(str(f))
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version_pinned == "2.31.0"


def test_xlsx_parser_no_header(tmp_path: Path) -> None:
    """XLSX ohne erkennbaren Header: erste Spalte = Name, zweite = Version."""
    pytest.importorskip("openpyxl")
    import openpyxl  # noqa: PLC0415

    from tools.dependency_auditor.data.xlsx_parser import parse_xlsx_dependencies

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["requests", "2.31.0"])  # type: ignore[union-attr]
    ws.append(["flask", "2.3.0"])  # type: ignore[union-attr]
    f = tmp_path / "noheader.xlsx"
    wb.save(str(f))

    deps = parse_xlsx_dependencies(str(f))
    assert len(deps) == 2
    assert {d.name for d in deps} == {"requests", "flask"}


# ---------------------------------------------------------------------------
# 6. file_parser dispatch
# ---------------------------------------------------------------------------


def test_file_parser_dispatches_txt(tmp_path: Path) -> None:
    """file_parser leitet.txt an requirements_parser weiter."""
    from tools.dependency_auditor.data.file_parser import parse_dependency_file

    f = tmp_path / "reqs.txt"
    f.write_text("requests==2.31.0\nflask>=2.0\n", encoding="utf-8")

    deps = parse_dependency_file(str(f))
    assert len(deps) == 2
    assert deps[0].name == "requests"


def test_file_parser_dispatches_json(tmp_path: Path) -> None:
    """file_parser leitet.json an json_parser weiter."""
    from tools.dependency_auditor.data.file_parser import parse_dependency_file

    f = tmp_path / "packages.json"
    f.write_text(
        json.dumps([{"name": "requests", "version": "2.31.0"}]), encoding="utf-8"
    )

    deps = parse_dependency_file(str(f))
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_file_parser_unsupported_extension(tmp_path: Path) -> None:
    """Nicht-unterstuetzte Endung → ValueError."""
    from tools.dependency_auditor.data.file_parser import parse_dependency_file

    f = tmp_path / "data.csv"
    f.write_text("requests,2.31.0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Nicht unterstütztes"):
        parse_dependency_file(str(f))


# ---------------------------------------------------------------------------
# 7. audit_service.audit_file — nur Parsen testen (kein Netzwerk)
# ---------------------------------------------------------------------------


def test_audit_service_audit_file_txt(tmp_path: Path) -> None:
    """audit_file(.txt) liefert DependencyAuditResult ohne Netzwerk."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    from tools.dependency_auditor.application.audit_service import (
        AuditService,  # noqa: PLC0415
    )

    advisory_mock = MagicMock()
    advisory_mock.query_vulnerabilities.return_value = []

    service = AuditService(advisory_source=advisory_mock)
    f = tmp_path / "reqs.txt"
    f.write_text("requests==2.31.0\n", encoding="utf-8")

    result = service.audit_file(str(f))

    assert result.error is None
    assert result.total_dependencies == 1
    assert advisory_mock.query_vulnerabilities.call_count == 1


def test_audit_service_audit_file_json(tmp_path: Path) -> None:
    """audit_file(.json) liefert DependencyAuditResult ohne Netzwerk."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    from tools.dependency_auditor.application.audit_service import (
        AuditService,  # noqa: PLC0415
    )

    advisory_mock = MagicMock()
    advisory_mock.query_vulnerabilities.return_value = []

    service = AuditService(advisory_source=advisory_mock)
    f = tmp_path / "packages.json"
    f.write_text(
        json.dumps([{"name": "requests", "version": "2.31.0"}]), encoding="utf-8"
    )

    result = service.audit_file(str(f))

    assert result.error is None
    assert result.total_dependencies == 1


def test_audit_service_audit_file_unsupported_returns_error(tmp_path: Path) -> None:
    """audit_file mit nicht-unterstuetztem Format → DependencyAuditResult mit error."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    from tools.dependency_auditor.application.audit_service import (
        AuditService,  # noqa: PLC0415
    )

    advisory_mock = MagicMock()
    service = AuditService(advisory_source=advisory_mock)
    f = tmp_path / "data.csv"
    f.write_text("requests,2.31.0\n", encoding="utf-8")

    result = service.audit_file(str(f))

    assert result.error is not None
    assert "Nicht unterstütztes" in result.error


def test_audit_service_audit_file_with_vulns(tmp_path: Path) -> None:
    """audit_file meldet gematchte Vulns aus OSV-Mock."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    from tools.dependency_auditor.application.audit_service import (
        AuditService,  # noqa: PLC0415
    )

    vuln = _make_vuln("requests", ">=2.0,<2.32")
    advisory_mock = MagicMock()
    advisory_mock.query_vulnerabilities.return_value = [vuln]

    service = AuditService(advisory_source=advisory_mock)
    f = tmp_path / "reqs.txt"
    f.write_text("requests==2.31.0\n", encoding="utf-8")

    result = service.audit_file(str(f))

    assert result.total_vulnerabilities == 1
    assert result.vulnerabilities[0].vuln_id == "GHSA-test-0001"
