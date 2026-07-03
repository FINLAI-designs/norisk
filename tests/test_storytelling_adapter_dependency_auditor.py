"""test_storytelling_adapter_dependency_auditor (a)+(b)."""

from __future__ import annotations

from core.security.severity import Severity
from tools.dependency_auditor.application.storytelling_adapter import (
    audit_to_ki_inputs,
)
from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    DependencyInfo,
    VulnerabilityInfo,
    VulnSeverity,
)


def _vuln(
    vuln_id: str = "GHSA-1234",
    package_name: str = "requests",
    severity: VulnSeverity = VulnSeverity.HIGH,
    fixed_version: str | None = "2.32.5",
    summary: str = "Buffer Overflow im Header-Parser",
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        vuln_id=vuln_id,
        package_name=package_name,
        affected_versions=">=2.0,<2.32",
        fixed_version=fixed_version,
        severity=severity,
        summary=summary,
        url="https://example.test/adv-1",
    )


def _dep(
    name: str = "requests",
    version_pinned: str | None = "2.30.0",
) -> DependencyInfo:
    return DependencyInfo(
        name=name,
        version_pinned=version_pinned,
        version_spec=f"=={version_pinned}" if version_pinned else "",
        line_number=1,
    )


def _result(
    vulns: list[VulnerabilityInfo] | None = None,
    deps: list[DependencyInfo] | None = None,
    error: str | None = None,
    unverified_vulns: list[VulnerabilityInfo] | None = None,
    unverified_deps: list[DependencyInfo] | None = None,
) -> DependencyAuditResult:
    # None nutzt Default; explizite leere Liste bleibt leer.
    if vulns is None:
        vulns = [_vuln()]
    if deps is None:
        deps = [_dep()]
    return DependencyAuditResult(
        source_file="requirements.txt",
        scan_timestamp="2026-05-08T10:00:00Z",
        total_dependencies=len(deps),
        total_vulnerabilities=len(vulns),
        dependencies=deps,
        vulnerabilities=vulns,
        unverified_vulnerabilities=unverified_vulns or [],
        unverified_dependencies=unverified_deps or [],
        error=error,
    )


class TestVulnerableMapping:
    def test_basic(self) -> None:
        inputs = audit_to_ki_inputs(_result())
        assert len(inputs) == 1
        fi = inputs[0]
        assert fi.tool == "dependency_auditor"
        assert fi.finding_type == "vulnerable_package"
        assert fi.subject == "requests"
        assert fi.details["package"] == "requests"
        assert fi.details["version"] == "2.30.0"
        assert fi.details["cve_id"] == "GHSA-1234"
        assert fi.details["fixed_version"] == "2.32.5"

    def test_summary_durchgereicht(self) -> None:
        inputs = audit_to_ki_inputs(_result())
        assert "Buffer Overflow" in inputs[0].details["summary"]

    def test_evidence_id_eindeutig(self) -> None:
        inputs = audit_to_ki_inputs(_result())
        assert inputs[0].evidence_id == "requests#GHSA-1234"


class TestSeverityMapping:
    def test_critical(self) -> None:
        result = _result(vulns=[_vuln(severity=VulnSeverity.CRITICAL)])
        assert audit_to_ki_inputs(result)[0].severity == Severity.CRITICAL

    def test_high(self) -> None:
        result = _result(vulns=[_vuln(severity=VulnSeverity.HIGH)])
        assert audit_to_ki_inputs(result)[0].severity == Severity.HIGH

    def test_medium(self) -> None:
        result = _result(vulns=[_vuln(severity=VulnSeverity.MEDIUM)])
        assert audit_to_ki_inputs(result)[0].severity == Severity.MEDIUM

    def test_low(self) -> None:
        result = _result(vulns=[_vuln(severity=VulnSeverity.LOW)])
        assert audit_to_ki_inputs(result)[0].severity == Severity.LOW


class TestVersionLookup:
    def test_version_aus_dependencies(self) -> None:
        result = _result(
            vulns=[_vuln(package_name="urllib3")],
            deps=[_dep(name="urllib3", version_pinned="1.26.5")],
        )
        assert audit_to_ki_inputs(result)[0].details["version"] == "1.26.5"

    def test_version_unbekannt_wenn_keine_passende_dep(self) -> None:
        """Vuln fuer ein Package, das nicht in deps gelistet ist → '?'."""
        result = _result(
            vulns=[_vuln(package_name="ghost-package")],
            deps=[_dep(name="other-package", version_pinned="1.0")],
        )
        assert audit_to_ki_inputs(result)[0].details["version"] == "?"

    def test_version_unbekannt_wenn_unpinned(self) -> None:
        result = _result(
            vulns=[_vuln()],
            deps=[_dep(version_pinned=None)],
        )
        assert audit_to_ki_inputs(result)[0].details["version"] == "?"


class TestFixedVersion:
    def test_kein_fix_default_questionmark(self) -> None:
        result = _result(vulns=[_vuln(fixed_version=None)])
        assert audit_to_ki_inputs(result)[0].details["fixed_version"] == "?"


class TestEmptyAndError:
    def test_keine_vulns(self) -> None:
        result = _result(vulns=[])
        assert audit_to_ki_inputs(result) == []

    def test_audit_mit_error(self) -> None:
        result = _result(error="parse-error")
        assert audit_to_ki_inputs(result) == []


class TestEmptyGuards:
    """ Hotfix: Defekte VulnerabilityInfo ueberspringen statt Pydantic-ValidationError."""

    def test_leerer_package_name_uebersprungen(self) -> None:
        result = _result(vulns=[_vuln(package_name="")])
        assert audit_to_ki_inputs(result) == []

    def test_leere_vuln_id_uebersprungen(self) -> None:
        result = _result(vulns=[_vuln(vuln_id="")])
        assert audit_to_ki_inputs(result) == []


class TestUnverifiedAggregation:
    """: unverifizierte Findings → hoechstens EIN Hinweis-Finding."""

    def _unverified_result(
        self, n_pkgs: int = 3, advisories_per_pkg: int = 2
    ) -> DependencyAuditResult:
        deps = [
            _dep(name=f"paket-{i}", version_pinned=None) for i in range(n_pkgs)
        ]
        unverified = [
            _vuln(vuln_id=f"GHSA-{i}-{j}", package_name=f"paket-{i}")
            for i in range(n_pkgs)
            for j in range(advisories_per_pkg)
        ]
        return _result(
            vulns=[],
            deps=deps,
            unverified_vulns=unverified,
            unverified_deps=deps,
        )

    def test_genau_ein_aggregiertes_finding(self) -> None:
        """6 unverifizierte Advisories → genau 1 Finding, keine Einzel-Tasks."""
        inputs = audit_to_ki_inputs(self._unverified_result(3, 2))
        assert len(inputs) == 1
        assert inputs[0].finding_type == "unpinned_dependency"

    def test_hinweis_severity_niedrig(self) -> None:
        inputs = audit_to_ki_inputs(self._unverified_result())
        assert inputs[0].severity == Severity.LOW

    def test_hinweis_details(self) -> None:
        inputs = audit_to_ki_inputs(self._unverified_result(3, 2))
        details = inputs[0].details
        assert details["count"] == 3
        assert details["advisories"] == 6
        assert "paket-0" in details["packages"]

    def test_evidence_id_stabil(self) -> None:
        """Zwei Audits liefern dieselbe evidence_id → KiTodo-Dedup greift."""
        a = audit_to_ki_inputs(self._unverified_result())[0]
        b = audit_to_ki_inputs(self._unverified_result())[0]
        assert a.evidence_id == b.evidence_id

    def test_evidence_id_self_audit_diskriminator(self) -> None:
        """Self-Audit erhaelt den stabilen Suffix '#self'."""
        hint = audit_to_ki_inputs(self._unverified_result(), self_audit=True)[0]
        assert hint.evidence_id == (
            "dependency_auditor#versionsabgleich-unbekannt#self"
        )

    def test_evidence_id_fremddatei_haengt_an_quelle(self) -> None:
        """Fremddatei-Audits: sha8(source_file) als Suffix — pro Datei stabil."""
        result_a = self._unverified_result()
        result_a.source_file = "C:/kunde/requirements.txt"
        result_b = self._unverified_result()
        result_b.source_file = "C:/anderer-kunde/requirements.txt"

        id_a1 = audit_to_ki_inputs(result_a)[0].evidence_id
        id_a2 = audit_to_ki_inputs(result_a)[0].evidence_id
        id_b = audit_to_ki_inputs(result_b)[0].evidence_id

        assert id_a1 == id_a2
        assert id_a1 != id_b
        assert id_a1.startswith("dependency_auditor#versionsabgleich-unbekannt#")

    def test_evidence_id_self_und_fremd_kollidieren_nicht(self) -> None:
        """Self-Audit und Fremdscan derselben Datei → verschiedene Karten."""
        result = self._unverified_result()
        id_self = audit_to_ki_inputs(result, self_audit=True)[0].evidence_id
        id_fremd = audit_to_ki_inputs(result)[0].evidence_id
        assert id_self != id_fremd

    def test_verifizierte_weiterhin_pro_cve(self) -> None:
        """Mix: verifizierte Vulns pro CVE + genau 1 Aggregat-Hinweis."""
        deps = [_dep(name="requests", version_pinned="2.30.0")]
        unverified_dep = _dep(name="ghost", version_pinned=None)
        result = _result(
            vulns=[_vuln(vuln_id="GHSA-a"), _vuln(vuln_id="GHSA-b")],
            deps=[*deps, unverified_dep],
            unverified_vulns=[_vuln(vuln_id="GHSA-x", package_name="ghost")],
            unverified_deps=[unverified_dep],
        )
        inputs = audit_to_ki_inputs(result)
        per_cve = [i for i in inputs if i.finding_type == "vulnerable_package"]
        hints = [i for i in inputs if i.finding_type == "unpinned_dependency"]
        assert len(per_cve) == 2
        assert len(hints) == 1

    def test_ohne_unverified_kein_hinweis(self) -> None:
        """Nur verifizierte Vulns → kein Aggregat-Finding."""
        inputs = audit_to_ki_inputs(_result())
        assert all(i.finding_type == "vulnerable_package" for i in inputs)

    def test_hinweis_template_rendert(self) -> None:
        """Integration: Template ist registriert und rendert die Headline."""
        from core.storytelling.narrative_builder import build_story

        hint = audit_to_ki_inputs(self._unverified_result(3, 2))[0]
        story = build_story(hint)
        assert "3 Pakete ohne verifizierbare Version" in story.headline
        assert "Versionsabgleich nicht möglich" in story.headline

    def test_version_aus_installierter_version(self) -> None:
        """Verifizierte Vuln einer unpinned Dep zeigt die installierte Version."""
        dep = _dep(name="requests", version_pinned=None)
        dep.version_installed = "2.30.0"
        result = _result(vulns=[_vuln()], deps=[dep])
        inputs = audit_to_ki_inputs(result)
        assert inputs[0].details["version"] == "2.30.0"


class _SpyEmitter:
    """Zeichnet emit-Aufrufe inkl. reconcile_tool-Kwarg auf."""

    def __init__(self) -> None:
        self.calls: list[tuple[list, str | None]] = []

    def emit(self, findings, *, reconcile_tool: str | None = None) -> None:
        self.calls.append((list(findings), reconcile_tool))


class TestEmitReconcile:
    """ Review-Fix: Self-Audit-Emit laeuft als Voll-Sync."""

    def test_self_audit_emittiert_mit_reconcile(self) -> None:
        from tools.dependency_auditor.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        spy = _SpyEmitter()
        emit_to_ki_emitter(spy, _result(), self_audit=True)
        assert len(spy.calls) == 1
        assert spy.calls[0][1] == "dependency_auditor"

    def test_self_audit_leere_findings_emittieren_trotzdem(self) -> None:
        """emit([]) MIT reconcile → Karten koennen auto-erledigt werden."""
        from tools.dependency_auditor.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        spy = _SpyEmitter()
        emit_to_ki_emitter(spy, _result(vulns=[]), self_audit=True)
        assert spy.calls == [([], "dependency_auditor")]

    def test_default_emittiert_ohne_reconcile(self) -> None:
        """Fremddatei-Pfad (Default): kein Voll-Sync."""
        from tools.dependency_auditor.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        spy = _SpyEmitter()
        emit_to_ki_emitter(spy, _result())
        assert len(spy.calls) == 1
        assert spy.calls[0][1] is None


class TestEmitToKiEmitterFailSafe:
    """``emit_to_ki_emitter`` schluckt Konvertierungs-Exceptions."""

    def test_konvertierungs_exception_geschluckt(self, caplog) -> None:
        import logging

        from tools.dependency_auditor.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        class _BrokenResult:
            error = None
            dependencies: list = []

            @property
            def vulnerabilities(self):
                raise RuntimeError("boom")

        class _FakeEmitter:
            calls = 0

            def emit(self, items):
                self.calls += 1

        emitter = _FakeEmitter()
        with caplog.at_level(logging.WARNING):
            result = emit_to_ki_emitter(emitter, _BrokenResult())
        assert result == []
        assert emitter.calls == 0
        assert any("fehlgeschlagen" in r.message for r in caplog.records)
