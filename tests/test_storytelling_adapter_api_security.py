"""test_storytelling_adapter_api_security (a)+(b).

Prueft den api_security-Findings-Adapter:
- Header-Findings werden auf ``missing_security_header`` gemappt mit
  passenden ``details`` (header_name, recommended_value, risk).
- Unbekannte Codes werden mit ``finding_type="unknown"`` durchgereicht
  (Storytelling-Engine ignoriert sie still).
- Severity-Konvertierung von ``api_security.Severity`` auf kanonisches
  ``core.security.severity.Severity``.
- Leere/Fehler-Scans liefern leere Liste.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.security.severity import Severity as CanonicalSeverity
from tools.api_security.application.storytelling_adapter import (
    findings_to_ki_inputs,
)
from tools.api_security.domain.models import (
    Finding,
    OWASPCategory,
    ScanResult,
    ScanTarget,
    Severity,
)


def _make_target(url: str = "https://example.test") -> ScanTarget:
    return ScanTarget(url=url, api_type="REST", auth_type="none")


def _make_finding(
    code: str,
    severity: Severity = Severity.HIGH,
    title: str = "Test-Befund",
    description: str = "Beschreibung",
    remediation: str = "",
) -> Finding:
    return Finding(
        code=code,
        title=title,
        description=description,
        severity=severity,
        owasp=OWASPCategory.API8,
        remediation=remediation,
    )


class TestHeaderFindings:
    """Bekannte Header-Codes → ``missing_security_header`` mit Details."""

    def test_missing_hsts(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS")],
            scan_time="2026-05-08T10:00:00Z",
        )
        inputs = findings_to_ki_inputs(result)
        assert len(inputs) == 1
        fi = inputs[0]
        assert fi.tool == "api_security"
        assert fi.finding_type == "missing_security_header"
        assert fi.details["header_name"] == "Strict-Transport-Security"
        assert "HTTPS" in fi.details["risk"]
        assert fi.subject == "https://example.test"
        assert fi.evidence_id == "https://example.test#MISSING_HSTS"

    def test_missing_csp(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_CSP", severity=Severity.MEDIUM)],
        )
        inputs = findings_to_ki_inputs(result)
        assert inputs[0].details["header_name"] == "Content-Security-Policy"
        assert "Cross-Site-Scripting" in inputs[0].details["risk"]

    def test_remediation_wird_durchgereicht(self) -> None:
        """``recommended_value`` kommt aus ``Finding.remediation``."""
        result = ScanResult(
            target=_make_target(),
            findings=[
                _make_finding(
                    "MISSING_X_FRAME_OPTIONS",
                    remediation="DENY oder SAMEORIGIN setzen",
                )
            ],
        )
        inputs = findings_to_ki_inputs(result)
        assert inputs[0].details["recommended_value"] == "DENY oder SAMEORIGIN setzen"

    def test_remediation_default_bei_leerem_remediation_string(self) -> None:
        """Leerer ``remediation``-String → Default-Hinweis 'siehe OWASP-Empfehlung'."""
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS", remediation="")],
        )
        inputs = findings_to_ki_inputs(result)
        assert "OWASP" in inputs[0].details["recommended_value"]


class TestUnknownFindings:
    """Unbekannte Codes → ``finding_type="unknown"`` mit Original-Code."""

    def test_unknown_code(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("WEAK_TLS", title="Schwaches TLS")],
        )
        inputs = findings_to_ki_inputs(result)
        assert len(inputs) == 1
        assert inputs[0].finding_type == "unknown"
        assert inputs[0].details["code"] == "WEAK_TLS"
        assert inputs[0].details["title"] == "Schwaches TLS"


class TestSeverityKonvertierung:
    """``api_security.Severity`` → kanonisches ``core.security.severity.Severity``."""

    def test_critical(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS", severity=Severity.CRITICAL)],
        )
        assert findings_to_ki_inputs(result)[0].severity == CanonicalSeverity.CRITICAL

    def test_high(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS", severity=Severity.HIGH)],
        )
        assert findings_to_ki_inputs(result)[0].severity == CanonicalSeverity.HIGH

    def test_info(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS", severity=Severity.INFO)],
        )
        assert findings_to_ki_inputs(result)[0].severity == CanonicalSeverity.INFO


class TestEmptyAndError:
    """Leere/Fehler-Scans → leere Liste."""

    def test_keine_findings(self) -> None:
        result = ScanResult(target=_make_target(), findings=[])
        assert findings_to_ki_inputs(result) == []

    def test_scan_mit_error(self) -> None:
        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS")],
            error="Network unreachable",
        )
        assert findings_to_ki_inputs(result) == []


class TestTargetLabel:
    """``target_label`` ueberschreibt Default-URL."""

    def test_custom_label(self) -> None:
        result = ScanResult(
            target=_make_target("https://internal.example/api"),
            findings=[_make_finding("MISSING_HSTS")],
        )
        inputs = findings_to_ki_inputs(result, target_label="Internal-API")
        assert inputs[0].subject == "Internal-API"


class TestEmitterIntegration:
    """``emit_to_ki_emitter`` ruft ``emitter.emit`` auf."""

    def test_emitter_wird_aufgerufen(self) -> None:
        from tools.api_security.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        calls = []

        class _StubEmitter:
            def emit(self, findings) -> None:
                calls.append(list(findings))

        result = ScanResult(
            target=_make_target(),
            findings=[_make_finding("MISSING_HSTS")],
        )
        inputs = emit_to_ki_emitter(_StubEmitter(), result)
        assert len(calls) == 1
        assert len(calls[0]) == 1
        assert calls[0][0].finding_type == "missing_security_header"
        # Convenience-Return liefert die gleiche Liste.
        assert list(inputs) == calls[0]


class TestEmptyGuards:
    """ Hotfix: Defekte Inputs ueberspringen statt Pydantic-ValidationError."""

    def test_leere_target_url_keine_findings(self) -> None:
        """Wenn target.url leer + target_label leer → leere Liste, kein Crash."""
        result = ScanResult(
            target=ScanTarget(url="", api_type="REST", auth_type="none"),
            findings=[_make_finding("MISSING_HSTS")],
        )
        assert findings_to_ki_inputs(result) == []

    def test_leeres_target_label_faellt_auf_url(self) -> None:
        """target_label leer → fallback target.url, normale Konvertierung."""
        result = ScanResult(
            target=_make_target("https://x.test"),
            findings=[_make_finding("MISSING_HSTS")],
        )
        inputs = findings_to_ki_inputs(result, target_label="")
        assert len(inputs) == 1
        assert inputs[0].subject == "https://x.test"


class TestEmitToKiEmitterFailSafe:
    """``emit_to_ki_emitter`` schluckt Konvertierungs-Exceptions."""

    def test_konvertierungs_exception_geschluckt(self, caplog) -> None:
        import logging

        from tools.api_security.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        class _BrokenResult:
            error = None
            findings = [object()]

            @property
            def target(self):
                raise RuntimeError("boom")

        class _FakeEmitter:
            calls = 0

            def emit(self, items):
                self.calls += 1

        emitter = _FakeEmitter()
        with caplog.at_level(logging.WARNING):
            result = emit_to_ki_emitter(emitter, _BrokenResult())
        assert list(result) == []
        assert emitter.calls == 0
        assert any("fehlgeschlagen" in r.message for r in caplog.records)
