"""test_storytelling_adapter_csaf_advisor (a)+(b)."""

from __future__ import annotations

from core.security.severity import Severity
from tools.csaf_advisor.application.storytelling_adapter import (
    matches_to_ki_inputs,
)
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch

_DEFAULT_CVE_IDS = ["CVE-2024-3094"]


def _advisory(
    advisory_id: str = "adv-1",
    severity: str = "high",
    cve_ids: list[str] | None = None,
    publisher: str = "OpenSSL Project",
    title: str = "OpenSSL CVE",
    summary: str = "Buffer Overflow",
    source_url: str = "https://example.test/adv-1",
) -> CsafAdvisory:
    # cve_ids=None nutzt Default; cve_ids=[] (explizit leer) bleibt leer.
    if cve_ids is None:
        cve_ids = list(_DEFAULT_CVE_IDS)
    return CsafAdvisory(
        id=advisory_id,
        title=title,
        publisher=publisher,
        tracking_id="TRACK-1",
        tracking_version="1.0",
        initial_release="2026-04-01",
        current_release="2026-05-01",
        severity=severity,
        cvss_score=7.5,
        cve_ids=cve_ids,
        affected_products=["openssl"],
        summary=summary,
        source_url=source_url,
    )


def _match(
    advisory_id: str = "adv-1",
    component: str = "openssl",
    version: str = "3.0.0",
    action: str = "update",
) -> AdvisoryMatch:
    return AdvisoryMatch(
        id=f"{advisory_id}_{component}",
        advisory_id=advisory_id,
        matched_component=component,
        matched_version=version,
        confidence=0.9,
        action_required=action,
    )


class TestActionRequiredFilter:
    def test_update_wird_gemeldet(self) -> None:
        adv = _advisory()
        m = _match(action="update")
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert len(inputs) == 1
        assert inputs[0].finding_type == "active_advisory_match"

    def test_workaround_wird_uebersprungen(self) -> None:
        adv = _advisory()
        m = _match(action="workaround")
        assert matches_to_ki_inputs([m], {adv.id: adv}) == []

    def test_monitor_wird_uebersprungen(self) -> None:
        adv = _advisory()
        m = _match(action="monitor")
        assert matches_to_ki_inputs([m], {adv.id: adv}) == []


class TestSeverityMapping:
    def test_critical(self) -> None:
        adv = _advisory(severity="critical")
        m = _match()
        assert matches_to_ki_inputs([m], {adv.id: adv})[0].severity == Severity.CRITICAL

    def test_high(self) -> None:
        adv = _advisory(severity="high")
        m = _match()
        assert matches_to_ki_inputs([m], {adv.id: adv})[0].severity == Severity.HIGH


class TestDetails:
    def test_advisory_id_aus_cve_ids(self) -> None:
        adv = _advisory(cve_ids=["CVE-2024-1234"])
        m = _match()
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert inputs[0].details["advisory_id"] == "CVE-2024-1234"

    def test_advisory_id_fallback_auf_tracking_id(self) -> None:
        adv = _advisory(cve_ids=[])
        m = _match()
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert inputs[0].details["advisory_id"] == "TRACK-1"

    def test_url_durchgereicht(self) -> None:
        adv = _advisory(source_url="https://cve.example/adv-42")
        m = _match()
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert inputs[0].details["url"] == "https://cve.example/adv-42"

    def test_subject_ist_component(self) -> None:
        adv = _advisory()
        m = _match(component="openssl")
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert inputs[0].subject == "openssl"


class TestMissingAdvisory:
    """Match ohne entsprechendes Advisory im Lookup → ueberspringen."""

    def test_unbekanntes_advisory_uebersprungen(self) -> None:
        m = _match(advisory_id="unknown-id")
        assert matches_to_ki_inputs([m], {}) == []


class TestEmptyGuards:
    """ Hotfix: Defekte Inputs ueberspringen statt Pydantic-ValidationError."""

    def test_leerer_component_und_titel_uebersprungen(self) -> None:
        """Wenn matched_component UND advisory.title leer sind, kein Crash."""
        adv = _advisory(title="")
        m = _match(component="")
        # Vorher: ValidationError aus subject=Field(min_length=1).
        # Jetzt: einfach uebersprungen.
        assert matches_to_ki_inputs([m], {adv.id: adv}) == []

    def test_leerer_component_aber_titel_da_uebernimmt_titel(self) -> None:
        """Fallback auf advisory.title bleibt erhalten."""
        adv = _advisory(title="OpenSSL CVE")
        m = _match(component="")
        inputs = matches_to_ki_inputs([m], {adv.id: adv})
        assert len(inputs) == 1
        assert inputs[0].subject == "OpenSSL CVE"

    def test_leere_match_id_uebersprungen(self) -> None:
        """evidence_id darf nicht leer sein."""
        adv = _advisory()
        m = AdvisoryMatch(
            id="",
            advisory_id="adv-1",
            matched_component="openssl",
            matched_version="3.0",
            confidence=0.9,
            action_required="update",
        )
        assert matches_to_ki_inputs([m], {adv.id: adv}) == []


class TestEmitToKiEmitterFailSafe:
    """``emit_to_ki_emitter`` schluckt Konvertierungs-Exceptions."""

    def test_konvertierungs_exception_geschluckt(self, caplog) -> None:
        import logging

        from tools.csaf_advisor.application.storytelling_adapter import (
            emit_to_ki_emitter,
        )

        # Advisory mit advisory_id der zur Match-ID passt + severity wirft
        class _BrokenAdvisory:
            id = "adv-1"  # passt zum _match Default-advisory_id
            title = "Some title"
            publisher = "X"
            tracking_id = "T1"
            cve_ids: list[str] = []
            summary = ""
            source_url = "u"

            @property
            def severity(self):
                raise RuntimeError("boom")

        class _FakeEmitter:
            calls = 0

            def emit(self, items):
                self.calls += 1

        m = _match()
        emitter = _FakeEmitter()
        with caplog.at_level(logging.WARNING):
            result = emit_to_ki_emitter(emitter, [m], [_BrokenAdvisory()])
        assert result == []
        assert emitter.calls == 0  # emit nicht aufgerufen wenn Konvertierung crasht
        assert any("fehlgeschlagen" in r.message for r in caplog.records)
