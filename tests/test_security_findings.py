"""
test_security_findings — Tests für den App-Ergebnis-Kontext des Assistenten.

Prüft ohne Ollama/Tools die reine Formatier- und Provider-Logik:

  * ``format_findings_block`` nimmt nur gesetzte Dimensionen auf (fail-soft).
  * Die zwei Dimensionen bleiben GETRENNT beschriftet — kein Mischwert.
  * ``CallableFindingsProvider`` ist fail-soft (None/leer/Exception → None).
  * DTOs sind unveränderlich (frozen).

Author: Patrick Riederich
"""

from __future__ import annotations

import dataclasses

import pytest

from core.assistant.security_findings import (
    AuditSummary,
    CallableFindingsProvider,
    CveExposureSummary,
    HardeningSummary,
    SecurityFindingsBundle,
    format_findings_block,
)


def _full_bundle() -> SecurityFindingsBundle:
    return SecurityFindingsBundle(
        hardening=HardeningSummary(
            overall_score=83.0,
            stage_label="Moderate",
            scale_hint="Secure ab 85, Moderate 65–84, At Risk 40–64, Critical unter 40",
            coverage_ratio=0.92,
            stage_capped_by_coverage=False,
            weakest_categories=("CVE/Patch", "Netzwerk"),
        ),
        audit=AuditSummary(
            overall_score=76.0,
            risk_level="Niedrig",
            scale_hint="Niedrig ab 75, Mittel ab 55, Hoch ab 35, sonst Kritisch",
            audit_count=3,
            top_risks=("Kein Notfallplan (Hoch)", "Backup unvollständig (Mittel)"),
        ),
        cve=CveExposureSummary(critical_count=2, high_count=5, kev_count=1),
        abweichung_hinweis="Selbsteinschätzung und Messung weichen um 7 Punkte ab (unkritisch).",
    )


class TestFormatFindingsBlock:
    def test_full_bundle_contains_both_dimensions(self):
        block = format_findings_block(_full_bundle())
        assert "Messung (Hardening): 83/100" in block
        assert "Moderate" in block
        assert "Selbsteinschätzung (Audit): 76/100" in block
        assert "Niedrig" in block

    def test_details_present(self):
        block = format_findings_block(_full_bundle())
        assert "Datenabdeckung 92%" in block
        assert "schwächste Bereiche: CVE/Patch, Netzwerk" in block
        assert "wichtigste Risiken: Kein Notfallplan (Hoch)" in block
        assert "2 kritisch, 5 hoch, davon 1 aktiv ausgenutzt (KEV)" in block
        assert "weichen um 7 Punkte ab" in block

    def test_no_mixed_score(self):
        # NIE ein gemittelter Gesamt-Score. (83+76)/2 = 79.5 → darf NICHT auftauchen.
        block = format_findings_block(_full_bundle())
        assert "79" not in block
        assert "Gesamt-Score" not in block
        assert "Mittelwert" in block  # nur im Verbots-Hinweis des Headers

    def test_score_rendered_as_integer(self):
        block = format_findings_block(
            SecurityFindingsBundle(
                hardening=HardeningSummary(overall_score=82.7, stage_label="Moderate")
            )
        )
        assert "83/100" in block  # 82.7 → gerundet 83, keine Nachkommastelle

    def test_hardening_only(self):
        block = format_findings_block(
            SecurityFindingsBundle(
                hardening=HardeningSummary(overall_score=90.0, stage_label="Secure")
            )
        )
        assert "Messung (Hardening): 90/100" in block
        assert "Selbsteinschätzung (Audit)" not in block
        assert "Offene Schwachstellen (CVE)" not in block

    def test_audit_only(self):
        block = format_findings_block(
            SecurityFindingsBundle(
                audit=AuditSummary(overall_score=40.0, risk_level="Hoch")
            )
        )
        assert "Selbsteinschätzung (Audit): 40/100" in block
        assert "Hoch" in block
        assert "Messung (Hardening)" not in block

    def test_coverage_cap_note(self):
        block = format_findings_block(
            SecurityFindingsBundle(
                hardening=HardeningSummary(
                    overall_score=50.0,
                    stage_label="At Risk",
                    coverage_ratio=0.4,
                    stage_capped_by_coverage=True,
                )
            )
        )
        assert "Datenabdeckung 40%" in block
        assert "gedeckelt" in block

    def test_empty_bundle_returns_empty_string(self):
        assert format_findings_block(SecurityFindingsBundle()) == ""


class TestBundleIsEmpty:
    def test_empty(self):
        assert SecurityFindingsBundle().is_empty is True

    def test_not_empty_with_any_dimension(self):
        assert SecurityFindingsBundle(
            cve=CveExposureSummary()
        ).is_empty is False


class TestCallableFindingsProvider:
    def test_returns_formatted_block(self):
        provider = CallableFindingsProvider(lambda: _full_bundle())
        block = provider.self_findings_block()
        assert block is not None
        assert "Messung (Hardening): 83/100" in block

    def test_none_bundle_returns_none(self):
        provider = CallableFindingsProvider(lambda: None)
        assert provider.self_findings_block() is None

    def test_empty_bundle_returns_none(self):
        provider = CallableFindingsProvider(lambda: SecurityFindingsBundle())
        assert provider.self_findings_block() is None

    def test_builder_exception_is_failsoft(self):
        def boom() -> SecurityFindingsBundle:
            raise RuntimeError("Repository weg")

        provider = CallableFindingsProvider(boom)
        assert provider.self_findings_block() is None


class TestImmutability:
    def test_bundle_frozen(self):
        bundle = _full_bundle()
        with pytest.raises(dataclasses.FrozenInstanceError):
            bundle.hardening = None  # type: ignore[misc]

    def test_summary_frozen(self):
        summary = HardeningSummary(overall_score=1.0, stage_label="x")
        with pytest.raises(dataclasses.FrozenInstanceError):
            summary.overall_score = 2.0  # type: ignore[misc]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
