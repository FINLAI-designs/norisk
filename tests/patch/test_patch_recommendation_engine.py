"""
test_patch_recommendation_engine — Tests fuer Stop-Step B.

Deckt die 5-Priorisierungs-Stufen ab + action_text-Bauer.
"""

from __future__ import annotations

import pytest

from core.patch_eol_resolver import EolStatus
from core.patch_recommendation_engine import apply_recommendation_engine
from core.patch_result import PatchScanResult, Recommendation
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_result(
    *,
    recommendation: Recommendation = "up_to_date",
    cvss_max: float | None = None,
    exploit: bool = False,
    name: str = "Mozilla Firefox",
    winget_id: str | None = "Mozilla.Firefox",
) -> PatchScanResult:
    """Minimal-Result fuer Engine-Tests."""
    return PatchScanResult(
        name=name,
        normalized_name=name.lower().replace(" ", "_"),
        vendor=None,
        winget_id=winget_id,
        source="winget",
        installed_version="120.0.1",
        available_version="121.0",
        channel="latest",
        policy_source="default",
        cve_ids=(),
        cvss_max=cvss_max,
        exploit_available=exploit,
        eol=False,
        confidence_score=1.0,
        recommendation=recommendation,
    )


def _advisory(
    *,
    advisory_id: str = "BSI-2026-001",
    action_required: str = "update",
    confidence: float = 0.95,
) -> AdvisoryMatch:
    return AdvisoryMatch(
        id=f"{advisory_id}_test",
        advisory_id=advisory_id,
        matched_component="Mozilla Firefox",
        matched_version="120.0.1",
        confidence=confidence,
        action_required=action_required,
        matched_at="2026-05-12T18:00:00Z",
    )


def _eol_status(
    *,
    is_eol: bool = True,
    cycle: str = "Office 2010",
    eol_date: str = "2020-10-13",
    replacement: str = "Office 365",
    source: str = "curated:office_2010",
) -> EolStatus:
    return EolStatus(
        is_eol=is_eol,
        cycle=cycle if is_eol else None,
        eol_date=eol_date if is_eol else None,
        replacement=replacement if is_eol else None,
        source=source if is_eol else "",
    )


# ---------------------------------------------------------------------------
# skipped_by_user ist terminal (User-Opt-out)
# ---------------------------------------------------------------------------


class TestSkippedByUserTerminal:
    def test_eol_ueberschreibt_skipped_by_user_nicht(self) -> None:
        """Selbst EOL darf den expliziten User-Opt-out nicht ueberschreiben."""
        result = _scan_result(recommendation="skipped_by_user")
        enriched = apply_recommendation_engine(result, eol_status=_eol_status())
        assert enriched.recommendation == "skipped_by_user"

    def test_csaf_update_ueberschreibt_skipped_by_user_nicht(self) -> None:
        result = _scan_result(recommendation="skipped_by_user")
        enriched = apply_recommendation_engine(
            result, advisories=[_advisory(action_required="update")]
        )
        assert enriched.recommendation == "skipped_by_user"


# ---------------------------------------------------------------------------
# Default-Pfad — kein Enrichment
# ---------------------------------------------------------------------------


class TestNoOpPath:
    def test_no_advisories_no_eol_returns_unchanged(self) -> None:
        result = _scan_result(recommendation="update")
        enriched = apply_recommendation_engine(result)
        assert enriched is result or enriched == result

    def test_empty_lists_treated_as_no_data(self) -> None:
        result = _scan_result(recommendation="up_to_date")
        enriched = apply_recommendation_engine(
            result, advisories=[], eol_status=EolStatus.not_eol()
        )
        assert enriched.recommendation == "up_to_date"
        assert enriched.action_text is None
        assert enriched.recommendation_source == ""


# ---------------------------------------------------------------------------
# Priorisierungs-Pfade
# ---------------------------------------------------------------------------


class TestEolOverridesEverything:
    def test_eol_beats_update_urgent(self) -> None:
        """Auch ein update_urgent-Basis muss ueberschrieben werden, wenn
        EOL erkannt wurde — Patch ist sinnlos wenn Vendor keinen liefert."""
        result = _scan_result(
            recommendation="update_urgent", cvss_max=9.8, exploit=True
        )
        eol = _eol_status()
        enriched = apply_recommendation_engine(result, eol_status=eol)
        assert enriched.recommendation == "eol_no_patch"
        assert "Office 2010" in (enriched.action_text or "")
        assert "2020-10-13" in (enriched.action_text or "")
        assert "Office 365" in (enriched.action_text or "")
        assert enriched.recommendation_source == "curated:office_2010"

    def test_eol_overrides_up_to_date(self) -> None:
        result = _scan_result(recommendation="up_to_date")
        eol = _eol_status(cycle="Windows 7", source="curated:windows_7")
        enriched = apply_recommendation_engine(result, eol_status=eol)
        assert enriched.recommendation == "eol_no_patch"
        assert "Windows 7" in (enriched.action_text or "")

    def test_eol_not_eol_status_does_not_trigger(self) -> None:
        result = _scan_result(recommendation="update")
        enriched = apply_recommendation_engine(
            result, eol_status=EolStatus.not_eol()
        )
        assert enriched.recommendation == "update"


class TestUpdateUrgentEnrichment:
    def test_update_urgent_stays_but_text_enriched_with_csaf(self) -> None:
        """update_urgent bleibt — bekommt aber Action-Text aus CSAF."""
        result = _scan_result(
            recommendation="update_urgent", cvss_max=9.5, exploit=True
        )
        adv = _advisory(advisory_id="CVE-2026-12345", action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert enriched.recommendation == "update_urgent"
        assert enriched.recommendation_source == "csaf:CVE-2026-12345"
        assert "Sofort updaten" in (enriched.action_text or "")
        assert "CVE-2026-12345" in (enriched.action_text or "")

    def test_update_urgent_without_csaf_returns_unchanged(self) -> None:
        result = _scan_result(
            recommendation="update_urgent", cvss_max=9.5, exploit=True
        )
        enriched = apply_recommendation_engine(result, advisories=[])
        assert enriched.recommendation == "update_urgent"
        assert enriched.action_text is None


class TestWorkaroundAvailable:
    def test_workaround_advisory_without_update_triggers_workaround(self) -> None:
        """``workaround`` action + Basis ist nicht ``update*`` → workaround_available."""
        result = _scan_result(recommendation="up_to_date")
        adv = _advisory(advisory_id="BSI-2026-005", action_required="workaround")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert enriched.recommendation == "workaround_available"
        assert "BSI-2026-005" in (enriched.action_text or "")
        assert "Workaround" in (enriched.action_text or "")
        assert enriched.recommendation_source == "csaf:BSI-2026-005"

    def test_workaround_advisory_with_update_basis_does_not_trigger(self) -> None:
        """Wenn Basis schon ``update_available`` ist, wird Patch bevorzugt
        (Update beats Workaround) und es geht in
        patch_available_with_csaf_context — aber nur wenn auch ein
        update-Advisory vorliegt. Bei nur-Workaround-Advisory + Basis-
        Update bleibt die Basis-Empfehlung."""
        result = _scan_result(recommendation="update_available")
        adv = _advisory(action_required="workaround")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        # Kein update-Advisory → kein patch_available_with_csaf_context.
        # Workaround-Pfad wird durch _has_update_available abgekehrt.
        # Resultat: Basis bleibt (up-to-date-Path).
        assert enriched.recommendation == "update_available"


class TestPatchAvailableWithCsafContext:
    def test_update_advisory_plus_update_basis(self) -> None:
        result = _scan_result(recommendation="update_available")
        adv = _advisory(advisory_id="CVE-2026-99999", action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert enriched.recommendation == "patch_available_with_csaf_context"
        assert "Update empfohlen" in (enriched.action_text or "")
        assert "CVE-2026-99999" in (enriched.action_text or "")
        assert enriched.recommendation_source == "csaf:CVE-2026-99999"

    def test_update_advisory_with_only_update_basis(self) -> None:
        result = _scan_result(recommendation="update", cvss_max=5.0)
        adv = _advisory(action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert enriched.recommendation == "patch_available_with_csaf_context"

    def test_update_advisory_no_update_basis_no_enrichment(self) -> None:
        """Wenn die Basis keine Update-Empfehlung gibt, aber CSAF Update
        verlangt — Engine respektiert die Basis (vermutlich pinned /
        notify_only / up_to_date). Kein patch_available_with_csaf_context."""
        result = _scan_result(recommendation="pinned")
        adv = _advisory(action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        # Basis bleibt — pinned ist User-Wunsch, wir ueberschreiben nicht
        assert enriched.recommendation == "pinned"


# ---------------------------------------------------------------------------
# Action-Text Inhalte
# ---------------------------------------------------------------------------


class TestActionTextContent:
    def test_eol_action_text_includes_replacement(self) -> None:
        result = _scan_result()
        eol = _eol_status(
            cycle="Python 2.x", eol_date="2020-01-01", replacement="Python 3.12+",
        )
        enriched = apply_recommendation_engine(result, eol_status=eol)
        assert "Python 2.x" in (enriched.action_text or "")
        assert "2020-01-01" in (enriched.action_text or "")
        assert "Python 3.12+" in (enriched.action_text or "")

    def test_eol_action_text_without_replacement(self) -> None:
        result = _scan_result()
        eol = EolStatus(
            is_eol=True,
            cycle="Some Unknown Product",
            eol_date="2099-01-01",
            replacement=None,
            source="curated:unknown",
        )
        enriched = apply_recommendation_engine(result, eol_status=eol)
        # Fallback-Text ohne explizite Replacement
        assert "Migration empfohlen" in (enriched.action_text or "")

    def test_csaf_workaround_text_references_advisory_id(self) -> None:
        result = _scan_result()
        adv = _advisory(advisory_id="MY-ADV-42", action_required="workaround")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert "MY-ADV-42" in (enriched.action_text or "")

    def test_csaf_update_text_shows_confidence(self) -> None:
        result = _scan_result(recommendation="update_available")
        adv = _advisory(action_required="update", confidence=0.78)
        enriched = apply_recommendation_engine(result, advisories=[adv])
        # 78% Confidence muss im Text auftauchen
        assert "78%" in (enriched.action_text or "")


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestT067TitleResolverIntegration:
    """: Engine nutzt optional einen TitleResolver fuer lesbare
    Action-Texte (Advisory-Titel statt nur ID)."""

    def test_update_text_ohne_resolver_zeigt_id(self) -> None:
        result = _scan_result(recommendation="update_urgent", cvss_max=9.5, exploit=True)
        adv = _advisory(advisory_id="CVE-2026-X", action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        assert "CVE-2026-X" in (enriched.action_text or "")
        # Kein Titel-Quote
        assert "'" not in (enriched.action_text or "")

    def test_update_text_mit_resolver_zeigt_titel(self) -> None:
        from unittest.mock import MagicMock

        result = _scan_result(recommendation="update_urgent", cvss_max=9.5, exploit=True)
        adv = _advisory(advisory_id="CVE-2026-X", action_required="update")
        resolver = MagicMock()
        resolver.get_title.return_value = "Firefox Heap Overflow"
        enriched = apply_recommendation_engine(
            result, advisories=[adv], title_resolver=resolver,
        )
        assert "Firefox Heap Overflow" in (enriched.action_text or "")
        assert "CVE-2026-X" in (enriched.action_text or "")

    def test_workaround_text_mit_resolver(self) -> None:
        from unittest.mock import MagicMock

        result = _scan_result(recommendation="up_to_date")
        adv = _advisory(advisory_id="BSI-2026-W", action_required="workaround")
        resolver = MagicMock()
        resolver.get_title.return_value = "pfSense SQL-Injection"
        enriched = apply_recommendation_engine(
            result, advisories=[adv], title_resolver=resolver,
        )
        assert "pfSense SQL-Injection" in (enriched.action_text or "")

    def test_resolver_returns_none_falls_back_to_id(self) -> None:
        from unittest.mock import MagicMock

        result = _scan_result(recommendation="update_available")
        adv = _advisory(action_required="update")
        resolver = MagicMock()
        resolver.get_title.return_value = None  # unbekannt
        enriched = apply_recommendation_engine(
            result, advisories=[adv], title_resolver=resolver,
        )
        # Fallback auf ID, kein 'None'-String
        assert "BSI-2026-001" in (enriched.action_text or "")
        assert "None" not in (enriched.action_text or "")

    def test_resolver_exception_falls_back_to_id(self) -> None:
        from unittest.mock import MagicMock

        result = _scan_result(recommendation="update_available")
        adv = _advisory(action_required="update")
        resolver = MagicMock()
        resolver.get_title.side_effect = RuntimeError("db down")
        enriched = apply_recommendation_engine(
            result, advisories=[adv], title_resolver=resolver,
        )
        assert "BSI-2026-001" in (enriched.action_text or "")


class TestImmutability:
    def test_enriched_is_new_instance(self) -> None:
        """``apply_recommendation_engine`` darf das Original nicht mutieren."""
        result = _scan_result(recommendation="update_available")
        original_id = id(result)
        adv = _advisory(action_required="update")
        enriched = apply_recommendation_engine(result, advisories=[adv])
        # Neue Instanz wenn Enrichment greift
        assert id(enriched) != original_id
        # Original bleibt unveraendert (frozen + replace)
        assert result.recommendation == "update_available"
        assert result.action_text is None

    def test_returned_result_is_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        result = _scan_result()
        eol = _eol_status()
        enriched = apply_recommendation_engine(result, eol_status=eol)
        with pytest.raises(FrozenInstanceError):
            enriched.recommendation = "up_to_date"  # type: ignore[misc]
