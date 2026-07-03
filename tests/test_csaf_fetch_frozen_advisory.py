"""
test_csaf_fetch_frozen_advisory — Regression fuer den FrozenInstance-
Bug im CSAF-Fetch follow-up, 2026-05-14).

Vor dem Fix: ``AdvisoryService.fetch_all_providers`` versuchte
``advisory.fetched_at = now`` zu setzen — ``CsafAdvisory`` ist aber
``@dataclass(frozen=True)``, deshalb crashte das mit
``FrozenInstanceError`` ("cannot assign to field 'fetched_at'") und die
GUI zeigte den Provider-Sync als fehlgeschlagen.

Vorher unentdeckt, weil alle Provider-URLs 404 lieferten — der Fetch
lieferte 0 Advisories, der Loop wurde gar nicht erst betreten.

Nach dem Fix: ``dataclasses.replace`` erzeugt eine neue Instanz mit
dem ``fetched_at``-Stempel.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.csaf_provider import CsafProvider


def _make_advisory(advisory_id: str = "ADV-1") -> CsafAdvisory:
    return CsafAdvisory(
        id=advisory_id,
        title="Test-Advisory",
        publisher="BSI",
        tracking_id="BSI-2026-001",
        tracking_version="1",
        initial_release="2026-05-14T00:00:00+00:00",
        current_release="2026-05-14T00:00:00+00:00",
        severity="high",
        cvss_score=7.5,
        cve_ids=["CVE-2026-1"],
        affected_products=[],
        summary="",
        source_url="https://example.com/adv-1.json",
        raw_json="",
        fetched_at="",
    )


def _make_provider(provider_id: str = "csaf-test") -> CsafProvider:
    return CsafProvider(
        id=provider_id,
        name="Test-Provider",
        provider_url="https://example.com/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=True,
    )


class TestFrozenAdvisoryFix:
    """Verifiziert dass das Speichern mit ``replace`` statt In-place-Assign
    funktioniert."""

    def test_in_place_assignment_wuerde_crashen(self) -> None:
        """Sanity: ``CsafAdvisory.fetched_at =...`` crasht immer noch — wir
        wollen sicherstellen dass kein anderer Code-Pfad zurueck-regrediert."""
        from dataclasses import FrozenInstanceError

        adv = _make_advisory()
        with pytest.raises(FrozenInstanceError):
            adv.fetched_at = "2026-05-14T09:00:00+00:00"  # type: ignore[misc]

    def test_fetch_all_providers_stempelt_fetched_at_per_replace(self) -> None:
        """``fetch_all_providers`` setzt ``fetched_at`` ueber
        ``dataclasses.replace`` und ruft ``save_advisory`` mit der neuen
        Instanz auf. Der gespeicherte Eintrag hat einen nicht-leeren
        ``fetched_at``-Wert; das Original-Advisory bleibt unangetastet."""
        repo = MagicMock()
        repo.list_providers.return_value = [_make_provider()]
        # advisory_count Aufruf nach Speichern
        repo.advisory_count.return_value = 1

        downloader = MagicMock()
        original_adv = _make_advisory()
        downloader.fetch_advisories.return_value = [original_adv]

        svc = AdvisoryService(
            repository=repo,
            downloader=downloader,
            ki_todo_emitter=MagicMock(),
        )
        total, errors = svc.fetch_all_providers()

        assert total == 1
        assert errors == []

        # Original-Advisory wurde NICHT mutiert (frozen)
        assert original_adv.fetched_at == ""

        # repo.save_advisory wurde mit einer neuen Instanz aufgerufen,
        # die einen fetched_at-Wert hat
        repo.save_advisory.assert_called_once()
        saved_adv = repo.save_advisory.call_args.args[0]
        assert saved_adv.fetched_at != ""
        # Inhalt sonst unveraendert (ID, severity, CVE-ID etc.)
        assert saved_adv.id == original_adv.id
        assert saved_adv.severity == original_adv.severity
        assert saved_adv.cve_ids == original_adv.cve_ids

    def test_fetch_all_providers_speichert_alle_advisories(self) -> None:
        repo = MagicMock()
        repo.list_providers.return_value = [_make_provider()]
        repo.advisory_count.return_value = 3
        downloader = MagicMock()
        downloader.fetch_advisories.return_value = [
            _make_advisory("ADV-1"),
            _make_advisory("ADV-2"),
            _make_advisory("ADV-3"),
        ]

        svc = AdvisoryService(
            repository=repo,
            downloader=downloader,
            ki_todo_emitter=MagicMock(),
        )
        total, _ = svc.fetch_all_providers()

        assert total == 3
        assert repo.save_advisory.call_count == 3

    def test_disabled_provider_wird_uebersprungen(self) -> None:
        repo = MagicMock()
        disabled = _make_provider("csaf-disabled")
        disabled.enabled = False
        repo.list_providers.return_value = [disabled]

        downloader = MagicMock()
        svc = AdvisoryService(
            repository=repo,
            downloader=downloader,
            ki_todo_emitter=MagicMock(),
        )
        total, errors = svc.fetch_all_providers()

        # Keine aktiven Provider → 0 + Info-Message
        assert total == 0
        assert "Keine aktiven" in errors[0]
        downloader.fetch_advisories.assert_not_called()


@pytest.fixture(autouse=True)
def _no_disk_io(monkeypatch, tmp_path):
    """Verhindert dass Tests die echte ~/.finlai/db anlegen."""
    monkeypatch.setenv("FINLAI_DB_DIR", str(tmp_path))
    yield
