"""
test_cve_tab_extended_sources — Tests fuer / Plan B+C.

Plan B (CVE-Tab additiv erweitert):
  * ``lade_cves_gefiltert(nur_stack=True)`` matched gegen den aktiven
    Tech-Stack (case-insensitive Substring).
  * Kombinierbar mit ``schweregrad`` und ``nur_kev``.
  * Leerer Stack oder kein Match → leere Liste, kein Fehler.

Plan C (NVD-Outage-Verhalten):
  * ``CONNECT_TIMEOUT`` reduziert auf 3, ``READ_TIMEOUT`` auf 8.
  * ``retry_on_timeout=False`` — bei NVD-Timeout sofort offline statt
    3 Retries (vermeidet Lade-Thread-Sperrung > 36 s).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.application.nvd_service import (
    CONNECT_TIMEOUT,
    READ_TIMEOUT,
)
from tools.cyber_dashboard.domain.models import CveEintrag, TechStackEintrag


def _make_cve(
    cve_id: str,
    *,
    schweregrad: str = "HIGH",
    produkte: list[str] | None = None,
    cisa_kev: bool = False,
) -> CveEintrag:
    """Baut einen CveEintrag fuer Tests."""
    now = datetime.now(UTC) - timedelta(days=1)
    return CveEintrag(
        cve_id=cve_id,
        beschreibung="test",
        schweregrad=schweregrad,
        cvss_score=9.0,
        veroeffentlicht=now,
        geaendert=now,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        cisa_kev=cisa_kev,
        cisa_frist="",
        betroffene_produkte=produkte or [],
    )


class TestDashboardServiceStackFilter:
    """B: nur_stack=True filtert CVEs auf den aktiven Tech-Stack."""

    def _service_mit_stack(
        self, stack: list[TechStackEintrag], cves: list[CveEintrag]
    ) -> DashboardService:
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.return_value = cves
        techstack = MagicMock()
        techstack.lade.return_value = stack
        return DashboardService(
            rss=rss, cache=cache, techstack=techstack, nvd=None, kev_client=None
        )

    def test_stack_filter_match_per_substring_case_insensitive(self) -> None:
        stack = [TechStackEintrag("Windows", "11", "OS", aktiv=True)]
        cves = [
            _make_cve("CVE-2026-1", produkte=["Microsoft Windows Shell"]),
            _make_cve("CVE-2026-2", produkte=["Linux Kernel"]),
            _make_cve("CVE-2026-3", produkte=["microsoft WINDOWS Defender"]),
        ]
        svc = self._service_mit_stack(stack, cves)
        result = svc.lade_cves_gefiltert(nur_stack=True, limit=50)
        ids = sorted(c.cve_id for c in result)
        assert ids == ["CVE-2026-1", "CVE-2026-3"]

    def test_stack_filter_ignoriert_inaktive_stack_eintraege(self) -> None:
        stack = [
            TechStackEintrag("Apache", "", "Webserver", aktiv=False),
            TechStackEintrag("Python", "3.12", "Runtime", aktiv=True),
        ]
        cves = [
            _make_cve("CVE-2026-1", produkte=["Apache HTTP Server"]),
            _make_cve("CVE-2026-2", produkte=["Python Software Foundation Python"]),
        ]
        svc = self._service_mit_stack(stack, cves)
        result = svc.lade_cves_gefiltert(nur_stack=True, limit=50)
        ids = [c.cve_id for c in result]
        assert ids == ["CVE-2026-2"]

    def test_stack_filter_leerer_stack_gibt_leere_liste(self) -> None:
        cves = [_make_cve("CVE-2026-1", produkte=["Anything"])]
        svc = self._service_mit_stack(stack=[], cves=cves)
        assert svc.lade_cves_gefiltert(nur_stack=True) == []

    def test_stack_filter_ohne_techstack_repo(self) -> None:
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.return_value = [_make_cve("CVE-2026-1", produkte=["X"])]
        svc = DashboardService(
            rss=rss, cache=cache, techstack=None, nvd=None, kev_client=None
        )
        assert svc.lade_cves_gefiltert(nur_stack=True) == []

    def test_stack_filter_kombiniert_mit_schweregrad(self) -> None:
        """nur_stack + schweregrad: DB filtert auf schweregrad, dann Stack-Match."""
        stack = [TechStackEintrag("Windows", "", "OS", aktiv=True)]
        # Cache liefert nur die CRITICAL-Variante (simuliert DB-Filter).
        cves = [_make_cve("CVE-2026-X", schweregrad="CRITICAL", produkte=["Windows"])]
        svc = self._service_mit_stack(stack, cves)
        result = svc.lade_cves_gefiltert(
            schweregrad="CRITICAL", nur_stack=True, limit=10
        )
        assert [c.cve_id for c in result] == ["CVE-2026-X"]
        # Cache wurde mit dem schweregrad-Filter aufgerufen, limit auf 200
        # angehoben (Pool-Vergrößerung).
        svc._cache.lade_cves.assert_called_once_with(
            schweregrad="CRITICAL", nur_kev=False, limit=200
        )

    def test_stack_filter_respektiert_limit_im_ergebnis(self) -> None:
        stack = [TechStackEintrag("Windows", "", "OS", aktiv=True)]
        cves = [
            _make_cve(f"CVE-2026-{i:04d}", produkte=["Windows"]) for i in range(20)
        ]
        svc = self._service_mit_stack(stack, cves)
        result = svc.lade_cves_gefiltert(nur_stack=True, limit=5)
        assert len(result) == 5

    def test_stack_filter_haelt_repo_exception_aus(self) -> None:
        """TechStack-Laden wirft OSError → leere Liste, kein Crash."""
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.return_value = [_make_cve("CVE-2026-1", produkte=["X"])]
        techstack = MagicMock()
        techstack.lade.side_effect = OSError("Disk fehlt")
        svc = DashboardService(
            rss=rss, cache=cache, techstack=techstack, nvd=None, kev_client=None
        )
        assert svc.lade_cves_gefiltert(nur_stack=True) == []

    def test_stack_filter_haelt_none_im_produkt_aus(self) -> None:
        """Manuell manipulierter Cache-JSON mit None in betroffene_produkte
        crasht den Stack-Match nicht."""
        stack = [TechStackEintrag("Windows", "", "OS", aktiv=True)]
        cve = _make_cve("CVE-2026-1", produkte=["Windows Defender"])
        # Direct attr-Manipulation simuliert korrupte DB-Daten — beim
        # production-Pfad würden None-Einträge schon in lade_cves
        # ausgefiltert, aber der Filter selbst soll robust bleiben.
        cve.betroffene_produkte.insert(0, None)  # type: ignore[arg-type]
        svc = self._service_mit_stack(stack, [cve])
        result = svc.lade_cves_gefiltert(nur_stack=True)
        assert [c.cve_id for c in result] == ["CVE-2026-1"]

    def test_stack_filter_kappt_zu_viele_namen(self) -> None:
        """Manipulierter techstack.json mit 1000 Eintraegen wird gekappt.

        Disjunkte UUID-Tokens vermeiden Substring-Kollisionen (z.B.
        ``"tool5"`` matcht in ``"tool50"`` etc.).
        """
        import uuid

        tokens = [uuid.uuid4().hex[:12] for _ in range(1000)]
        stack = [TechStackEintrag(t, "", "App", aktiv=True) for t in tokens]
        # Match auf Stack[5] (innerhalb 200 → muss treffen)
        cve_early = _make_cve("CVE-2026-EARLY", produkte=[tokens[5]])
        # Match auf Stack[500] (außerhalb Cap=200 → darf nicht treffen)
        cve_late = _make_cve("CVE-2026-LATE", produkte=[tokens[500]])
        svc = self._service_mit_stack(stack, [cve_late, cve_early])
        result = svc.lade_cves_gefiltert(nur_stack=True)
        ids = [c.cve_id for c in result]
        assert "CVE-2026-EARLY" in ids
        assert "CVE-2026-LATE" not in ids

    def test_stack_filter_kappt_zu_lange_namen(self) -> None:
        """100-KB-Stack-Name wird auf _MAX_STACK_NAME_LEN gekappt — kein
        Memory-/CPU-Spike beim Filter."""
        long_name = "X" * 100_000
        stack = [TechStackEintrag(long_name, "", "App", aktiv=True)]
        # CVE-Produkt enthaelt den gekappten Namen-Prefix (128 Zeichen "X")
        cve = _make_cve("CVE-2026-1", produkte=["X" * 128])
        svc = self._service_mit_stack(stack, [cve])
        result = svc.lade_cves_gefiltert(nur_stack=True)
        # Filter trifft, weil "x" * 128 substring von "x" * 128 ist
        assert [c.cve_id for c in result] == ["CVE-2026-1"]


class TestDashboardServiceLadeCvesGefiltertBackwardsCompat:
    """Bestehender Pfad (kein nur_stack) bleibt unverändert."""

    def test_default_aufruf_unveraendert(self) -> None:
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.return_value = [_make_cve("CVE-2026-1")]
        svc = DashboardService(
            rss=rss, cache=cache, techstack=None, nvd=None, kev_client=None
        )

        result = svc.lade_cves_gefiltert()
        assert [c.cve_id for c in result] == ["CVE-2026-1"]
        cache.lade_cves.assert_called_once_with(
            schweregrad=None, nur_kev=False, limit=50
        )

    def test_nur_kev_unveraendert(self) -> None:
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.return_value = []
        svc = DashboardService(
            rss=rss, cache=cache, techstack=None, nvd=None, kev_client=None
        )

        svc.lade_cves_gefiltert(nur_kev=True, limit=10)
        cache.lade_cves.assert_called_once_with(
            schweregrad=None, nur_kev=True, limit=10
        )

    def test_oserror_im_cache_gibt_leere_liste(self) -> None:
        rss = MagicMock()
        cache = MagicMock()
        cache.lade_cves.side_effect = OSError("DB locked")
        svc = DashboardService(
            rss=rss, cache=cache, techstack=None, nvd=None, kev_client=None
        )
        assert svc.lade_cves_gefiltert() == []


class TestBriefingPool:
    """: lade_cves_briefing_pool merged generische + dedizierte Stack-CVEs."""

    def test_merged_dedupliziert_stack_ergaenzt(self) -> None:
        svc = DashboardService(
            rss=MagicMock(), cache=MagicMock(), techstack=None, nvd=None, kev_client=None
        )
        generisch = [_make_cve("CVE-2026-1"), _make_cve("CVE-2026-2")]
        stack = [_make_cve("CVE-2026-2"), _make_cve("CVE-2026-3")]  # CVE-2 ueberlappt
        svc.lade_cves_gefiltert = MagicMock(return_value=generisch)  # type: ignore[method-assign]
        svc.suche_cves_fuer_stack = MagicMock(return_value=stack)  # type: ignore[method-assign]

        pool = svc.lade_cves_briefing_pool(limit=40)

        ids = [c.cve_id for c in pool]
        # generisch zuerst, CVE-3 ergaenzt, CVE-2 nicht doppelt
        assert ids == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
        svc.lade_cves_gefiltert.assert_called_once_with(limit=40)
        svc.suche_cves_fuer_stack.assert_called_once()

    def test_leerer_stack_nur_generisch(self) -> None:
        svc = DashboardService(
            rss=MagicMock(), cache=MagicMock(), techstack=None, nvd=None, kev_client=None
        )
        svc.lade_cves_gefiltert = MagicMock(  # type: ignore[method-assign]
            return_value=[_make_cve("CVE-2026-1")]
        )
        svc.suche_cves_fuer_stack = MagicMock(return_value=[])  # type: ignore[method-assign]

        pool = svc.lade_cves_briefing_pool()

        assert [c.cve_id for c in pool] == ["CVE-2026-1"]


class TestNvdServiceTimeoutOptimierung:
    """C: NVD-Timeouts reduziert, kein Retry mehr."""

    def test_connect_timeout_ist_3_sekunden(self) -> None:
        assert CONNECT_TIMEOUT == 3

    def test_read_timeout_ist_8_sekunden(self) -> None:
        assert READ_TIMEOUT == 8

    def test_background_bulk_fetch_uses_retry_on_timeout_false(self) -> None:
        """Background-Bulk-Lade (lade_neueste_cves) → retry_on_timeout=False."""
        from unittest.mock import patch

        from tools.cyber_dashboard.application.nvd_service import NvdService

        with patch(
            "tools.cyber_dashboard.application.nvd_service.get_http_client"
        ) as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.get.return_value = mock_response

            cache = MagicMock()
            cache.get.return_value = None
            svc = NvdService(cache=cache)
            svc._api_key = "test-key"

            svc.lade_neueste_cves(tage=7, schweregrad="CRITICAL")

            _, kwargs = mock_client.return_value.get.call_args
            assert kwargs["retry_on_timeout"] is False
            assert kwargs["timeout"] == (3, 8)

    def test_kev_bulk_fetch_uses_retry_on_timeout_false(self) -> None:
        """Background-Bulk-Lade (lade_kev_cves) → retry_on_timeout=False."""
        from unittest.mock import patch

        from tools.cyber_dashboard.application.nvd_service import NvdService

        with patch(
            "tools.cyber_dashboard.application.nvd_service.get_http_client"
        ) as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.get.return_value = mock_response

            cache = MagicMock()
            cache.get.return_value = None
            svc = NvdService(cache=cache)
            svc._api_key = "test-key"

            svc.lade_kev_cves(max_results=10)

            _, kwargs = mock_client.return_value.get.call_args
            assert kwargs["retry_on_timeout"] is False

    def test_user_search_uses_retry_on_timeout_true(self) -> None:
        """User-Action (suche_produkt) → retry_on_timeout=True für Resilience."""
        from unittest.mock import patch

        from tools.cyber_dashboard.application.nvd_service import NvdService

        with patch(
            "tools.cyber_dashboard.application.nvd_service.get_http_client"
        ) as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_response.raise_for_status.return_value = None
            mock_client.return_value.get.return_value = mock_response

            cache = MagicMock()
            cache.get.return_value = None
            svc = NvdService(cache=cache)
            svc._api_key = "test-key"

            svc.suche_produkt("Windows", tage=30)

            _, kwargs = mock_client.return_value.get.call_args
            assert kwargs["retry_on_timeout"] is True
            assert kwargs["timeout"] == (3, 8)


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path, monkeypatch):
    """Verhindert dass Tests die echte SQLCipher-DB anfassen.

    Mocks der Repositories sind in Anwendung-Service-Tests primär, dies
    ist zusätzliche Belt-and-Suspenders gegen versehentliche I/O.
    """
    monkeypatch.setenv("FINLAI_DB_DIR", str(tmp_path))
    yield
