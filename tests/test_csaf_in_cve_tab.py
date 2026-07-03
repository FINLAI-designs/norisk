"""
test_csaf_in_cve_tab — Tests fuer die CSAF-in-CVE-Tab-Integration
follow-up).

CSAF-Advisories aus dem ``csaf_advisor``-Tool werden über einen Adapter
in ``CveEintrag``-Objekte konvertiert und über ``DashboardService.lade_cves``
in den cyber_dashboard-Cache geschrieben. Effekt: echte CRITICAL/HIGH/
MEDIUM/LOW-Severities im CVE-Tab, EU-Hersteller-Bezug (BSI WID).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.cyber_dashboard.application.csaf_to_cve_adapter import (
    csaf_advisories_to_cves,
)
from tools.cyber_dashboard.application.dashboard_service import DashboardService


def _make_advisory(
    *,
    advisory_id: str = "ADV-001",
    tracking_id: str = "BSI-2026-001",
    severity: str = "high",
    cvss_score: float | None = 8.5,
    cve_ids: list[str] | None = None,
    affected_products: list[str] | None = None,
    current_release: str = "2026-05-13T10:00:00+00:00",
    summary: str = "Demo-Advisory fuer Tests",
) -> CsafAdvisory:
    return CsafAdvisory(
        id=advisory_id,
        title="Demo-Title",
        publisher="BSI",
        tracking_id=tracking_id,
        tracking_version="1",
        initial_release=current_release,
        current_release=current_release,
        severity=severity,
        cvss_score=cvss_score,
        cve_ids=cve_ids or [],
        affected_products=affected_products or [],
        summary=summary,
        source_url=f"https://wid.cert-bund.de/portal/wid/{tracking_id}",
    )


class TestCsafAdvisoryAdapter:
    """Adapter csaf_advisories_to_cves."""

    def test_eine_cve_id_pro_advisory(self) -> None:
        adv = _make_advisory(cve_ids=["CVE-2026-1234"])
        result = csaf_advisories_to_cves([adv])
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2026-1234"

    def test_mehrere_cve_ids_pro_advisory_ergeben_mehrere_eintraege(self) -> None:
        adv = _make_advisory(cve_ids=["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"])
        result = csaf_advisories_to_cves([adv])
        assert sorted(c.cve_id for c in result) == [
            "CVE-2026-1",
            "CVE-2026-2",
            "CVE-2026-3",
        ]

    def test_advisory_ohne_cve_id_bekommt_synthetische_id(self) -> None:
        adv = _make_advisory(tracking_id="BSI-2026-9999", cve_ids=[])
        result = csaf_advisories_to_cves([adv])
        assert len(result) == 1
        assert result[0].cve_id == "CSAF-BSI-2026-9999"

    def test_severity_uppercase_und_default_info(self) -> None:
        adv_high = _make_advisory(severity="high", cve_ids=["CVE-X-1"])
        adv_mid = _make_advisory(severity="medium", cve_ids=["CVE-X-2"])
        adv_low = _make_advisory(severity="low", cve_ids=["CVE-X-3"])
        adv_crit = _make_advisory(severity="critical", cve_ids=["CVE-X-4"])
        adv_unknown = _make_advisory(severity="weird", cve_ids=["CVE-X-5"])
        result = csaf_advisories_to_cves(
            [adv_high, adv_mid, adv_low, adv_crit, adv_unknown]
        )
        sev_map = {c.cve_id: c.schweregrad for c in result}
        assert sev_map == {
            "CVE-X-1": "HIGH",
            "CVE-X-2": "MEDIUM",
            "CVE-X-3": "LOW",
            "CVE-X-4": "CRITICAL",
            "CVE-X-5": "INFO",
        }

    def test_cvss_score_none_wird_zu_null(self) -> None:
        adv = _make_advisory(cvss_score=None, cve_ids=["CVE-2026-1"])
        result = csaf_advisories_to_cves([adv])
        assert result[0].cvss_score == 0.0

    def test_affected_products_cap_auf_3(self) -> None:
        produkte = [f"Produkt {i}" for i in range(10)]
        adv = _make_advisory(affected_products=produkte, cve_ids=["CVE-2026-1"])
        result = csaf_advisories_to_cves([adv])
        assert result[0].betroffene_produkte == [
            "Produkt 0",
            "Produkt 1",
            "Produkt 2",
        ]

    def test_source_url_landet_in_cve_url(self) -> None:
        adv = _make_advisory(
            tracking_id="BSI-2026-XYZ", cve_ids=["CVE-2026-1"]
        )
        result = csaf_advisories_to_cves([adv])
        assert "BSI-2026-XYZ" in result[0].url

    def test_cisa_kev_ist_immer_false(self) -> None:
        """CSAF-Eintraege duerfen nicht als KEV markiert werden — sonst
        wuerde der KEV-Counter sie mitzählen."""
        adv = _make_advisory(cve_ids=["CVE-2026-1"])
        result = csaf_advisories_to_cves([adv])
        assert result[0].cisa_kev is False

    def test_leere_liste_gibt_leere_liste(self) -> None:
        assert csaf_advisories_to_cves([]) == []

    def test_release_date_parse_iso_with_z(self) -> None:
        adv = _make_advisory(
            current_release="2026-05-13T10:00:00Z", cve_ids=["CVE-2026-1"]
        )
        result = csaf_advisories_to_cves([adv])
        # ISO-Datum erhalten + tz-aware UTC
        assert result[0].veroeffentlicht.tzinfo is not None
        assert result[0].veroeffentlicht.year == 2026

    def test_release_date_invalid_fallback_epoch(self) -> None:
        """Korruptes Datum → 1970-01-01 (sortiert ans Ende statt oben).

        Korrektheits-Review P1: Fallback ``datetime.now(UTC)`` würde
        den Eintrag im ``ORDER BY veroeffentlicht DESC`` ganz oben
        einsortieren, was bei einem korrupten Provider Misleading wäre.
        """
        adv = _make_advisory(current_release="not-a-date", cve_ids=["CVE-2026-1"])
        result = csaf_advisories_to_cves([adv])
        assert result[0].veroeffentlicht.year == 1970

    def test_synthetic_id_sanitisiert_sonderzeichen(self) -> None:
        """Sonderzeichen in tracking_id werden durch _ ersetzt."""
        adv = _make_advisory(
            tracking_id="BSI/2026/foo bar!", cve_ids=[]
        )
        result = csaf_advisories_to_cves([adv])
        assert result[0].cve_id.startswith("CSAF-BSI_2026_foo_bar_")

    def test_synthetic_id_gecappt_auf_64(self) -> None:
        """Bösartig langer tracking_id wird gekappt — Schutz gegen DB-Bloat."""
        adv = _make_advisory(tracking_id="X" * 1000, cve_ids=[])
        result = csaf_advisories_to_cves([adv])
        # "CSAF-" Prefix + max 64 Zeichen = max 69
        assert len(result[0].cve_id) <= 69

    def test_dedup_hoehere_cvss_score_gewinnt(self) -> None:
        """Zwei Advisories mit derselben CVE-ID: hoechster CVSS-Score gewinnt."""
        adv_low = _make_advisory(
            advisory_id="ADV-1", cvss_score=5.0, cve_ids=["CVE-2026-DUP"]
        )
        adv_high = _make_advisory(
            advisory_id="ADV-2", cvss_score=9.5, cve_ids=["CVE-2026-DUP"]
        )
        result = csaf_advisories_to_cves([adv_low, adv_high])
        assert len(result) == 1
        assert result[0].cvss_score == 9.5

    def test_dedup_reihenfolge_unabhaengig(self) -> None:
        """Reihenfolge der Eingabe egal — höchster Score gewinnt."""
        adv_high = _make_advisory(
            advisory_id="ADV-1", cvss_score=9.5, cve_ids=["CVE-2026-DUP"]
        )
        adv_low = _make_advisory(
            advisory_id="ADV-2", cvss_score=5.0, cve_ids=["CVE-2026-DUP"]
        )
        result = csaf_advisories_to_cves([adv_high, adv_low])
        assert result[0].cvss_score == 9.5

    def test_affected_product_string_capped(self) -> None:
        """Einzelner Produktname > 200 Zeichen wird gekappt."""
        long_product = "X" * 500
        adv = _make_advisory(
            affected_products=[long_product], cve_ids=["CVE-2026-1"]
        )
        result = csaf_advisories_to_cves([adv])
        assert len(result[0].betroffene_produkte[0]) == 200

    def test_summary_truncate_300(self) -> None:
        long = "X" * 500
        adv = _make_advisory(summary=long, cve_ids=["CVE-2026-1"])
        result = csaf_advisories_to_cves([adv])
        assert len(result[0].beschreibung) == 300


class TestDashboardServiceCsafLoad:
    """DashboardService._lade_csaf_cves: defensive Read aus advisory_service."""

    def _service_with_advisory(
        self, advisory_service: object | None
    ) -> tuple[DashboardService, MagicMock]:
        rss = MagicMock()
        cache = MagicMock()
        return (
            DashboardService(
                rss=rss,
                cache=cache,
                nvd=None,
                techstack=None,
                kev_client=None,
                advisory_service=advisory_service,
            ),
            cache,
        )

    def test_kein_advisory_service_kein_call(self) -> None:
        svc, cache = self._service_with_advisory(None)
        svc._lade_csaf_cves()
        cache.speichere_cves.assert_not_called()

    def test_leere_advisory_liste_kein_speichern(self) -> None:
        adv_svc = MagicMock()
        adv_svc.list_advisories.return_value = []
        svc, cache = self._service_with_advisory(adv_svc)
        svc._lade_csaf_cves()
        adv_svc.list_advisories.assert_called_once_with(days=90)
        cache.speichere_cves.assert_not_called()

    def test_advisories_werden_konvertiert_und_gespeichert(self) -> None:
        advisories = [
            _make_advisory(
                severity="critical",
                cvss_score=9.8,
                cve_ids=["CVE-2026-100"],
                summary="Kritisches Problem",
            ),
            _make_advisory(
                tracking_id="BSI-X",
                severity="medium",
                cvss_score=5.0,
                cve_ids=["CVE-2026-200", "CVE-2026-201"],
            ),
        ]
        adv_svc = MagicMock()
        adv_svc.list_advisories.return_value = advisories
        svc, cache = self._service_with_advisory(adv_svc)
        svc._lade_csaf_cves()
        cache.speichere_cves.assert_called_once()
        gespeichert = cache.speichere_cves.call_args[0][0]
        # 1 Eintrag aus erstem Advisory + 2 aus zweitem = 3
        assert len(gespeichert) == 3
        ids = sorted(c.cve_id for c in gespeichert)
        assert ids == ["CVE-2026-100", "CVE-2026-200", "CVE-2026-201"]

    def test_advisory_service_wirft_exception_keine_speicherung(self) -> None:
        adv_svc = MagicMock()
        adv_svc.list_advisories.side_effect = RuntimeError("DB locked")
        svc, cache = self._service_with_advisory(adv_svc)
        svc._lade_csaf_cves()  # darf nicht crashen
        cache.speichere_cves.assert_not_called()


class TestDashboardServiceLadeCvesOrdered:
    """lade_cves ruft KEV / CSAF / NVD in der erwarteten Reihenfolge."""

    def test_csaf_ladet_auch_ohne_kev_client(self) -> None:
        """Wenn kein KEV-Client da ist, läuft CSAF trotzdem."""
        adv_svc = MagicMock()
        adv_svc.list_advisories.return_value = [
            _make_advisory(cve_ids=["CVE-2026-1"])
        ]
        rss = MagicMock()
        cache = MagicMock()
        svc = DashboardService(
            rss=rss,
            cache=cache,
            nvd=None,
            techstack=None,
            kev_client=None,  # KEV nicht verfügbar
            advisory_service=adv_svc,
        )
        svc.lade_cves()
        adv_svc.list_advisories.assert_called_once_with(days=90)
        cache.speichere_cves.assert_called_once()


def _make_advisory_helper_smoke() -> None:
    """Sanity-Smoke: Helper liefert valides CsafAdvisory."""
    adv = _make_advisory()
    assert adv.severity == "high"
    assert adv.publisher == "BSI"


class TestUrlWhitelist:
    """`_open_external_url` lehnt unerwünschte Schemes ab (Security P1)."""

    def test_https_wird_geoeffnet(self) -> None:
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("https://nvd.nist.gov/vuln/detail/CVE-2026-1")
            mock_open.assert_called_once()

    def test_http_wird_geoeffnet(self) -> None:
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("http://example.com")
            mock_open.assert_called_once()

    def test_file_scheme_blockiert(self) -> None:
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("file:///C:/Windows/System32/cmd.exe")
            mock_open.assert_not_called()

    def test_javascript_scheme_blockiert(self) -> None:
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("javascript:alert(1)")
            mock_open.assert_not_called()

    def test_ms_msdt_scheme_blockiert(self) -> None:
        """Follina-Klasse — ms-msdt: würde Code-Execution triggern."""
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("ms-msdt:/id PCWDiagnostic /skip force")
            mock_open.assert_not_called()

    def test_leere_url_no_op(self) -> None:
        from unittest.mock import patch

        from tools.cyber_dashboard.gui.dashboard_widget import _open_external_url

        with patch(
            "tools.cyber_dashboard.gui.dashboard_widget.QDesktopServices.openUrl"
        ) as mock_open:
            _open_external_url("")
            mock_open.assert_not_called()
