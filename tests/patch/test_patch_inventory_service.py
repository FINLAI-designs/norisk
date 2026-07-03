"""
test_patch_inventory_service — Tests fuer Stop-Step B Service.

Deckt:
* full_scan: PatchService.scan → Persistenz (inventory + available + cves
  + scan_history)
* full_scan: Monthly-Full loescht deinstallierte Apps
* full_scan: Exception → scan_history mit error
* daily_refresh: winget-Reconcile (bekannte aktualisiert, neu installierte
  aufgenommen, deinstallierte entfernt) + stale-CVE-refresh
* load_from_db: Recommendation-Rekonstruktion via _recommend (gleiche
  Logik wie Live-Scan)
* is_inventory_empty
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from core.patch_collector import SoftwareItem
from core.patch_cve_matcher import CveMatch
from core.patch_result import PatchScanResult
from core.patch_strategy import PatchStrategy
from tools.patch_monitor.application.patch_inventory_service import (
    PatchInventoryService,
)
from tools.patch_monitor.data.patch_inventory_repository import (
    AvailableVersionEntry,
    CveMatchEntry,
    InventoryEntry,
    PatchInventoryRepository,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    *,
    name: str = "Mozilla Firefox",
    winget_id: str | None = "Mozilla.Firefox",
    installed_version: str = "123.0",
    available_version: str | None = "124.0",
    channel: str = "latest",
    recommendation: str = "update_available",
    cve_ids: tuple[str, ...] = (),
    cvss_max: float | None = None,
    exploit_available: bool = False,
    eol: bool = False,
    vendor: str | None = "mozilla",
    normalized_name: str = "mozilla firefox",
    source: str = "winget",
) -> PatchScanResult:
    return PatchScanResult(
        name=name,
        normalized_name=normalized_name,
        vendor=vendor,
        winget_id=winget_id,
        source=source,  # type: ignore[arg-type]
        installed_version=installed_version,
        available_version=available_version,
        channel=channel,
        policy_source="default",
        cve_ids=cve_ids,
        cvss_max=cvss_max,
        exploit_available=exploit_available,
        eol=eol,
        confidence_score=1.0,
        recommendation=recommendation,  # type: ignore[arg-type]
    )


def _service_with_mocks(
    *,
    scan_results: list[PatchScanResult] | None = None,
    winget_items: list[SoftwareItem] | None = None,
    cve_lookup: dict[str, list[CveMatch]] | None = None,
) -> PatchInventoryService:
    """Baut einen Service mit echtem Repo (via Test-Fixture) und Mock-
    PatchService / Mock-Matcher."""
    repo = PatchInventoryRepository()

    patch_service = MagicMock()
    patch_service.scan.return_value = scan_results or []

    matcher = MagicMock()
    if cve_lookup is not None:
        matcher.get_cves.side_effect = lambda cpe: cve_lookup.get(cpe, [])
    else:
        matcher.get_cves.return_value = []

    service = PatchInventoryService(
        repo=repo,
        patch_service=patch_service,
        matcher=matcher,
    )
    # Patch collect_winget_inventory wenn winget_items uebergeben
    service._winget_items_mock = winget_items  # type: ignore[attr-defined]
    return service


def _inv_entry(
    winget_id: str,
    *,
    name: str = "App",
    source: str = "winget",
    installed_version: str = "1.0",
) -> InventoryEntry:
    """Kompakter ``InventoryEntry``-Helfer fuer die Reconcile-Tests."""
    now = datetime.now(UTC)
    return InventoryEntry(
        winget_id=winget_id,
        name=name,
        normalized_name=name.lower(),
        vendor=None,
        source=source,  # type: ignore[arg-type]
        installed_version=installed_version,
        cpe_string=None,
        channel="latest",
        policy_source="default",
        confidence_score=1.0,
        last_seen_at=now,
        last_full_scan_at=now,
    )


def _winget_item(winget_id: str, *, name: str = "App", update: bool = True) -> SoftwareItem:
    """Kompakter live-winget ``SoftwareItem``-Helfer."""
    return SoftwareItem(
        name=name,
        version="1.0",
        winget_id=winget_id,
        source="winget",
        is_update_available=update,
        latest_available="2.0" if update else None,
    )


def _patch_winget(monkeypatch, items: list[SoftwareItem]) -> None:
    monkeypatch.setattr(
        "tools.patch_monitor.application.patch_inventory_service."
        "collect_winget_inventory",
        lambda: items,
    )


# ---------------------------------------------------------------------------
# full_scan
# ---------------------------------------------------------------------------


class TestFullScan:
    def test_persistiert_inventory_und_available_versions(self) -> None:
        service = _service_with_mocks(
            scan_results=[_result()],
        )
        summary = service.full_scan(scan_type="initial")

        assert summary.items_total == 1
        assert summary.items_with_updates == 1
        assert summary.items_with_cves == 0
        # Inventory hat 1 Eintrag
        assert service._repo.count_inventory() == 1  # type: ignore[attr-defined]
        # available_versions hat den Eintrag
        av = service._repo.get_available_version("Mozilla.Firefox")  # type: ignore[attr-defined]
        assert av is not None
        assert av.available_version == "124.0"
        assert av.is_update_available is True

    def test_ohne_winget_id_uebersprungen(self) -> None:
        """Registry-Apps ohne winget_id sind nicht persistierbar (FK +
        PK)."""
        service = _service_with_mocks(
            scan_results=[
                _result(winget_id=None, name="Some Registry App"),
                _result(winget_id="A.A", name="A"),
            ],
        )
        summary = service.full_scan()
        assert summary.items_total == 1  # nur A.A persistiert

    def test_synthetische_id_persistiert_und_laedt(self) -> None:
        """Registry-App mit synthetischer Id (regid:) wird via full_scan
        persistiert und von load_from_db zurueckgegeben — sie ueberlebt
        damit Neustart/Daily-Refresh (Kern des Fixes)."""
        service = _service_with_mocks(
            scan_results=[
                _result(
                    name="7-Zip",
                    winget_id="regid:7-zip",
                    source="registry",  # type: ignore[arg-type]
                    vendor=None,
                    available_version=None,
                    recommendation="up_to_date",
                ),
            ],
        )
        summary = service.full_scan(scan_type="initial")
        assert summary.items_total == 1
        assert service._repo.count_inventory() == 1  # type: ignore[attr-defined]

        # Reload aus DB: die synthetische Id kommt opak zurueck.
        results = service.load_from_db()
        by_id = {r.winget_id: r for r in results}
        assert "regid:7-zip" in by_id
        assert by_id["regid:7-zip"].name == "7-Zip"

    def test_mit_cves_persistiert_cve_matches(self) -> None:
        service = _service_with_mocks(
            scan_results=[
                _result(
                    cve_ids=("CVE-2024-1", "CVE-2024-2"),
                    cvss_max=9.5,
                    exploit_available=True,
                    recommendation="update_urgent",
                )
            ],
        )
        summary = service.full_scan()
        assert summary.items_with_cves == 1
        cves = service._repo.list_cve_matches_for_cpe(  # type: ignore[attr-defined]
            "cpe:2.3:a:mozilla:firefox:123.0:*:*:*:*:windows:*:*"
        )
        assert {c.cve_id for c in cves} == {"CVE-2024-1", "CVE-2024-2"}
        assert cves[0].cvss_score == 9.5
        assert cves[0].exploit_available is True

    def test_monthly_full_loescht_deinstallierte_apps(self) -> None:
        """Ein App das in einem frueheren Scan war, aber im neuen nicht
        mehr, muss aus inventory_snapshot raus."""
        service = _service_with_mocks(
            scan_results=[_result(winget_id="A.A", name="A")],
        )
        service.full_scan(scan_type="initial")
        assert service._repo.count_inventory() == 1  # type: ignore[attr-defined]

        # Naechster Scan: A.A ist weg, B.B kommt neu
        service._patch_service.scan.return_value = [  # type: ignore[attr-defined]
            _result(winget_id="B.B", name="B"),
        ]
        summary = service.full_scan(scan_type="monthly_full")
        assert summary.items_total == 1
        # Inventory hat nur B.B
        ids = {e.winget_id for e in service._repo.list_inventory()}  # type: ignore[attr-defined]
        assert ids == {"B.B"}

    def test_scan_history_eintrag_angelegt(self) -> None:
        service = _service_with_mocks(scan_results=[_result()])
        summary = service.full_scan(scan_type="initial")
        history = service._repo.list_scan_history()  # type: ignore[attr-defined]
        assert len(history) == 1
        assert history[0].id == summary.scan_id
        assert history[0].scan_type == "initial"
        assert history[0].error is None
        assert history[0].items_total == 1

    def test_exception_schreibt_error_in_scan_history(self) -> None:
        service = _service_with_mocks()
        service._patch_service.scan.side_effect = RuntimeError("boom")  # type: ignore[attr-defined]

        with pytest.raises(RuntimeError):
            service.full_scan(scan_type="initial")

        history = service._repo.list_scan_history()  # type: ignore[attr-defined]
        assert len(history) == 1
        assert history[0].error is not None
        assert "boom" in history[0].error


# ---------------------------------------------------------------------------
# daily_refresh
# ---------------------------------------------------------------------------


class TestDailyRefresh:
    def test_reconcile_bekannte_aktualisiert_neue_aufgenommen(
        self, monkeypatch
    ) -> None:
        """daily_refresh gleicht winget-Apps mit der Live-Liste ab (Reconcile
        2026-07-02): bekannte werden aktualisiert, NEU installierte aufgenommen."""
        service = _service_with_mocks()
        service._repo.upsert_inventory(_inv_entry("A.A", name="A"))  # type: ignore[attr-defined]
        _patch_winget(
            monkeypatch,
            [_winget_item("A.A", name="A"), _winget_item("B.B", name="B")],
        )

        summary = service.daily_refresh()

        assert summary.items_total == 2
        assert service._repo.get_available_version("A.A") is not None  # type: ignore[attr-defined]
        # NEU installierte B.B wird jetzt aufgenommen (nicht mehr uebersprungen).
        assert service._repo.get_available_version("B.B") is not None  # type: ignore[attr-defined]
        inv_ids = {e.winget_id for e in service._repo.list_inventory()}  # type: ignore[attr-defined]
        assert "B.B" in inv_ids

    def test_reconcile_deinstallierte_winget_app_entfernt(self, monkeypatch) -> None:
        """Phantom-Cleanup: eine winget-App, die nicht mehr live gelistet ist,
        gilt als deinstalliert und wird aus dem Inventar entfernt — Registry-/
        Store-/synthetische Apps bleiben geschuetzt (Live-Test 2026-07-02:
        stale „Firefox 123->124" verschwand erst nach einem Vollscan)."""
        service = _service_with_mocks()
        service._repo.upsert_inventory(_inv_entry("Mozilla.Firefox", name="Firefox"))  # type: ignore[attr-defined]
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            _inv_entry("regid:7-zip", name="7-Zip", source="registry")
        )
        # winget listet nur noch Graphviz (Firefox deinstalliert).
        _patch_winget(monkeypatch, [_winget_item("Graphviz.Graphviz", name="Graphviz")])

        service.daily_refresh()

        inv_ids = {e.winget_id for e in service._repo.list_inventory()}  # type: ignore[attr-defined]
        assert "Mozilla.Firefox" not in inv_ids  # deinstalliert -> entfernt
        assert "regid:7-zip" in inv_ids  # Registry-App geschuetzt
        assert "Graphviz.Graphviz" in inv_ids  # neu aufgenommen

    def test_reconcile_leere_winget_liste_loescht_nichts(self, monkeypatch) -> None:
        """Guard: eine leere winget-Liste (winget-Fehler) darf NICHT das gesamte
        winget-Inventar loeschen."""
        service = _service_with_mocks()
        service._repo.upsert_inventory(_inv_entry("A.A", name="A"))  # type: ignore[attr-defined]
        _patch_winget(monkeypatch, [])

        service.daily_refresh()

        inv_ids = {e.winget_id for e in service._repo.list_inventory()}  # type: ignore[attr-defined]
        assert "A.A" in inv_ids

    def test_synthetische_ids_nicht_gegen_winget_abgeglichen(
        self, monkeypatch
    ) -> None:
        """daily_refresh ueberspringt synthetische Ids (regid:/msix:) —
        winget kennt sie nicht, sie duerfen nicht abgefragt werden."""
        service = _service_with_mocks()
        # Inventar: eine Registry-App mit synthetischer Id ist bekannt.
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="regid:7-zip",
                name="7-Zip",
                normalized_name="7-zip",
                vendor=None,
                source="registry",
                installed_version="23.01",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=datetime.now(UTC),
                last_full_scan_at=datetime.now(UTC),
            )
        )
        # winget liefert (hypothetisch) ein Item mit derselben synthetischen
        # Id zurueck — der Skip muss greifen, sonst landet es in
        # available_versions.
        monkeypatch.setattr(
            "tools.patch_monitor.application.patch_inventory_service."
            "collect_winget_inventory",
            lambda: [
                SoftwareItem(
                    name="7-Zip",
                    version="23.01",
                    winget_id="regid:7-zip",
                    source="registry",
                    is_update_available=True,
                    latest_available="24.08",
                ),
            ],
        )

        summary = service.daily_refresh()
        # Nichts aktualisiert — die synthetische Id wurde uebersprungen.
        assert summary.items_total == 0
        assert service._repo.get_available_version("regid:7-zip") is None  # type: ignore[attr-defined]

    def test_aktualisiert_stale_cves(self, monkeypatch) -> None:
        """Stale CPEs werden via Matcher.get_cves neu gefetcht."""
        service = _service_with_mocks(
            cve_lookup={
                "cpe:stale": [
                    CveMatch(
                        cve_id="CVE-2025-NEW",
                        cvss_score=8.5,
                        cvss_version="3.1",
                        description="new",
                        exploit_available=False,
                        published="",
                        affected_versions="",
                    )
                ],
            },
        )
        # Pre-populate cve_matches mit altem Eintrag (>24h alt)
        service._repo.upsert_cve_match(  # type: ignore[attr-defined]
            CveMatchEntry(
                cpe_string="cpe:stale",
                cve_id="CVE-2025-OLD",
                cvss_score=5.0,
                exploit_available=False,
                eol=False,
                fetched_at=datetime.now(UTC) - timedelta(hours=48),
            )
        )
        monkeypatch.setattr(
            "tools.patch_monitor.application.patch_inventory_service."
            "collect_winget_inventory",
            lambda: [],
        )

        summary = service.daily_refresh(cve_age_threshold_hours=24)
        assert summary.cves_refreshed == 1
        cves = service._repo.list_cve_matches_for_cpe("cpe:stale")  # type: ignore[attr-defined]
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2025-NEW" in cve_ids

    def test_scan_history_typ_daily_refresh(self, monkeypatch) -> None:
        service = _service_with_mocks()
        monkeypatch.setattr(
            "tools.patch_monitor.application.patch_inventory_service."
            "collect_winget_inventory",
            lambda: [],
        )
        summary = service.daily_refresh()
        history = service._repo.list_scan_history()  # type: ignore[attr-defined]
        assert history[0].id == summary.scan_id
        assert history[0].scan_type == "daily_refresh"

    def test_exception_im_winget_call_schreibt_error(self, monkeypatch) -> None:
        service = _service_with_mocks()

        def boom() -> list:
            raise RuntimeError("winget kaputt")

        monkeypatch.setattr(
            "tools.patch_monitor.application.patch_inventory_service."
            "collect_winget_inventory",
            boom,
        )

        with pytest.raises(RuntimeError):
            service.daily_refresh()

        history = service._repo.list_scan_history()  # type: ignore[attr-defined]
        assert history[0].error is not None


# ---------------------------------------------------------------------------
# load_from_db
# ---------------------------------------------------------------------------


class TestLoadFromDb:
    def test_leer_wenn_inventory_leer(self) -> None:
        service = _service_with_mocks()
        assert service.load_from_db() == []

    def test_rekonstruiert_recommendation_aus_db(self) -> None:
        """Wenn DB ``is_update_available=True`` enthaelt, soll
        load_from_db dieselbe Recommendation wie ein Live-Scan liefern."""
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="vendor-x",
                source="winget",
                installed_version="1.0",
                cpe_string="cpe:2.3:a:vendor-x:a:1.0:*:*:*:*:windows:*:*",
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version="2.0",
                is_update_available=True,
                last_checked_at=now,
            )
        )

        results = service.load_from_db()
        assert len(results) == 1
        r = results[0]
        assert r.name == "A"
        assert r.installed_version == "1.0"
        assert r.available_version == "2.0"
        assert r.recommendation == "update_available"

    def test_recommendation_up_to_date_ohne_update(self) -> None:
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version=None,
                is_update_available=False,
                last_checked_at=now,
            )
        )
        results = service.load_from_db()
        assert results[0].recommendation == "up_to_date"

    def test_recommendation_update_urgent_bei_cvss_high(self) -> None:
        """-Pattern: cvss_max >= 9.0 → update_urgent, unabhaengig
        von is_update_available."""
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string="cpe:fake",
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_cve_match(  # type: ignore[attr-defined]
            CveMatchEntry(
                cpe_string="cpe:fake",
                cve_id="CVE-X",
                cvss_score=9.5,
                exploit_available=False,
                eol=False,
                fetched_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version=None,
                is_update_available=False,
                last_checked_at=now,
            )
        )
        results = service.load_from_db()
        assert results[0].recommendation == "update_urgent"

    def test_recommendation_update_available_trotz_low_cve(self) -> None:
        """Verfuegbares Update mit NIEDRIG-schwerer CVE (0 < cvss < 4) bleibt
        installierbar → ``update_available``, NICHT ``up_to_date``.

        Live-Test 2026-07-02: Quick-Check fand 8 Updates (``is_update_available``),
        aber die Haupttabelle „Updates verfuegbar" zeigte 0 und das Popup ging
        nicht auf — weil ein verfuegbares Update mit gecachter Low-CVE faelschlich
        als ``up_to_date`` klassifiziert wurde.
        """
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string="cpe:fake",
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_cve_match(  # type: ignore[attr-defined]
            CveMatchEntry(
                cpe_string="cpe:fake",
                cve_id="CVE-LOW",
                cvss_score=2.5,
                exploit_available=False,
                eol=False,
                fetched_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version="2.0",
                is_update_available=True,
                last_checked_at=now,
            )
        )
        results = service.load_from_db()
        assert results[0].recommendation == "update_available"

    def test_notify_only_kanal_traegt_is_update_available(self) -> None:
        """Live-Test 2026-07-02 (Option A): eine winget-App mit verfuegbarem
        Update, deren Kanal der konservative Default ``notify_only`` ist, hat
        recommendation ``notify_only`` — traegt aber ``is_update_available=True``.

        So erscheint sie im Quick-Check-Filter/-Popup („Updates verfuegbar" =
        is_update_available), wo der User den Kanal auf Stabil/Neueste stellen und
        patchen kann. Zuvor blieben genau solche Apps unsichtbar (Toast „7", Tabelle
        „0", kein Popup).
        """
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="notify_only",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version="2.0",
                is_update_available=True,
                last_checked_at=now,
            )
        )
        r = service.load_from_db()[0]
        assert r.recommendation == "notify_only"
        assert r.is_update_available is True

    def test_strategy_none_liefert_skipped_by_user(self) -> None:
        """: persistierte NONE-Strategie ueberschreibt die Empfehlung
        beim DB-Load — selbst bei verfuegbarem Update + hoher CVE."""
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string="cpe:fake",
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.upsert_available_version(  # type: ignore[attr-defined]
            AvailableVersionEntry(
                winget_id="A.A",
                available_version="2.0",
                is_update_available=True,
                last_checked_at=now,
            )
        )
        service._repo.upsert_cve_match(  # type: ignore[attr-defined]
            CveMatchEntry(
                cpe_string="cpe:fake",
                cve_id="CVE-X",
                cvss_score=9.5,
                exploit_available=True,
                eol=False,
                fetched_at=now,
            )
        )
        # User waehlt NONE
        service._repo.update_strategy("A.A", PatchStrategy.NONE)  # type: ignore[attr-defined]

        r = service.load_from_db()[0]
        assert r.recommendation == "skipped_by_user"
        # Risikodaten bleiben sichtbar
        assert r.cvss_max == 9.5
        assert r.cve_ids == ("CVE-X",)

    def test_load_from_db_traegt_persistierte_strategie(self) -> None:
        """: PatchScanResult.patch_strategy spiegelt den DB-Wert
        (fuer die Dropdown-Vorbelegung im GUI)."""
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        service._repo.update_strategy("A.A", PatchStrategy.LATEST)  # type: ignore[attr-defined]
        assert service.load_from_db()[0].patch_strategy is PatchStrategy.LATEST


# ---------------------------------------------------------------------------
# set_strategy (Application-Fassade fuer das GUI)
# ---------------------------------------------------------------------------


class TestSetStrategy:
    def test_set_strategy_persistiert(self) -> None:
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        assert service.set_strategy("A.A", PatchStrategy.NONE) is True
        loaded = service._repo.get_inventory("A.A")  # type: ignore[attr-defined]
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.NONE

    def test_set_strategy_unbekannt_ist_false(self) -> None:
        service = _service_with_mocks()
        assert service.set_strategy("X.X", PatchStrategy.LATEST) is False

    def test_set_strategy_akzeptiert_plain_str(self) -> None:
        """: Qt castet StrEnum-userData zu plain str-Klasse).

        Der GUI-Signalpfad lieferte "none" statt PatchStrategy.NONE —
        update_strategy crashte mit AttributeError ('str' hat kein.value)
        und die User-Wahl ging verloren. Der Service normalisiert jetzt
        via Value-Lookup.
        """
        service = _service_with_mocks()
        now = datetime.now(UTC)
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="A.A",
                name="A",
                normalized_name="a",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        assert service.set_strategy("A.A", "none") is True  # type: ignore[arg-type]
        loaded = service._repo.get_inventory("A.A")  # type: ignore[attr-defined]
        assert loaded is not None
        assert loaded.patch_strategy is PatchStrategy.NONE

    def test_set_strategy_ungueltiger_wert_raises(self) -> None:
        """: Unbekannte Strategie-Strings schlagen laut fehl (fail-closed)."""
        service = _service_with_mocks()
        with pytest.raises(ValueError, match="quatsch"):
            service.set_strategy("A.A", "quatsch")  # type: ignore[arg-type]


class TestSetChannelOverride:
    """: per-App-Channel-Override (behebt das notify_only-Dead-End)."""

    def test_set_channel_override_aktualisiert_zeile_und_policy(self) -> None:
        service = _service_with_mocks()
        now = datetime.now(UTC)
        # Eindeutiger Name -> keine Kollision mit anderen Tests im selben
        # (Session-)Policy-DB-Envelope.
        name = "ZzzServiceChannelTestApp"
        service._repo.upsert_inventory(  # type: ignore[attr-defined]
            InventoryEntry(
                winget_id="Zzz.ChannelTest",
                name=name,
                normalized_name="zzzservicechanneltestapp",
                vendor="v",
                source="winget",
                installed_version="1.0",
                cpe_string=None,
                channel="notify_only",
                policy_source="default",
                confidence_score=0.0,
                last_seen_at=now,
                last_full_scan_at=now,
            )
        )
        ok = service.set_channel_override(name, "Zzz.ChannelTest", "stable")
        assert ok is True
        # 1) Sofort-Update der Inventar-Zeile.
        loaded = service._repo.get_inventory("Zzz.ChannelTest")  # type: ignore[attr-defined]
        assert loaded is not None
        assert loaded.channel == "stable"
        assert loaded.policy_source == "user"
        # 2) Dauerhafter Override in der PolicyDB (ueberlebt Vollscans).
        policy = service._resolver.policy.get(name)  # type: ignore[attr-defined]
        assert policy.channel == "stable"
        assert policy.source == "user"

    def test_set_channel_override_ohne_winget_id_setzt_nur_policy(self) -> None:
        service = _service_with_mocks()
        name = "ZzzServiceChannelNoWinget"
        # Kein winget_id -> nur der dauerhafte Override, kein Zeilen-Update.
        assert service.set_channel_override(name, None, "pinned") is True
        policy = service._resolver.policy.get(name)  # type: ignore[attr-defined]
        assert policy.channel == "pinned"
        assert policy.source == "user"

    def test_set_channel_override_notify_only_erlaubt(self) -> None:
        """: notify_only ist als expliziter Override zulaessig."""
        service = _service_with_mocks()
        name = "ZzzServiceChannelNotifyOnly"
        assert service.set_channel_override(name, None, "notify_only") is True
        assert service._resolver.policy.get(name).channel == "notify_only"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Custom-Sources: kein Tier-Gate mehr, für alle frei)
# ---------------------------------------------------------------------------


class TestCustomSourceService:
    def test_add_persistiert(self) -> None:
        service = _service_with_mocks()
        src = service.add_custom_source(
            name="Vendor-Tool", vendor_url="https://u", version_regex="r"
        )
        assert src.id
        assert [s.name for s in service.list_custom_sources()] == ["Vendor-Tool"]

    def test_delete_custom_source(self) -> None:
        service = _service_with_mocks()
        src = service.add_custom_source(
            name="X", vendor_url="https://u", version_regex="r"
        )
        assert service.delete_custom_source(src.id) is True
        assert service.list_custom_sources() == []

    def test_load_from_db_listet_custom_source_als_notify_only(self) -> None:
        service = _service_with_mocks()
        service.add_custom_source(
            name="Vendor-Tool",
            vendor_url="https://vendor.example/dl",
            version_regex=r"(\d+\.\d+)",
            installed_version="1.0",
        )
        custom = [r for r in service.load_from_db() if r.source == "custom"]
        assert len(custom) == 1
        r = custom[0]
        assert r.name == "Vendor-Tool"
        assert r.recommendation == "notify_only"
        assert r.winget_id is None  # keine Checkbox / kein Strategie-Dropdown
        assert "https://vendor.example/dl" in (r.action_text or "")

    def test_check_custom_sources_persistiert_ergebnis(self) -> None:
        import dataclasses

        service = _service_with_mocks()
        src = service.add_custom_source(
            name="X", vendor_url="https://u", version_regex=r"(\d+\.\d+)"
        )
        # Fake-Checker: liefert eine available_version (kein echter HTTP-Call).
        checker = MagicMock()
        checker.check.side_effect = lambda s: dataclasses.replace(
            s, available_version="2.0", last_error=None
        )
        service._custom_source_checker = checker  # type: ignore[attr-defined]

        assert service.check_custom_sources() == 1
        loaded = service._repo.get_custom_source(src.id)  # type: ignore[attr-defined]
        assert loaded is not None
        assert loaded.available_version == "2.0"


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


class TestT067EnrichmentPipeline:
    """: load_from_db reichert die Basis-Recommendation mit
    EOL + CSAF-Context via Recommendation-Engine an."""

    def test_eol_resolver_default_ist_curated(self) -> None:
        """Default-Konstruktor injiziert ``CuratedEolResolver``."""
        from core.patch_eol_resolver import CuratedEolResolver

        service = _service_with_mocks()
        assert isinstance(service._eol_resolver, CuratedEolResolver)  # noqa: SLF001

    def test_advisory_repository_default_none(self) -> None:
        """Default-Konstruktor injiziert kein Advisory-Repo (CSAF-
        Anreicherung optional)."""
        service = _service_with_mocks()
        assert service._advisory_repository is None  # noqa: SLF001

    def test_load_from_db_enriched_mit_eol(self) -> None:
        """Office 2010-Result wird durch CuratedEolResolver auf
        ``eol_no_patch`` umgeschrieben — komplett ohne Advisory-Repo.

        Wir injizieren das Result via mocked Repo-Pfad — die
        ``_build_result_from_db``-Konstruktion liefert die Basis und
        ``_enrich_result`` haengt EOL drauf.
        """
        service = _service_with_mocks()
        repo = MagicMock()
        repo.list_inventory.return_value = [
            InventoryEntry(
                winget_id="Microsoft.Office.2010",
                name="Microsoft Office 2010",
                normalized_name="office",
                vendor="microsoft",
                source="winget",
                installed_version="14.0.7184",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=datetime.now(tz=UTC),
                last_full_scan_at=datetime.now(tz=UTC),
            )
        ]
        repo.list_available_versions.return_value = []
        repo.list_cve_matches_for_cpe.return_value = []
        service._repo = repo  # noqa: SLF001

        results = service.load_from_db()
        assert len(results) == 1
        assert results[0].recommendation == "eol_no_patch"
        assert "Office 2010" in (results[0].action_text or "")
        assert results[0].recommendation_source == "curated:office_2010"

    def test_load_from_db_ohne_eol_basis_bleibt(self) -> None:
        """Modern Office (16.x) ist NICHT EOL → Recommendation bleibt
        unveraendert."""
        repo = MagicMock()
        repo.list_inventory.return_value = [
            InventoryEntry(
                winget_id="Microsoft.Office",
                name="Microsoft Office 2021",
                normalized_name="office",
                vendor="microsoft",
                source="winget",
                installed_version="16.0.16130",
                cpe_string=None,
                channel="latest",
                policy_source="default",
                confidence_score=1.0,
                last_seen_at=datetime.now(tz=UTC),
                last_full_scan_at=datetime.now(tz=UTC),
            )
        ]
        repo.list_available_versions.return_value = []
        repo.list_cve_matches_for_cpe.return_value = []

        service = _service_with_mocks()
        service._repo = repo  # noqa: SLF001

        results = service.load_from_db()
        assert results[0].recommendation == "up_to_date"
        assert results[0].action_text is None

    def test_advisory_index_mit_repo(self) -> None:
        """Wenn Advisory-Repo injiziert ist, baut der Service einen
        Index nach matched_component (lowercase)."""
        from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch

        adv_repo = MagicMock()
        adv_repo.list_matches.return_value = [
            AdvisoryMatch(
                id="A_firefox",
                advisory_id="CVE-2026-1",
                matched_component="Mozilla Firefox",
                action_required="update",
            ),
            AdvisoryMatch(
                id="B_firefox",
                advisory_id="CVE-2026-2",
                matched_component="MOZILLA FIREFOX",  # case-variation
                action_required="workaround",
            ),
        ]

        service = PatchInventoryService(
            repo=MagicMock(),
            patch_service=MagicMock(),
            resolver=MagicMock(),
            matcher=MagicMock(),
            advisory_repository=adv_repo,
        )
        index = service._build_advisory_index()  # noqa: SLF001
        # Beide Eintraege landen unter dem normalisierten Key
        assert "mozilla firefox" in index
        assert len(index["mozilla firefox"]) == 2

    def test_advisory_index_repo_exception_tolerant(self) -> None:
        """list_matches darf werfen — load_from_db crasht nicht."""
        adv_repo = MagicMock()
        adv_repo.list_matches.side_effect = RuntimeError("db down")
        service = PatchInventoryService(
            repo=MagicMock(),
            patch_service=MagicMock(),
            resolver=MagicMock(),
            matcher=MagicMock(),
            advisory_repository=adv_repo,
        )
        index = service._build_advisory_index()  # noqa: SLF001
        assert index == {}

    def test_title_resolver_adapter_liefert_advisory_title(self) -> None:
        """Wenn ein Advisory-Repo injiziert ist, baut der Service einen
        AdvisoryTitleAdapter, der get_title via repo.get_advisory liefert."""
        from tools.csaf_advisor.domain.advisory import CsafAdvisory

        adv_repo = MagicMock()
        adv_repo.get_advisory.return_value = CsafAdvisory(
            id="adv-1",
            title="Firefox Heap Overflow",
            publisher="BSI",
            tracking_id="CVE-2026-1",
            tracking_version="1.0",
            initial_release="2026-05-01",
            current_release="2026-05-01",
            severity="critical",
            cvss_score=9.0,
        )
        service = PatchInventoryService(
            repo=MagicMock(),
            patch_service=MagicMock(),
            resolver=MagicMock(),
            matcher=MagicMock(),
            advisory_repository=adv_repo,
        )
        title_resolver = service._title_resolver()  # noqa: SLF001
        assert title_resolver is not None
        assert title_resolver.get_title("CVE-2026-1") == "Firefox Heap Overflow"

    def test_title_resolver_none_ohne_repo(self) -> None:
        service = _service_with_mocks()
        assert service._title_resolver() is None  # noqa: SLF001


class TestConvenience:
    def test_is_inventory_empty_initial_true(self) -> None:
        service = _service_with_mocks()
        assert service.is_inventory_empty() is True

    def test_is_inventory_empty_nach_scan_false(self) -> None:
        service = _service_with_mocks(scan_results=[_result()])
        service.full_scan()
        assert service.is_inventory_empty() is False

    def test_get_last_full_scan_at_propagated(self) -> None:
        service = _service_with_mocks(scan_results=[_result()])
        assert service.get_last_full_scan_at() is None
        service.full_scan()
        assert service.get_last_full_scan_at() is not None


# ---------------------------------------------------------------------------
# KiTodoEmitter-Hook
# ---------------------------------------------------------------------------


class TestKiTodoEmitterHook:
    """Verifiziert dass Patch-Findings nach full_scan/daily_refresh
    in den KI-Todo-Emitter wandern."""

    @pytest.fixture(autouse=True)
    def _winget_modul_verfuegbar(self, monkeypatch):
        """Default: winget-Modul AVAILABLE → Reconcile-Modus aktiv.

        Einzelne Tests überschreiben das gezielt, um den
        Vertrauens-Guard (Tabular-Fallback) zu prüfen.
        """
        import tools.patch_monitor.application.patch_inventory_service as pis
        from core.patch_module_detection import ModuleStatus

        status = MagicMock()
        status.status = ModuleStatus.AVAILABLE
        monkeypatch.setattr(pis, "get_winget_module_status", lambda: status)

    def _service_with_emitter(
        self,
        emitter,  # noqa: ANN001
        scan_results: list[PatchScanResult] | None = None,
    ) -> PatchInventoryService:
        repo = PatchInventoryRepository()
        patch_service = MagicMock()
        patch_service.scan.return_value = scan_results or []
        matcher = MagicMock()
        matcher.get_cves.return_value = []
        return PatchInventoryService(
            repo=repo,
            patch_service=patch_service,
            matcher=matcher,
            ki_todo_emitter=emitter,
        )

    def test_full_scan_emits_findings_for_actionable_recommendations(
        self,
    ) -> None:
        """Emitter bekommt nur actionable Findings.

        Hinweis: ``load_from_db`` re-computed die Recommendation aus
        den persistierten Feldern via ``_recommend``. Damit Chrome
        wirklich als ``up_to_date`` klassifiziert wird, muss
        available_version == installed_version sein (nicht: nur
        Recommendation auf "up_to_date" setzen).
        """
        emitter = MagicMock()
        service = self._service_with_emitter(
            emitter,
            scan_results=[
                _result(
                    name="Firefox",
                    winget_id="Mozilla.Firefox",
                    installed_version="123.0",
                    available_version="124.0",
                    recommendation="update_urgent",
                    cve_ids=("CVE-2024-1234",),
                    cvss_max=8.5,
                ),
                _result(
                    name="Chrome",
                    winget_id="Google.Chrome",
                    installed_version="120.0",
                    available_version="120.0",  # = installed → kein Update
                    recommendation="up_to_date",
                ),
            ],
        )
        service.full_scan(scan_type="initial")
        assert emitter.emit.called
        emitted = emitter.emit.call_args[0][0]
        # Firefox (update_urgent / update_available — actionable);
        # Chrome up_to_date wird geskippt.
        evidence_ids = [f.evidence_id for f in emitted]
        assert "Mozilla.Firefox" in evidence_ids
        assert "Google.Chrome" not in evidence_ids
        # Voll-Sync-Modus — Reconciliation schließt erledigte Tasks.
        assert emitter.emit.call_args.kwargs["reconcile_tool"] == "patch_monitor"

    def test_full_scan_all_up_to_date_emittiert_leere_liste_fuer_reconcile(
        self,
    ) -> None:
        """-Kernfall: 'alles installiert' MUSS den Sync erreichen.

        Vorher wurde bei leerer Findings-Liste gar nicht emittiert — damit
        konnten offene Patch-Tasks nie automatisch schließen.
        """
        emitter = MagicMock()
        service = self._service_with_emitter(
            emitter,
            scan_results=[
                _result(name="Firefox", winget_id="Mozilla.Firefox", recommendation="up_to_date"),
                _result(name="Chrome", winget_id="Google.Chrome", recommendation="up_to_date"),
            ],
        )
        service.full_scan(scan_type="initial")
        assert emitter.emit.called
        assert emitter.emit.call_args[0][0] == []
        assert emitter.emit.call_args.kwargs["reconcile_tool"] == "patch_monitor"

    def test_leeres_inventar_reconciled_nicht(self) -> None:
        """Review-P1-Guard: Collector-Crash (scan=[]) darf NICHT reconcilen.

        PatchService.scan ist fail-open — ein leeres Inventar bedeutet
        degradierten Collector oder Frisch-DB, nicht "alles installiert".
        """
        emitter = MagicMock()
        service = self._service_with_emitter(emitter, scan_results=[])
        service.full_scan(scan_type="initial")
        # Keine Findings + kein Reconcile → Hook ist komplett No-op.
        assert not emitter.emit.called

    def test_tabular_fallback_reconciled_nicht(self, monkeypatch) -> None:
        """Review-P1-Guard: ohne winget-Modul kein Reconcile.

        Der Tabular-Fallback liefert kein ``is_update_available`` —
        Update-Findings verschwänden scheinbar, offene Tasks würden
        fälschlich massenhaft geschlossen.
        """
        import tools.patch_monitor.application.patch_inventory_service as pis
        from core.patch_module_detection import ModuleStatus

        status = MagicMock()
        status.status = ModuleStatus.BLOCKED
        monkeypatch.setattr(pis, "get_winget_module_status", lambda: status)

        emitter = MagicMock()
        service = self._service_with_emitter(
            emitter,
            scan_results=[
                _result(
                    name="Firefox",
                    winget_id="Mozilla.Firefox",
                    installed_version="123.0",
                    available_version="124.0",
                    recommendation="update_urgent",
                    cve_ids=("CVE-2024-1234",),
                    cvss_max=8.5,
                ),
            ],
        )
        service.full_scan(scan_type="initial")
        assert emitter.emit.called
        assert emitter.emit.call_args.kwargs["reconcile_tool"] is None

    def test_full_scan_emit_exception_does_not_break_scan(self) -> None:
        emitter = MagicMock()
        emitter.emit.side_effect = RuntimeError("mainpage-DB weg")
        service = self._service_with_emitter(
            emitter,
            scan_results=[
                _result(
                    name="Firefox",
                    winget_id="Mozilla.Firefox",
                    recommendation="update_urgent",
                ),
            ],
        )
        # Scan darf nicht crashen trotz Emitter-Exception
        summary = service.full_scan(scan_type="initial")
        assert summary is not None
        assert summary.items_total == 1
