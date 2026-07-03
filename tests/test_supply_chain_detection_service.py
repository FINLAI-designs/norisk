"""
test_supply_chain_detection_service.

End-to-End-Tests fuer:class:`DetectionService` und:class:`CatalogSeeder`
mit In-Memory-DB und injizierten Detector-Readern.
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.supply_chain_monitor.application.catalog_seeder import CatalogSeeder
from tools.supply_chain_monitor.application.detection_service import DetectionService
from tools.supply_chain_monitor.application.detectors import (
    CertIssuerDetector,
    InstalledAppsDetector,
    MxLookupDetector,
)
from tools.supply_chain_monitor.application.vendor_service import VendorService
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.data.vendor_detection_repository import (
    VendorDetectionRepository,
)
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import (
    DetectionConfidence,
    DetectionStatus,
    VendorCategory,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    """Geteilte In-Memory-DB — alle Repositories teilen sich dieselbe
    sqlite-Connection wie die Produktion auf einer Datei."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture
def shared_db() -> _InMemoryDB:
    return _InMemoryDB()


@pytest.fixture
def service(shared_db: _InMemoryDB) -> DetectionService:
    catalog_repo = VendorCatalogRepository(db=shared_db)
    detection_repo = VendorDetectionRepository(db=shared_db)
    vendor_repo = VendorRepository(db=shared_db)
    vendor_service = VendorService(repository=vendor_repo)

    # Catalog mit ein paar Eintraegen befuellen.
    CatalogSeeder(repository=catalog_repo).seed_if_empty()

    # Detectors mit Mocks injizieren — keine Windows-Registry / DNS / TLS.
    installed = InstalledAppsDetector(
        reader=lambda: ["Microsoft OneDrive", "DATEV ProFin", "Notepad++"]
    )
    mx_map = {"kanzlei.de": ["outlook-com.olc.protection.outlook.com"]}

    def mx_resolver(d: str) -> list[str]:
        return mx_map.get(d, [])

    mx = MxLookupDetector(resolver=mx_resolver)
    cert_map = {"kanzlei.de": "Microsoft RSA TLS CA 01"}

    def cert_scanner(d: str) -> str:
        return cert_map.get(d, "")

    cert = CertIssuerDetector(scanner=cert_scanner)

    return DetectionService(
        catalog_repository=catalog_repo,
        detection_repository=detection_repo,
        vendor_service=vendor_service,
        installed_apps_detector=installed,
        mx_lookup_detector=mx,
        cert_issuer_detector=cert,
    )


# ---------------------------------------------------------------------------
# CatalogSeeder
# ---------------------------------------------------------------------------


class TestCatalogSeeder:
    def test_seed_if_empty_fuegt_alle_eintraege_ein(self) -> None:
        catalog_repo = VendorCatalogRepository(db=_InMemoryDB())
        inserted = CatalogSeeder(repository=catalog_repo).seed_if_empty()
        assert inserted == CatalogSeeder.seed_size()
        assert catalog_repo.count() == CatalogSeeder.seed_size()

    def test_seed_if_empty_zweiter_aufruf_tut_nichts(self) -> None:
        catalog_repo = VendorCatalogRepository(db=_InMemoryDB())
        seeder = CatalogSeeder(repository=catalog_repo)
        first = seeder.seed_if_empty()
        second = seeder.seed_if_empty()
        assert first > 0
        assert second == 0

    def test_force_reseed_ergaenzt_fehlende_aber_belaesst_user_edits(self) -> None:
        catalog_repo = VendorCatalogRepository(db=_InMemoryDB())
        seeder = CatalogSeeder(repository=catalog_repo)
        seeder.seed_if_empty()
        # User loescht einen Eintrag.
        microsoft = catalog_repo.get_by_canonical_name("Microsoft")
        assert microsoft is not None
        assert microsoft.id is not None
        catalog_repo.delete(microsoft.id)
        # force_reseed legt Microsoft wieder an.
        ergaenzt = seeder.force_reseed()
        assert ergaenzt == 1
        assert catalog_repo.get_by_canonical_name("Microsoft") is not None


# ---------------------------------------------------------------------------
# DetectionService.run_detection
# ---------------------------------------------------------------------------


class TestRunDetection:
    def test_run_detection_persistiert_alle_treffer(
        self, service: DetectionService
    ) -> None:
        summary = service.run_detection(["kanzlei.de"])
        assert summary.installed_apps_count >= 2  # Microsoft + DATEV
        assert summary.mx_lookup_count == 1  # Microsoft via MX
        assert summary.cert_issuer_count == 1  # Microsoft via Cert

    def test_run_detection_ohne_domains_macht_nur_installed_apps(
        self, service: DetectionService
    ) -> None:
        summary = service.run_detection([])
        assert summary.installed_apps_count >= 2
        assert summary.mx_lookup_count == 0
        assert summary.cert_issuer_count == 0

    def test_zweiter_run_dupliziert_keine_treffer(
        self, service: DetectionService
    ) -> None:
        service.run_detection(["kanzlei.de"])
        # Suggestions sind aus den DB-Eintraegen aggregiert.
        first_run = service.list_suggestions()
        ms_first = next(s for s in first_run if s.catalog_entry.canonical_name == "Microsoft")
        first_detection_count = len(ms_first.detections)

        service.run_detection(["kanzlei.de"])
        second_run = service.list_suggestions()
        ms_second = next(s for s in second_run if s.catalog_entry.canonical_name == "Microsoft")
        # Anzahl Detections darf NICHT wachsen — Upsert dedup auf
        # (catalog_entry_id, source, raw_match).
        assert len(ms_second.detections) == first_detection_count


class TestSuggestions:
    def test_microsoft_bekommt_high_confidence(
        self, service: DetectionService
    ) -> None:
        service.run_detection(["kanzlei.de"])
        sugs = service.list_suggestions()
        ms = next(s for s in sugs if s.catalog_entry.canonical_name == "Microsoft")
        # Installed (OneDrive=1) + MX (=2) + Cert (=3) = 6 → HIGH
        assert ms.source_points == 6
        assert ms.confidence is DetectionConfidence.HIGH

    def test_datev_nur_installed_app_ist_low(self, service: DetectionService) -> None:
        service.run_detection(["kanzlei.de"])
        sugs = service.list_suggestions()
        datev = next(s for s in sugs if s.catalog_entry.canonical_name == "DATEV")
        assert datev.source_points == 1
        assert datev.confidence is DetectionConfidence.LOW

    def test_suggestions_sortiert_nach_confidence_desc(
        self, service: DetectionService
    ) -> None:
        service.run_detection(["kanzlei.de"])
        sugs = service.list_suggestions()
        ranks = [s.confidence for s in sugs]
        # HIGH muss vor MEDIUM vor LOW kommen.
        order = ["HIGH", "MEDIUM", "LOW"]
        idx = [order.index(c.value.upper()) for c in ranks]
        assert idx == sorted(idx)


# ---------------------------------------------------------------------------
# Status-Lifecycle (accept / reject / defer)
# ---------------------------------------------------------------------------


class TestAcceptSuggestion:
    def test_accept_legt_vendor_an_und_markiert_detections(
        self, service: DetectionService, shared_db: _InMemoryDB
    ) -> None:
        service.run_detection(["kanzlei.de"])
        sugs = service.list_suggestions()
        ms = next(s for s in sugs if s.catalog_entry.canonical_name == "Microsoft")
        assert ms.catalog_entry.id is not None

        vendor = service.accept_suggestion(ms.catalog_entry.id, criticality_score=5)
        assert vendor.name == "Microsoft"
        assert vendor.category is VendorCategory.CLOUD
        assert vendor.criticality_score == 5

        # Alle PENDING-Detections sind jetzt ACCEPTED.
        det_repo = VendorDetectionRepository(db=shared_db)
        for det in det_repo.list_for_catalog_entry(ms.catalog_entry.id):
            assert det.status is DetectionStatus.ACCEPTED
            assert det.vendor_id == vendor.id

        # Microsoft taucht nicht mehr in Suggestions auf.
        sugs_after = service.list_suggestions()
        assert "Microsoft" not in {s.catalog_entry.canonical_name for s in sugs_after}

    def test_accept_unbekannter_catalog_eintrag_wirft(
        self, service: DetectionService
    ) -> None:
        with pytest.raises(ValueError, match="Kein Catalog"):
            service.accept_suggestion(9999)


class TestRejectSuggestion:
    def test_reject_markiert_actionable_und_kommt_nicht_wieder(
        self, service: DetectionService
    ) -> None:
        service.run_detection(["kanzlei.de"])
        ms = next(
            s for s in service.list_suggestions()
            if s.catalog_entry.canonical_name == "Microsoft"
        )
        assert ms.catalog_entry.id is not None

        affected = service.reject_suggestion(ms.catalog_entry.id)
        assert affected >= 3  # Installed + MX + Cert mindestens

        # Re-Scan triggert keinen erneuten Vorschlag.
        service.run_detection(["kanzlei.de"])
        sugs_after = {s.catalog_entry.canonical_name for s in service.list_suggestions()}
        assert "Microsoft" not in sugs_after


class TestDeferSuggestion:
    def test_defer_setzt_pending_auf_deferred_bleibt_actionable(
        self, service: DetectionService
    ) -> None:
        service.run_detection(["kanzlei.de"])
        ms = next(
            s for s in service.list_suggestions()
            if s.catalog_entry.canonical_name == "Microsoft"
        )
        assert ms.catalog_entry.id is not None

        affected = service.defer_suggestion(ms.catalog_entry.id)
        assert affected >= 3

        # Microsoft bleibt actionable — DEFERRED zaehlt weiter als Vorschlag.
        sugs_after = service.list_suggestions()
        assert "Microsoft" in {s.catalog_entry.canonical_name for s in sugs_after}
