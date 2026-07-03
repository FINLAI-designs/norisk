"""
test_supply_chain_patch_linker-i.

Tests fuer:class:`PatchMonitorLinker`. Patch-Monitor-Repo wird mit
einem Test-Double simuliert (kein real-DB-Zugriff noetig).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from tools.supply_chain_monitor.application.patch_monitor_linker import (
    PatchMonitorLinker,
)
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import (
    VendorCatalogEntry,
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
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


# ---------------------------------------------------------------------------
# Test-Doubles fuer Patch-Monitor-Repo
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FakeInventoryEntry:
    """Minimaler InventoryEntry-Stub — nur die Felder die der Linker liest."""

    name: str
    vendor: str | None
    winget_id: str
    cpe_string: str | None


@dataclass(frozen=True)
class _FakeAvailableVersion:
    winget_id: str
    is_update_available: bool


@dataclass(frozen=True)
class _FakeCveMatch:
    cpe_string: str
    cve_id: str
    cvss_score: float | None
    exploit_available: bool
    eol: bool
    fetched_at: datetime


class _FakePatchRepo:
    def __init__(
        self,
        inventory: list[_FakeInventoryEntry],
        available_versions: list[_FakeAvailableVersion],
        cves_per_cpe: dict[str, list[_FakeCveMatch]],
    ) -> None:
        self._inventory = inventory
        self._available_versions = available_versions
        self._cves_per_cpe = cves_per_cpe

    def list_inventory(self) -> list[_FakeInventoryEntry]:
        return list(self._inventory)

    def list_available_versions(self) -> list[_FakeAvailableVersion]:
        return list(self._available_versions)

    def list_cve_matches_for_cpe(self, cpe: str) -> list[_FakeCveMatch]:
        return list(self._cves_per_cpe.get(cpe, []))


def _make_cve(cpe: str, cvss: float, exploit: bool = False) -> _FakeCveMatch:
    return _FakeCveMatch(
        cpe_string=cpe,
        cve_id="CVE-2024-0001",
        cvss_score=cvss,
        exploit_available=exploit,
        eol=False,
        fetched_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def linker_setup() -> tuple[VendorRepository, VendorCatalogRepository]:
    db = _InMemoryDB()
    vrepo = VendorRepository(db=db)
    crepo = VendorCatalogRepository(db=db)
    return vrepo, crepo


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_linker(
    *,
    vendors: Iterable[tuple[str, VendorCategory]] = (),
    catalog: Iterable[tuple[str, tuple[str, ...]]] = (),
    inventory: list[_FakeInventoryEntry] | None = None,
    available_versions: list[_FakeAvailableVersion] | None = None,
    cves_per_cpe: dict[str, list[_FakeCveMatch]] | None = None,
) -> tuple[PatchMonitorLinker, VendorRepository]:
    db = _InMemoryDB()
    vrepo = VendorRepository(db=db)
    crepo = VendorCatalogRepository(db=db)

    from tools.supply_chain_monitor.domain.models import Vendor  # noqa: PLC0415

    for name, category in vendors:
        vrepo.add(
            Vendor(
                id=None,
                name=name,
                category=category,
                criticality_score=3,
            )
        )
    for name, patterns in catalog:
        crepo.add(
            VendorCatalogEntry(
                id=None,
                canonical_name=name,
                default_category=VendorCategory.CLOUD,
                app_name_patterns=patterns,
            )
        )
    patch_repo = _FakePatchRepo(
        inventory=inventory or [],
        available_versions=available_versions or [],
        cves_per_cpe=cves_per_cpe or {},
    )
    linker = PatchMonitorLinker(
        vendor_repository=vrepo,
        catalog_repository=crepo,
        patch_repository=patch_repo,
    )
    return linker, vrepo


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSummarize:
    def test_vendor_ohne_catalog_eintrag_liefert_empty(self) -> None:
        linker, vrepo = _make_linker(
            vendors=[("Microsoft", VendorCategory.CLOUD)],
            catalog=[],  # KEIN Catalog-Eintrag
        )
        summaries = linker.summarize_per_vendor()
        v = vrepo.list_all()[0]
        assert v.id is not None
        s = summaries[v.id]
        assert s.matched_app_count == 0
        assert s.has_findings is False

    def test_pattern_match_zaehlt_matched_apps(self) -> None:
        linker, vrepo = _make_linker(
            vendors=[("Microsoft", VendorCategory.CLOUD)],
            catalog=[("Microsoft", ("microsoft", "onedrive"))],
            inventory=[
                _FakeInventoryEntry(
                    name="Microsoft Office Professional",
                    vendor="Microsoft Corp",
                    winget_id="Microsoft.Office",
                    cpe_string=None,
                ),
                _FakeInventoryEntry(
                    name="Microsoft OneDrive",
                    vendor="Microsoft Corp",
                    winget_id="Microsoft.OneDrive",
                    cpe_string=None,
                ),
                _FakeInventoryEntry(
                    name="Notepad++",
                    vendor=None,
                    winget_id="Notepad++.Notepad++",
                    cpe_string=None,
                ),
            ],
        )
        v = vrepo.list_all()[0]
        assert v.id is not None
        s = linker.summarize_per_vendor()[v.id]
        assert s.matched_app_count == 2
        assert s.apps_with_cves == 0
        assert s.apps_with_updates == 0

    def test_updates_und_cves_aggregiert(self) -> None:
        linker, vrepo = _make_linker(
            vendors=[("Microsoft", VendorCategory.CLOUD)],
            catalog=[("Microsoft", ("microsoft",))],
            inventory=[
                _FakeInventoryEntry(
                    name="Microsoft Office",
                    vendor="MS",
                    winget_id="Microsoft.Office",
                    cpe_string="cpe:2.3:a:microsoft:office:2021:*:*:*:*:*:*:*",
                ),
                _FakeInventoryEntry(
                    name="Microsoft Teams",
                    vendor="MS",
                    winget_id="Microsoft.Teams",
                    cpe_string=None,
                ),
            ],
            available_versions=[
                _FakeAvailableVersion(
                    winget_id="Microsoft.Office", is_update_available=True
                ),
                _FakeAvailableVersion(
                    winget_id="Microsoft.Teams", is_update_available=False
                ),
            ],
            cves_per_cpe={
                "cpe:2.3:a:microsoft:office:2021:*:*:*:*:*:*:*": [
                    _make_cve(
                        "cpe:2.3:a:microsoft:office:2021:*:*:*:*:*:*:*",
                        cvss=7.5,
                    ),
                    _make_cve(
                        "cpe:2.3:a:microsoft:office:2021:*:*:*:*:*:*:*",
                        cvss=9.8,
                        exploit=True,
                    ),
                ],
            },
        )
        v = vrepo.list_all()[0]
        assert v.id is not None
        s = linker.summarize_per_vendor()[v.id]
        assert s.matched_app_count == 2
        assert s.apps_with_updates == 1  # nur Office hat is_update_available
        assert s.apps_with_cves == 1  # nur Office hat einen CPE+CVEs
        assert s.total_cves == 2
        assert s.max_cvss == 9.8
        assert s.has_exploit is True
        assert s.has_findings is True

    def test_keine_patch_repo_liefert_leere_summaries(self) -> None:
        # patch_repository=None → alle Summaries leer
        db = _InMemoryDB()
        vrepo = VendorRepository(db=db)
        crepo = VendorCatalogRepository(db=db)
        from tools.supply_chain_monitor.domain.models import Vendor  # noqa: PLC0415

        vrepo.add(
            Vendor(
                id=None,
                name="DATEV",
                category=VendorCategory.KANZLEISOFTWARE,
                criticality_score=3,
            )
        )
        crepo.add(
            VendorCatalogEntry(
                id=None,
                canonical_name="DATEV",
                default_category=VendorCategory.KANZLEISOFTWARE,
                app_name_patterns=("datev",),
            )
        )

        # Sentinel-Wert sorgt dafuer, dass _lazy_patch_repository NICHT
        # aufgerufen wird (sonst wuerde es eine echte EncryptedDatabase ziehen
        # und im Test-Environment crashen).
        class _NullRepo:
            def list_inventory(self) -> list:
                return []

            def list_available_versions(self) -> list:
                return []

            def list_cve_matches_for_cpe(self, cpe: str) -> list:
                return []

        linker = PatchMonitorLinker(
            vendor_repository=vrepo,
            catalog_repository=crepo,
            patch_repository=_NullRepo(),
        )
        summaries = linker.summarize_per_vendor()
        v = vrepo.list_all()[0]
        assert v.id is not None
        assert summaries[v.id].matched_app_count == 0

    def test_summary_for_vendor_unbekannt_liefert_empty(self) -> None:
        linker, _ = _make_linker(
            vendors=[("X", VendorCategory.CLOUD)],
            catalog=[],
        )
        s = linker.summary_for_vendor(99999)
        assert s.matched_app_count == 0
        assert s.has_findings is False
