"""
patch_monitor_linker — Verknuepft Vendoren mit Patch-Monitor-Befunden.

Iter 2d-i:

Pro Vendor aggregiert dieser Service Patch-Monitor-Daten (offene CVEs,
verfuegbare Updates), basierend auf den App-Patterns des zugehoerigen
:class:`VendorCatalogEntry` (Patrick-Direktive 2026-05-15 — Catalog-
Patterns wiederverwenden, statt manuelles Linking neu zu bauen).

Matching-Pipeline:
    1. Pro Vendor: ``VendorCatalogRepository.get_by_canonical_name(
       vendor.canonical_name)`` lookup. Kein Catalog-Eintrag → keine
       Patch-Daten (User soll dann via Catalog-Tab einen Eintrag mit
       Patterns anlegen, oder den Vendor umbenennen).
    2. ``app_name_patterns`` (lowercase Substring) gegen jeden
:class:`InventoryEntry.name` matchen.
    3. Aggregieren: pro Vendor ``apps_with_updates``,
       ``apps_with_cves``, ``total_cves`` und ``max_cvss``.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1-i, 2026-05-15)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from core.logger import get_logger
from tools.supply_chain_monitor.data.vendor_catalog_repository import (
    VendorCatalogRepository,
)
from tools.supply_chain_monitor.data.vendor_repository import VendorRepository
from tools.supply_chain_monitor.domain.models import Vendor

_log = get_logger(__name__)


@dataclass(frozen=True)
class VendorPatchSummary:
    """Patch-Monitor-Aggregat pro Vendor (transient, nicht persistiert).

    Attributes:
        vendor_id: ID des:class:`Vendor`.
        matched_app_count: Anzahl Patch-Monitor-Apps, die zu diesem
                            Vendor (per Catalog-Patterns) matchen.
        apps_with_updates: Davon Apps mit ``is_update_available = True``.
        apps_with_cves: Davon Apps mit mindestens einem CVE-Match.
        total_cves: Summe aller CVE-Matches ueber alle Apps
                            (Mehrfachzaehlung pro App moeglich).
        max_cvss: Hoechster CVSS-Score ueber alle gematchten
                            CVEs, ``None`` wenn keine CVEs.
        has_exploit: ``True`` wenn mindestens ein CVE-Match
                            ``exploit_available=True`` hat.
    """

    vendor_id: int
    matched_app_count: int
    apps_with_updates: int
    apps_with_cves: int
    total_cves: int
    max_cvss: float | None
    has_exploit: bool

    @property
    def has_findings(self) -> bool:
        """``True`` wenn der Vendor in irgendeiner Form auffaellig ist."""
        return self.apps_with_updates > 0 or self.apps_with_cves > 0


def _empty_summary(vendor_id: int) -> VendorPatchSummary:
    return VendorPatchSummary(
        vendor_id=vendor_id,
        matched_app_count=0,
        apps_with_updates=0,
        apps_with_cves=0,
        total_cves=0,
        max_cvss=None,
        has_exploit=False,
    )


class PatchMonitorLinker:
    """Service, der Patch-Monitor-Daten pro Vendor aggregiert.

    Die Patch-Monitor-Abhaengigkeit ist OPTIONAL: wenn ``patch_repository``
    nicht gesetzt ist (z. B. Tests oder Tool-Sub-Anlauf), liefern alle
    Methoden leere Summaries. Damit faellt das Tool nie aus weil der
    Patch-Monitor noch keinen Scan hatte.
    """

    def __init__(
        self,
        *,
        vendor_repository: VendorRepository | None = None,
        catalog_repository: VendorCatalogRepository | None = None,
        patch_repository: object | None = None,
    ) -> None:
        self._vendor_repo = vendor_repository or VendorRepository()
        self._catalog_repo = catalog_repository or VendorCatalogRepository()
        self._patch_repo = patch_repository
        if self._patch_repo is None:
            # Lazy-Import — patch_monitor-Repo ist optional und ein
            # ImportError darf den Supply-Chain-Monitor nicht crashen.
            self._patch_repo = _lazy_patch_repository()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summarize_per_vendor(self) -> dict[int, VendorPatchSummary]:
        """Liefert pro Vendor das Patch-Monitor-Aggregat.

        Vendoren ohne Catalog-Eintrag oder ohne Patterns landen mit
        leerem Summary in der Map — der Caller kann sie damit von
        Vendoren mit Findings unterscheiden.

        Returns:
            Mapping ``vendor_id → VendorPatchSummary``. Vendoren ohne
            persistierte ID werden ueberspringen.
        """
        vendors = self._vendor_repo.list_all()
        if not vendors:
            return {}
        inventory = self._read_inventory()
        available_versions = self._read_available_versions()
        cves_per_cpe = self._read_cves_per_cpe(inventory)

        result: dict[int, VendorPatchSummary] = {}
        for vendor in vendors:
            if vendor.id is None:
                continue
            patterns = self._lookup_patterns(vendor)
            if not patterns:
                result[vendor.id] = _empty_summary(vendor.id)
                continue
            result[vendor.id] = _summarize_for_patterns(
                vendor_id=vendor.id,
                patterns=patterns,
                inventory=inventory,
                available_versions=available_versions,
                cves_per_cpe=cves_per_cpe,
            )
        return result

    def summary_for_vendor(self, vendor_id: int) -> VendorPatchSummary:
        """Convenience: Aggregat fuer einen einzelnen Vendor.

        Liefert ``_empty_summary`` wenn der Vendor unbekannt oder ohne
        Catalog-Patterns ist — kein Wurf.
        """
        vendor = self._vendor_repo.get_by_id(vendor_id)
        if vendor is None:
            return _empty_summary(vendor_id)
        patterns = self._lookup_patterns(vendor)
        if not patterns:
            return _empty_summary(vendor_id)
        inventory = self._read_inventory()
        available_versions = self._read_available_versions()
        cves_per_cpe = self._read_cves_per_cpe(inventory)
        return _summarize_for_patterns(
            vendor_id=vendor_id,
            patterns=patterns,
            inventory=inventory,
            available_versions=available_versions,
            cves_per_cpe=cves_per_cpe,
        )

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _lookup_patterns(self, vendor: Vendor) -> tuple[str, ...]:
        entry = self._catalog_repo.get_by_canonical_name(vendor.name)
        if entry is None:
            return ()
        return entry.app_name_patterns

    def _read_inventory(self) -> list:
        """Liefert alle:class:`InventoryEntry`-Objekte oder leere Liste."""
        if self._patch_repo is None:
            return []
        list_inventory = getattr(self._patch_repo, "list_inventory", None)
        if list_inventory is None or not callable(list_inventory):
            return []
        try:
            return list(list_inventory())
        except Exception as exc:  # noqa: BLE001 — Patch-DB darf uns nicht crashen
            _log.warning(
                "PatchMonitorLinker: list_inventory fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []

    def _read_available_versions(self) -> dict[str, bool]:
        """Liefert ``winget_id → is_update_available``-Map."""
        if self._patch_repo is None:
            return {}
        list_av = getattr(self._patch_repo, "list_available_versions", None)
        if list_av is None or not callable(list_av):
            return {}
        try:
            entries = list(list_av())
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "PatchMonitorLinker: list_available_versions fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return {}
        return {
            getattr(e, "winget_id", ""): bool(getattr(e, "is_update_available", False))
            for e in entries
            if getattr(e, "winget_id", "")
        }

    def _read_cves_per_cpe(self, inventory: Iterable) -> dict[str, list]:
        """Holt pro CPE-String die:class:`CveMatchEntry`-Liste."""
        if self._patch_repo is None:
            return {}
        get_cves = getattr(self._patch_repo, "list_cve_matches_for_cpe", None)
        if get_cves is None or not callable(get_cves):
            return {}
        seen_cpes: set[str] = set()
        for entry in inventory:
            cpe = getattr(entry, "cpe_string", None)
            if cpe:
                seen_cpes.add(cpe)
        result: dict[str, list] = {}
        for cpe in seen_cpes:
            try:
                result[cpe] = list(get_cves(cpe))
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "PatchMonitorLinker: list_cve_matches_for_cpe(%r) "
                    "fehlgeschlagen: %s",
                    cpe,
                    type(exc).__name__,
                )
                result[cpe] = []
        return result


def _summarize_for_patterns(
    *,
    vendor_id: int,
    patterns: tuple[str, ...],
    inventory: Iterable,
    available_versions: dict[str, bool],
    cves_per_cpe: dict[str, list],
) -> VendorPatchSummary:
    """Aggregiert die Patch-Daten fuer einen einzelnen Vendor.

    Patterns sind in:class:`VendorCatalogEntry.__post_init__` bereits
    lowercase + getrimmt — wir matchen gegen ``entry.name.lower``.
    """
    matched_apps: list = []
    for entry in inventory:
        name = getattr(entry, "name", None)
        if not isinstance(name, str):
            continue
        name_lc = name.lower()
        if any(pattern in name_lc for pattern in patterns):
            matched_apps.append(entry)

    apps_with_updates = 0
    apps_with_cves = 0
    total_cves = 0
    max_cvss: float | None = None
    has_exploit = False

    for app in matched_apps:
        winget_id = getattr(app, "winget_id", "")
        if winget_id and available_versions.get(winget_id):
            apps_with_updates += 1
        cpe = getattr(app, "cpe_string", None)
        if not cpe:
            continue
        cves = cves_per_cpe.get(cpe, [])
        if not cves:
            continue
        apps_with_cves += 1
        total_cves += len(cves)
        for cve in cves:
            cvss = getattr(cve, "cvss_score", None)
            if cvss is not None:
                max_cvss = cvss if max_cvss is None else max(max_cvss, cvss)
            if getattr(cve, "exploit_available", False):
                has_exploit = True

    return VendorPatchSummary(
        vendor_id=vendor_id,
        matched_app_count=len(matched_apps),
        apps_with_updates=apps_with_updates,
        apps_with_cves=apps_with_cves,
        total_cves=total_cves,
        max_cvss=max_cvss,
        has_exploit=has_exploit,
    )


def _lazy_patch_repository() -> object | None:
    """Versucht das Patch-Monitor-Repo zu importieren — bei Fehler ``None``."""
    try:
        from tools.patch_monitor.data.patch_inventory_repository import (  # noqa: PLC0415
            PatchInventoryRepository,
        )

        return PatchInventoryRepository()
    except Exception as exc:  # noqa: BLE001 — ImportError + DB-Init-Fehler beide OK
        _log.info(
            "PatchMonitorLinker: Patch-Monitor-Repo nicht verfuegbar (%s) — "
            "Summaries bleiben leer.",
            type(exc).__name__,
        )
        return None
