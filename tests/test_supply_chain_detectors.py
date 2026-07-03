"""
test_supply_chain_detectors.

Tests fuer die drei Detector-Klassen. Wir injizieren feste Reader-Callables,
damit die Tests ohne Windows-Registry, DNS oder Netzwerk laufen.
"""

from __future__ import annotations

import pytest

from tools.supply_chain_monitor.application.detectors import (
    CertIssuerDetector,
    InstalledAppsDetector,
    MxLookupDetector,
)
from tools.supply_chain_monitor.domain.models import (
    DetectionSource,
    VendorCatalogEntry,
    VendorCategory,
)


def _make_catalog() -> list[VendorCatalogEntry]:
    return [
        VendorCatalogEntry(
            id=1,
            canonical_name="Microsoft",
            default_category=VendorCategory.CLOUD,
            app_name_patterns=("microsoft", "onedrive"),
            mx_hostname_patterns=("protection.outlook.com",),
            cert_issuer_patterns=("microsoft",),
        ),
        VendorCatalogEntry(
            id=2,
            canonical_name="Hetzner",
            default_category=VendorCategory.MSP,
            mx_hostname_patterns=("your-server.de", "hetzner.com"),
            cert_issuer_patterns=("hetzner",),
        ),
        VendorCatalogEntry(
            id=3,
            canonical_name="DATEV",
            default_category=VendorCategory.KANZLEISOFTWARE,
            app_name_patterns=("datev",),
        ),
    ]


# ---------------------------------------------------------------------------
# InstalledAppsDetector
# ---------------------------------------------------------------------------


class TestInstalledAppsDetector:
    def test_detect_matched_app_name(self) -> None:
        detector = InstalledAppsDetector(
            reader=lambda: ["Microsoft OneDrive", "Notepad++", "DATEV-Schluessel"]
        )
        hits = detector.detect(_make_catalog())
        # Microsoft matched 2x (microsoft + onedrive in OneDrive) → dedup
        # auf 1 Detection. DATEV matched 1x.
        catalogs_hit = {h.catalog_entry_id for h in hits}
        assert catalogs_hit == {1, 3}
        for h in hits:
            assert h.source is DetectionSource.INSTALLED_APP

    def test_detect_case_insensitive(self) -> None:
        detector = InstalledAppsDetector(reader=lambda: ["MICROSOFT OFFICE 365"])
        hits = detector.detect(_make_catalog())
        assert len(hits) == 1
        assert hits[0].catalog_entry_id == 1

    def test_detect_leerer_reader_liefert_nichts(self) -> None:
        detector = InstalledAppsDetector(reader=lambda: [])
        assert detector.detect(_make_catalog()) == []

    def test_detect_leerer_catalog_liefert_nichts(self) -> None:
        detector = InstalledAppsDetector(reader=lambda: ["Microsoft Office"])
        assert detector.detect([]) == []

    def test_detect_faengt_reader_fehler_ab(self) -> None:
        def broken_reader() -> list[str]:
            raise RuntimeError("Registry kaputt")

        detector = InstalledAppsDetector(reader=broken_reader)
        # Darf nicht crashen, sondern leere Liste liefern.
        assert detector.detect(_make_catalog()) == []


# ---------------------------------------------------------------------------
# MxLookupDetector
# ---------------------------------------------------------------------------


class TestMxLookupDetector:
    def test_detect_matched_mx_hostname(self) -> None:
        resolver = {
            "kanzlei.de": ["outlook-com.olc.protection.outlook.com"],
            "hosting.de": ["mx.your-server.de"],
        }
        detector = MxLookupDetector(resolver=lambda d: resolver.get(d, []))
        hits = detector.detect(_make_catalog(), ["kanzlei.de", "hosting.de"])
        catalogs_hit = {h.catalog_entry_id for h in hits}
        assert catalogs_hit == {1, 2}
        for h in hits:
            assert h.source is DetectionSource.MX_LOOKUP

    def test_detect_keine_domains_liefert_nichts(self) -> None:
        detector = MxLookupDetector(resolver=lambda _: [])
        assert detector.detect(_make_catalog(), []) == []

    def test_detect_resolver_fehler_wird_protokolliert_nicht_geworfen(self) -> None:
        def broken(_d: str) -> list[str]:
            raise RuntimeError("DNS down")

        detector = MxLookupDetector(resolver=broken)
        # Sollte einfach leere Treffer liefern, nicht crashen.
        assert detector.detect(_make_catalog(), ["kanzlei.de"]) == []

    def test_detect_trim_punkt_am_ende(self) -> None:
        # Erfasste Domain "kanzlei.de." mit trailing dot → wird normalisiert.
        resolver_calls: list[str] = []

        def capture(domain: str) -> list[str]:
            resolver_calls.append(domain)
            return []

        detector = MxLookupDetector(resolver=capture)
        detector.detect(_make_catalog(), ["kanzlei.de.", "  HOSTING.DE  "])
        assert resolver_calls == ["kanzlei.de", "hosting.de"]


# ---------------------------------------------------------------------------
# CertIssuerDetector
# ---------------------------------------------------------------------------


class TestCertIssuerDetector:
    def test_detect_matched_issuer(self) -> None:
        issuers = {
            "kanzlei.de": "Microsoft RSA TLS CA 01",
            "hosting.de": "Hetzner Online GmbH Root CA",
        }
        detector = CertIssuerDetector(scanner=lambda d: issuers.get(d, ""))
        hits = detector.detect(_make_catalog(), list(issuers))
        catalogs_hit = {h.catalog_entry_id for h in hits}
        assert catalogs_hit == {1, 2}
        for h in hits:
            assert h.source is DetectionSource.CERT_ISSUER

    def test_detect_leerer_issuer_zaehlt_nicht(self) -> None:
        detector = CertIssuerDetector(scanner=lambda _: "")
        hits = detector.detect(_make_catalog(), ["kanzlei.de"])
        assert hits == []

    def test_detect_scanner_fehler_wird_geschluckt(self) -> None:
        def broken(_d: str) -> str:
            raise TimeoutError("TLS-Handshake-Timeout")

        detector = CertIssuerDetector(scanner=broken)
        assert detector.detect(_make_catalog(), ["kanzlei.de"]) == []


# ---------------------------------------------------------------------------
# Shared: kein Pattern → kein Treffer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "DetectorCls,raw_args",
    [
        (InstalledAppsDetector, ()),
        (MxLookupDetector, (["kanzlei.de"],)),
        (CertIssuerDetector, (["kanzlei.de"],)),
    ],
)
def test_catalog_eintrag_ohne_pattern_wird_nie_getroffen(
    DetectorCls, raw_args: tuple
) -> None:
    """Catalog-Eintraege ohne Pattern fuer eine Quelle generieren keine Treffer."""
    catalog = [
        VendorCatalogEntry(
            id=1,
            canonical_name="Apple",
            default_category=VendorCategory.CLOUD,
            # KEIN Pattern in keinem Feld — soll nie matchen.
        ),
    ]
    if DetectorCls is InstalledAppsDetector:
        detector = DetectorCls(reader=lambda: ["Apple iCloud", "Apple Software Update"])
    elif DetectorCls is MxLookupDetector:
        detector = DetectorCls(resolver=lambda _: ["mx.apple.com"])
    else:
        detector = DetectorCls(scanner=lambda _: "Apple Inc")

    if raw_args:
        hits = detector.detect(catalog, *raw_args)
    else:
        hits = detector.detect(catalog)
    assert hits == []
