"""
test_patch_cve_matcher — pytest-Tests fuer core/patch_cve_matcher.py.

PM-1.5. Deckt:

*:class:`CveMatch` frozen dataclass.
*:meth:`CveMatcher.get_cves` — happy path, keine cpe, NVD-Fehler.
* OS-Filter (Linux/macOS-only werden ausgesiebt).
* Version-Range-Heuristik (``before X.Y`` Pattern).
* In-Memory-Cache (zweiter Aufruf ohne neuen NVD-Call).
*:meth:`CveMatcher.enrich_decision` →:class:`PatchScanResult`.
*:meth:`PatchScanResult.from_decision_and_cves` Recommendation-Mapping.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from core.patch_channel_resolver import ChannelDecision
from core.patch_collector import SoftwareItem
from core.patch_cve_matcher import CveMatch, CveMatcher
from core.patch_result import PatchScanResult
from core.patch_strategy import PatchStrategy

# ===========================================================================
# CveEintrag-Stub (kein Import aus tools/, statt dessen Duck-Type)
# ===========================================================================


class _CveEintragStub:
    """Stub fuer tools.cyber_dashboard.domain.models.CveEintrag.

    Genau die Felder, die ``CveMatcher`` aus dem Eintrag liest.
    """

    def __init__(
        self,
        cve_id: str,
        cvss_score: float,
        beschreibung: str = "",
        cisa_kev: bool = False,
        betroffene_produkte: list[str] | None = None,
        veroeffentlicht: datetime | None = None,
    ) -> None:
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.beschreibung = beschreibung
        self.cisa_kev = cisa_kev
        self.betroffene_produkte = betroffene_produkte or []
        self.veroeffentlicht = veroeffentlicht or datetime(2024, 1, 1, tzinfo=UTC)


class _NvdServiceFake:
    """In-Memory NvdService-Mock — kein HTTP, keine DB."""

    def __init__(
        self, results_for: dict[str, list[_CveEintragStub]] | None = None
    ) -> None:
        # Mapping product (lowercase) → CveEintrag-Liste.
        self._results: dict[str, list[_CveEintragStub]] = {
            k.lower(): v for k, v in (results_for or {}).items()
        }
        self.calls: list[tuple[str, int]] = []

    def suche_produkt(self, produkt: str, tage: int = 180):
        self.calls.append((produkt, tage))
        return self._results.get(produkt.lower(), [])


def _item(name="Mozilla Firefox", version="120.0",
           winget_id="Mozilla.Firefox", source="winget",
           is_update_available=False, latest_available=None):
    return SoftwareItem(
        name=name, version=version, winget_id=winget_id, source=source,
        is_update_available=is_update_available,
        latest_available=latest_available,
    )


def _decision(item=None, channel="latest", policy_source="policy",
              confidence=0.95, cpe="cpe:2.3:a:mozilla:firefox:120.0:"
              "*:*:*:*:windows:*:*", reason="ok"):
    return ChannelDecision(
        item=item or _item(),
        channel=channel,
        policy_source=policy_source,
        confidence=confidence,
        normalized_name="mozilla firefox",
        cpe=cpe,
        reason=reason,
    )


# ===========================================================================
# CveMatch dataclass
# ===========================================================================


class TestCveMatchDataclass:
    def test_frozen(self):
        m = CveMatch(
            cve_id="CVE-2024-1", cvss_score=8.5, cvss_version="3.1",
            description="x", exploit_available=False,
            published="2024-01-01T00:00:00", affected_versions="firefox 120",
        )
        with pytest.raises(FrozenInstanceError):
            m.cve_id = "CVE-2024-2"  # type: ignore[misc]


# ===========================================================================
# get_cves — happy path + Edge Cases
# ===========================================================================


class TestGetCves:
    def test_cpe_none_gibt_leere_liste(self):
        m = CveMatcher(nvd=_NvdServiceFake())
        assert m.get_cves(None) == []
        assert m.get_cves("") == []

    def test_happy_path_mappt_cveeintrag_zu_cvematch(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-1234",
                    cvss_score=9.5,
                    beschreibung="Critical RCE in Firefox",
                    cisa_kev=True,
                    betroffene_produkte=["mozilla firefox"],
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*"
        )
        assert len(cves) == 1
        c = cves[0]
        assert c.cve_id == "CVE-2024-1234"
        assert c.cvss_score == 9.5
        assert c.exploit_available is True
        assert "Firefox" in c.description

    def test_nvd_exception_gibt_leere_liste(self):
        class _CrashNvd:
            def suche_produkt(self, *a, **kw):
                raise RuntimeError("NVD on fire")

        m = CveMatcher(nvd=_CrashNvd())
        cves = m.get_cves(
            "cpe:2.3:a:mozilla:firefox:1.0:*:*:*:*:windows:*:*"
        )
        assert cves == []  # kein Crash, leere Liste

    def test_kein_treffer_in_nvd_gibt_leere_liste(self):
        m = CveMatcher(nvd=_NvdServiceFake(results_for={}))
        cves = m.get_cves(
            "cpe:2.3:a:vendor:nothing:1.0:*:*:*:*:windows:*:*"
        )
        assert cves == []

    def test_invalid_cpe_format_gibt_leere_liste(self):
        m = CveMatcher(nvd=_NvdServiceFake())
        cves = m.get_cves("nicht:valider:cpe")
        assert cves == []

    def test_wildcard_product_gibt_leere_liste(self):
        m = CveMatcher(nvd=_NvdServiceFake())
        cves = m.get_cves("cpe:2.3:a:vendor:*:1.0:*:*:*:*:windows:*:*")
        assert cves == []


# ===========================================================================
# OS-Filter (Description-Heuristik)
# ===========================================================================


class TestOsFilter:
    def test_linux_only_cve_wird_gefiltert(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-LX",
                    cvss_score=7.0,
                    beschreibung=(
                        "This issue affects only on Linux installations of "
                        "Firefox. Versions before 121."
                    ),
                ),
                _CveEintragStub(
                    cve_id="CVE-2024-WIN",
                    cvss_score=8.0,
                    beschreibung="Heap overflow in Firefox 120 (Windows).",
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*"
        )
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2024-WIN" in cve_ids
        assert "CVE-2024-LX" not in cve_ids

    def test_macos_only_cve_wird_gefiltert(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-MAC",
                    cvss_score=5.0,
                    beschreibung=(
                        "This vulnerability is macos only and unreachable "
                        "on other platforms."
                    ),
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*"
        )
        assert cves == []

    def test_kein_os_qualifier_bleibt(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-ANY",
                    cvss_score=6.0,
                    beschreibung="Cross-platform memory corruption.",
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*"
        )
        assert len(cves) == 1


# ===========================================================================
# Version-Range
# ===========================================================================


class TestVersionRange:
    def test_installed_kleiner_als_endexcluding_betroffen(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-V",
                    cvss_score=7.5,
                    beschreibung="Versions before 126.0 affected.",
                    betroffene_produkte=[
                        "mozilla firefox before 126.0",
                    ],
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*",
            version="120.0",
        )
        assert len(cves) == 1

    def test_installed_groesser_als_endexcluding_nicht_betroffen(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-V",
                    cvss_score=7.5,
                    beschreibung="x",
                    betroffene_produkte=[
                        "mozilla firefox before 121.0",
                    ],
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:125.0:*:*:*:*:windows:*:*",
            version="125.0",
        )
        assert cves == []  # 125 ist nicht "before 121"

    def test_unparsbare_version_keep_alle(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    cve_id="CVE-2024-X",
                    cvss_score=5.0,
                    beschreibung="x",
                    betroffene_produkte=["unsicheres firefox"],
                ),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        cves = matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:120.0:*:*:*:*:windows:*:*",
            version="malformed-version-123abc",
        )
        # Version unparsbar → kein Filter → alle Matches durch
        assert len(cves) == 1


# ===========================================================================
# Cache
# ===========================================================================


class TestCache:
    def test_zweiter_aufruf_kein_zweiter_nvd_call(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [_CveEintragStub("CVE-1", 5.0)]
        })
        matcher = CveMatcher(nvd=nvd)
        cpe = "cpe:2.3:a:mozilla:firefox:1.0:*:*:*:*:windows:*:*"
        matcher.get_cves(cpe)
        matcher.get_cves(cpe)
        assert len(nvd.calls) == 1  # zweiter Aufruf aus Cache

    def test_unterschiedliche_cpes_separate_cache_keys(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [_CveEintragStub("CVE-FF", 5.0)],
            "chrome": [_CveEintragStub("CVE-CR", 6.0)],
        })
        matcher = CveMatcher(nvd=nvd)
        matcher.get_cves(
            "cpe:2.3:a:mozilla:firefox:1.0:*:*:*:*:windows:*:*"
        )
        matcher.get_cves(
            "cpe:2.3:a:google:chrome:120.0:*:*:*:*:windows:*:*"
        )
        assert len(nvd.calls) == 2

    def test_cache_eviction_bei_ueber_limit(self):
        nvd = _NvdServiceFake()
        matcher = CveMatcher(nvd=nvd)
        matcher._CACHE_LIMIT = 5
        # Fuelle Cache mit 5 Eintraegen
        for i in range(5):
            matcher.get_cves(
                f"cpe:2.3:a:vendor:product{i}:1.0:*:*:*:*:windows:*:*"
            )
        # 6. Eintrag triggert Eviction
        matcher.get_cves(
            "cpe:2.3:a:vendor:product5:1.0:*:*:*:*:windows:*:*"
        )
        # Mind. 1 alter Eintrag wurde verworfen.
        assert len(matcher._cache) <= 5


# ===========================================================================
# enrich_decision → PatchScanResult
# ===========================================================================


class TestEnrichDecision:
    def test_enrich_full_cve_data(self):
        nvd = _NvdServiceFake(results_for={
            "firefox": [
                _CveEintragStub(
                    "CVE-2024-CRIT", 9.5,
                    beschreibung="Critical RCE",
                    cisa_kev=True,
                ),
                _CveEintragStub("CVE-2024-MED", 5.5, beschreibung="Medium"),
            ]
        })
        matcher = CveMatcher(nvd=nvd)
        d = _decision()
        result = matcher.enrich_decision(d)

        assert isinstance(result, PatchScanResult)
        assert "CVE-2024-CRIT" in result.cve_ids
        assert "CVE-2024-MED" in result.cve_ids
        assert result.cvss_max == 9.5
        assert result.exploit_available is True
        assert result.recommendation == "update_urgent"
        assert result.vendor == "mozilla"
        assert result.confidence_score == 0.95

    def test_enrich_ohne_cpe_leere_cve_liste(self):
        nvd = _NvdServiceFake()
        matcher = CveMatcher(nvd=nvd)
        d = _decision(cpe=None)
        result = matcher.enrich_decision(d)

        assert result.cve_ids == ()
        assert result.cvss_max is None
        assert result.exploit_available is False
        # Kein NVD-Call passiert
        assert nvd.calls == []


# ===========================================================================
# Recommendation-Mapping (in PatchScanResult.from_decision_and_cves)
# ===========================================================================


class TestRecommendation:
    def test_update_urgent_bei_cvss_9_5(self):
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=9.5, cvss_version="3.1",
            description="", exploit_available=False,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(d, cves)
        assert r.recommendation == "update_urgent"

    def test_update_urgent_bei_exploit_unabhaengig_von_cvss(self):
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=4.0, cvss_version="3.1",
            description="", exploit_available=True,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(d, cves)
        assert r.recommendation == "update_urgent"

    def test_update_bei_cvss_5_0(self):
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=5.0, cvss_version="3.1",
            description="", exploit_available=False,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(d, cves)
        assert r.recommendation == "update"

    def test_up_to_date_ohne_cve(self):
        d = _decision(channel="latest")
        r = PatchScanResult.from_decision_and_cves(d, [])
        assert r.recommendation == "up_to_date"

    def test_pinned_channel_egal_welche_cves(self):
        d = _decision(channel="pinned", policy_source="user", confidence=1.0)
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=9.9, cvss_version="3.1",
            description="", exploit_available=True,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(d, cves)
        assert r.recommendation == "pinned"

    def test_notify_only_bei_default_channel(self):
        d = _decision(channel="notify_only", policy_source="default",
                      confidence=0.0, cpe=None)
        r = PatchScanResult.from_decision_and_cves(d, [])
        assert r.recommendation == "notify_only"


# ===========================================================================
# Patch-Strategie beeinflusst die Recommendation
# ===========================================================================


class TestStrategyRecommendation:
    def test_none_liefert_skipped_by_user_trotz_urgent(self):
        """NONE ueberschreibt selbst update_urgent — CVE-Daten bleiben aber."""
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=9.9, cvss_version="3.1",
            description="", exploit_available=True,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(
            d, cves, strategy=PatchStrategy.NONE
        )
        assert r.recommendation == "skipped_by_user"
        # Risikodaten bleiben sichtbar
        assert r.cvss_max == 9.9
        assert r.cve_ids == ("CVE-X",)
        assert r.exploit_available is True

    def test_stable_strategy_unveraendert(self):
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=9.5, cvss_version="3.1",
            description="", exploit_available=False,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(
            d, cves, strategy=PatchStrategy.STABLE
        )
        assert r.recommendation == "update_urgent"

    def test_latest_strategy_aendert_recommendation_klasse_nicht(self):
        # LATEST aendert nur den Upgrade-Command, nicht die Empfehlungs-Klasse.
        d = _decision(
            item=_item(is_update_available=True, latest_available="126.0")
        )
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="126.0", strategy=PatchStrategy.LATEST
        )
        assert r.recommendation == "update_available"

    def test_default_strategy_ist_stable(self):
        d = _decision(channel="latest")
        r = PatchScanResult.from_decision_and_cves(d, [])
        assert r.recommendation == "up_to_date"

    def test_result_traegt_strategie_feld(self):
        # PatchScanResult.patch_strategy spiegelt die Strategie
        # (UI-Dropdown-Vorbelegung).
        d = _decision(channel="latest")
        r = PatchScanResult.from_decision_and_cves(
            d, [], strategy=PatchStrategy.LATEST
        )
        assert r.patch_strategy is PatchStrategy.LATEST


# ===========================================================================
# PM-1.8 — available_version + update_available Recommendation
# ===========================================================================


class TestUpdateAvailableRecommendation:
    """2026-05-12: Recommendation nutzt IsUpdateAvailable autoritativ
    statt String-Vergleich (Patrick-Smoke).
    """

    def test_update_available_wenn_is_update_available_true(self):
        d = _decision(
            item=_item(is_update_available=True, latest_available="126.0")
        )
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="126.0"
        )
        assert r.recommendation == "update_available"
        assert r.available_version == "126.0"

    def test_up_to_date_wenn_is_update_available_false(self):
        """Default-Item hat ``is_update_available=False`` → up_to_date,
        unabhaengig vom Versions-String."""
        d = _decision()
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="120.0"
        )
        assert r.recommendation == "up_to_date"

    def test_kein_update_wenn_available_none(self):
        d = _decision()
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version=None
        )
        assert r.recommendation == "up_to_date"
        assert r.available_version is None

    def test_nextcloud_pattern_installed_newer_than_manifest(self):
        """Regression-Test 2026-05-12: Nextcloud zeigt
        ``InstalledVersion='> 33.0.3'`` (winget-Marker fuer
        "neuer als manifest"). ``IsUpdateAvailable=False`` ist
        autoritativ — kein update_available, auch wenn die
        Versions-Strings ungleich sind."""
        d = _decision(item=_item(
            version="> 33.0.3",
            is_update_available=False,
            latest_available="33.0.3",
        ))
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="33.0.3"
        )
        assert r.recommendation == "up_to_date"

    def test_msstore_pattern_winget_id_none(self):
        """Regression-Test 2026-05-12: KeePassXC aus dem Microsoft
        Store hat ``winget_id=None`` und damit
        ``available_version=None`` aus dem PatchService-Lookup.
        Trotzdem soll ``IsUpdateAvailable=True`` zur
        ``update_available``-Empfehlung fuehren."""
        d = _decision(item=_item(
            name="KeePassXC", winget_id=None, source="msix",
            version="2.7.10",
            is_update_available=True,
            latest_available="2.7.12",
        ))
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version=None
        )
        assert r.recommendation == "update_available"

    def test_update_urgent_hat_vorrang_vor_update_available(self):
        # CVSS >= 9 schlaegt update_available
        d = _decision(item=_item(is_update_available=True))
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=9.5, cvss_version="3.1",
            description="critical", exploit_available=False,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(
            d, cves, available_version="126.0"
        )
        assert r.recommendation == "update_urgent"

    def test_update_hat_vorrang_vor_update_available(self):
        # CVSS >= 4 schlaegt update_available
        d = _decision(channel="latest")
        cves = [CveMatch(
            cve_id="CVE-X", cvss_score=5.5, cvss_version="3.1",
            description="medium", exploit_available=False,
            published="", affected_versions="",
        )]
        r = PatchScanResult.from_decision_and_cves(
            d, cves, available_version="126.0"
        )
        assert r.recommendation == "update"

    def test_pinned_ueberschreibt_update_available(self):
        d = _decision(channel="pinned")
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="126.0"
        )
        assert r.recommendation == "pinned"

    def test_notify_only_ueberschreibt_update_available(self):
        d = _decision(channel="notify_only")
        r = PatchScanResult.from_decision_and_cves(
            d, [], available_version="126.0"
        )
        assert r.recommendation == "notify_only"

    def test_enrich_decision_propagiert_available_version(self):
        nvd = _NvdServiceFake()
        matcher = CveMatcher(nvd=nvd)
        # 2026-05-12: is_update_available autoritativ Patrick-Smoke).
        d = _decision(item=_item(is_update_available=True), cpe=None)
        result = matcher.enrich_decision(d, available_version="126.0")
        assert result.available_version == "126.0"
        assert result.recommendation == "update_available"
