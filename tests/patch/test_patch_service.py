"""
test_patch_service — pytest-Tests fuer core/patch_service.py.

PM-1.6. Deckt:

* Pipeline: collect_all → ChannelResolver → CveMatcher →
  PatchScanResult-Liste.
* Fail-Open: collect_all-Crash, per-Item enrich-Exception,
  progress_cb-Crash.
* Progress-Callback (kein leerer Initial-Tick, 1-basiert,
  fuer jedes Item gefeuert).
* scan_summary Aggregat-Felder.
* DI: Custom Resolver/Matcher injizierbar.
"""

from __future__ import annotations

from core import patch_service
from core.patch_channel_resolver import ChannelDecision
from core.patch_collector import SoftwareItem
from core.patch_result import PatchScanResult
from core.patch_service import PatchService

# ===========================================================================
# Fakes — kein Qt, kein Netzwerk, keine DB
# ===========================================================================


def _item(name="App", version="1.0", winget_id=None, source="winget"):
    return SoftwareItem(
        name=name, version=version, winget_id=winget_id, source=source
    )


def _decision(name="App", channel="latest", policy_source="policy",
              confidence=0.9, cpe=None):
    return ChannelDecision(
        item=_item(name=name),
        channel=channel,
        policy_source=policy_source,
        confidence=confidence,
        normalized_name=name.lower(),
        cpe=cpe,
        reason="ok",
    )


def _result(name="App", recommendation="up_to_date", cve_ids=()):
    return PatchScanResult(
        name=name,
        normalized_name=name.lower(),
        vendor=None,
        winget_id=None,
        source="winget",
        installed_version="1.0",
        available_version=None,
        channel="latest",
        policy_source="policy",
        cve_ids=cve_ids,
        cvss_max=None,
        exploit_available=False,
        eol=False,
        confidence_score=0.9,
        recommendation=recommendation,
    )


class _FakeResolver:
    """Liefert pro Item eine ChannelDecision aus einer Mapping-Tabelle.

    Standard: jedes Item bekommt eine generische ``channel="latest"``-
    Decision.
    """

    def __init__(self, decisions_for: dict[str, ChannelDecision] | None = None) -> None:
        self._decisions = decisions_for or {}

    def resolve(self, item):
        return self._decisions.get(
            item.name,
            ChannelDecision(
                item=item, channel="latest", policy_source="policy",
                confidence=0.9, normalized_name=item.name.lower(),
                cpe=None, reason="default",
            ),
        )

    def resolve_batch(self, items):
        return [self.resolve(i) for i in items]


class _FakeMatcher:
    """Mappt ChannelDecision → PatchScanResult mit definierbaren
    Recommendations."""

    def __init__(
        self,
        results_by_name: dict[str, PatchScanResult] | None = None,
        crash_for: set[str] | None = None,
    ) -> None:
        self._results = results_by_name or {}
        self._crash_for = crash_for or set()
        self.calls: list[str] = []

    def enrich_decision(self, decision, available_version=None):
        self.calls.append((decision.item.name, available_version))
        if decision.item.name in self._crash_for:
            raise RuntimeError(f"boom for {decision.item.name}")
        if decision.item.name in self._results:
            return self._results[decision.item.name]
        return PatchScanResult(
            name=decision.item.name,
            normalized_name=decision.normalized_name,
            vendor=None,
            winget_id=decision.item.winget_id,
            source=decision.item.source,
            installed_version=decision.item.version,
            available_version=available_version,
            channel=decision.channel,
            policy_source=decision.policy_source,
            cve_ids=(),
            cvss_max=None,
            exploit_available=False,
            eol=False,
            confidence_score=decision.confidence,
            recommendation="up_to_date",
        )


# ===========================================================================
# Konstruktor — DI + ohne Argumente
# ===========================================================================


class TestConstruction:
    def test_di_resolver_und_matcher_injizierbar(self):
        r = _FakeResolver()
        m = _FakeMatcher()
        svc = PatchService(resolver=r, matcher=m)
        assert svc._resolver is r
        assert svc._matcher is m


# ===========================================================================
# scan — Happy Path + Edge Cases
# ===========================================================================


class TestScan:
    def test_collect_all_leer_gibt_leere_liste(self, monkeypatch):
        monkeypatch.setattr(patch_service, "collect_all", lambda: [])
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        assert svc.scan() == []

    def test_collect_all_exception_gibt_leere_liste(self, monkeypatch):
        def crash():
            raise RuntimeError("collect_all on fire")

        monkeypatch.setattr(patch_service, "collect_all", crash)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        # Kein Crash, leere Liste
        assert svc.scan() == []

    def test_pipeline_happy_path(self, monkeypatch):
        items = [
            _item("Mozilla Firefox"),
            _item("Python"),
            _item("Random"),
        ]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        results = svc.scan()
        assert [r.name for r in results] == [
            "Mozilla Firefox", "Python", "Random"
        ]

    def test_per_item_matcher_exception_skip_und_weiter(self, monkeypatch):
        items = [_item("A"), _item("B"), _item("C")]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        matcher = _FakeMatcher(crash_for={"B"})
        svc = PatchService(resolver=_FakeResolver(), matcher=matcher)
        results = svc.scan()
        # B ist uebersprungen, A + C kommen durch
        assert [r.name for r in results] == ["A", "C"]
        # Matcher wurde fuer ALLE 3 Items aufgerufen
        assert [c[0] for c in matcher.calls] == ["A", "B", "C"]


# ===========================================================================
# progress_cb
# ===========================================================================


class TestProgressCallback:
    def test_progress_cb_pro_item_gefeuert(self, monkeypatch):
        items = [_item(f"App {i}") for i in range(3)]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())

        ticks = []
        svc.scan(progress_cb=lambda cur, tot: ticks.append((cur, tot)))

        assert ticks == [(1, 3), (2, 3), (3, 3)]

    def test_kein_initial_zero_tick(self, monkeypatch):
        items = [_item("A")]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())

        ticks = []
        svc.scan(progress_cb=lambda cur, tot: ticks.append((cur, tot)))

        # Kein (0, 1) am Anfang — nur (1, 1)
        assert (0, 1) not in ticks
        assert ticks == [(1, 1)]

    def test_progress_cb_crash_isoliert_scan_laeuft_durch(
        self, monkeypatch
    ):
        items = [_item("A"), _item("B")]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())

        def crash_cb(cur, tot):
            raise RuntimeError("UI dead")

        results = svc.scan(progress_cb=crash_cb)
        # Beide Results da, trotz cb-Crash
        assert len(results) == 2

    def test_kein_progress_cb_kein_call(self, monkeypatch):
        items = [_item("A")]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        # Sollte nicht crashen ohne progress_cb
        results = svc.scan(progress_cb=None)
        assert len(results) == 1


# ===========================================================================
# scan_summary
# ===========================================================================


class TestScanSummary:
    def test_alle_keys_vorhanden(self, monkeypatch):
        monkeypatch.setattr(patch_service, "collect_all", lambda: [])
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        summary = svc.scan_summary()
        for key in ("total", "urgent", "update", "up_to_date",
                    "notify_only", "with_cves", "results"):
            assert key in summary

    def test_zaehler_korrekt(self, monkeypatch):
        items = [_item(f"App{i}") for i in range(5)]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)

        results_by_name = {
            "App0": _result("App0", recommendation="update_urgent",
                            cve_ids=("CVE-1",)),
            "App1": _result("App1", recommendation="update",
                            cve_ids=("CVE-2",)),
            "App2": _result("App2", recommendation="update"),
            "App3": _result("App3", recommendation="up_to_date"),
            "App4": _result("App4", recommendation="notify_only"),
        }
        svc = PatchService(
            resolver=_FakeResolver(),
            matcher=_FakeMatcher(results_by_name=results_by_name),
        )
        summary = svc.scan_summary()

        assert summary["total"] == 5
        assert summary["urgent"] == 1
        assert summary["update"] == 2
        assert summary["up_to_date"] == 1
        assert summary["notify_only"] == 1
        assert summary["with_cves"] == 2
        assert len(summary["results"]) == 5

    def test_total_gleich_len_results(self, monkeypatch):
        items = [_item("A"), _item("B")]
        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        summary = svc.scan_summary()
        assert summary["total"] == len(summary["results"])

    def test_summary_bei_leerer_pipeline(self, monkeypatch):
        monkeypatch.setattr(patch_service, "collect_all", lambda: [])
        svc = PatchService(resolver=_FakeResolver(), matcher=_FakeMatcher())
        summary = svc.scan_summary()
        assert summary["total"] == 0
        assert summary["urgent"] == 0
        assert summary["results"] == []


# ===========================================================================
# Available-Version Pipeline: nur noch Item-basierter Pfad)
# ===========================================================================


class TestAvailableVersion:
    """Verfuegbare Updates kommen ausschliesslich aus ``item.latest_available``.

    Vor gab es einen zweiten Pfad ueber ``collect_available_versions``
    (Tabular-Subprocess). Dieser ist mit entfernt — Tabular-/Registry-/
    MSIX-Items haben ``latest_available = None`` und fallen aus dem Lookup
    heraus, der Onboarding-Dialog draengt User auf den Modul-Pfad.
    """

    def test_lookup_dict_kommt_aus_item_latest_available(self, monkeypatch):
        items = [
            SoftwareItem(
                name="Firefox", version="120.0",
                winget_id="Mozilla.Firefox", source="winget",
                is_update_available=True, latest_available="126.0",
            ),
            SoftwareItem(
                name="PowerToys", version="0.75",
                winget_id="Microsoft.PowerToys", source="winget",
                is_update_available=True, latest_available="0.80.0",
            ),
            SoftwareItem(  # Tabular-Item: latest_available=None
                name="LegacyApp", version="1.0",
                winget_id="Some.Legacy", source="winget",
            ),
            SoftwareItem(  # Registry-Item: kein winget_id
                name="Random", version="1.0",
                winget_id=None, source="registry",
            ),
        ]

        monkeypatch.setattr(patch_service, "collect_all", lambda: items)
        matcher = _FakeMatcher()
        svc = PatchService(resolver=_FakeResolver(), matcher=matcher)
        svc.scan()

        names_and_avail = dict(matcher.calls)
        assert names_and_avail["Firefox"] == "126.0"
        assert names_and_avail["PowerToys"] == "0.80.0"
        # Tabular-/Registry-Items: keine Update-Info im Lookup-Dict
        assert names_and_avail["LegacyApp"] is None
        assert names_and_avail["Random"] is None


# ===========================================================================
# Default-Konstruktion
# ===========================================================================


class TestDefaultConstruction:
    def test_patchservice_ohne_argumente_instanziierbar(self):
        # Darf nicht crashen — die Default-Komponenten sind lazy /
        # haben definierte Fallbacks.
        # PolicyDB legt eine SQLCipher-DB an (echter Disk-IO);
        # CveMatcher konstruiert NvdService nicht hier (lazy).
        svc = PatchService()
        assert svc._resolver is not None
        assert svc._matcher is not None
