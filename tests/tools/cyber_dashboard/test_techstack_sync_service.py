"""
test_techstack_sync_service — Tech-Stack-Sync aus Scan + Patch-Monitor.

Deckt ab:
  - ``TechStackSyncService.ermittle_kandidaten``: Dedup über beide Quellen,
    CPE-Übernahme aus dem Patch-Monitor, Versions-Vorrang, leere/fehlende
    Quellen.
  - ``TechStackSyncService.cves_fuer_cpes`` + Adapter ``_cve_match_zu_eintrag``:
    Mapping der Patch-Monitor-``CveMatchEntry`` auf ``CveEintrag`` (Schweregrad
    aus CVSS-Band, None-CVSS, Exploit-Hinweis, Dedup über CVE-ID).
  - ``DashboardService``-Verdrahtung: ``techstack_sync_kandidaten`` filtert den
    Bestand, ``techstack_uebernehmen`` zählt + dedupt, ``suche_cves_fuer_stack``
    merged CPE-Treffer auch ohne NVD-Key.

Quell-Repos werden als leichtgewichtige Duck-Typing-Fakes gestellt (der
Service liest sie defensiv per getattr) — kein echtes SQLCipher.

Schichtzugehörigkeit: tests/ — keine GUI-Imports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from tools.cyber_dashboard.application import techstack_sync_service as sync_mod
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.application.techstack_sync_service import (
    QUELLE_PATCH,
    QUELLE_SCAN,
    TechStackSyncService,
    _cve_match_zu_eintrag,
)
from tools.cyber_dashboard.domain.models import CveEintrag, TechStackEintrag
from tools.patch_monitor.data.patch_inventory_repository import CveMatchEntry
from tools.system_scanner.domain.entities import InstalledSoftware

# ---------------------------------------------------------------------------
# Duck-Typing-Fakes für die Quell-Repositories
# ---------------------------------------------------------------------------


class _FakeScanRepo:
    """Stellt ``load_latest.software_list`` ohne DB bereit."""

    def __init__(self, software: list[InstalledSoftware] | None) -> None:
        self._software = software

    def load_latest(self) -> object | None:
        if self._software is None:
            return None
        return type("_Result", (), {"software_list": list(self._software)})()


class _FakeInventory:
    """Minimaler ``InventoryEntry``-Ersatz (nur die gelesenen Attribute)."""

    def __init__(
        self, name: str, installed_version: str = "", cpe_string: str | None = None
    ) -> None:
        self.name = name
        self.installed_version = installed_version
        self.cpe_string = cpe_string


class _FakePatchRepo:
    """Stellt ``list_inventory`` + ``list_cve_matches_for_cpe`` bereit."""

    def __init__(
        self,
        inventory: list[_FakeInventory] | None = None,
        cve_map: dict[str, list[CveMatchEntry]] | None = None,
    ) -> None:
        self._inventory = inventory or []
        self._cve_map = cve_map or {}

    def list_inventory(self) -> list[_FakeInventory]:
        return list(self._inventory)

    def list_cve_matches_for_cpe(self, cpe: str) -> list[CveMatchEntry]:
        return list(self._cve_map.get(cpe, []))


class _FakeTechStackRepo:
    """In-Memory-Tech-Stack-Repo (lade/speichere) für DashboardService-Tests."""

    def __init__(self, eintraege: list[TechStackEintrag] | None = None) -> None:
        self._stack = list(eintraege or [])

    def lade(self) -> list[TechStackEintrag]:
        return list(self._stack)

    def speichere(self, stack: list[TechStackEintrag]) -> None:
        self._stack = list(stack)


def _cve_match(
    cve_id: str,
    cvss: float | None,
    *,
    exploit: bool = False,
    fetched: datetime | None = None,
) -> CveMatchEntry:
    return CveMatchEntry(
        cpe_string="cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
        cve_id=cve_id,
        cvss_score=cvss,
        exploit_available=exploit,
        eol=False,
        fetched_at=fetched or datetime(2026, 1, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# ermittle_kandidaten — Sync + Dedup + CPE-Merge
# ---------------------------------------------------------------------------


class TestErmittleKandidaten:
    """Sync-Kandidaten aus beiden Quellen mit Dedup + CPE-Übernahme."""

    def test_nur_scan_quelle(self) -> None:
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo(
                [InstalledSoftware(name="Python", version="3.12")]
            ),
            patch_repo=_FakePatchRepo(),
        )
        kandidaten = svc.ermittle_kandidaten()
        assert len(kandidaten) == 1
        assert kandidaten[0].eintrag.name == "Python"
        assert kandidaten[0].eintrag.version == "3.12"
        assert kandidaten[0].eintrag.cpe == ""
        assert kandidaten[0].quellen == (QUELLE_SCAN,)

    def test_nur_patch_quelle_uebernimmt_cpe(self) -> None:
        cpe = "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo([]),
            patch_repo=_FakePatchRepo(
                inventory=[
                    _FakeInventory("Python", installed_version="3.12.1", cpe_string=cpe)
                ]
            ),
        )
        kandidaten = svc.ermittle_kandidaten()
        assert len(kandidaten) == 1
        assert kandidaten[0].eintrag.cpe == cpe
        assert kandidaten[0].eintrag.version == "3.12.1"
        assert kandidaten[0].quellen == (QUELLE_PATCH,)

    def test_dedup_ueber_beide_quellen_merged_cpe_und_version(self) -> None:
        """Gleicher Name in beiden Quellen → ein Kandidat, Patch-Version + CPE."""
        cpe = "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo(
                [InstalledSoftware(name="Python", version="3.12")]
            ),
            patch_repo=_FakePatchRepo(
                inventory=[
                    _FakeInventory(
                        "python", installed_version="3.12.4", cpe_string=cpe
                    )
                ]
            ),
        )
        kandidaten = svc.ermittle_kandidaten()
        assert len(kandidaten) == 1
        eintrag = kandidaten[0].eintrag
        assert eintrag.cpe == cpe
        # Patch-Monitor-Version hat Vorrang.
        assert eintrag.version == "3.12.4"
        # Beide Quellen, in Verarbeitungsreihenfolge (Scan zuerst).
        assert kandidaten[0].quellen == (QUELLE_SCAN, QUELLE_PATCH)

    def test_scan_version_bleibt_wenn_patch_keine_hat(self) -> None:
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo(
                [InstalledSoftware(name="OpenSSL", version="3.0.2")]
            ),
            patch_repo=_FakePatchRepo(
                inventory=[_FakeInventory("OpenSSL", installed_version="")]
            ),
        )
        kandidaten = svc.ermittle_kandidaten()
        assert kandidaten[0].eintrag.version == "3.0.2"

    def test_leere_und_namenlose_eintraege_werden_uebersprungen(self) -> None:
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo([InstalledSoftware(name="   ")]),
            patch_repo=_FakePatchRepo(inventory=[_FakeInventory("")]),
        )
        assert svc.ermittle_kandidaten() == []

    def test_sortiert_nach_name(self) -> None:
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo(
                [
                    InstalledSoftware(name="Zoom"),
                    InstalledSoftware(name="Apache"),
                ]
            ),
            patch_repo=_FakePatchRepo(),
        )
        namen = [k.eintrag.name for k in svc.ermittle_kandidaten()]
        assert namen == ["Apache", "Zoom"]

    def test_fehlende_repos_liefern_leere_liste(self, monkeypatch) -> None:
        """Lazy-Default liefert None (Tool/DB nicht da) → keine Kandidaten."""
        monkeypatch.setattr(sync_mod, "_lazy_scan_repository", lambda: None)
        monkeypatch.setattr(sync_mod, "_lazy_patch_repository", lambda: None)
        svc = TechStackSyncService()
        assert svc.ermittle_kandidaten() == []
        assert svc.cves_fuer_cpes([("cpe:x", "X")]) == []

    def test_quell_repo_exception_crasht_nicht(self) -> None:
        boom = MagicMock()
        boom.load_latest.side_effect = RuntimeError("DB kaputt")
        boom.list_inventory.side_effect = RuntimeError("DB kaputt")
        svc = TechStackSyncService(scan_repo=boom, patch_repo=boom)
        assert svc.ermittle_kandidaten() == []


# ---------------------------------------------------------------------------
# cves_fuer_cpes + Adapter
# ---------------------------------------------------------------------------


class TestCvesFuerCpes:
    """CPE → CVE-Auflösung aus den lokalen Patch-Monitor-Treffern."""

    def test_adapter_mapping_grundfelder(self) -> None:
        match = _cve_match("CVE-2024-1234", 9.8, exploit=True)
        eintrag = _cve_match_zu_eintrag(match, "Python")
        assert isinstance(eintrag, CveEintrag)
        assert eintrag.cve_id == "CVE-2024-1234"
        assert eintrag.cvss_score == 9.8
        assert eintrag.schweregrad == "CRITICAL"
        assert eintrag.url.endswith("CVE-2024-1234")
        assert eintrag.betroffene_produkte == ["Python"]
        assert "[Exploit verfügbar]" in eintrag.beschreibung
        assert "Python" in eintrag.beschreibung

    @pytest.mark.parametrize(
        ("score", "label"),
        [
            (None, "INFO"),
            (0.0, "INFO"),
            (3.9, "LOW"),
            (4.0, "MEDIUM"),
            (7.0, "HIGH"),
            (9.0, "CRITICAL"),
        ],
    )
    def test_schweregrad_baender(self, score: float | None, label: str) -> None:
        eintrag = _cve_match_zu_eintrag(_cve_match("CVE-X", score), "X")
        assert eintrag.schweregrad == label
        # None-CVSS wird zu 0.0 (CveEintrag verlangt float).
        assert eintrag.cvss_score == (score or 0.0)

    def test_dedup_ueber_cve_id(self) -> None:
        cpe_a = "cpe:2.3:a:a:a:1:*:*:*:*:*:*:*"
        cpe_b = "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*"
        repo = _FakePatchRepo(
            cve_map={
                cpe_a: [_cve_match("CVE-1", 7.5), _cve_match("CVE-2", 5.0)],
                cpe_b: [_cve_match("CVE-1", 7.5)],  # Duplikat
            }
        )
        svc = TechStackSyncService(scan_repo=_FakeScanRepo([]), patch_repo=repo)
        eintraege = svc.cves_fuer_cpes([(cpe_a, "A"), (cpe_b, "B")])
        ids = sorted(e.cve_id for e in eintraege)
        assert ids == ["CVE-1", "CVE-2"]

    def test_leere_cpe_wird_uebersprungen(self) -> None:
        repo = _FakePatchRepo(cve_map={"cpe:x": [_cve_match("CVE-9", 8.0)]})
        svc = TechStackSyncService(scan_repo=_FakeScanRepo([]), patch_repo=repo)
        assert svc.cves_fuer_cpes([("", "Leer")]) == []

    def test_korrupter_match_killt_nicht_alle(self) -> None:
        """Ein nicht-adaptierbarer Match wird übersprungen, gute bleiben (P3)."""

        class _BadMatch:
            cve_id = "CVE-BAD"
            cvss_score = "n/a"  # float schlägt fehl
            exploit_available = False
            fetched_at = datetime(2026, 1, 1, tzinfo=UTC)

        cpe = "cpe:x"
        repo = _FakePatchRepo(
            cve_map={cpe: [_BadMatch(), _cve_match("CVE-GOOD", 7.0)]}
        )
        svc = TechStackSyncService(scan_repo=_FakeScanRepo([]), patch_repo=repo)
        ids = [e.cve_id for e in svc.cves_fuer_cpes([(cpe, "X")])]
        assert ids == ["CVE-GOOD"]


class TestDefensiveSchranken:
    """Caps gegen aufgeblähtes/manipuliertes Inventar (Konsistenz mit Bestand)."""

    def test_kandidaten_cap(self) -> None:
        viele = [
            InstalledSoftware(name=f"Paket-{i:04d}")
            for i in range(sync_mod._MAX_KANDIDATEN + 100)
        ]
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo(viele), patch_repo=_FakePatchRepo()
        )
        assert len(svc.ermittle_kandidaten()) == sync_mod._MAX_KANDIDATEN

    def test_feld_laenge_getrimmt(self) -> None:
        langer_name = "X" * (sync_mod._MAX_FELD_LEN + 50)
        svc = TechStackSyncService(
            scan_repo=_FakeScanRepo([InstalledSoftware(name=langer_name)]),
            patch_repo=_FakePatchRepo(),
        )
        kandidaten = svc.ermittle_kandidaten()
        assert len(kandidaten[0].eintrag.name) == sync_mod._MAX_FELD_LEN


# ---------------------------------------------------------------------------
# DashboardService-Verdrahtung
# ---------------------------------------------------------------------------


def _dashboard(
    *,
    techstack: _FakeTechStackRepo | None = None,
    techstack_sync: object | None = None,
    nvd: object | None = None,
) -> DashboardService:
    return DashboardService(
        rss=MagicMock(),
        cache=MagicMock(),
        nvd=nvd,
        techstack=techstack,
        techstack_sync=techstack_sync,
    )


class TestDashboardServiceVerdrahtung:
    """techstack_sync_kandidaten / techstack_uebernehmen / suche_cves_fuer_stack."""

    def test_kandidaten_filtert_bestand(self) -> None:
        svc = _dashboard(
            techstack=_FakeTechStackRepo([TechStackEintrag(name="Python")]),
            techstack_sync=TechStackSyncService(
                scan_repo=_FakeScanRepo(
                    [
                        InstalledSoftware(name="Python"),  # schon im Stack
                        InstalledSoftware(name="Apache"),  # neu
                    ]
                ),
                patch_repo=_FakePatchRepo(),
            ),
        )
        kandidaten = svc.techstack_sync_kandidaten()
        assert [k.eintrag.name for k in kandidaten] == ["Apache"]

    def test_kandidaten_ohne_sync_service_leer(self) -> None:
        svc = _dashboard(techstack=_FakeTechStackRepo(), techstack_sync=None)
        assert svc.techstack_sync_kandidaten() == []

    def test_uebernehmen_zaehlt_und_dedupt(self) -> None:
        repo = _FakeTechStackRepo([TechStackEintrag(name="Python")])
        svc = _dashboard(techstack=repo)
        anzahl = svc.techstack_uebernehmen(
            [
                TechStackEintrag(name="Apache", cpe="cpe:apache"),
                TechStackEintrag(name="python"),  # Duplikat (case-insensitive)
            ]
        )
        assert anzahl == 1
        namen = {e.name for e in repo.lade()}
        assert namen == {"Python", "Apache"}
        # CPE wird mitpersistiert.
        apache = next(e for e in repo.lade() if e.name == "Apache")
        assert apache.cpe == "cpe:apache"

    def test_uebernehmen_leere_liste(self) -> None:
        svc = _dashboard(techstack=_FakeTechStackRepo())
        assert svc.techstack_uebernehmen([]) == 0

    def test_suche_cves_cpe_pfad_ohne_nvd_key(self) -> None:
        """Ohne NVD-Key liefert der CPE-Pfad trotzdem Treffer."""
        cpe = "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"
        repo = _FakePatchRepo(cve_map={cpe: [_cve_match("CVE-2024-1", 9.1)]})
        svc = _dashboard(
            techstack=_FakeTechStackRepo(
                [TechStackEintrag(name="Python", cpe=cpe, aktiv=True)]
            ),
            techstack_sync=TechStackSyncService(
                scan_repo=_FakeScanRepo([]), patch_repo=repo
            ),
            nvd=None,  # kein NVD → nvd_aktiv False
        )
        cves = svc.suche_cves_fuer_stack()
        assert [c.cve_id for c in cves] == ["CVE-2024-1"]

    def test_suche_cves_inaktive_eintraege_ignoriert(self) -> None:
        cpe = "cpe:2.3:a:x:x:1:*:*:*:*:*:*:*"
        repo = _FakePatchRepo(cve_map={cpe: [_cve_match("CVE-X", 8.0)]})
        svc = _dashboard(
            techstack=_FakeTechStackRepo(
                [TechStackEintrag(name="X", cpe=cpe, aktiv=False)]
            ),
            techstack_sync=TechStackSyncService(
                scan_repo=_FakeScanRepo([]), patch_repo=repo
            ),
            nvd=None,
        )
        assert svc.suche_cves_fuer_stack() == []

    def test_suche_cves_merged_nvd_und_cpe_dedupt(self) -> None:
        """NVD-Namenssuche + CPE-Treffer, Dedup über CVE-ID (NVD gewinnt)."""
        cpe = "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"
        nvd = MagicMock()
        nvd.api_key_gesetzt.return_value = True
        nvd.suche_produkt.return_value = [
            CveEintrag(
                cve_id="CVE-DUP",
                beschreibung="NVD-Beschreibung",
                schweregrad="HIGH",
                cvss_score=7.5,
                veroeffentlicht=datetime(2026, 1, 1, tzinfo=UTC),
                geaendert=datetime(2026, 1, 1, tzinfo=UTC),
                url="https://nvd.nist.gov/vuln/detail/CVE-DUP",
            )
        ]
        repo = _FakePatchRepo(
            cve_map={
                cpe: [_cve_match("CVE-DUP", 7.5), _cve_match("CVE-ONLY-CPE", 9.9)]
            }
        )
        svc = _dashboard(
            techstack=_FakeTechStackRepo(
                [TechStackEintrag(name="Python", cpe=cpe, aktiv=True)]
            ),
            techstack_sync=TechStackSyncService(
                scan_repo=_FakeScanRepo([]), patch_repo=repo
            ),
            nvd=nvd,
        )
        cves = svc.suche_cves_fuer_stack()
        # 2 eindeutige, nach CVSS sortiert (9.9 zuerst).
        assert [c.cve_id for c in cves] == ["CVE-ONLY-CPE", "CVE-DUP"]
        # NVD-Variante von CVE-DUP gewinnt (bessere Beschreibung).
        dup = next(c for c in cves if c.cve_id == "CVE-DUP")
        assert dup.beschreibung == "NVD-Beschreibung"
