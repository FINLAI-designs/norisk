"""Tests fuer PatchAffectedCveQuelle /, Phase 3).

Deckt die Aggregation der pro (App, CVE)-Paar gelieferten Patch-Monitor-Zeilen
zu einem AffectedCveItem je CVE-ID, Konfidenz-Markierung, Update-Oder-Logik,
Reihenfolge-Erhalt, distinktes CVE-Limit und Passthrough.
"""

from __future__ import annotations

from datetime import UTC, datetime

from tools.cyber_dashboard.application.risiko_briefing_patch_adapter import (
    PatchAffectedCveQuelle,
)
from tools.cyber_dashboard.domain.risiko_briefing import Konfidenz
from tools.patch_monitor.data.patch_inventory_repository import AffectedCveRow


def _row(
    cve_id: str = "CVE-1",
    cvss: float | None = 8.0,
    *,
    exploit: bool = False,
    eol: bool = False,
    app: str = "App-A",
    update: bool = False,
) -> AffectedCveRow:
    return AffectedCveRow(
        winget_id=app,
        app_name=app,
        cpe_string="cpe:x",
        installed_version="1.0",
        is_update_available=update,
        available_version="2.0" if update else None,
        cve_id=cve_id,
        cvss_score=cvss,
        exploit_available=exploit,
        eol=eol,
        fetched_at=datetime.now(tz=UTC),
    )


class _FakeSource:
    def __init__(self, rows: list[AffectedCveRow], apps_without: int = 0) -> None:
        self._rows = rows
        self._apps_without = apps_without

    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 200
    ) -> list[AffectedCveRow]:
        return list(self._rows)

    def anzahl_apps_ohne_cpe(self) -> int:
        return self._apps_without


def test_leer() -> None:
    quelle = PatchAffectedCveQuelle(_FakeSource([]))
    assert quelle.lade_betroffene_cves() == []


def test_aggregiert_apps_pro_cve() -> None:
    quelle = PatchAffectedCveQuelle(
        _FakeSource([_row(cve_id="A", app="Firefox"), _row(cve_id="A", app="Chrome")])
    )
    items = quelle.lade_betroffene_cves()
    assert len(items) == 1
    assert items[0].cve_id == "A"
    assert items[0].affected_apps == ("Firefox", "Chrome")
    assert items[0].konfidenz is Konfidenz.BESTAETIGT


def test_update_available_ist_oder_ueber_apps() -> None:
    quelle = PatchAffectedCveQuelle(
        _FakeSource(
            [
                _row(cve_id="A", app="X", update=False),
                _row(cve_id="A", app="Y", update=True),
            ]
        )
    )
    assert quelle.lade_betroffene_cves()[0].update_available is True


def test_reihenfolge_erhalten() -> None:
    # Quelle liefert bereits cvss-absteigend; erste Begegnung bestimmt die Folge.
    quelle = PatchAffectedCveQuelle(
        _FakeSource(
            [
                _row(cve_id="HIGH", cvss=9.5),
                _row(cve_id="MID", cvss=6.0),
                _row(cve_id="LOW", cvss=3.0),
            ]
        )
    )
    assert [i.cve_id for i in quelle.lade_betroffene_cves()] == ["HIGH", "MID", "LOW"]


def test_limit_kappt_distinkte_cves() -> None:
    rows = [_row(cve_id=f"CVE-{i}", cvss=float(10 - i)) for i in range(5)]
    quelle = PatchAffectedCveQuelle(_FakeSource(rows))
    items = quelle.lade_betroffene_cves(limit=2)
    assert [i.cve_id for i in items] == ["CVE-0", "CVE-1"]


def test_exploit_und_eol_uebernommen() -> None:
    quelle = PatchAffectedCveQuelle(
        _FakeSource([_row(cve_id="A", exploit=True, eol=True)])
    )
    item = quelle.lade_betroffene_cves()[0]
    assert item.exploit_available is True
    assert item.eol is True


def test_anzahl_apps_ohne_cpe_passthrough() -> None:
    quelle = PatchAffectedCveQuelle(_FakeSource([], apps_without=7))
    assert quelle.anzahl_apps_ohne_cpe() == 7
