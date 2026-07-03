"""GUI-Tests fuer RisikoLageTab (Tab 1 /).

Deterministisch: ``auto_load=False`` (kein Worker-Thread), Rendering wird
direkt ueber ``render_snapshot`` geprueft.
"""

from __future__ import annotations

import pytest

from tools.cyber_dashboard.domain.risiko_briefing import (
    AffectedCveItem,
    AuditScoreInfo,
    HardeningInfo,
    Konfidenz,
    Prioritaet,
    RisikoPunkt,
    RiskBriefingSnapshot,
)
from tools.cyber_dashboard.gui.risiko_lage_tab import (
    RisikoLageTab,
    _CveZeile,
    _RisikoPunktCard,
)

pytestmark = pytest.mark.gui


def _punkt(titel: str, prio: Prioritaet) -> RisikoPunkt:
    return RisikoPunkt(
        titel=titel,
        kategorie="CVE",
        prioritaet=prio,
        befund="Befund",
        risiko_bei_nichtbeachtung="Folge",
        empfohlene_massnahme="Tun",
        quelle="Quelle",
    )


def _cve(cve_id: str, konf: Konfidenz, *, exploit: bool = False) -> AffectedCveItem:
    return AffectedCveItem(
        cve_id=cve_id,
        cvss_score=9.8,
        exploit_available=exploit,
        eol=False,
        konfidenz=konf,
        affected_apps=("Firefox",),
    )


class _FakeService:
    def __init__(self, snapshot: RiskBriefingSnapshot) -> None:
        self._snapshot = snapshot

    def build_snapshot(self, *, max_cves: int = 50) -> RiskBriefingSnapshot:
        return self._snapshot


def test_render_punkte_kacheln_und_cves(qtbot, app) -> None:
    snap = RiskBriefingSnapshot(
        risiko_punkte=(
            _punkt("KEV", Prioritaet.KRITISCH),
            _punkt("Update", Prioritaet.MITTEL),
        ),
        affected_cves=(
            _cve("CVE-1", Konfidenz.BESTAETIGT, exploit=True),
            _cve("CVE-2", Konfidenz.MOEGLICH),
        ),
        hardening=HardeningInfo(score=72.0, stage_label="Moderate"),
        audit=AuditScoreInfo(score=60.0),
        apps_without_cpe=3,
    )
    tab = RisikoLageTab(service=_FakeService(snap), auto_load=False)
    qtbot.addWidget(tab)
    tab.render_snapshot(snap)

    assert len(tab.findChildren(_RisikoPunktCard)) == 2
    assert len(tab.findChildren(_CveZeile)) == 2
    # Zwei getrennte Score-Kacheln — beide gesetzt, nie gemittelt.
    assert tab._tile_audit._lbl_wert.text() == "60/100"
    assert tab._tile_hardening._lbl_wert.text() == "72/100"
    # Recall-Transparenz-Hinweis sichtbar (apps_without_cpe > 0).
    # isHidden statt isVisible: das Top-Level wird im Test nicht gezeigt.
    assert not tab._lbl_hinweis.isHidden()
    assert "3 Programme" in tab._lbl_hinweis.text()


def test_render_leerer_snapshot(qtbot, app) -> None:
    snap = RiskBriefingSnapshot(risiko_punkte=(), affected_cves=())
    tab = RisikoLageTab(service=_FakeService(snap), auto_load=False)
    qtbot.addWidget(tab)
    tab.render_snapshot(snap)

    assert tab.findChildren(_RisikoPunktCard) == []
    assert tab.findChildren(_CveZeile) == []
    assert tab._tile_audit._lbl_wert.text() == "—"
    assert tab._tile_hardening._lbl_wert.text() == "—"
    assert tab._lbl_hinweis.isHidden()


def test_konstruktion_ohne_autoload_startet_keinen_worker(qtbot, app) -> None:
    snap = RiskBriefingSnapshot(risiko_punkte=(), affected_cves=())
    tab = RisikoLageTab(service=_FakeService(snap), auto_load=False)
    qtbot.addWidget(tab)
    assert tab._worker is None


def test_idempotentes_refresh_ersetzt_inhalt(qtbot, app) -> None:
    snap1 = RiskBriefingSnapshot(
        risiko_punkte=(_punkt("A", Prioritaet.HOCH),), affected_cves=()
    )
    snap2 = RiskBriefingSnapshot(
        risiko_punkte=(
            _punkt("B", Prioritaet.HOCH),
            _punkt("C", Prioritaet.MITTEL),
        ),
        affected_cves=(),
    )
    tab = RisikoLageTab(service=_FakeService(snap1), auto_load=False)
    qtbot.addWidget(tab)
    tab.render_snapshot(snap1)
    assert len(tab.findChildren(_RisikoPunktCard)) == 1
    tab.render_snapshot(snap2)
    # Alte Karten werden via deleteLater entfernt — nach Event-Verarbeitung 2.
    qtbot.waitUntil(lambda: len(tab.findChildren(_RisikoPunktCard)) == 2, timeout=2000)
