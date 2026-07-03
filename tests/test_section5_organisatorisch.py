"""
test_section5_organisatorisch — Tests für Sektion 5 (Organisatorische Sicherheit).

Abdeckung:
  - OrganizationalSection zeigt CTA bei fehlendem Assessment
  - OrganizationalSection versteckt CTA bei vorhandenem Assessment
  - Responsives Raster wechselt zwischen 4 und 2 Spalten
  - tiles_from_components baut vier OrgTiles aus ScoreComponents
  - CTA-Klick emittiert navigate("security_scoring")

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

import pytest

from tools.norisk_dashboard.application.dashboard_aggregator import (
    tiles_from_components,
)
from tools.norisk_dashboard.domain.models import OrgSnapshot, OrgTile
from tools.security_scoring.domain.models import ScoreComponent


def _sample_tiles() -> list[OrgTile]:
    return [
        OrgTile(key="dsgvo", label="DSGVO-Compliance", score=80.0, findings_open=2),
        OrgTile(key="phishing", label="Phishing-Schutz", score=65.0, findings_open=3),
        OrgTile(key="mfa", label="Multi-Factor Auth", score=90.0, findings_open=0),
        OrgTile(
            key="passwort_manager",
            label="Passwort-Manager",
            score=70.0,
            findings_open=1,
        ),
    ]


def test_tiles_from_components_match_by_label() -> None:
    comps = [
        ScoreComponent(
            name="DSGVO-Compliance", score=82.0, weight=0.25, findings_high=1
        ),
        ScoreComponent(
            name="Phishing-Schutz", score=55.0, weight=0.25, findings_high=4
        ),
    ]
    tiles = tiles_from_components(comps)
    assert len(tiles) == 4
    by_key = {t.key: t for t in tiles}
    assert by_key["dsgvo"].score == pytest.approx(82.0)
    assert by_key["dsgvo"].findings_open == 1
    assert by_key["phishing"].findings_open == 4
    assert by_key["mfa"].score is None
    assert by_key["passwort_manager"].score is None


def test_tiles_from_components_leere_liste() -> None:
    tiles = tiles_from_components([])
    assert len(tiles) == 4
    assert all(t.score is None for t in tiles)


@pytest.mark.gui
def test_section5_cta_bei_fehlendem_assessment(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.section_organizational import (
        OrganizationalSection,
    )

    w = OrganizationalSection()
    qtbot.addWidget(w)
    w.resize(1200, 300)
    w.show()

    snapshot = OrgSnapshot(tiles=_sample_tiles(), has_assessment=False)
    w.update_data(snapshot)
    assert w._cta_host.isVisible()


@pytest.mark.gui
def test_section5_cta_versteckt_bei_vorhandenem_assessment(
    qtbot,  # noqa: ANN001
) -> None:
    from tools.norisk_dashboard.gui.section_organizational import (
        OrganizationalSection,
    )

    w = OrganizationalSection()
    qtbot.addWidget(w)
    w.resize(1200, 300)
    w.show()

    snapshot = OrgSnapshot(tiles=_sample_tiles(), has_assessment=True)
    w.update_data(snapshot)
    assert not w._cta_host.isVisible()


@pytest.mark.gui
def test_section5_cta_klick_emittiert_navigate(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.section_organizational import (
        OrganizationalSection,
    )

    w = OrganizationalSection()
    qtbot.addWidget(w)
    w.resize(1200, 300)
    w.show()

    snapshot = OrgSnapshot(tiles=_sample_tiles(), has_assessment=False)
    w.update_data(snapshot)

    with qtbot.waitSignal(w.navigate, timeout=500) as sig:
        w._cta_btn.click()
    assert sig.args == ["security_scoring"]


@pytest.mark.gui
def test_section5_responsive_raster(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.section_organizational import (
        OrganizationalSection,
    )

    w = OrganizationalSection()
    qtbot.addWidget(w)
    w.resize(1200, 300)
    w.show()

    snapshot = OrgSnapshot(tiles=_sample_tiles(), has_assessment=True)
    w.update_data(snapshot)
    # Sollte 4 Spalten sein bei >= 1000 px
    assert w._current_cols == 4

    w.resize(800, 400)
    qtbot.wait(50)
    # resizeEvent stellt auf 2 Spalten um
    assert w._current_cols == 2
