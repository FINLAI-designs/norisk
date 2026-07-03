"""
test_cve_klick — Tests für die CVE-Klick-Weiterleitung.

Abdeckung:
  - _CveRow emittiert clicked(cve_id) bei Linksklick
  - CvesScansSection leitet das Signal nach außen durch
  - NoRiskDashboardWidget mapped cve_clicked auf open_with_filter
  - CsafAdvisoryWidget.set_cve_filter filtert korrekt auf cve_ids

Author: Patrick Riederich
Version: 0.2 (Phase 2)
"""

from __future__ import annotations

from datetime import datetime

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent

from tools.norisk_dashboard.domain.models import CveListEntry


def _left_click(widget) -> None:  # noqa: ANN001
    ev = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPoint(5, 5),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    widget.mousePressEvent(ev)


@pytest.mark.gui
def test_cve_row_emittiert_clicked(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.section_cves_scans import _CveRow

    entry = CveListEntry(
        cve_id="CVE-2026-5555",
        product="OpenSSL",
        description="Overflow",
        published=datetime.now(),
    )
    row = _CveRow(entry)
    qtbot.addWidget(row)
    row.show()

    with qtbot.waitSignal(row.clicked, timeout=500) as sig:
        _left_click(row)
    assert sig.args == ["CVE-2026-5555"]


@pytest.mark.gui
def test_section_cves_scans_leitet_cve_click_durch(qtbot) -> None:  # noqa: ANN001
    from tools.norisk_dashboard.gui.section_cves_scans import CvesScansSection

    w = CvesScansSection()
    qtbot.addWidget(w)
    w.resize(1200, 400)
    w.show()
    cves = [
        CveListEntry(
            cve_id="CVE-2026-6666",
            product="",
            description="",
            published=datetime.now(),
        )
    ]
    w.update_data(cves, [])

    received = []
    w.cve_clicked.connect(received.append)
    w._cve_container.cve_clicked.emit("CVE-2026-6666")
    assert received == ["CVE-2026-6666"]


@pytest.mark.gui
def test_dashboard_widget_mappt_cve_klick_auf_open_with_filter(
    qtbot,  # noqa: ANN001
) -> None:
    from tools.norisk_dashboard.application.dashboard_aggregator import (
        DashboardAggregator,
    )
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    class _NoopAgg(DashboardAggregator):
        def aggregate(self, time_range, target_name="Allgemein"):  # noqa: ANN001
            raise RuntimeError("nicht aufrufen")

    dash = NoRiskDashboardWidget(aggregator=_NoopAgg())
    qtbot.addWidget(dash)

    received = []
    dash.open_with_filter.connect(lambda k, p: received.append((k, p)))

    dash._on_cve_clicked("CVE-2026-7777")
    assert received == [("csaf_advisor", "CVE-2026-7777")]

    # Leere CVE-ID darf nichts emittieren
    received.clear()
    dash._on_cve_clicked("")
    assert received == []


def test_csaf_set_cve_filter_setzt_attribut_und_ruft_apply_filters() -> None:
    """Reiner Filter-Logik-Test — ohne das volle UI aufzubauen."""
    from tools.csaf_advisor.gui.csaf_advisor_widget import CsafAdvisorWidget

    class _Stub:
        def __init__(self) -> None:
            self._cve_id_filter: str | None = None
            self._apply_calls: list[None] = []

        def _apply_filters(self) -> None:
            self._apply_calls.append(None)

    stub = _Stub()
    CsafAdvisorWidget.set_cve_filter(stub, "CVE-2026-0001")  # type: ignore[arg-type]
    assert stub._cve_id_filter == "CVE-2026-0001"
    assert len(stub._apply_calls) == 1

    # Whitespace-only → Filter aufheben
    CsafAdvisorWidget.set_cve_filter(stub, "   ")  # type: ignore[arg-type]
    assert stub._cve_id_filter is None
    assert len(stub._apply_calls) == 2

    # Leer-String → Filter aufheben
    stub._cve_id_filter = "X"
    CsafAdvisorWidget.set_cve_filter(stub, "")  # type: ignore[arg-type]
    assert stub._cve_id_filter is None
