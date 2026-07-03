"""
test_dashboard_error_banner — GUI-Tests für die Fehler-Sichtbarkeit im
NoRisk-Dashboard.

Abdeckung:
- Schlägt die Aggregation fehl, wird das Fehler-Banner sichtbar, statt den
  Fehler stumm zu schlucken (der Aktualisieren-Button wirkte sonst tot).
- Nach erfolgreichem Refresh ist das Banner wieder versteckt.
- Recovery: erholt sich der Aggregator, verschwindet das Banner beim nächsten
  Refresh.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from tools.norisk_dashboard.domain.models import (
    DashboardData,
    ScoreSnapshot,
    TimeRange,
)

pytestmark = pytest.mark.gui


def _empty_data() -> DashboardData:
    return DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="ACME GmbH"),
        generated=datetime(2026, 4, 21, 12, 0, 0),
    )


def _make_widget(qtbot, aggregator):
    from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget

    w = NoRiskDashboardWidget(aggregator=aggregator, export_service=MagicMock())
    qtbot.addWidget(w)
    # Der Initial-Refresh laeuft jetzt deferred (0-ms-Timer) UND im
    # Worker-Thread. Auf das ``refreshed``-Signal warten, damit der erste Refresh
    # — und damit der Banner-Zustand — feststeht (feuert bei Erfolg UND Fehler).
    with qtbot.waitSignal(w.refreshed, timeout=3000):
        pass
    return w


@pytest.mark.usefixtures("app")
class TestDashboardFehlerBanner:
    def test_aggregations_fehler_zeigt_banner(self, qtbot) -> None:
        agg = MagicMock()
        agg.aggregate.side_effect = RuntimeError("keine Datenbank")
        w = _make_widget(qtbot, agg)
        assert w._error_banner.isVisibleTo(w)
        assert w._error_label.text()  # Meldung nicht leer

    def test_erfolgreicher_refresh_versteckt_banner(self, qtbot) -> None:
        agg = MagicMock()
        agg.aggregate.return_value = _empty_data()
        w = _make_widget(qtbot, agg)
        # Banner künstlich einblenden, dann erfolgreich refreshen. refresh ist
        # synchron (nur der Initial-Lauf ist async) -> wirkt sofort.
        w._error_banner.setVisible(True)
        w.refresh()
        assert not w._error_banner.isVisibleTo(w)

    def test_recovery_nach_fehler(self, qtbot) -> None:
        agg = MagicMock()
        agg.aggregate.side_effect = RuntimeError("keine Datenbank")
        w = _make_widget(qtbot, agg)
        assert w._error_banner.isVisibleTo(w)
        # Aggregator erholt sich → Banner verschwindet beim nächsten Refresh.
        agg.aggregate.side_effect = None
        agg.aggregate.return_value = _empty_data()
        w.refresh()  # synchron (warm) — wirkt sofort
        assert not w._error_banner.isVisibleTo(w)
