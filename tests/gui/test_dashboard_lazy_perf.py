"""GUI-Tests fuer die Cockpit-Erstladezeit-Optimierung (Loesung A).

Deckt die zwei Kern-Invarianten der Perf-Massnahme ab:

(a) Defer: Die ``NoRiskDashboardWidget``-Konstruktion loest NICHT synchron
    ``DashboardAggregator.aggregate`` aus (der schwere Cross-Tool-Scan mit
    ~25 SQLCipher-Oeffnungen). Der Initial-Refresh laeuft erst im naechsten
    Event-Loop-Tick (Kind-QTimer, 0 ms) — also nach dem ersten Paint.

(b) Lazy-on-expand: Eine zugeklappte Schwerlast-Sektion (hier Light-SIEM,
    deren ctor eigene DB-Reads via ``reload`` faehrt) baut ihr Inner-Widget
    NICHT im ``_build_ui``-Konstruktor, sondern erst beim ERSTEN Aufklappen —
    danach genau einmal (gecacht).

Headless via pytest-qt (offscreen). Kein Netzwerk, kein echter Aggregator-Lauf.

Author: Patrick Riederich
Version: 1.0 (Cockpit-Perf A)
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from tools.norisk_dashboard.domain.models import (
    DashboardData,
    ScoreSnapshot,
    TimeRange,
)
from tools.norisk_dashboard.gui.dashboard_widget import NoRiskDashboardWidget
from tools.norisk_dashboard.gui.light_siem_section import LightSiemSection

pytestmark = pytest.mark.gui


def _empty_data() -> DashboardData:
    """Minimal befuellbarer, render-sicherer DashboardData-Stand (kein Mock)."""
    return DashboardData(
        time_range=TimeRange.WEEK,
        score=ScoreSnapshot(target="Allgemein"),
        generated=datetime(2026, 6, 22, 12, 0, 0),
    )


# ---------------------------------------------------------------------------
# (a) Defer: Konstruktion ruft aggregate NICHT synchron auf
# ---------------------------------------------------------------------------


def test_konstruktion_loest_aggregate_nicht_synchron_aus(qtbot, app):  # noqa: ARG001
    """Direkt nach ``__init__`` darf ``aggregate`` NICHT gelaufen sein.

    Erst ein Event-Loop-Tick (der den deferred Initial-Refresh feuert) loest
    den schweren Aggregator-Lauf aus.
    """
    agg = MagicMock()
    agg.aggregate.return_value = _empty_data()
    # Subjekt-Selektor aus (sonst ruft _build_ui subjects auf, nicht aggregate).
    agg.subjects.return_value = []

    widget = NoRiskDashboardWidget(aggregator=agg)
    qtbot.add_widget(widget)

    # Unmittelbar nach der Konstruktion: noch KEIN aggregate-Aufruf.
    assert agg.aggregate.call_count == 0

    # Nach einem Event-Loop-Tick feuert der deferred Initial-Refresh — jetzt in
    # einem Worker-Thread, daher robust per waitUntil statt fixem Timeout.
    qtbot.waitUntil(lambda: agg.aggregate.call_count >= 1, timeout=3000)


def test_expliziter_refresh_ruft_aggregate(qtbot, app):  # noqa: ARG001
    """Gegenprobe: ein expliziter ``refresh`` ruft ``aggregate`` sofort."""
    agg = MagicMock()
    agg.aggregate.return_value = _empty_data()
    agg.subjects.return_value = []

    widget = NoRiskDashboardWidget(aggregator=agg)
    qtbot.add_widget(widget)
    agg.aggregate.reset_mock()

    widget.refresh()
    assert agg.aggregate.call_count == 1


# ---------------------------------------------------------------------------
# (b) Lazy-on-expand: zugeklappte Light-SIEM-Sektion baut ihr Inner erst
# beim Aufklappen
# ---------------------------------------------------------------------------


def test_light_siem_inner_nicht_im_konstruktor_gebaut(qtbot, app):  # noqa: ARG001
    """Der ``LightSiemSection``-ctor laeuft NICHT beim Cockpit-Bau.

    Spy auf den Sektions-Konstruktor (ueber das im dashboard_widget importierte
    Symbol): 0 Aufrufe nach ``__init__``, genau 1 nach dem ersten Aufklappen,
    und kein weiterer bei erneutem Auf-/Zuklappen (gecacht).
    """
    agg = MagicMock()
    agg.aggregate.return_value = _empty_data()
    agg.subjects.return_value = []

    # side_effect=LightSiemSection ruft die echte Klasse und reicht die echte
    # Instanz durch (anders als wraps=, das den Mock-Returnwert liefert) — so
    # bleibt das gebaute Inner ein echtes LightSiemSection, der Spy zaehlt nur.
    ctor_spy = MagicMock(side_effect=LightSiemSection)
    with patch(
        "tools.norisk_dashboard.gui.dashboard_widget.LightSiemSection",
        ctor_spy,
    ):
        widget = NoRiskDashboardWidget(aggregator=agg)
        qtbot.add_widget(widget)

        # Sektions-Huelle existiert, aber das teure Inner wurde NICHT gebaut.
        assert widget._section_light_siem is not None  # noqa: SLF001
        assert widget._light_siem_section_inner is None  # noqa: SLF001
        assert ctor_spy.call_count == 0

        # Erstes Aufklappen materialisiert das Inner genau einmal.
        widget._section_light_siem.set_expanded(True)  # noqa: SLF001
        assert ctor_spy.call_count == 1
        assert isinstance(
            widget._light_siem_section_inner, LightSiemSection  # noqa: SLF001
        )

        # Zu- und wieder Aufklappen baut NICHT erneut (Factory verbraucht).
        widget._section_light_siem.set_expanded(False)  # noqa: SLF001
        widget._section_light_siem.set_expanded(True)  # noqa: SLF001
        assert ctor_spy.call_count == 1
