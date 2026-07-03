"""GUI-Tests für die Sprint-S3c-Quick-Win-Widgets.

Pure Widget-Tests — kein Aggregator, kein DB-Zugriff. Wir setzen die
Daten direkt per ``set_data`` / ``set_entries`` und prüfen den Render-
Zustand (Texte, Tooltip, Farb-Trigger via Pin-Status).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.norisk_dashboard.domain.models import (
    CertBurndown,
    CompletenessEntry,
    CompletenessStatus,
    CvssPercentiles,
)
from tools.norisk_dashboard.gui.cert_burndown_tile import CertBurndownTile
from tools.norisk_dashboard.gui.cvss_percentile_widget import (
    CvssPercentileWidget,
    _Sparkline,
)
from tools.norisk_dashboard.gui.score_completeness_banner import (
    ScoreCompletenessBanner,
    _ToolPin,
)

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# CertBurndownTile
# ---------------------------------------------------------------------------


def test_cert_tile_empty_state(qtbot, app):  # noqa: ARG001
    """``set_data(None)`` zeigt den Empty-State."""
    tile = CertBurndownTile()
    qtbot.add_widget(tile)
    tile.set_data(None)
    assert tile._value.text() == "—"  # noqa: SLF001
    assert "Keine Zertifikate" in tile._unit.text()  # noqa: SLF001


def test_cert_tile_critical_zone(qtbot, app):  # noqa: ARG001
    """min_days <= 7 → Tooltip + Subline + DANGER-Farb-Trigger."""
    tile = CertBurndownTile()
    qtbot.add_widget(tile)
    tile.set_data(
        CertBurndown(
            min_days=3,
            domain="api.example.de",
            count_total=4,
            count_warning=2,
            count_critical=1,
        )
    )
    assert tile._value.text() == "3"  # noqa: SLF001
    assert "verbleibend" in tile._unit.text()  # noqa: SLF001
    assert "api.example.de" in tile._sub.text()  # noqa: SLF001
    assert "1 kritisch" in tile._sub.text()  # noqa: SLF001


def test_cert_tile_expired_negative_days(qtbot, app):  # noqa: ARG001
    """Negative Tage → 'abgelaufen'-Suffix."""
    tile = CertBurndownTile()
    qtbot.add_widget(tile)
    tile.set_data(CertBurndown(min_days=-2, domain="x.de", count_total=1))
    assert "abgelaufen" in tile._unit.text()  # noqa: SLF001


def test_cert_tile_click_signal(qtbot, app):  # noqa: ARG001
    """Linksklick → ``clicked``-Signal."""
    from PySide6.QtCore import QPoint, Qt
    from PySide6.QtGui import QMouseEvent

    tile = CertBurndownTile()
    qtbot.add_widget(tile)
    received: list[None] = []
    tile.clicked.connect(lambda: received.append(None))
    event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPoint(10, 10),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    tile.mousePressEvent(event)
    assert len(received) == 1


# ---------------------------------------------------------------------------
# CvssPercentileWidget
# ---------------------------------------------------------------------------


def test_cvss_widget_empty_state(qtbot, app):  # noqa: ARG001
    widget = CvssPercentileWidget()
    qtbot.add_widget(widget)
    widget.set_data(None)
    assert widget._labels["p50"].text() == "—"  # noqa: SLF001
    assert "noch keine cve" in widget._sub.text().lower()  # noqa: SLF001


def test_cvss_widget_zeigt_perzentile_und_count(qtbot, app):  # noqa: ARG001
    widget = CvssPercentileWidget()
    qtbot.add_widget(widget)
    widget.set_data(
        CvssPercentiles(
            sample_count=12, p10=2.1, p50=6.4, p90=9.0, sparkline=[5, 6, 7, 8]
        )
    )
    assert widget._labels["p10"].text() == "2.1"  # noqa: SLF001
    assert widget._labels["p50"].text() == "6.4"  # noqa: SLF001
    assert widget._labels["p90"].text() == "9.0"  # noqa: SLF001
    assert "12 CVEs" in widget._sub.text()  # noqa: SLF001


def test_sparkline_set_values_idempotent(qtbot, app):  # noqa: ARG001
    """Sparkline akzeptiert leere und nicht-leere Wertelisten ohne Crash."""
    s = _Sparkline()
    qtbot.add_widget(s)
    s.set_values([])
    s.set_values([1.0, 2.0, 3.0])
    s.set_values([5.0])  # Single-Value: zeichnet leeren Strich
    assert s._values == [5.0]  # noqa: SLF001


# ---------------------------------------------------------------------------
# ScoreCompletenessBanner
# ---------------------------------------------------------------------------


def test_banner_unbekannt_wenn_leer(qtbot, app):  # noqa: ARG001
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    banner.set_entries([])
    assert "unbekannt" in banner._headline.text().lower()  # noqa: SLF001


def test_banner_alle_fresh_zeigt_ok_text(qtbot, app):  # noqa: ARG001
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    now = datetime.now(UTC)
    entries = [
        CompletenessEntry(
            tool_key=k,
            tool_label=k,
            last_scan=now - timedelta(days=1),
            status=CompletenessStatus.FRESH,
        )
        for k in ("cert_monitor", "api_security")
    ]
    banner.set_entries(entries)
    assert "frisch" in banner._headline.text().lower()  # noqa: SLF001


def test_banner_outdated_zeigt_warnung(qtbot, app):  # noqa: ARG001
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    entries = [
        CompletenessEntry(
            tool_key="cert_monitor",
            tool_label="Cert-Monitor",
            last_scan=datetime.now(UTC) - timedelta(days=10),
            status=CompletenessStatus.OUTDATED,
        ),
        CompletenessEntry(
            tool_key="api_security",
            tool_label="API-Security",
            last_scan=datetime.now(UTC) - timedelta(days=2),
            status=CompletenessStatus.FRESH,
        ),
    ]
    banner.set_entries(entries)
    assert "veraltet" in banner._headline.text().lower()  # noqa: SLF001


def test_banner_missing_zeigt_kritischen_text(qtbot, app):  # noqa: ARG001
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    entries = [
        CompletenessEntry(
            tool_key="cert_monitor",
            tool_label="Cert-Monitor",
            last_scan=None,
            status=CompletenessStatus.MISSING,
        ),
    ]
    banner.set_entries(entries)
    assert "ohne scan" in banner._headline.text().lower()  # noqa: SLF001


def test_banner_pin_anzahl_passt(qtbot, app):  # noqa: ARG001
    """Pro Eintrag wird ein Pin-Widget gerendert."""
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    entries = [
        CompletenessEntry(
            tool_key=f"tool_{i}",
            tool_label=f"Tool {i}",
            last_scan=None,
            status=CompletenessStatus.MISSING,
        )
        for i in range(3)
    ]
    banner.set_entries(entries)
    pins = banner.findChildren(_ToolPin)
    assert len(pins) == 3


def test_banner_pin_tooltip_enthaelt_status(qtbot, app):  # noqa: ARG001
    banner = ScoreCompletenessBanner()
    qtbot.add_widget(banner)
    entries = [
        CompletenessEntry(
            tool_key="cert_monitor",
            tool_label="Cert-Monitor",
            last_scan=datetime(2026, 4, 1, tzinfo=UTC),
            status=CompletenessStatus.OUTDATED,
        ),
    ]
    banner.set_entries(entries)
    pin = banner.findChildren(_ToolPin)[0]
    assert "veraltet" in pin.toolTip().lower()
    assert "01.04.2026" in pin.toolTip()
