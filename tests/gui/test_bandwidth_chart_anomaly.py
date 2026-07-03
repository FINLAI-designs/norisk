"""Tests fuer den Bandwidth-Chart-Anomaly-Marker.

Pure-Function-Tests fuer ``marker_color_for`` + Widget-Tests fuer
``append_sample(anomaly=...)`` + Rolling-Buffer-Verhalten.
"""

from __future__ import annotations

import pytest

from core import theme
from tools.network_monitor.domain.models import AnomalyType
from tools.network_monitor.gui.bandwidth_chart import (
    BandwidthChart,
    marker_color_for,
)

pytestmark = pytest.mark.gui


class TestMarkerColorFor:
    def test_volume_spike_is_danger(self):
        assert marker_color_for(AnomalyType.VOLUME_SPIKE) == theme.DARK_DANGER

    def test_single_ip_is_danger(self):
        assert marker_color_for(AnomalyType.SINGLE_IP) == theme.DARK_DANGER

    def test_unknown_path_is_danger(self):
        assert marker_color_for(AnomalyType.UNKNOWN_PATH) == theme.DARK_DANGER

    def test_dns_tunneling_is_danger(self):
        assert marker_color_for(AnomalyType.DNS_TUNNELING) == theme.DARK_DANGER

    def test_off_hours_is_warning_orange(self):
        assert marker_color_for(AnomalyType.OFF_HOURS) == theme.WARNING_ORANGE

    def test_game_cdn_is_info_grey(self):
        assert marker_color_for(AnomalyType.GAME_CDN) == theme.SEVERITY_SIGNAL_INFO


def test_append_sample_without_anomaly_keeps_buffer_in_sync(app, qtbot):
    chart = BandwidthChart()
    qtbot.addWidget(chart)
    chart.append_sample(100, 200)
    chart.append_sample(110, 210)
    assert len(chart._uploads) == 2
    assert len(chart._downloads) == 2
    assert len(chart._anomalies) == 2
    assert list(chart._anomalies) == [None, None]


def test_append_sample_with_anomaly_stores_kind(app, qtbot):
    chart = BandwidthChart()
    qtbot.addWidget(chart)
    chart.append_sample(100, 200)
    chart.append_sample(900, 1000, anomaly=AnomalyType.VOLUME_SPIKE)
    chart.append_sample(120, 220)
    assert list(chart._anomalies) == [
        None,
        AnomalyType.VOLUME_SPIKE,
        None,
    ]


def test_clear_resets_anomaly_buffer(app, qtbot):
    chart = BandwidthChart()
    qtbot.addWidget(chart)
    chart.append_sample(900, 1000, anomaly=AnomalyType.VOLUME_SPIKE)
    chart.clear()
    assert len(chart._anomalies) == 0


def test_anomalies_roll_off_after_60_samples(app, qtbot):
    chart = BandwidthChart()
    qtbot.addWidget(chart)
    chart.append_sample(900, 1000, anomaly=AnomalyType.VOLUME_SPIKE)
    for _ in range(60):
        chart.append_sample(100, 100)
    # Erste Anomaly aus dem 60s-Fenster geschoben
    assert list(chart._anomalies).count(AnomalyType.VOLUME_SPIKE) == 0
    assert len(chart._anomalies) == 60


def test_paint_event_with_anomalies_does_not_crash(app, qtbot):
    """Sanity: paintEvent mit gemischten None/AnomalyType-Eintraegen rendert."""
    chart = BandwidthChart()
    qtbot.addWidget(chart)
    chart.resize(640, 200)
    for i in range(30):
        anomaly = None
        if i == 10:
            anomaly = AnomalyType.VOLUME_SPIKE
        elif i == 20:
            anomaly = AnomalyType.OFF_HOURS
        chart.append_sample(50 + i * 5, 100 + i * 8, anomaly=anomaly)
    chart.show()
    qtbot.waitExposed(chart)
    chart.repaint()
