"""Tests für die Sprint-S3c-Quick-Win-Felder.

Service-Schicht (Aggregator-Loader-Defensive + ``_percentile``-Helper) —
GUI-Tests in:mod:`tests.gui.test_dashboard_quick_wins_gui`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from tools.norisk_dashboard.application.dashboard_aggregator import (
    DashboardAggregator,
)
from tools.norisk_dashboard.domain.models import (
    CertBurndown,
    CompletenessEntry,
    CompletenessStatus,
    CvssPercentiles,
    TimeRange,
)
from tools.norisk_dashboard.tool import _percentile

# ---------------------------------------------------------------------------
# Aggregator-Loader-Defensive
# ---------------------------------------------------------------------------


def test_aggregator_ohne_loader_setzt_quick_win_felder_auf_defaults():
    """Ohne Loader: cert_burndown / cvss_percentiles None, completeness leer."""
    agg = DashboardAggregator()
    data = agg.aggregate(TimeRange.WEEK)
    assert data.cert_burndown is None
    assert data.cvss_percentiles is None
    assert data.completeness == []


def test_aggregator_cert_burndown_loader_durchgereicht():
    """``cert_burndown_loader`` wird aufgerufen, Resultat landet in DashboardData."""
    expected = CertBurndown(
        min_days=5, domain="example.com", count_total=3, count_warning=1, count_critical=1
    )
    loader = MagicMock(return_value=expected)
    agg = DashboardAggregator(cert_burndown_loader=loader)
    data = agg.aggregate(TimeRange.WEEK)
    loader.assert_called_once()
    assert data.cert_burndown == expected


def test_aggregator_cert_burndown_swallows_loader_error():
    """Exception im Loader führt zu None — kein Crash."""

    def _explode():
        raise RuntimeError("Repo aus")

    agg = DashboardAggregator(cert_burndown_loader=_explode)
    data = agg.aggregate(TimeRange.WEEK)
    assert data.cert_burndown is None


def test_aggregator_cvss_percentile_loader_durchgereicht():
    """CVSS-Loader liefert Daten ans Dashboard."""
    expected = CvssPercentiles(
        sample_count=42, p10=2.0, p50=5.5, p90=9.1, sparkline=[7.0, 7.2, 6.8]
    )
    agg = DashboardAggregator(cvss_percentile_loader=MagicMock(return_value=expected))
    data = agg.aggregate(TimeRange.WEEK)
    assert data.cvss_percentiles == expected


def test_aggregator_cvss_percentile_swallows_loader_error():
    agg = DashboardAggregator(
        cvss_percentile_loader=MagicMock(side_effect=OSError("kein Cache"))
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.cvss_percentiles is None


def test_aggregator_completeness_loader_durchgereicht():
    """Completeness-Loader liefert Liste — wird 1:1 weitergegeben."""
    entries = [
        CompletenessEntry(
            tool_key="cert_monitor",
            tool_label="Cert-Monitor",
            last_scan=datetime.now(UTC),
            status=CompletenessStatus.FRESH,
        )
    ]
    agg = DashboardAggregator(completeness_loader=MagicMock(return_value=entries))
    data = agg.aggregate(TimeRange.WEEK)
    assert data.completeness == entries


def test_aggregator_completeness_swallows_loader_error():
    """Loader-Exception → leere Completeness-Liste."""
    agg = DashboardAggregator(
        completeness_loader=MagicMock(side_effect=ValueError("kaputt"))
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.completeness == []


def test_aggregator_completeness_none_zu_leerer_liste():
    """Loader, der ``None`` zurueckgibt → leere Liste statt Crash."""
    agg = DashboardAggregator(
        completeness_loader=MagicMock(return_value=None)
    )
    data = agg.aggregate(TimeRange.WEEK)
    assert data.completeness == []


# ---------------------------------------------------------------------------
# _percentile-Helper
# ---------------------------------------------------------------------------


def test_percentile_leer():
    assert _percentile([], 50) == 0.0


def test_percentile_einzelwert():
    """Bei einem einzigen Wert ist jedes Perzentil dieser Wert."""
    assert _percentile([7.5], 10) == 7.5
    assert _percentile([7.5], 50) == 7.5
    assert _percentile([7.5], 90) == 7.5


def test_percentile_p50_median():
    """p50 entspricht dem Median bei sortierten Werten."""
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(values, 50) == 3.0


def test_percentile_grenzwerte():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(values, 0) == 1.0
    assert _percentile(values, 100) == 5.0


def test_percentile_interpolation():
    """Linear-Interpolation: p25 bei [1,2,3,4,5] ist 2.0."""
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(values, 25) == 2.0
