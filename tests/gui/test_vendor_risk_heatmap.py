"""Tests fuer VendorRiskHeatmap und die AVV-Health-/Cell-Helper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tools.supply_chain_monitor.domain.models import (
    AvvDocument,
    AvvDocumentStatus,
    Vendor,
    VendorCategory,
)
from tools.supply_chain_monitor.gui.widgets.vendor_risk_heatmap import (
    VendorRiskHeatmap,
    avv_health_for_vendor,
    build_vendor_risk_cells,
)

pytestmark = pytest.mark.gui


def _vendor(
    vid: int, name: str, criticality: int = 3, category: VendorCategory = VendorCategory.CLOUD
) -> Vendor:
    return Vendor(
        id=vid,
        name=name,
        category=category,
        criticality_score=criticality,
    )


def _avv(
    vid: int,
    valid_from: datetime,
    valid_until: datetime,
    *,
    sha: str = "a" * 64,
) -> AvvDocument:
    return AvvDocument(
        id=None,
        vendor_id=vid,
        file_path=f"/tmp/{vid}.pdf",
        sha256=sha,
        size_bytes=1024,
        original_filename=f"{vid}.pdf",
        valid_from=valid_from,
        valid_until=valid_until,
        status=AvvDocumentStatus.ACTIVE,
    )


class TestAvvHealthForVendor:
    """Pure-Function-Tests fuer das 4-Stufen-Mapping."""

    NOW = datetime(2026, 6, 1, tzinfo=UTC)

    def test_no_avv_returns_zero(self):
        vendor = _vendor(1, "X")
        assert avv_health_for_vendor(vendor, {}, now=self.NOW) == 0

    def test_overdue_avv_returns_one(self):
        vendor = _vendor(1, "X")
        doc = _avv(
            1,
            self.NOW - timedelta(days=400),
            self.NOW - timedelta(days=30),  # Frist ueberschritten
        )
        assert avv_health_for_vendor(vendor, {1: [doc]}, now=self.NOW) == 1

    def test_expiring_avv_returns_two(self):
        vendor = _vendor(1, "X")
        doc = _avv(
            1,
            self.NOW - timedelta(days=400),
            self.NOW + timedelta(days=30),  # < 90 Tage Rest
        )
        assert avv_health_for_vendor(vendor, {1: [doc]}, now=self.NOW) == 2

    def test_ok_avv_returns_three(self):
        vendor = _vendor(1, "X")
        doc = _avv(
            1,
            self.NOW - timedelta(days=30),
            self.NOW + timedelta(days=200),  # > 90 Tage Rest
        )
        assert avv_health_for_vendor(vendor, {1: [doc]}, now=self.NOW) == 3

    def test_best_of_multiple_avvs_wins(self):
        """Hat ein Vendor mehrere AVVs, zaehlt der best-Status."""
        vendor = _vendor(1, "X")
        overdue = _avv(
            1, self.NOW - timedelta(days=400), self.NOW - timedelta(days=30)
        )
        ok = _avv(
            1,
            self.NOW - timedelta(days=30),
            self.NOW + timedelta(days=200),
            sha="b" * 64,
        )
        assert (
            avv_health_for_vendor(vendor, {1: [overdue, ok]}, now=self.NOW) == 3
        )

    def test_vendor_without_id_returns_zero(self):
        # Pre-INSERT Vendor (id=None) → kann nicht im Mapping liegen
        vendor = Vendor(
            id=None, name="Neu", category=VendorCategory.CLOUD, criticality_score=3
        )
        assert avv_health_for_vendor(vendor, {}, now=self.NOW) == 0


class TestBuildVendorRiskCells:
    """Cell-Aggregation 5x4 mit Score-Mapping."""

    def test_empty_returns_20_cells(self):
        cells = build_vendor_risk_cells([], {})
        assert len(cells) == 20
        for cell in cells.values():
            assert cell.label == ""

    def test_single_vendor_in_correct_bucket(self):
        vendor = _vendor(1, "Acme", criticality=4)
        # KEIN_AVV → col 0
        cells = build_vendor_risk_cells([vendor], {})
        # K=4 → row 1, col 0
        assert cells[(1, 0)].label == "1"

    def test_top_left_is_critical_score(self):
        """K=5 + KEIN_AVV → criticality=5 * (4-0) = 20 → value=1.0 (rot)."""
        cells = build_vendor_risk_cells([], {})
        assert cells[(0, 0)].value == 1.0  # max risk

    def test_bottom_right_is_zero_score(self):
        """K=1 + AVV_OK → criticality=1 * (4-3) = 1 → value=0.05 (gruen)."""
        cells = build_vendor_risk_cells([], {})
        assert cells[(4, 3)].value == pytest.approx(0.05)

    def test_counter_increments_in_same_bucket(self):
        v1 = _vendor(1, "Acme", criticality=5)
        v2 = _vendor(2, "Bingo", criticality=5)
        v3 = _vendor(3, "Cube", criticality=5)
        cells = build_vendor_risk_cells([v1, v2, v3], {})
        # Alle 3 in K=5/KEIN_AVV-Bucket
        assert cells[(0, 0)].label == "3"


def test_widget_initial_state(app, qtbot):
    widget = VendorRiskHeatmap()
    qtbot.addWidget(widget)
    assert widget._vendors == []
    assert widget.selected_cell() is None


def test_set_data_populates_summary(app, qtbot):
    widget = VendorRiskHeatmap()
    qtbot.addWidget(widget)
    vendors = [
        _vendor(1, "Acme", criticality=5),
        _vendor(2, "Bingo", criticality=2),
    ]
    widget.set_data(vendors, {}, now=datetime(2026, 6, 1, tzinfo=UTC))
    assert widget._vendor_list.count() == 2


def test_cell_selected_signal_emits_criticality_health(app, qtbot):
    widget = VendorRiskHeatmap()
    qtbot.addWidget(widget)
    vendors = [_vendor(1, "Acme", criticality=5)]
    widget.set_data(vendors, {}, now=datetime(2026, 6, 1, tzinfo=UTC))
    with qtbot.waitSignal(widget.cell_selected, timeout=1000) as blocker:
        widget._on_cell_clicked(row_idx=0, col_idx=0)  # K=5, KEIN_AVV
    assert blocker.args == [5, 0]
    assert widget.selected_cell() == (5, 0)


def test_filter_after_click_shows_only_bucket_vendors(app, qtbot):
    widget = VendorRiskHeatmap()
    qtbot.addWidget(widget)
    vendors = [
        _vendor(1, "InBucket1", criticality=5),
        _vendor(2, "InBucket2", criticality=5),
        _vendor(3, "OtherBucket", criticality=2),
    ]
    widget.set_data(vendors, {}, now=datetime(2026, 6, 1, tzinfo=UTC))
    widget._on_cell_clicked(row_idx=0, col_idx=0)  # K=5, KEIN_AVV
    assert widget._vendor_list.count() == 2
