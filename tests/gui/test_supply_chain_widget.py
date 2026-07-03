"""test_supply_chain_widget — Verdrahtung der Konzentrationsrisiko-Heatmap.

Prueft, dass ``_refresh_risk_heatmap`` Vendoren + AVVs laedt und in die
eigenstaendig getestete:class:`VendorRiskHeatmap` speist. Der volle Tab-Aufbau
wird bewusst NICHT konstruiert — die anderen Tab-Views (Vendor-Management etc.)
rendern echte Daten und liessen sich nur mit aufwaendig geformten Mocks bauen;
die Heatmap-Aggregation selbst deckt ``test_vendor_risk_heatmap`` ab.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory
from tools.supply_chain_monitor.gui.supply_chain_widget import SupplyChainWidget
from tools.supply_chain_monitor.gui.widgets.vendor_risk_heatmap import (
    VendorRiskHeatmap,
)

pytestmark = pytest.mark.gui


def test_refresh_risk_heatmap_feeds_heatmap(app) -> None:
    """Laedt Vendoren + je Vendor die AVVs und speist die Heatmap."""
    heatmap = VendorRiskHeatmap()
    service = MagicMock()
    service.list_vendors.return_value = [
        Vendor(id=1, name="Acme", category=VendorCategory.CLOUD, criticality_score=5),
        Vendor(id=2, name="Beta", category=VendorCategory.CLOUD, criticality_score=2),
    ]
    avv_service = MagicMock()
    avv_service.list_for_vendor.return_value = []
    fake = SimpleNamespace(
        _service=service, _avv_service=avv_service, _risk_heatmap=heatmap
    )

    SupplyChainWidget._refresh_risk_heatmap(fake)

    service.list_vendors.assert_called_once()
    assert avv_service.list_for_vendor.call_count == 2
    assert len(heatmap._vendors) == 2


def test_refresh_risk_heatmap_fail_safe(app) -> None:
    """Ein Service-Fehler crasht den Tab nicht (fail-safe)."""
    heatmap = VendorRiskHeatmap()
    service = MagicMock()
    service.list_vendors.side_effect = RuntimeError("DB weg")
    fake = SimpleNamespace(
        _service=service, _avv_service=MagicMock(), _risk_heatmap=heatmap
    )

    SupplyChainWidget._refresh_risk_heatmap(fake)  # darf NICHT werfen

    assert len(heatmap._vendors) == 0
