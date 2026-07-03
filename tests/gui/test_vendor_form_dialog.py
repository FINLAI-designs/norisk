"""Regressionstests fuer ``VendorFormDialog.collected_vendor`` (Add-Pfad).

Der Add-Zweig von ``collected_vendor`` las ``self._criticality_spin``
(Ueberbleibsel vom QSpinBox->QComboBox-Refactor) — das Attribut existiert nicht,
das Widget heisst ``_criticality_combo``. Folge: jedes Anlegen eines Vendors ueber
den manuellen Dialog crashte mit ``AttributeError`` (Crash-Handler fing ab, aber
kein Vendor wurde gespeichert). Der Edit-Zweig war korrekt.

Diese Tests decken den bisher ungetesteten Qt-Collect-Pfad ab: die bestehenden
Supply-Chain-Tests pruefen Domain/Repository/Service, aber nie den Dialog-Roundtrip
(gleiches Muster wie/).
"""

from __future__ import annotations

import pytest

from tools.supply_chain_monitor.domain.models import Vendor, VendorCategory
from tools.supply_chain_monitor.gui.vendor_form_dialog import VendorFormDialog

pytestmark = pytest.mark.gui


def test_add_mode_collected_vendor_uses_selected_criticality(app):
    """Add-Modus liefert den im Combo gewaehlten Kritikalitaets-Score (kein Crash)."""
    dialog = VendorFormDialog()
    dialog._name_input.setText("DATEV eG")
    idx = dialog._criticality_combo.findData(5)
    assert idx >= 0
    dialog._criticality_combo.setCurrentIndex(idx)

    vendor = dialog.collected_vendor()

    assert isinstance(vendor, Vendor)
    assert vendor.id is None
    assert vendor.name == "DATEV eG"
    assert vendor.criticality_score == 5


def test_add_mode_collected_vendor_default_criticality_is_three(app):
    """Ohne Auswahl bleibt die Default-Kritikalitaet (Combo-Default = 3) erhalten."""
    dialog = VendorFormDialog()
    dialog._name_input.setText("Microsoft 365")

    vendor = dialog.collected_vendor()

    assert vendor.criticality_score == 3


def test_add_mode_collected_vendor_keeps_selected_category(app):
    """Die Kategorie (plain Enum) round-trippt durch Qt-userData (anders als StrEnum)."""
    dialog = VendorFormDialog()
    dialog._name_input.setText("Hetzner")
    idx = dialog._category_combo.findData(VendorCategory.CLOUD)
    assert idx >= 0
    dialog._category_combo.setCurrentIndex(idx)

    vendor = dialog.collected_vendor()

    assert vendor.category is VendorCategory.CLOUD
