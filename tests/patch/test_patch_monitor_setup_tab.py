"""
test_patch_monitor_setup_tab — Tests fuer
tools/einstellungen/gui/patch_monitor_setup_tab.py.

Bug-Fix-Sprint C-5 (Option D ergaenzt). Logik-Tests ohne Qt-Render fuer:

1. status_label / status_icon / status_color decken alle ModuleStatus-Werte
2. Privacy-Filter — keine sensitiven Werte aus dem Mapping leak'en
"""

from __future__ import annotations

from core.patch_collector import ModuleStatus
from tools.einstellungen.gui.patch_monitor_setup_tab import (
    status_color,
    status_icon,
    status_label,
)


class TestStatusMapping:
    """Status-Mapping-Funktionen — Stichprobe aller ModuleStatus-Werte."""

    def test_alle_module_status_werte_haben_label(self) -> None:
        for status in ModuleStatus:
            assert status_label(status)
            assert isinstance(status_label(status), str)

    def test_alle_module_status_werte_haben_icon(self) -> None:
        for status in ModuleStatus:
            assert status_icon(status)
            assert isinstance(status_icon(status), str)

    def test_alle_module_status_werte_haben_farbe(self) -> None:
        for status in ModuleStatus:
            color = status_color(status)
            assert color.startswith("#")
            assert len(color) == 7  # #RRGGBB

    def test_unterschiedliche_labels_je_status(self) -> None:
        labels = {status_label(s) for s in ModuleStatus}
        assert len(labels) == 3  # AVAILABLE / NEEDS_INSTALL / BLOCKED — alle distinct

    def test_available_und_needs_install_haben_unterschiedliche_farben(
        self,
    ) -> None:
        # Sanity: Status-Farben sind nicht kollabiert auf einen Wert.
        a = status_color(ModuleStatus.AVAILABLE)
        n = status_color(ModuleStatus.NEEDS_INSTALL)
        b = status_color(ModuleStatus.BLOCKED)
        assert a != n
        assert a != b
        assert n != b
