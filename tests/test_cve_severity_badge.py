"""
test_cve_severity_badge.

Die Schweregrad-Spalte im Schwachstellen-Tab wird seit dieser Iteration
als kraeftiges Badge gerendert (statt nur dezenter Zeilen-Tint). Das
macht insbesondere LOW/INFO-Stufen erkennbar, die vorher gar keine
Eigenfarbe hatten.

Pruefungen:

1. ``_cve_badge_farben`` liefert ein Mapping fuer alle fuenf Stufen
   (CRITICAL/HIGH/MEDIUM/LOW/INFO) — vivid SEVERITY_SIGNAL_*-Werte.
2. ``_apply_severity_badge`` setzt Hintergrund, Vordergrund, Fett-Stil
   und zentrierte Ausrichtung.
3. Unbekannter Schweregrad → kein Crash, Item bleibt unveraendert.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.gui


def test_badge_farben_decken_alle_fuenf_stufen_ab() -> None:
    from tools.cyber_dashboard.gui.dashboard_widget import _cve_badge_farben

    farben = _cve_badge_farben()
    for stufe in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert stufe in farben
        bg, text = farben[stufe]
        assert bg.startswith("#"), f"BG fuer {stufe} muss Hex sein"
        assert text.startswith("#"), f"Text fuer {stufe} muss Hex sein"


def test_apply_severity_badge_setzt_bg_und_fett(qapp, qtbot) -> None:  # noqa: ARG001
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

    from tools.cyber_dashboard.gui.dashboard_widget import (
        _apply_severity_badge,
        _cve_badge_farben,
    )

    tbl = QTableWidget(1, 1)
    qtbot.add_widget(tbl)
    item = QTableWidgetItem("CRITICAL")
    tbl.setItem(0, 0, item)

    _apply_severity_badge(item)

    expected_bg, expected_text = _cve_badge_farben()["CRITICAL"]
    assert item.background().color().name().lower() == expected_bg.lower()
    assert item.foreground().color().name().lower() == expected_text.lower()
    assert item.font().bold() is True
    assert item.textAlignment() == Qt.AlignmentFlag.AlignCenter


def test_apply_severity_badge_ignoriert_unbekannte_stufe(qapp, qtbot) -> None:  # noqa: ARG001
    """Unbekannter Severity-String darf nicht crashen und faerbt nichts."""
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

    from tools.cyber_dashboard.gui.dashboard_widget import _apply_severity_badge

    tbl = QTableWidget(1, 1)
    qtbot.add_widget(tbl)
    item = QTableWidgetItem("UNBEKANNT")
    tbl.setItem(0, 0, item)

    _apply_severity_badge(item)

    # Kein Crash, kein Bold (Default-Font)
    assert item.font().bold() is False


def test_low_und_info_bekommen_jetzt_eigene_badge_farbe() -> None:
    """Regression-Test: vor hatten LOW/INFO im _cve_farben-Mapping
    keine Werte — sie blieben farblos. Das Badge-Mapping deckt jetzt
    explizit beide ab."""
    from tools.cyber_dashboard.gui.dashboard_widget import _cve_badge_farben

    bg_low, _ = _cve_badge_farben()["LOW"]
    bg_info, _ = _cve_badge_farben()["INFO"]
    assert bg_low != ""
    assert bg_info != ""
    assert bg_low != bg_info  # unterscheidbare Farben
