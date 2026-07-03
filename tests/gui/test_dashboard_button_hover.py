""": Buttons unter Container-Stylesheets brauchen eigenes Button-QSS.

Das Dashboard-Root setzt ein selektorloses ``setStyleSheet("background:...")``
(``dashboard_widget.py``), das TechStack-Widget ein ``QWidget {...}``-Container-
Stylesheet — darunter malt Qt den Hover-Fill der globalen
``QPushButton:hover``-Regel nicht, die dunkle Hover-``color`` greift aber:
Schrift wird unsichtbar (Bug-Klasse/R26). Diese Tests sichern, dass die
betroffenen Buttons ihr eigenes vollstaendiges Stylesheet aus
``core/widgets/button_styles.py`` tragen.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core import theme
from tools.norisk_dashboard.domain.anomaly_models import AnomalyReport
from tools.norisk_dashboard.gui.anomaly_section import AnomalySection
from tools.norisk_dashboard.gui.light_siem_section import LightSiemSection
from tools.norisk_dashboard.gui.nis2_status_section import Nis2StatusSection
from tools.techstack.gui.techstack_widget import TechStackWidget

pytestmark = pytest.mark.gui


class _FakeDetector:
    def compute_report(self) -> AnomalyReport:
        return AnomalyReport()


class _FakeNis2Service:
    def list_open_incidents(self) -> list:
        return []


class _FailingAggregator:
    """reload faengt Exceptions defensiv — Buttons sind dann schon gestylt."""

    def summary(self):
        raise RuntimeError("kein Light-SIEM im Test")

    def list_recent(self, **_kwargs) -> list:
        return []


def _assert_link_button(btn) -> None:
    qss = btn.styleSheet()
    assert "QPushButton:hover" in qss
    assert theme.ACCENT_HOVER in qss
    assert theme.get().BG_DARK not in qss


def test_anomaly_refresh_button_hat_link_stylesheet(qtbot) -> None:
    section = AnomalySection(detector=_FakeDetector())
    qtbot.addWidget(section)
    _assert_link_button(section._refresh_btn)


def test_nis2_tool_button_hat_link_stylesheet(qtbot) -> None:
    section = Nis2StatusSection(service=_FakeNis2Service())
    qtbot.addWidget(section)
    _assert_link_button(section._tool_btn)


def test_light_siem_refresh_button_hat_link_stylesheet(qtbot) -> None:
    section = LightSiemSection(aggregator=_FailingAggregator(), auto_ingest=False)
    qtbot.addWidget(section)
    _assert_link_button(section._refresh_btn)


def test_techstack_buttons_haben_outline_stylesheet(qtbot) -> None:
    """Alle fuenf TechStack-Buttons sind als Outline-Buttons erkennbar."""
    fake_service = MagicMock()
    fake_service.techstack_laden.return_value = []
    fake_service.techstack_anzahl.return_value = 0
    fake_service.nvd_aktiv.return_value = False

    widget = TechStackWidget(fake_service)
    qtbot.addWidget(widget)

    c = theme.get()
    for btn in (
        widget._btn_hinzufuegen,
        widget._btn_entfernen,
        widget._btn_sync,
        widget._btn_cve_suchen,
        widget._btn_starter,
    ):
        qss = btn.styleSheet()
        assert "QPushButton:hover" in qss, btn.text()
        # Outline-Charakteristik: Teal-Rahmen im Normal-State, Hover paart
        # Teal-Fill mit dunkler Schrift im selben Block.
        assert f"border: 2px solid {c.ACCENT}" in qss, btn.text()
        assert f"background-color: {c.ACCENT}" in qss, btn.text()
