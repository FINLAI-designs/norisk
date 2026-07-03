"""
test_display_mode_state — Tests fuer den globalen Einfach/Profi-Singleton.

Spiegelt das ExplainMode-Singleton-Testmuster: Default, Persistenz, Signal,
kein Doppel-Signal, Toggle. QSettings wird pro Test isoliert.
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings

from core.help.display_mode import DisplayMode
from core.help.display_mode_state import DisplayModeState


@pytest.fixture(autouse=True)
def _clean_state():
    QSettings("FINLAI", "DisplayMode").clear()
    DisplayModeState.reset_for_tests()
    yield
    QSettings("FINLAI", "DisplayMode").clear()
    DisplayModeState.reset_for_tests()


def test_default_ist_easy() -> None:
    state = DisplayModeState.instance()
    assert state.mode() is DisplayMode.EASY
    assert state.is_easy() and not state.is_expert()


def test_instance_ist_singleton() -> None:
    assert DisplayModeState.instance() is DisplayModeState.instance()


def test_direkter_konstruktor_verboten() -> None:
    from core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError):
        DisplayModeState()


def test_set_mode_emittiert_und_persistiert() -> None:
    state = DisplayModeState.instance()
    empfangen: list = []
    state.mode_changed.connect(empfangen.append)

    state.set_mode(DisplayMode.EXPERT)

    assert state.mode() is DisplayMode.EXPERT
    assert empfangen == [DisplayMode.EXPERT]
    # Persistiert als String-Wert in QSettings.
    assert QSettings("FINLAI", "DisplayMode").value("mode", type=str) == "expert"


def test_kein_doppelsignal_bei_wert_identitaet() -> None:
    state = DisplayModeState.instance()
    empfangen: list = []
    state.mode_changed.connect(empfangen.append)

    state.set_mode(DisplayMode.EASY)  # ist bereits EASY → No-op
    assert empfangen == []


def test_toggle_wechselt() -> None:
    state = DisplayModeState.instance()
    assert state.is_easy()
    state.toggle()
    assert state.is_expert()
    state.toggle()
    assert state.is_easy()


def test_initialwert_wird_aus_qsettings_geladen() -> None:
    QSettings("FINLAI", "DisplayMode").setValue("mode", "expert")
    DisplayModeState.reset_for_tests()
    assert DisplayModeState.instance().mode() is DisplayMode.EXPERT
