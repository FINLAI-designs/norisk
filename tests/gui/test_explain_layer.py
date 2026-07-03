"""Tests für den Erklär-Layer (Sprint S1c).

Deckt ab:
  - ``ExplainMode``-Singleton: Singleton-Identität, Default = aus,
    Toggle ändert Wert + persistiert + emittiert Signal.
  - ``ExplainableLabel``: Default-Verhalten ohne Tooltip/Border,
    Reaktion auf Mode-Wechsel, ``set_explanation``-Live-Update.
  - ``HelpContent.explanations``: Erweiterung ist additiv (vorhandene
    Tools haben weiter ein leeres Dict, network_monitor hat 15 Einträge).

GUI-Tests verwenden die ``app``-Fixture aus:mod:`tests.gui.conftest`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from PySide6.QtCore import QSettings

from core.help.display_mode_state import DisplayModeState
from core.help.explain_mode import ExplainMode
from core.help.explainable_label import ExplainableLabel
from core.help.help_content import (
    ALL_HELP_CONTENTS,
    HELP_NETWORK_MONITOR,
    HelpContent,
)

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_explain_mode(app):  # noqa: ARG001 -- app fixture aktiviert QApplication
    """Setzt das ExplainMode-Singleton + QSettings vor jedem Test zurück.

    Damit Tests reproduzierbar starten — kein Leaking zwischen Tests
    und kein QSettings-Wert vom Host-System.
    """
    for app_name in ("ExplainMode", "DisplayMode"):
        s = QSettings("FINLAI", app_name)
        s.clear()
        s.sync()
    DisplayModeState.reset_for_tests()
    ExplainMode.reset_for_tests()
    yield
    for app_name in ("ExplainMode", "DisplayMode"):
        s = QSettings("FINLAI", app_name)
        s.clear()
        s.sync()
    DisplayModeState.reset_for_tests()
    ExplainMode.reset_for_tests()


# ---------------------------------------------------------------------------
# ExplainMode-Singleton
# ---------------------------------------------------------------------------


def test_explain_mode_ist_singleton():
    """``instance`` liefert immer dieselbe Referenz."""
    a = ExplainMode.instance()
    b = ExplainMode.instance()
    assert a is b


def test_explain_mode_default_an():
    """Default-Modus ist Einfach → Erklär-Layer ist sichtbar."""
    mode = ExplainMode.instance()
    assert mode.is_enabled() is True


def test_explain_mode_toggle_persists():
    """``toggle`` schreibt den Modus in QSettings — über Reset hinweg lesbar."""
    mode = ExplainMode.instance()
    assert mode.is_enabled() is True  # Default Einfach
    mode.toggle()
    assert mode.is_enabled() is False  # → Profi

    # Beide Singletons verwerfen → Re-Read aus QSettings (DisplayMode-Quelle).
    ExplainMode.reset_for_tests()
    DisplayModeState.reset_for_tests()
    mode2 = ExplainMode.instance()
    assert mode2.is_enabled() is False


def test_explain_mode_emittiert_signal():
    """``set_enabled`` löst ``mode_changed`` mit dem neuen Bool aus."""
    mode = ExplainMode.instance()  # Default True (Einfach)
    received: list[bool] = []
    mode.mode_changed.connect(received.append)

    mode.set_enabled(False)  # → Profi
    assert received == [False]

    mode.set_enabled(True)  # → Einfach
    assert received == [False, True]


def test_explain_mode_set_enabled_kein_doppelsignal():
    """Set auf den aktuellen Wert ist no-op — kein redundantes Signal."""
    mode = ExplainMode.instance()
    received: list[bool] = []
    mode.mode_changed.connect(received.append)

    mode.set_enabled(True)  # bereits Default (Einfach) → no-op
    assert received == []


def test_explain_mode_direkter_konstruktor_verboten():
    """Direkter ``ExplainMode``-Aufruf hinter ``instance`` raised."""
    ExplainMode.instance()  # bringt _instance auf Wert
    with pytest.raises(RuntimeError):
        ExplainMode()


# ---------------------------------------------------------------------------
# ExplainableLabel
# ---------------------------------------------------------------------------


def test_explainable_label_default_einfach_zeigt_tooltip(qtbot):
    """Im Default (Einfach) zeigt das Label Erklär-Tooltip + Akzent-Border."""
    label = ExplainableLabel("Netzwerkmonitor", "Live-Bild deines Verkehrs")
    qtbot.add_widget(label)
    assert label.text() == "Netzwerkmonitor"
    assert label.toolTip() == "Live-Bild deines Verkehrs"
    assert "border" in label.styleSheet()


def test_explainable_label_profi_kein_tooltip(qtbot):
    """Im Profi-Modus zeigt das Label nur den Text, keinen Erklär-Tooltip."""
    ExplainMode.instance().set_enabled(False)  # Profi
    label = ExplainableLabel("Netzwerkmonitor", "Live-Bild deines Verkehrs")
    qtbot.add_widget(label)
    assert label.toolTip() == ""
    assert label.styleSheet() == ""


def test_explainable_label_aktiviert_tooltip_im_mode(qtbot):
    """Mode-Toggle setzt den Tooltip + Border-Stylesheet auf das Label."""
    label = ExplainableLabel("X", "Erklärt was X bedeutet")
    qtbot.add_widget(label)

    ExplainMode.instance().set_enabled(True)
    assert label.toolTip() == "Erklärt was X bedeutet"
    assert "border" in label.styleSheet()


def test_explainable_label_zurueck_in_default_bei_mode_off(qtbot):
    """Mode aus räumt Tooltip + Stylesheet wieder weg."""
    label = ExplainableLabel("X", "Erklär-Text")
    qtbot.add_widget(label)

    mode = ExplainMode.instance()
    mode.set_enabled(True)
    mode.set_enabled(False)
    assert label.toolTip() == ""
    assert label.styleSheet() == ""


def test_explainable_label_set_explanation_aktualisiert_live(qtbot):
    """``set_explanation`` wirkt live, wenn der Mode an ist."""
    label = ExplainableLabel("X", "alt")
    qtbot.add_widget(label)
    ExplainMode.instance().set_enabled(True)

    label.set_explanation("neu")
    assert label.toolTip() == "neu"


def test_explainable_label_initialer_push_wenn_mode_bereits_an(qtbot):
    """Wird ein Label erzeugt, während Mode bereits an ist, ist Tooltip sofort gesetzt."""
    ExplainMode.instance().set_enabled(True)
    label = ExplainableLabel("X", "Eintritt mit Mode an")
    qtbot.add_widget(label)
    assert label.toolTip() == "Eintritt mit Mode an"


# ---------------------------------------------------------------------------
# HelpContent.explanations
# ---------------------------------------------------------------------------


def test_help_content_explanations_default_leer():
    """``HelpContent`` ohne explizites ``explanations``-Argument: leeres Dict."""
    hc = HelpContent(
        tool_name="x",
        nav_key="x",
        short_description="x",
        purpose="x",
        when_to_use="x",
        steps=["x"],
        result_explanation="x",
        next_steps="x",
    )
    assert hc.explanations == {}


def test_help_network_monitor_hat_15_explanations():
    """Sprint S1c liefert genau 15 Erklär-Texte für den Network-Monitor."""
    assert len(HELP_NETWORK_MONITOR.explanations) == 15


def test_help_network_monitor_kennt_alle_pilot_keys():
    """Die 15 von der Pilot-Integration erwarteten element_ids sind alle da."""
    expected = {
        "title_widget",
        "col_remote_ip",
        "col_remote_port",
        "col_local_port",
        "col_process",
        "col_pid",
        "col_status",
        "status_established",
        "status_listen",
        "status_time_wait",
        "status_close_wait",
        "status_syn_sent",
        "iface_card",
        "tier_label",
        "last_update_label",
    }
    assert set(HELP_NETWORK_MONITOR.explanations.keys()) == expected


def test_help_explanations_alle_nicht_leer():
    """Jeder Erklär-Text ist mindestens 30 Zeichen lang (kein Stub)."""
    for key, text in HELP_NETWORK_MONITOR.explanations.items():
        assert len(text.strip()) >= 30, f"explanation too short: {key}"


def test_explanations_wenn_vorhanden_nicht_leer():
    """Erklär-Layer sind seit (nis2_incidents) und Phase 1.4 toolüber-
    greifend erlaubt — der frühere S1c-Whitelist-Guard (nur network_monitor)
    ist überholt. Invariante jetzt: jede VORHANDENE Erklärung ist substantiell
    (kein Stub), egal welches Tool sie definiert.
    """
    for hc in ALL_HELP_CONTENTS:
        for key, text in hc.explanations.items():
            assert len(text.strip()) >= 30, (
                f"Tool '{hc.nav_key}' Erklär-Layer '{key}' zu kurz "
                f"({len(text.strip())} Zeichen, min. 30)."
            )


# ---------------------------------------------------------------------------
# Sicherheits-Check: HELP_OUTLINE-Icon ist registriert
# ---------------------------------------------------------------------------


def test_icon_help_outline_registered():
    """Material-Icon ``help_outline`` ist in ``Icons``-Enum verfügbar."""
    from core.icons import Icons  # noqa: PLC0415

    # Indirekter Zugriff — falls das Attribut entfernt wird, raised AttributeError.
    with patch.object(Icons, "HELP_OUTLINE", "help_outline"):
        assert Icons.HELP_OUTLINE == "help_outline"
    # Direkter Zugriff (außerhalb des Patch-Kontexts) muss ebenfalls greifen.
    assert Icons.HELP_OUTLINE == "help_outline"
