"""test_sidebar_six_bereiche — config-driven Bereiche-Sidebar, Phase 3).

Verifiziert, dass die App im config-driven Modus
(``groups=NORISK_CONFIG.sidebar_groups``) die statischen Bereiche baut und JEDEN
konfigurierten ``tool_key`` real als Nav-Item rendert — der Schnittmengen-
Filter in ``core.sidebar._build_group_from_config`` darf nichts still
schlucken (Bestandsbug-Schutz aus dem Refactoring-Plan §4).

Bereich „Assistenz" (Security-Chat) entfernt → 5 statt 6
statische Bereiche (vereinter FINLAI-Assistent lebt als Handbuch-Dialog-Reiter).
"""

from __future__ import annotations

import pytest
from apps.app_config import NORISK_CONFIG
from PySide6.QtCore import Qt

from core.auth.session import Session
from core.sidebar import SidebarWidget
from core.ui_settings import UISettings

pytestmark = pytest.mark.gui

# Reihenfolge cockpit · lage · bewerten („Sicherheit & Audit")
# · ueberwachen („Überwachung") · pruefen („Scanner") · links. Interne Keys stabil.
_EXPECTED_GROUP_ORDER: list[str] = [
    "cockpit",
    "lage",
    "bewerten",
    "ueberwachen",
    "pruefen",
    "links",
]


def _build(qtbot) -> SidebarWidget:
    widget = SidebarWidget(
        [], Session(), UISettings.load(), groups=NORISK_CONFIG.sidebar_groups
    )
    qtbot.addWidget(widget)
    return widget


def test_config_driven_sidebar_rendert_alle_tool_keys(qtbot, app) -> None:
    """Jeder konfigurierte tool_key muss als Nav-Item gerendert werden."""
    widget = _build(qtbot)
    rendered = {getattr(i, "_key", None) for i in widget._all_nav_items}
    for grp in NORISK_CONFIG.sidebar_groups:
        for tool_key in grp.get("tool_keys", []):
            assert tool_key in rendered, (
                f"{tool_key} (Gruppe '{grp['key']}') wird nicht gerendert"
            )
    # Einstellungen lebt fix in der Bottom-Leiste (kein eigener Bereich)
    assert "einstellungen" in rendered


def test_statische_bereiche_plus_links(qtbot, app) -> None:
    """Genau 5 statische Bereiche + dynamische Links-Gruppe, in Reihenfolge
: „Assistenz" entfernt, vorher 6)."""
    widget = _build(qtbot)
    keys = [getattr(g, "_key", None) for g in widget._all_groups]
    assert keys == _EXPECTED_GROUP_ORDER


def test_cockpit_hat_home_item_als_erstes(qtbot, app) -> None:
    """: Die Cockpit-Gruppe enthält das 'home'-Item an erster Stelle —
    es ersetzt den entfernten Sidebar-Logo-Klick als einzigen Home-Pfad."""
    widget = _build(qtbot)
    cockpit = next(g for g in widget._all_groups if g._key == "cockpit")
    child_keys = [getattr(c, "_key", None) for c in cockpit._children]
    assert child_keys[0] == "home"


def test_klick_auf_home_item_emittiert_navigate_home(qtbot, app) -> None:
    """: Klick auf das 'home'-Item feuert ``navigate`` mit 'home'
    (gleicher Vertrag wie der frühere Logo-Button)."""
    widget = _build(qtbot)
    widget.show()
    home_item = next(
        i for i in widget._all_nav_items if getattr(i, "_key", None) == "home"
    )
    with qtbot.waitSignal(widget.navigate, timeout=1000) as blocker:
        qtbot.mouseClick(home_item, Qt.MouseButton.LeftButton)
    assert blocker.args == ["home"]


def test_sidebar_hat_keinen_logo_header_mehr(qtbot, app) -> None:
    """: Der Logo-Header (Dublette der Titelbar) ist entfernt."""
    widget = _build(qtbot)
    assert not hasattr(widget, "_logo_container")
    assert not hasattr(widget, "_logo_btn")
    assert not hasattr(widget, "_lbl_logo_title")
