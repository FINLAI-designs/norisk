"""
test_nav_tool_map_completeness — Regression fuer.

Jeder Sidebar-Item mit nicht-spezial-Key muss einen Eintrag im
``_NAV_TOOL_MAP`` haben — sonst fuehrt der Sidebar-Klick zu
``Unbekannter Navigationsschluessel`` statt das Dock zu oeffnen.

Historischer Aufhaenger: ``security_chat`` (entfernt 2026-05-14 in
) fehlte in ``_NAV_TOOL_MAP``. Dieser Generic-Test deckt das
Pattern fuer alle aktuellen + kuenftigen Tools ab.
"""

from __future__ import annotations

from apps.app_config import NORISK_CONFIG

from core.main_window import MainWindow

# Keys die KEINEN ``_NAV_TOOL_MAP``-Eintrag brauchen weil sie kein Tool sind
# (``home``). DeepL (``ki:deepl``) wurde am 2026-05-28 durch
# entfernt; der Security-Chat (``ki:ollama``) am 2026-06-13 durch
# (vereinter FINLAI-Assistent als Handbuch-Dialog-Reiter, kein Sidebar-Tool).
_SIDEBAR_KEYS_WITHOUT_NAV_MAP_ENTRY: frozenset[str] = frozenset({"home"})


def test_alle_sidebar_items_haben_nav_tool_map_eintrag() -> None:
    """Jeder Sidebar-Item ohne Spezial-Key muss im _NAV_TOOL_MAP stehen
    — sonst fuehrt der Klick ins Leere."""
    nav_keys = {nav_key for nav_key, *_ in MainWindow._NAV_TOOL_MAP}
    fehlende: list[str] = []
    for group in NORISK_CONFIG.sidebar_groups:
        for tool_key in group.get("tool_keys", []):
            if tool_key in _SIDEBAR_KEYS_WITHOUT_NAV_MAP_ENTRY:
                continue
            if tool_key not in nav_keys:
                fehlende.append(
                    f"{tool_key} (in Sidebar-Gruppe '{group.get('key')}')"
                )
    assert fehlende == [], (
        "Sidebar-Items ohne _NAV_TOOL_MAP-Eintrag: "
        + ", ".join(fehlende)
        + ". Bitte in core/main_window.py ergaenzen."
    )


def test_keine_doppelten_nav_keys() -> None:
    """``_NAV_TOOL_MAP`` darf keine doppelten Nav-Keys haben — sonst
    waere die Dock-Zuordnung mehrdeutig."""
    nav_keys = [nav_key for nav_key, *_ in MainWindow._NAV_TOOL_MAP]
    duplikate = [k for k in nav_keys if nav_keys.count(k) > 1]
    assert duplikate == [], (
        f"Doppelte Nav-Keys in _NAV_TOOL_MAP: {set(duplikate)}"
    )


def test_security_chat_nicht_mehr_in_sidebar() -> None:
    """: Security-Chat-Tool wurde entfernt — darf
    weder in tool_modules noch in sidebar_groups auftauchen.

    Regression-Schutz gegen versehentliches Re-Add aus alten Configs.
    """
    assert (
        "tools.security_chat.tool" not in NORISK_CONFIG.tool_modules
    ), "security_chat darf nicht mehr in tool_modules sein"
    for group in NORISK_CONFIG.sidebar_groups:
        assert "security_chat" not in group.get("tool_keys", []), (
            f"security_chat darf nicht mehr in Sidebar-Gruppe "
            f"'{group.get('key')}' stehen"
        )


def test_ki_integration_nicht_mehr_in_sidebar() -> None:
    """: Der Security-Chat (ki_integration / ki:ollama) wurde
    als Sidebar-Tool entfernt — der vereinte FINLAI-Assistent lebt als Reiter im
    Handbuch-Dialog. Weder Tool-Modul noch Sidebar-Key duerfen wieder auftauchen.

    Regression-Schutz gegen versehentliches Re-Add aus alten Configs.
    """
    assert (
        "tools.ki_integration.tool" not in NORISK_CONFIG.tool_modules
    ), "tools.ki_integration.tool darf nicht mehr in tool_modules sein (T-363)"
    for group in NORISK_CONFIG.sidebar_groups:
        assert "ki:ollama" not in group.get("tool_keys", []), (
            f"ki:ollama darf nicht mehr in Sidebar-Gruppe "
            f"'{group.get('key')}' stehen (T-363)"
        )
