"""test_t310_nis2_tab Phase B, fortgeschrieben fuer.

Sperrt die Invarianten der ``nis2_incidents``-Integration ein. hat die Bewerten-Tools in EINEN Container ``security_assessment``
gemergt; die hier gelockten Invarianten wurden entsprechend nachgezogen:

- Der Deeplink-Kontrakt ``navigate('customer_audit', tab='nis2')`` bleibt
  registriert (Dashboard-NIS2-CTA); der Router biegt ihn per Alias auf den
  Container + Sub-Tab ``nis2`` um.
- nis2_incidents bleibt als Modul registriert (Container-Factory + Build-Spec),
  hat aber kein eigenes Sidebar-Dock mehr — es ist der vierte Sub-Tab des
  Bewerten-Containers. Gleiches gilt fuer customer_audit/security_scoring/
  awareness_tracker.
- ``dock_state``-Reset bei Versionssprung (verwaiste ``dock_*``-objectNames der
  entfallenen Einzel-Docks).

Bezug: [[-bewerten-bereich-ia]],
``docs/audits/AUDIT_T310_SECURITY_BEREICH_IA.md``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from apps.app_config import NORISK_CONFIG

from core.deeplink_registry import (
    DEEPLINK_TARGETS,
    accepted_kwargs,
    dashboard_filter_kwarg,
)


def test_nis2_ist_subtab_kein_sidebar_item() -> None:
    """: nis2_incidents bleibt registriert (Container-Factory + Build-Spec),
    ist aber KEIN eigener Sidebar-Eintrag mehr — es ist der vierte Sub-Tab des
    Bewerten-Containers. Im ``bewerten``-tool_keys steht nur der Container;
    nis2_incidents taucht in keiner Sidebar-Gruppe als tool_key auf."""
    assert "tools.nis2_incidents.tool" in NORISK_CONFIG.tool_modules
    bewerten = next(
        g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "bewerten"
    )
    assert "security_assessment" in bewerten["tool_keys"]
    for group in NORISK_CONFIG.sidebar_groups:
        assert "nis2_incidents" not in group.get("tool_keys", []), (
            f"nis2_incidents faelschlich als Sidebar-tool_key in "
            f"'{group.get('key')}'"
        )
    from tools.security_assessment.tool import _build_tab_specs  # noqa: PLC0415

    assert "nis2" in [spec[0] for spec in _build_tab_specs()]


def test_bewerten_einzeltools_kein_eigenes_dock_alias_stattdessen() -> None:
    """: Die Bewerten-Einzel-Tools haben kein eigenes Dock mehr — weder
    nis2_incidents noch customer_audit/security_scoring/awareness_tracker (und
    techstack) stehen im _NAV_TOOL_MAP. Stattdessen ist der Container
    ``security_assessment`` registriert, und der Router-Alias biegt die alten
    Keys auf ihn (bzw. techstack auf den Advisory-Monitor) um."""
    from core.main_window import MainWindow  # noqa: PLC0415
    from core.navigation_mixin import _TOOL_ALIASES  # noqa: PLC0415

    by_key = {nav_key: rest for nav_key, *rest in MainWindow._NAV_TOOL_MAP}  # noqa: SLF001
    assert "security_assessment" in by_key
    assert by_key["security_assessment"][0] == "Security-Bewertung"
    for old in (
        "customer_audit",
        "nis2_incidents",
        "security_scoring",
        "awareness_tracker",
        "techstack",
    ):
        assert old not in by_key, f"{old} hat faelschlich noch ein eigenes Dock"
    assert _TOOL_ALIASES["nis2_incidents"] == ("security_assessment", "nis2")
    assert _TOOL_ALIASES["customer_audit"] == ("security_assessment", "audit")
    assert _TOOL_ALIASES["techstack"][0] == "csaf_advisor"


def test_deeplink_customer_audit_tab_registriert() -> None:
    """Deeplink-Kontrakt für die NIS2-Tab-Vorauswahl ist vorhanden."""
    assert DEEPLINK_TARGETS.get("customer_audit") == {"tab": str}
    assert accepted_kwargs("customer_audit") == {"tab": str}
    assert dashboard_filter_kwarg("customer_audit") == "tab"


def test_deeplink_drift_guard_haelt() -> None:
    """Jedes Deeplink-Target ist ein gueltiger Nav-Key, Welcome-Dock-Sonderkey
    ODER ein Router-Alias.

 3c 1b Vision B): ``norisk:dashboard`` (Cockpit) ist ein
    Welcome-Dock-Sonderkey ohne eigenen _NAV_TOOL_MAP-Eintrag (wie ``home``).
    ``customer_audit`` ist jetzt ein Router-Alias auf den Bewerten-
    Container statt eines eigenen Nav-Keys.
    """
    from core.main_window import MainWindow  # noqa: PLC0415
    from core.navigation_mixin import _TOOL_ALIASES  # noqa: PLC0415

    nav_keys = {nav_key for nav_key, *_ in MainWindow._NAV_TOOL_MAP}  # noqa: SLF001
    welcome_dock_keys = {"home", "norisk:dashboard"}
    allowed = nav_keys | welcome_dock_keys | set(_TOOL_ALIASES)
    assert set(DEEPLINK_TARGETS) <= allowed


def test_dock_state_reset_bei_versionssprung() -> None:
    """Alt-Blob wird bei ``version < CURRENT`` einmalig verworfen."""
    from core.dock_mixin import _DOCK_STATE_VERSION, DockMixin  # noqa: PLC0415
    from core.ui_settings import UISettings  # noqa: PLC0415

    settings = UISettings(dock_state="QlpoOTFBWS==", dock_state_version=0)
    stub = DockMixin.__new__(DockMixin)
    stub._settings = settings  # noqa: SLF001
    stub._inner_main = MagicMock()  # noqa: SLF001 -- darf im Reset-Pfad nicht angefasst werden
    DockMixin._restore_dock_state(stub)  # noqa: SLF001

    assert settings.dock_state == ""
    assert settings.dock_state_version == _DOCK_STATE_VERSION
    stub._inner_main.restoreState.assert_not_called()  # noqa: SLF001


def test_dock_state_restore_bei_aktueller_version() -> None:
    """Bei aktueller Version wird der gespeicherte Blob normal restauriert."""
    from core.dock_mixin import _DOCK_STATE_VERSION, DockMixin  # noqa: PLC0415
    from core.ui_settings import UISettings  # noqa: PLC0415

    settings = UISettings(
        dock_state="QlpoOTFBWS==", dock_state_version=_DOCK_STATE_VERSION
    )
    stub = DockMixin.__new__(DockMixin)
    stub._settings = settings  # noqa: SLF001
    stub._inner_main = MagicMock()  # noqa: SLF001
    # c0b 4178a86: _restore_dock_state liest auf dem Aktuell-Version-Pfad jetzt
    # self._docks (Floating-Redock); der Stub muss es wie der echte __init__ setzen.
    stub._docks = {}  # noqa: SLF001
    DockMixin._restore_dock_state(stub)  # noqa: SLF001

    stub._inner_main.restoreState.assert_called_once()  # noqa: SLF001
    assert settings.dock_state == "QlpoOTFBWS=="  # unverändert
