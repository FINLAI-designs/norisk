"""
test_deeplink_registry — Tests für core/deeplink_registry + Router.

Abdeckung:
  * Registry-Lookups (bekannt/unbekannt; Dashboard-Filter-kwarg).
  * Manifest-Konsistenz (jeder Dashboard-Filter-kwarg ist im Tool-Manifest).
  * Router ``_on_dashboard_open_with_filter`` übersetzt den Payload generisch
    über die Registry in ``navigate_to(key, <kwarg>=payload)`` — kein hart
    kodierter ``if key == "csaf_advisor"`` mehr.
  * CSAF-Receiver ``apply_navigation(cve_id=…)`` delegiert an set_cve_filter.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.deeplink_registry import (
    _DASHBOARD_FILTER_KWARG,
    DEEPLINK_TARGETS,
    accepted_kwargs,
    dashboard_filter_kwarg,
)
from core.navigation_mixin import NavigationMixin


class TestRegistryLookups:
    def test_accepted_kwargs_bekanntes_tool(self):
        assert accepted_kwargs("csaf_advisor") == {"cve_id": str}
        assert accepted_kwargs("network_scanner") == {"target": str}

    def test_accepted_kwargs_unbekanntes_tool_leer(self):
        assert accepted_kwargs("gibt_es_nicht") == {}

    def test_dashboard_filter_kwarg(self):
        assert dashboard_filter_kwarg("csaf_advisor") == "cve_id"
        # network_scanner akzeptiert target via apply_navigation, aber KEINEN
        # Dashboard-Filter-Payload → None.
        assert dashboard_filter_kwarg("network_scanner") is None
        assert dashboard_filter_kwarg("gibt_es_nicht") is None

    def test_manifest_konsistent(self):
        # Jeder Dashboard-Filter-kwarg muss im Tool-Manifest deklariert sein.
        for key, kwarg in _DASHBOARD_FILTER_KWARG.items():
            assert kwarg in DEEPLINK_TARGETS.get(key, {}), (key, kwarg)

    def test_alle_targets_sind_gueltige_nav_keys(self):
        # Drift-Guard: jeder DEEPLINK_TARGETS-Key muss ein echter Nav-Key sein
        # (sonst läuft der Deep-Link still ins Leere). Quelle wie
        # test_nav_tool_map_completeness.
        #
        # 3c 1b Vision B): ``norisk:dashboard`` (Cockpit) hat
        # KEINEN _NAV_TOOL_MAP-Eintrag mehr — es IST das Welcome-Dock und wird in
        # ``NavigationMixin._on_sidebar_navigate`` explizit aufs Welcome-Dock
        # geroutet. Der Deep-Link landet also nicht im Leeren; daher wie ``home``
        # ein erlaubter Sonder-Key ohne eigenen Dock-Eintrag.
        # ``customer_audit`` ist jetzt ein Router-Alias auf den Bewerten-
        # Container (``security_assessment``) — ebenfalls ein gueltiges Ziel.
        from core.main_window import MainWindow
        from core.navigation_mixin import _TOOL_ALIASES

        nav_keys = {nav_key for nav_key, *_ in MainWindow._NAV_TOOL_MAP}
        welcome_dock_keys = {"home", "norisk:dashboard"}
        allowed = nav_keys | welcome_dock_keys | set(_TOOL_ALIASES)
        unbekannt = set(DEEPLINK_TARGETS) - allowed
        assert not unbekannt, f"DEEPLINK_TARGETS-Keys ohne Nav-Eintrag: {unbekannt}"


class _Win(NavigationMixin):
    """Minimaler Router-Stub: zeichnet navigate_to-Aufrufe auf."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def navigate_to(self, key, **kwargs):  # type: ignore[override]
        self.calls.append((key, kwargs))


class TestRouterDispatch:
    def test_registrierter_key_uebersetzt_payload_in_kwarg(self):
        w = _Win()
        w._on_dashboard_open_with_filter("csaf_advisor", "CVE-2026-0001")
        assert w.calls == [("csaf_advisor", {"cve_id": "CVE-2026-0001"})]

    def test_unregistrierter_key_nur_oeffnen(self):
        w = _Win()
        w._on_dashboard_open_with_filter("system_scanner", object())
        assert w.calls == [("system_scanner", {})]

    def test_registriert_ohne_dashboard_filter_nur_oeffnen(self):
        # network_scanner steht in DEEPLINK_TARGETS, hat aber keinen
        # Dashboard-Filter-kwarg -> nur öffnen.
        w = _Win()
        w._on_dashboard_open_with_filter("network_scanner", "irgendwas")
        assert w.calls == [("network_scanner", {})]

    def test_payload_typ_mismatch_oeffnet_fail_safe_ohne_filter(self):
        # csaf_advisor erwartet cve_id:str; ein int-Payload ist ungültig
        # -> fail-safe: Tool ohne Filter öffnen, kein Crash.
        w = _Win()
        w._on_dashboard_open_with_filter("csaf_advisor", 123)
        assert w.calls == [("csaf_advisor", {})]


class TestCsafReceiver:
    def test_apply_navigation_delegiert_an_set_cve_filter(self):
        from tools.csaf_advisor.gui.csaf_advisor_widget import CsafAdvisorWidget

        class _Stub:
            def __init__(self):
                self.received: list[str] = []

            def set_cve_filter(self, value):
                self.received.append(value)

        stub = _Stub()
        CsafAdvisorWidget.apply_navigation(stub, cve_id="CVE-2026-0001")
        assert stub.received == ["CVE-2026-0001"]

    def test_apply_navigation_ohne_cve_id_ignoriert(self):
        from tools.csaf_advisor.gui.csaf_advisor_widget import CsafAdvisorWidget

        class _Stub:
            def __init__(self):
                self.received: list[str] = []

            def set_cve_filter(self, value):
                self.received.append(value)

        stub = _Stub()
        CsafAdvisorWidget.apply_navigation(stub, foo="bar")
        assert stub.received == []
