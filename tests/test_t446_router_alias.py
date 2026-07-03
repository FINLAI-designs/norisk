"""test_t446_router_alias — Router-Alias-Auflösung für den Bewerten-Merge.

Nach dem Merge der vier Bewerten-Tools in den Container
``security_assessment`` und dem Techstack-Umzug in den Advisory-Monitor biegt
``NavigationMixin._resolve_tool_alias`` die alten Einzel-Tool-Keys transparent
auf den richtigen Container + Sub-Tab um — damit bestehende CTAs/Deeplinks
(Cockpit-Kacheln, Dashboard-NIS2-Sektion) ohne Änderung weiterlaufen.

Reine Logik (kein Qt) — läuft im schnellen Nicht-GUI-Gate.
"""

from __future__ import annotations

import pytest

from core.navigation_mixin import NavigationMixin
from core.navigation_mixin import _resolve_tool_alias as _resolve


def test_customer_audit_default_auf_audit_tab() -> None:
    assert _resolve("customer_audit", {}) == ("security_assessment", {"tab": "audit"})


def test_customer_audit_tab_nis2_wird_durchgereicht() -> None:
    """Dashboard-NIS2-CTA: navigate('customer_audit', tab='nis2')."""
    assert _resolve("customer_audit", {"tab": "nis2"}) == (
        "security_assessment",
        {"tab": "nis2"},
    )


def test_customer_audit_tab_audits_wird_auf_audit_gemappt() -> None:
    """Alt-Wert 'audits' (Plural) -> Container-Sub-Tab 'audit'."""
    assert _resolve("customer_audit", {"tab": "audits"}) == (
        "security_assessment",
        {"tab": "audit"},
    )


@pytest.mark.parametrize(
    ("old_key", "sub_tab"),
    [
        ("nis2_incidents", "nis2"),
        ("security_scoring", "score"),
        ("awareness_tracker", "awareness"),
    ],
)
def test_einzeltool_keys_auf_container_subtab(old_key: str, sub_tab: str) -> None:
    assert _resolve(old_key, {}) == ("security_assessment", {"tab": sub_tab})


def test_techstack_auf_advisory_monitor_ohne_tab() -> None:
    """techstack lebt im Advisory-Monitor (Tab 0); Alias öffnet ihn ohne tab-kwarg."""
    assert _resolve("techstack", {}) == ("csaf_advisor", {})


def test_unbekannter_key_unveraendert() -> None:
    """Nicht-Alias-Keys werden samt kwargs unverändert durchgereicht."""
    assert _resolve("patch_monitor", {"focus": "outdated"}) == (
        "patch_monitor",
        {"focus": "outdated"},
    )


# ---------------------------------------------------------------------------
# Integrationspfad: navigate_to(<alt-key>) -> _on_sidebar_navigate(Container) +
# apply_navigation(tab=...). Regressions-Lock fuer den P0-Fix (Cockpit-CTA, die
# alte Keys ueber navigate_to schicken, muessen den richtigen Sub-Tab oeffnen).
# ---------------------------------------------------------------------------


class _ApplyRecorder:
    """Container-Widget-Stub: zeichnet apply_navigation-Aufrufe auf."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def apply_navigation(self, **kwargs) -> None:  # noqa: ANN003
        self.calls.append(kwargs)


class _RouterStub:
    """Minimaler NavigationMixin-Router-Stub (wie test_navigate_to_kwargs)."""

    def __init__(self) -> None:
        self.navigated: list[str] = []
        self.widget = _ApplyRecorder()

    def _on_sidebar_navigate(self, key: str) -> None:
        self.navigated.append(key)

    def _get_active_widget_for(self, key: str) -> object:  # noqa: ARG002
        return self.widget


def _drive(key: str, **kwargs) -> _RouterStub:  # noqa: ANN003
    stub = _RouterStub()
    NavigationMixin.navigate_to(stub, key, **kwargs)  # type: ignore[arg-type]
    return stub


def test_navigate_to_customer_audit_oeffnet_container_audit_tab() -> None:
    stub = _drive("customer_audit")
    assert stub.navigated == ["security_assessment"]
    assert stub.widget.calls == [{"tab": "audit"}]


def test_navigate_to_customer_audit_nis2_payload_oeffnet_nis2_tab() -> None:
    """Cockpit-NIS2-CTA: navigate_to('customer_audit', tab='nis2')."""
    stub = _drive("customer_audit", tab="nis2")
    assert stub.navigated == ["security_assessment"]
    assert stub.widget.calls == [{"tab": "nis2"}]


def test_navigate_to_security_scoring_oeffnet_score_tab() -> None:
    stub = _drive("security_scoring")
    assert stub.navigated == ["security_assessment"]
    assert stub.widget.calls == [{"tab": "score"}]


def test_navigate_to_techstack_oeffnet_advisory_monitor_ohne_tab() -> None:
    """techstack -> Advisory-Monitor (Tab 0); kein tab-kwarg -> kein apply_navigation."""
    stub = _drive("techstack")
    assert stub.navigated == ["csaf_advisor"]
    assert stub.widget.calls == []
