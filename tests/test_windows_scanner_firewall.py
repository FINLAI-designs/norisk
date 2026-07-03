"""test_windows_scanner_firewall.

Firewall-False-Negative: Patrick (Live-Test) hat Bitdefender installiert.
Der Scan vertraute frueher AUSSCHLIESSLICH dem im Security Center registrierten
Drittprodukt — war dessen Firewall inaktiv/sekundaer (waehrend die
Windows-Defender-Firewall die tatsaechlich aktive ist), meldete der Scan
faelschlich "keine aktive Firewall".

Deckt die Aggregations-Logik von ``_build_firewall_components`` ab. Der
Bitmask-Parser ``_parse_product_state`` wird gemockt (kein Raten von
WSC-productState-Werten) — getestet wird der Backstop-Entscheid.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.system_scanner.data import windows_scanner as ws


def test_no_thirdparty_uses_builtin_fallback(monkeypatch):
    monkeypatch.setattr(ws, "_query_wmi_security_center", lambda cls: [])
    monkeypatch.setattr(
        ws,
        "_get_windows_firewall_fallback",
        lambda: (ws.ComponentStatus.ACTIVE, "Windows-Firewall aktiv (Profile: Domain)"),
    )
    comps = ws._build_firewall_components()
    assert len(comps) == 1
    assert comps[0].name == "Windows Firewall"
    assert comps[0].status == ws.ComponentStatus.ACTIVE


def test_inactive_thirdparty_still_checks_builtin(monkeypatch):
    # Bitdefender registriert eine INAKTIVE Firewall; Windows-Defender-FW ist aktiv.
    monkeypatch.setattr(
        ws,
        "_query_wmi_security_center",
        lambda cls: [{"displayName": "Bitdefender Firewall", "productState": "0"}],
    )
    monkeypatch.setattr(
        ws, "_parse_product_state", lambda s: ws.ComponentStatus.INACTIVE
    )
    monkeypatch.setattr(
        ws,
        "_get_windows_firewall_fallback",
        lambda: (
            ws.ComponentStatus.ACTIVE,
            "Windows-Firewall aktiv (Profile: Domain, Private, Public)",
        ),
    )
    comps = ws._build_firewall_components()
    status_by_name = {c.name: c.status for c in comps}
    # Drittprodukt erscheint mit seinem (inaktiven) Status...
    assert status_by_name.get("Bitdefender Firewall") == ws.ComponentStatus.INACTIVE
    #... UND die eingebaute Windows-Firewall als aktiver Backstop-Fix).
    assert status_by_name.get("Windows Firewall") == ws.ComponentStatus.ACTIVE


def test_active_thirdparty_skips_builtin(monkeypatch):
    # Aktives Drittprodukt -> kein redundanter Windows-Firewall-Backstop.
    monkeypatch.setattr(
        ws,
        "_query_wmi_security_center",
        lambda cls: [{"displayName": "Bitdefender Firewall", "productState": "1"}],
    )
    monkeypatch.setattr(
        ws, "_parse_product_state", lambda s: ws.ComponentStatus.ACTIVE
    )
    called = {"fallback": False}

    def _fb():
        called["fallback"] = True
        return (ws.ComponentStatus.ACTIVE, "x")

    monkeypatch.setattr(ws, "_get_windows_firewall_fallback", _fb)
    comps = ws._build_firewall_components()
    assert len(comps) == 1
    assert comps[0].name == "Bitdefender Firewall"
    assert called["fallback"] is False
