"""Tests für die Windows-Edition-/Generations-Erkennung (system_tuner).

Schwerpunkt: ``ProductName`` meldet auf Windows 11 weiterhin "Windows 10" —
erst ``CurrentBuild >= 22000`` unterscheidet die Generationen (Live-Test-Bug
2026-06-27: "warum steht hier 'Sie nutzen Windows 10 Home'?").
"""

from __future__ import annotations

from tools.system_tuner.application.edition_gate import _normalize_product


def test_win11_build_korrigiert_windows_10():
    assert _normalize_product("Windows 10 Home", "22631") == "Windows 11 Home"
    assert _normalize_product("Windows 10 Pro", "22000") == "Windows 11 Pro"


def test_win10_build_bleibt_windows_10():
    assert _normalize_product("Windows 10 Home", "19045") == "Windows 10 Home"


def test_unbekannter_oder_kaputter_build_unveraendert():
    assert _normalize_product("Windows 10 Home", None) == "Windows 10 Home"
    assert _normalize_product("Windows 10 Home", "") == "Windows 10 Home"
    assert _normalize_product("Windows 10 Home", "n/a") == "Windows 10 Home"


def test_nicht_windows10_oder_none_unangetastet():
    assert _normalize_product("Windows 11 Pro", "22631") == "Windows 11 Pro"
    assert _normalize_product("Windows Server 2022", "20348") == "Windows Server 2022"
    assert _normalize_product(None, "22631") is None
