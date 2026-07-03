"""Tests für core.os_info Phase E — Host-OS-Eckdaten, fail-soft)."""

from __future__ import annotations

import pytest

from core.os_info import HostOsInfo, _normalize_product, detect_host_os_info


class TestNormalizeProduct:
    def test_win10_zu_win11_ab_build_22000(self) -> None:
        assert _normalize_product("Windows 10 Pro", "22631") == "Windows 11 Pro"

    def test_win10_bleibt_unter_22000(self) -> None:
        assert _normalize_product("Windows 10 Pro", "19045") == "Windows 10 Pro"

    def test_kein_win10_unveraendert(self) -> None:
        assert _normalize_product("Windows 11 Home", "22631") == "Windows 11 Home"

    def test_unparsebarer_build_unveraendert(self) -> None:
        # fail-soft: ohne verwertbaren Build keine (falsche) Korrektur.
        assert _normalize_product("Windows 10 Pro", None) == "Windows 10 Pro"
        assert _normalize_product("Windows 10 Pro", "xx") == "Windows 10 Pro"

    def test_leeres_produkt(self) -> None:
        assert _normalize_product(None, "22631") == ""


class TestAnzeige:
    def test_voll(self) -> None:
        info = HostOsInfo(
            system="Windows",
            product="Windows 11 Pro",
            display_version="23H2",
            build="22631",
            architecture="AMD64",
        )
        assert info.anzeige == "Windows 11 Pro · 23H2 · Build 22631 · AMD64"

    def test_nur_system(self) -> None:
        assert HostOsInfo(system="Linux").anzeige == "Linux"

    def test_leere_felder_werden_ausgelassen(self) -> None:
        info = HostOsInfo(system="Windows", product="Windows 11 Pro", build="22631")
        assert info.anzeige == "Windows 11 Pro · Build 22631"


class TestDetect:
    def test_liefert_hostosinfo_ohne_crash(self) -> None:
        # fail-soft Smoke auf der echten Plattform — system nie leer.
        info = detect_host_os_info()
        assert isinstance(info, HostOsInfo)
        assert info.system
        assert info.anzeige  # mindestens system

    def test_nicht_windows_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("core.os_info.platform.system", lambda: "Linux")
        monkeypatch.setattr("core.os_info.platform.release", lambda: "6.8.0")
        monkeypatch.setattr("core.os_info.platform.machine", lambda: "x86_64")
        monkeypatch.setattr("core.os_info.platform.version", lambda: "#1 SMP")
        info = detect_host_os_info()
        assert info.system == "Linux"
        assert info.product == "Linux 6.8.0"
        assert info.architecture == "x86_64"
        assert info.display_version == ""  # keine Registry auf Nicht-Windows
