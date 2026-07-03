"""Tests für die nutzer-editierbare Whitelist F-D-GUI).

Deckt den Data-Writer (``save_whitelist``, ``user_whitelist_path``, Seed-Fallback,
atomares Schreiben) und den DB-freien:class:`WhitelistService` (add/remove/dedup/
Validierung/Persistenz) ab. Keine DB, kein Netz — reine Datei-Operationen.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from tools.network_monitor.application.whitelist_service import WhitelistService
from tools.network_monitor.data import blocklist_loader
from tools.network_monitor.data.blocklist_loader import (
    load_whitelist,
    save_whitelist,
    user_whitelist_path,
)
from tools.network_monitor.domain.exceptions import WhitelistEntryError


@pytest.fixture
def finlai_home(tmp_path: Path):
    """Isoliert ``finlai_dir`` auf ein Wegwerf-Verzeichnis."""
    from core.finlai_paths import set_finlai_home

    set_finlai_home(tmp_path)
    yield tmp_path
    set_finlai_home(None)


# ── Data-Writer ───────────────────────────────────────────────────────────────


class TestSaveWhitelist:
    def test_user_path_unter_finlai_home(self, finlai_home: Path) -> None:
        expected = finlai_home / "network_monitor" / "whitelist.txt"
        assert user_whitelist_path() == expected

    def test_save_legt_verzeichnis_an_und_roundtrip(self, finlai_home: Path) -> None:
        nets = [
            ipaddress.ip_network("203.0.113.10/32"),
            ipaddress.ip_network("10.0.0.0/8"),
        ]
        written = save_whitelist(nets)
        assert written.exists()
        assert written.parent.is_dir()
        loaded = {str(n) for n in load_whitelist()}
        assert loaded == {"203.0.113.10/32", "10.0.0.0/8"}

    def test_save_schreibt_header(self, finlai_home: Path) -> None:
        save_whitelist([ipaddress.ip_network("1.2.3.4/32")])
        text = user_whitelist_path().read_text(encoding="utf-8")
        assert text.startswith("#")
        assert "1.2.3.4/32" in text

    def test_leere_liste_schreibt_nur_header(self, finlai_home: Path) -> None:
        save_whitelist([])
        nets = load_whitelist()
        assert nets == []
        # Datei existiert (nur Kommentar-Header)
        assert user_whitelist_path().exists()

    def test_kein_tmp_artefakt_nach_save(self, finlai_home: Path) -> None:
        save_whitelist([ipaddress.ip_network("1.2.3.4/32")])
        leftovers = list((finlai_home / "network_monitor").glob("*.tmp"))
        assert leftovers == []

    def test_save_explizit_pfad(self, tmp_path: Path) -> None:
        target = tmp_path / "custom.txt"
        save_whitelist([ipaddress.ip_network("9.9.9.9/32")], target)
        assert target.exists()
        assert {str(n) for n in load_whitelist(target)} == {"9.9.9.9/32"}


class TestSeedFallback:
    def test_none_ohne_userdatei_liest_seed(
        self, finlai_home: Path, tmp_path: Path, monkeypatch
    ) -> None:
        # Seed mit echtem Inhalt unterschieben; User-Datei existiert noch nicht.
        seed = tmp_path / "seed.txt"
        seed.write_text("# seed\n198.51.100.7\n", encoding="utf-8")
        monkeypatch.setattr(blocklist_loader, "_seed_whitelist_path", lambda: seed)
        nets = load_whitelist()  # path=None → Profil fehlt → Seed
        assert {str(n) for n in nets} == {"198.51.100.7/32"}

    def test_userdatei_gewinnt_ueber_seed(
        self, finlai_home: Path, tmp_path: Path, monkeypatch
    ) -> None:
        seed = tmp_path / "seed.txt"
        seed.write_text("198.51.100.7\n", encoding="utf-8")
        monkeypatch.setattr(blocklist_loader, "_seed_whitelist_path", lambda: seed)
        save_whitelist([ipaddress.ip_network("203.0.113.1/32")])
        nets = {str(n) for n in load_whitelist()}
        assert nets == {"203.0.113.1/32"}  # Seed ignoriert, sobald Profil da ist

    def test_expliziter_pfad_hat_keinen_seed_fallback(self, tmp_path: Path) -> None:
        assert load_whitelist(tmp_path / "gibtsnicht.txt") == []


# ── WhitelistService ──────────────────────────────────────────────────────────


class TestWhitelistService:
    def _svc(self, tmp_path: Path) -> WhitelistService:
        return WhitelistService(whitelist_path=tmp_path / "wl.txt")

    def test_frisch_leer(self, tmp_path: Path) -> None:
        assert self._svc(tmp_path).load() == []

    def test_add_gueltig(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        net = svc.add("203.0.113.10")
        assert str(net) == "203.0.113.10/32"
        assert {str(n) for n in svc.load()} == {"203.0.113.10/32"}

    def test_add_cidr_und_port_suffix(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("10.0.0.0/8")
        svc.add("8.8.8.8:443")  # Port wird abgetrennt (parse_network_token)
        assert {str(n) for n in svc.load()} == {"10.0.0.0/8", "8.8.8.8/32"}

    def test_add_whitespace_wird_getrimmt(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("  1.2.3.4  ")
        assert {str(n) for n in svc.load()} == {"1.2.3.4/32"}

    def test_add_duplikat_wirft(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("10.0.0.0/8")
        with pytest.raises(WhitelistEntryError):
            svc.add("10.0.0.0/8")

    def test_add_muell_wirft(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        with pytest.raises(WhitelistEntryError):
            svc.add("kein-netz")

    @pytest.mark.parametrize(
        "token", ["0.0.0.0/0", "::/0", "128.0.0.0/1", "10.0.0.0/4", "2001:db8::/16"]
    )
    def test_add_zu_breiter_bereich_wird_abgelehnt(
        self, tmp_path: Path, token: str
    ) -> None:
        # Blanket-Override würde die gesamte Bedrohungserkennung still abschalten.
        svc = self._svc(tmp_path)
        with pytest.raises(WhitelistEntryError):
            svc.add(token)
        assert svc.load() == []  # nichts persistiert

    def test_add_enger_bereich_am_floor_erlaubt(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("10.0.0.0/8")  # IPv4-Floor → erlaubt
        svc.add("2001:db8::/32")  # IPv6-Floor → erlaubt
        assert {str(n) for n in svc.load()} == {"10.0.0.0/8", "2001:db8::/32"}

    def test_add_host_bits_gesetzt_wird_abgelehnt(self, tmp_path: Path) -> None:
        # "203.0.113.10/24" wuerde still zu 203.0.113.0/24 verbreitert -> ablehnen.
        svc = self._svc(tmp_path)
        with pytest.raises(WhitelistEntryError):
            svc.add("203.0.113.10/24")
        assert svc.load() == []

    def test_add_netzadresse_und_einzelhost_ok(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("203.0.113.0/24")  # saubere Netz-Adresse (keine Host-Bits)
        svc.add("203.0.113.5")  # einzelne Host-IP -> /32
        assert {str(n) for n in svc.load()} == {"203.0.113.0/24", "203.0.113.5/32"}

    def test_add_leer_wirft(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        with pytest.raises(WhitelistEntryError):
            svc.add("   ")

    def test_remove(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("10.0.0.0/8")
        n = svc.add("9.9.9.9")
        svc.remove(n)
        assert {str(x) for x in svc.load()} == {"10.0.0.0/8"}

    def test_remove_nicht_vorhanden_ist_noop(self, tmp_path: Path) -> None:
        svc = self._svc(tmp_path)
        svc.add("10.0.0.0/8")
        svc.remove(ipaddress.ip_network("1.2.3.4/32"))  # nicht vorhanden
        assert {str(x) for x in svc.load()} == {"10.0.0.0/8"}

    def test_persistenz_ueber_neue_instanz(self, tmp_path: Path) -> None:
        path = tmp_path / "wl.txt"
        WhitelistService(whitelist_path=path).add("203.0.113.5")
        assert {str(n) for n in WhitelistService(whitelist_path=path).load()} == {
            "203.0.113.5/32"
        }

    def test_default_pfad_nutzt_finlai_home(self, finlai_home: Path) -> None:
        WhitelistService().add("203.0.113.9")  # path=None → Profil
        assert (finlai_home / "network_monitor" / "whitelist.txt").exists()
