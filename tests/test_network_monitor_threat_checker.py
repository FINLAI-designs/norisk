"""Tests für ThreatChecker + blocklist_loader.

Deckt IP-Exact-Match, CIDR-Match, IPv6, ungültige Zeilen und Kommentar-Parsing
sowie F-D) Whitelist-Override und atomaren Live-Refresh ab.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from tools.network_monitor.application.threat_checker import ThreatChecker
from tools.network_monitor.data.blocklist_loader import load_blocklist, load_whitelist


class TestThreatChecker:
    def test_leere_blocklist_meldet_nichts(self) -> None:
        checker = ThreatChecker([])
        assert checker.is_suspicious("8.8.8.8") == (False, "")

    def test_ipv4_exakt(self, tmp_path: Path) -> None:
        f = tmp_path / "b.txt"
        f.write_text("1.2.3.4\n", encoding="utf-8")
        checker = ThreatChecker(load_blocklist(f))
        matched, _reason = checker.is_suspicious("1.2.3.4")
        assert matched is True
        assert checker.is_suspicious("1.2.3.5") == (False, "")

    def test_cidr_match(self, tmp_path: Path) -> None:
        f = tmp_path / "b.txt"
        f.write_text("10.0.0.0/8 # internes Netz\n", encoding="utf-8")
        checker = ThreatChecker(load_blocklist(f))
        matched, reason = checker.is_suspicious("10.1.2.3")
        assert matched is True
        assert reason == "internes Netz"
        assert checker.is_suspicious("11.0.0.1") == (False, "")

    def test_ipv6_cidr(self, tmp_path: Path) -> None:
        f = tmp_path / "b.txt"
        f.write_text("2001:db8::/32\n", encoding="utf-8")
        checker = ThreatChecker(load_blocklist(f))
        matched, _ = checker.is_suspicious("2001:db8::1")
        assert matched is True
        assert checker.is_suspicious("2002::1") == (False, "")

    def test_ungueltige_ip_ist_nicht_suspicious(self, tmp_path: Path) -> None:
        f = tmp_path / "b.txt"
        f.write_text("1.2.3.4\n", encoding="utf-8")
        checker = ThreatChecker(load_blocklist(f))
        assert checker.is_suspicious("nicht-eine-ip") == (False, "")
        assert checker.is_suspicious("") == (False, "")

    def test_leere_und_kommentarzeilen_werden_ignoriert(self, tmp_path: Path) -> None:
        f = tmp_path / "b.txt"
        f.write_text(
            "# Header\n" "\n" "   # eingerückter Kommentar\n" "1.2.3.4\n",
            encoding="utf-8",
        )
        entries = load_blocklist(f)
        assert len(entries) == 1

    def test_ungueltige_zeile_wird_ignoriert_und_crasht_nicht(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "b.txt"
        f.write_text("not-a-network\n1.2.3.4\n", encoding="utf-8")
        entries = load_blocklist(f)
        # Nur die gültige Zeile wird übernommen
        assert len(entries) == 1

    def test_fehlende_datei_liefert_leere_liste(self, tmp_path: Path) -> None:
        assert load_blocklist(tmp_path / "gibts-nicht.txt") == []


class TestWhitelistOverride:
    """ F-D — Whitelist hebt einen Blocklist-/Feed-Treffer auf."""

    def _net(self, spec: str):
        return ipaddress.ip_network(spec, strict=False)

    def test_whitelist_ueberschreibt_exakten_treffer(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("9.9.9.9"), "böse")],
            whitelist=[self._net("9.9.9.9")],
        )
        assert checker.is_suspicious("9.9.9.9") == (False, "")

    def test_whitelist_cidr_ueberschreibt(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("10.1.2.3"), "böse")],
            whitelist=[self._net("10.0.0.0/8")],
        )
        assert checker.is_suspicious("10.1.2.3") == (False, "")

    def test_ohne_whitelist_bleibt_treffer(self) -> None:
        checker = ThreatChecker(entries=[(self._net("9.9.9.9"), "böse")])
        matched, reason = checker.is_suspicious("9.9.9.9")
        assert matched is True
        assert reason == "böse"

    def test_nicht_gewhitelistete_ip_bleibt_verdaechtig(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("9.9.9.9"), "böse"), (self._net("8.8.8.8"), "böse")],
            whitelist=[self._net("9.9.9.9")],
        )
        assert checker.is_suspicious("9.9.9.9") == (False, "")
        assert checker.is_suspicious("8.8.8.8")[0] is True

    def test_fehlende_whitelist_datei_liefert_leere_liste(self, tmp_path: Path) -> None:
        assert load_whitelist(tmp_path / "gibts-nicht.txt") == []

    def test_load_whitelist_parst_netze(self, tmp_path: Path) -> None:
        f = tmp_path / "w.txt"
        f.write_text("# kommentar\n9.9.9.9\n10.0.0.0/8\n", encoding="utf-8")
        nets = load_whitelist(f)
        assert {str(n) for n in nets} == {"9.9.9.9/32", "10.0.0.0/8"}


class TestReplaceEntries:
    """ F-D — atomarer Live-Refresh der Checker-Einträge."""

    def _net(self, spec: str):
        return ipaddress.ip_network(spec, strict=False)

    def test_replace_entries_tauscht_aus(self) -> None:
        checker = ThreatChecker(entries=[(self._net("1.1.1.1"), "alt")])
        assert checker.is_suspicious("1.1.1.1")[0] is True
        checker.replace_entries([(self._net("2.2.2.2"), "neu")])
        assert checker.is_suspicious("1.1.1.1") == (False, "")
        assert checker.is_suspicious("2.2.2.2") == (True, "neu")

    def test_replace_entries_behaelt_whitelist_bei_none(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("1.1.1.1"), "alt")],
            whitelist=[self._net("2.2.2.2")],
        )
        checker.replace_entries([(self._net("2.2.2.2"), "neu")])
        # Whitelist bleibt aktiv → 2.2.2.2 trotz Eintrag nicht verdächtig
        assert checker.is_suspicious("2.2.2.2") == (False, "")

    def test_replace_entries_setzt_neue_whitelist(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("1.1.1.1"), "x")],
            whitelist=[self._net("9.9.9.9")],
        )
        checker.replace_entries([(self._net("1.1.1.1"), "x")], whitelist=[])
        assert checker.is_suspicious("1.1.1.1")[0] is True


class TestReplaceWhitelist:
    """ F-D-GUI — nur die Whitelist tauschen, Einträge unangetastet."""

    def _net(self, spec: str):
        return ipaddress.ip_network(spec, strict=False)

    def test_replace_whitelist_haelt_eintraege(self) -> None:
        checker = ThreatChecker(entries=[(self._net("9.9.9.9"), "böse")])
        assert checker.is_suspicious("9.9.9.9")[0] is True
        checker.replace_whitelist([self._net("9.9.9.9")])
        # Eintrag bleibt, wird aber durch die neue Whitelist aufgehoben
        assert checker.is_suspicious("9.9.9.9") == (False, "")
        assert checker.entry_count() == 1

    def test_replace_whitelist_leert_ausnahmen(self) -> None:
        checker = ThreatChecker(
            entries=[(self._net("9.9.9.9"), "böse")],
            whitelist=[self._net("9.9.9.9")],
        )
        assert checker.is_suspicious("9.9.9.9") == (False, "")
        checker.replace_whitelist([])
        assert checker.is_suspicious("9.9.9.9")[0] is True

    def test_whitelist_count(self) -> None:
        checker = ThreatChecker(entries=[(self._net("1.1.1.1"), "x")])
        assert checker.whitelist_count() == 0
        checker.replace_whitelist([self._net("2.2.2.2"), self._net("3.3.3.3")])
        assert checker.whitelist_count() == 2
        assert checker.entry_count() == 1
