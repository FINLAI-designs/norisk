"""Fuzz-/Property-Tests der ETW-Normalizer F-C-3/F-C-4).

Der ETW-Collector laeuft **elevated** (RunLevel HIGHEST) und verarbeitet Roh-
Events, deren Inhalt ein lokaler (unprivilegierter) Prozess beeinflussen kann:
DNS-Query-Namen, Image-Pfade, Adress-/Port-Felder. Diese Tests verankern, dass
die Normalizer (data-Schicht) gegen feindliche/kaputte Eingaben robust sind:

- sie **werfen nie** (ein kaputtes Event darf die Capture nicht stoppen),
- DNS-Namen + Image-Pfade sind **laengen-begrenzt** und **druckbar** (kein
  unbounded String, keine Steuerzeichen -> kein Log-/Anzeige-Injection, kein
  DB-Bloat),
- Adressen sind valide IP-Strings oder ``""`` (nie Garbage).

Pure data-Funktionen — keine GUI, kein Admin, kein echter ETW-Lauf. Der Zufalls-
Fuzz nutzt einen **festen Seed** (reproduzierbar; ``hypothesis`` ist nicht im
Dependency-Set).
"""

from __future__ import annotations

import ipaddress
import random
import string
from typing import Any

import pytest

from tools.network_monitor.data.dns_event_normalizer import (
    _MAX_QUERY_NAME_LEN,
    normalize_dns_event,
)
from tools.network_monitor.data.etw_event_normalizer import (
    decode_address,
    normalize_kernel_network_event,
)
from tools.network_monitor.data.etw_sanitize import sanitize_text
from tools.network_monitor.data.process_path_tracker import (
    _MAX_ENTRIES,
    _MAX_IMAGE_PATH_LEN,
    KERNEL_PROCESS_START_EVENT_ID,
    ProcessPathTracker,
)

_PS = KERNEL_PROCESS_START_EVENT_ID


def _is_printable(text: str) -> bool:
    return all(ch.isprintable() for ch in text)


# ── sanitize_text (geteilte Haertung) ────────────────────────────────────────


class TestSanitizeText:
    @pytest.mark.parametrize(
        "value",
        [None, 0, -1, 2**64, 3.14, True, b"\x00\x01", [1, 2], {"a": 1}, "ok.com", "", "   "],
    )
    def test_wirft_nie_und_ist_begrenzt_druckbar(self, value: Any) -> None:
        out = sanitize_text(value, max_len=255)
        assert isinstance(out, str)
        assert len(out) <= 255
        assert _is_printable(out)

    def test_begrenzt_laenge(self) -> None:
        assert sanitize_text("a" * 10_000, max_len=255) == "a" * 255

    def test_strippt_steuerzeichen(self) -> None:
        assert sanitize_text("ab\x00\r\n\tcd", max_len=255) == "abcd"

    def test_lone_surrogate_kein_crash(self) -> None:
        assert sanitize_text("x\ud800y", max_len=255) == "xy"

    def test_negatives_max_len_ergibt_leer(self) -> None:
        assert sanitize_text("abc", max_len=-5) == ""


# ── decode_address / Kernel-Network-Adressen ─────────────────────────────────


class TestDecodeAddressRobust:
    @pytest.mark.parametrize(
        "value",
        [
            None, "", "not-an-ip", "999999999999", -1, 2**40, 3.14, True, False,
            b"\x01\x02\x03", b"\x00" * 16, b"", "1.2.3.4", "::1", [1, 2, 3], {"x": 1},
        ],
    )
    def test_gibt_valide_ip_oder_leer(self, value: Any) -> None:
        out = decode_address(value)
        assert isinstance(out, str)
        if out:
            ipaddress.ip_address(out)  # wirft, falls kein valider IP-String


# ── DNS-Normalizer-Haertung ──────────────────────────────────────────────────


class TestDnsNormalizerHardening:
    def test_query_name_laenge_begrenzt(self) -> None:
        out = normalize_dns_event({"ProcessId": 1, "QueryName": "x" * 5000})
        assert len(out["query_name"]) == _MAX_QUERY_NAME_LEN

    def test_query_name_steuerzeichen_gestrippt(self) -> None:
        out = normalize_dns_event({"ProcessId": 1, "QueryName": "evil\r\n\x00.com"})
        assert out["query_name"] == "evil.com"
        assert _is_printable(out["query_name"])

    def test_query_name_nur_steuerzeichen_weggelassen(self) -> None:
        out = normalize_dns_event({"ProcessId": 1, "QueryName": "\x00\r\n"})
        assert "query_name" not in out

    def test_kaputtes_event_kein_crash(self) -> None:
        assert normalize_dns_event({"QueryName": b"\xff\xfe", "EventHeader": 5}) is not None


# ── Process-Path-Tracker-Haertung ────────────────────────────────────────────


class TestProcessPathHardening:
    def test_image_pfad_laenge_begrenzt(self) -> None:
        tracker = ProcessPathTracker()
        tracker.add_event(_PS, {"ProcessId": 42, "ImageName": "C:\\" + "a" * 5000})
        assert len(tracker.resolve(42)) == _MAX_IMAGE_PATH_LEN

    def test_image_steuerzeichen_gestrippt(self) -> None:
        tracker = ProcessPathTracker()
        tracker.add_event(_PS, {"ProcessId": 7, "ImageName": "C:\\evil\x00.exe\r\n"})
        assert tracker.resolve(7) == "C:\\evil.exe"

    def test_image_nur_steuerzeichen_nicht_abgelegt(self) -> None:
        tracker = ProcessPathTracker()
        tracker.add_event(_PS, {"ProcessId": 9, "ImageName": "\x00\r\n"})
        assert tracker.resolve(9) == ""


# ── Zufalls-Fuzz ueber alle Normalizer (fester Seed) ─────────────────────────


def _random_value(rng: random.Random) -> Any:
    kind = rng.randrange(10)
    if kind == 0:
        return None
    if kind == 1:
        return rng.randint(-(2**48), 2**48)
    if kind == 2:
        return rng.uniform(-1e12, 1e12)
    if kind == 3:
        return rng.choice([True, False])
    if kind == 4:  # druckbar; gelegentlich > Pfad-Bound (1024) -> exerziert Truncation
        return "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 2200)))
    if kind == 5:  # bytes; haeufig 4/16 -> exerziert IPv4/IPv6-Adress-Dekodierung
        n = rng.choice([4, 16, rng.randint(0, 20)])
        return bytes(rng.getrandbits(8) for _ in range(n))
    if kind == 6:  # beliebige Unicode-Codepoints inkl. Steuerzeichen/Surrogates
        return "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(rng.randint(0, 80)))
    if kind == 7:
        return [rng.randint(0, 255) for _ in range(rng.randint(0, 4))]
    if kind == 8:
        return {"ProcessId": rng.randint(0, 70_000)}
    return ""


_EVENT_KEYS = (
    "PID", "pid", "size", "Size", "daddr", "saddr", "dport", "sport",
    "QueryName", "queryname", "Name", "QueryType", "querytype",
    "ProcessId", "ProcessID", "ImageName", "ImageFileName", "EventHeader", "junk",
)


def _random_event(rng: random.Random) -> dict[str, Any]:
    return {k: _random_value(rng) for k in _EVENT_KEYS if rng.random() < 0.6}


class TestNormalizerFuzz:
    def test_alle_normalizer_robust_unter_zufalls_input(self) -> None:
        rng = random.Random(0xF1A1)  # fester Seed -> reproduzierbar
        tracker = ProcessPathTracker()
        for _ in range(3000):
            event = _random_event(rng)

            net = normalize_kernel_network_event(event)  # darf nie werfen
            for key in ("daddr", "saddr"):
                if key in net:
                    assert net[key]  # nie leer abgelegt
                    ipaddress.ip_address(net[key])  # valider IP-String

            dns = normalize_dns_event(event)  # darf nie werfen
            if "query_name" in dns:
                assert len(dns["query_name"]) <= _MAX_QUERY_NAME_LEN
                assert _is_printable(dns["query_name"])
            if "pid" in dns:
                assert isinstance(dns["pid"], int)

            tracker.add_event(_PS, event)  # darf nie werfen

        assert len(tracker._paths) <= _MAX_ENTRIES  # noqa: SLF001 — Test prueft SUT-Invariante
        for path in tracker._paths.values():  # noqa: SLF001
            assert len(path) <= _MAX_IMAGE_PATH_LEN
            assert _is_printable(path)
