"""Tests fuer den ETW-Event-Normalizer B2.1).

Deckt die IP-Dekodierung (UInt32/Binary/String) und die Event-Normalisierung
ab — alles admin-frei, ohne ETW.
"""

from __future__ import annotations

import socket

from tools.network_monitor.data.etw_event_normalizer import (
    decode_address,
    decode_ipv4_uint32,
    decode_ipv6_bytes,
    normalize_kernel_network_event,
)

# "1.2.3.4" als Little-Endian-UInt32: 1 + 2*256 + 3*65536 + 4*16777216.
_IPV4_1234_LE: int = 67_305_985


class TestDecodeIpv4:
    def test_uint32_little_endian(self) -> None:
        assert decode_ipv4_uint32(_IPV4_1234_LE) == "1.2.3.4"

    def test_zero_ist_null_adresse(self) -> None:
        assert decode_ipv4_uint32(0) == "0.0.0.0"

    def test_ausserhalb_bereich_gibt_leer(self) -> None:
        assert decode_ipv4_uint32(-1) == ""
        assert decode_ipv4_uint32(0x1_0000_0000) == ""


class TestDecodeIpv6:
    def test_roundtrip(self) -> None:
        raw = socket.inet_pton(socket.AF_INET6, "2607:f8b0::1")
        assert decode_ipv6_bytes(raw) == "2607:f8b0::1"

    def test_falsche_laenge_gibt_leer(self) -> None:
        assert decode_ipv6_bytes(b"\x00\x01\x02") == ""


class TestDecodeAddress:
    def test_gueltiger_string_passthrough(self) -> None:
        assert decode_address("8.8.8.8") == "8.8.8.8"

    def test_zahl_string_wird_uint32(self) -> None:
        assert decode_address(str(_IPV4_1234_LE)) == "1.2.3.4"

    def test_int_wird_ipv4(self) -> None:
        assert decode_address(_IPV4_1234_LE) == "1.2.3.4"

    def test_vier_bytes_network_order(self) -> None:
        assert decode_address(b"\x01\x02\x03\x04") == "1.2.3.4"

    def test_sechzehn_bytes_wird_ipv6(self) -> None:
        raw = socket.inet_pton(socket.AF_INET6, "2607:f8b0::1")
        assert decode_address(raw) == "2607:f8b0::1"

    def test_none_gibt_leer(self) -> None:
        assert decode_address(None) == ""

    def test_bool_gibt_leer(self) -> None:
        # bool ist int-Subklasse — darf NICHT als Adresse durchgehen.
        assert decode_address(True) == ""

    def test_unbekannte_laenge_gibt_leer(self) -> None:
        assert decode_address(b"\x01\x02\x03") == ""


class TestNormalizeEvent:
    def test_send_event_decodiert_daddr_mit_port(self) -> None:
        raw = {"PID": "1234", "size": "500", "daddr": _IPV4_1234_LE, "dport": 443}
        out = normalize_kernel_network_event(raw)
        assert out == {
            "PID": "1234",
            "size": "500",
            "daddr": "1.2.3.4",
            "dport": 443,
        }

    def test_recv_event_decodiert_saddr_mit_port(self) -> None:
        raw = {"PID": 99, "size": 200, "saddr": b"\x08\x08\x08\x08", "sport": 5040}
        out = normalize_kernel_network_event(raw)
        assert out == {"PID": 99, "size": 200, "saddr": "8.8.8.8", "sport": 5040}

    def test_pid_kleingeschrieben_wird_erkannt(self) -> None:
        out = normalize_kernel_network_event({"pid": 7, "Size": 10})
        assert out == {"PID": 7, "size": 10}

    def test_fehlende_felder_werden_ausgelassen(self) -> None:
        assert normalize_kernel_network_event({}) == {}

    def test_leere_adresse_wird_nicht_aufgenommen(self) -> None:
        out = normalize_kernel_network_event({"PID": 1, "size": 2, "daddr": None})
        assert out == {"PID": 1, "size": 2}
